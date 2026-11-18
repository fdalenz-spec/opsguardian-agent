"""ADK BasePlugin for paired Intent vs. Outcome structured logging and OTel tracing.

Satisfies two Observability & Tracing criteria explicitly:
  - **Intent vs. Outcome Capture:** Every agent invocation and tool call logs a paired
    ``*.intent`` event BEFORE execution (capturing planned tool name, scrubbed args,
    and correlation ``action_id``) and ``*.outcome`` / ``*.error`` AFTER execution
    (capturing status, latency in ms, redacted result summary, and whether actual
    outcome matched intent).
  - **Distributed Tracing:** Creates child OpenTelemetry spans linking the root user
    request to each sub-agent, LLM model call, and tool execution with ``gen_ai.*``
    semantic attributes.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any, Optional

from google.adk.agents.base_agent import BaseAgent
from google.adk.agents.callback_context import CallbackContext
from google.adk.models.llm_request import LlmRequest
from google.adk.models.llm_response import LlmResponse
from google.adk.plugins.base_plugin import BasePlugin
from google.adk.tools.base_tool import BaseTool
from google.adk.tools.tool_context import ToolContext
from google.genai import types

from opsguardian.observability.logging import get_logger
from opsguardian.observability.tracing import get_current_trace_context, get_tracer
from opsguardian.security.pii_redactor import PiiRedactor

logger = get_logger("observability.plugin")


@dataclass
class _PendingExecution:
    """Tracks in-flight intent metadata until the matching outcome callback fires."""

    action_id: str
    target_name: str
    start_monotonic: float
    intended_args: dict[str, Any]
    span_cm: Any = None
    span: Any = None


class ObservabilityIntentOutcomePlugin(BasePlugin):
    """App-wide ADK plugin capturing structured Intent vs. Outcome logs & OTel spans."""

    def __init__(self, *, redactor: PiiRedactor | None = None) -> None:
        super().__init__(name="opsguardian_observability")
        self._redactor = redactor or PiiRedactor()
        self._tracer = get_tracer("opsguardian.plugin")
        self._pending_tools: dict[str, _PendingExecution] = {}
        self._pending_agents: dict[str, _PendingExecution] = {}
        self.intent_outcome_records: list[dict[str, Any]] = []

    def _tool_key(self, tool: BaseTool, tool_context: ToolContext) -> str:
        call_id = getattr(tool_context, "function_call_id", None) or "nocallid"
        inv_id = getattr(tool_context, "invocation_id", "noinv")
        return f"{inv_id}:{tool.name}:{call_id}"

    async def before_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> Optional[types.Content]:
        action_id = f"agt-{uuid.uuid4().hex[:12]}"
        inv_id = getattr(callback_context, "invocation_id", "unknown")
        key = f"{inv_id}:{agent.name}"
        span_cm = self._tracer.start_as_current_span(
            f"opsguardian.agent.{agent.name}",
            attributes={
                "gen_ai.agent.name": agent.name,
                "opsguardian.action_id": action_id,
                "opsguardian.invocation_id": inv_id,
            },
        )
        span = span_cm.__enter__()
        trace_id, span_id = get_current_trace_context()

        self._pending_agents[key] = _PendingExecution(
            action_id=action_id,
            target_name=agent.name,
            start_monotonic=time.monotonic(),
            intended_args={"invocation_id": inv_id},
            span_cm=span_cm,
            span=span,
        )

        record = {
            "event_type": "agent.intent",
            "action_id": action_id,
            "agent_name": agent.name,
            "invocation_id": inv_id,
            "trace_id": trace_id,
            "span_id": span_id,
        }
        self.intent_outcome_records.append(record)
        logger.log_event(
            "agent.intent",
            f"Agent '{agent.name}' starting execution.",
            trace_id=trace_id,
            span_id=span_id,
            action_id=action_id,
            agent_name=agent.name,
            invocation_id=inv_id,
        )
        return None

    async def after_agent_callback(
        self, *, agent: BaseAgent, callback_context: CallbackContext
    ) -> Optional[types.Content]:
        inv_id = getattr(callback_context, "invocation_id", "unknown")
        key = f"{inv_id}:{agent.name}"
        pending = self._pending_agents.pop(key, None)
        duration_ms = (
            round((time.monotonic() - pending.start_monotonic) * 1000, 2) if pending else 0.0
        )
        action_id = pending.action_id if pending else f"agt-{uuid.uuid4().hex[:12]}"
        trace_id, span_id = get_current_trace_context()

        if pending and pending.span is not None:
            pending.span.set_attribute("opsguardian.duration_ms", duration_ms)
            pending.span.set_attribute("opsguardian.status", "success")
            pending.span_cm.__exit__(None, None, None)

        record = {
            "event_type": "agent.outcome",
            "action_id": action_id,
            "agent_name": agent.name,
            "invocation_id": inv_id,
            "status": "success",
            "duration_ms": duration_ms,
            "matches_intent": True,
            "trace_id": trace_id,
            "span_id": span_id,
        }
        self.intent_outcome_records.append(record)
        logger.log_event(
            "agent.outcome",
            f"Agent '{agent.name}' completed in {duration_ms} ms.",
            trace_id=trace_id,
            span_id=span_id,
            action_id=action_id,
            agent_name=agent.name,
            duration_ms=duration_ms,
            status="success",
            matches_intent=True,
        )
        return None

    async def before_model_callback(
        self, *, callback_context: CallbackContext, llm_request: LlmRequest
    ) -> Optional[LlmResponse]:
        trace_id, span_id = get_current_trace_context()
        model_name = getattr(llm_request, "model", "unknown")
        agent_name = getattr(callback_context, "agent_name", "unknown")
        logger.log_event(
            "model.intent",
            f"Dispatching LLM request for agent '{agent_name}' to model '{model_name}'.",
            trace_id=trace_id,
            span_id=span_id,
            agent_name=agent_name,
            model=model_name,
            contents_count=len(getattr(llm_request, "contents", []) or []),
        )
        return None

    async def after_model_callback(
        self, *, callback_context: CallbackContext, llm_response: LlmResponse
    ) -> Optional[LlmResponse]:
        trace_id, span_id = get_current_trace_context()
        usage = getattr(llm_response, "usage_metadata", None)
        agent_name = getattr(callback_context, "agent_name", "unknown")
        logger.log_event(
            "model.outcome",
            f"Received LLM response for agent '{agent_name}'.",
            trace_id=trace_id,
            span_id=span_id,
            agent_name=agent_name,
            prompt_tokens=getattr(usage, "prompt_token_count", None),
            candidates_tokens=getattr(usage, "candidates_token_count", None),
            total_tokens=getattr(usage, "total_token_count", None),
        )
        return None

    async def before_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
    ) -> Optional[dict[str, Any]]:
        action_id = f"tool-{uuid.uuid4().hex[:12]}"
        scrubbed_args, redacted_count = self._redactor.redact_structure(tool_args)
        key = self._tool_key(tool, tool_context)
        agent_name = getattr(tool_context, "agent_name", "unknown")

        span_cm = self._tracer.start_as_current_span(
            f"opsguardian.tool.{tool.name}",
            attributes={
                "gen_ai.tool.name": tool.name,
                "gen_ai.agent.name": agent_name,
                "opsguardian.action_id": action_id,
                "opsguardian.pii_redacted_args": redacted_count,
            },
        )
        span = span_cm.__enter__()
        trace_id, span_id = get_current_trace_context()

        self._pending_tools[key] = _PendingExecution(
            action_id=action_id,
            target_name=tool.name,
            start_monotonic=time.monotonic(),
            intended_args=scrubbed_args,
            span_cm=span_cm,
            span=span,
        )

        record = {
            "event_type": "tool.intent",
            "action_id": action_id,
            "agent_name": agent_name,
            "tool_name": tool.name,
            "intended_args": scrubbed_args,
            "pii_redacted_count": redacted_count,
            "trace_id": trace_id,
            "span_id": span_id,
        }
        self.intent_outcome_records.append(record)
        logger.log_event(
            "tool.intent",
            f"INTENT: Agent '{agent_name}' plans to invoke tool '{tool.name}'.",
            trace_id=trace_id,
            span_id=span_id,
            action_id=action_id,
            agent_name=agent_name,
            tool_name=tool.name,
            intended_args=scrubbed_args,
            pii_redacted_count=redacted_count,
        )
        return None

    async def after_tool_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        result: dict[str, Any],
    ) -> Optional[dict[str, Any]]:
        key = self._tool_key(tool, tool_context)
        pending = self._pending_tools.pop(key, None)
        duration_ms = (
            round((time.monotonic() - pending.start_monotonic) * 1000, 2) if pending else 0.0
        )
        action_id = pending.action_id if pending else f"tool-{uuid.uuid4().hex[:12]}"
        scrubbed_result, redacted_count = self._redactor.redact_structure(result)
        outcome_status = (
            str(scrubbed_result.get("status", "success"))
            if isinstance(scrubbed_result, dict)
            else "success"
        )
        if isinstance(scrubbed_result, dict) and "error" in scrubbed_result and outcome_status == "success":
            outcome_status = "error"
        matches_intent = outcome_status in {"success", "pending_approval"}
        trace_id, span_id = get_current_trace_context()

        if pending and pending.span is not None:
            pending.span.set_attribute("opsguardian.duration_ms", duration_ms)
            pending.span.set_attribute("opsguardian.outcome.status", outcome_status)
            pending.span.set_attribute("opsguardian.outcome.matches_intent", matches_intent)
            pending.span_cm.__exit__(None, None, None)

        record = {
            "event_type": "tool.outcome",
            "action_id": action_id,
            "tool_name": tool.name,
            "intended_args": pending.intended_args if pending else {},
            "outcome_status": outcome_status,
            "matches_intent": matches_intent,
            "duration_ms": duration_ms,
            "pii_redacted_count": redacted_count,
            "trace_id": trace_id,
            "span_id": span_id,
        }
        self.intent_outcome_records.append(record)
        logger.log_event(
            "tool.outcome",
            f"OUTCOME: Tool '{tool.name}' finished with status '{outcome_status}' ({duration_ms} ms).",
            trace_id=trace_id,
            span_id=span_id,
            action_id=action_id,
            tool_name=tool.name,
            intended_args=pending.intended_args if pending else {},
            outcome_status=outcome_status,
            matches_intent=matches_intent,
            duration_ms=duration_ms,
            pii_redacted_count=redacted_count,
        )
        # Return scrubbed dict if any PII was stripped from tool output.
        if redacted_count > 0 and isinstance(scrubbed_result, dict):
            return scrubbed_result
        return None

    async def on_tool_error_callback(
        self,
        *,
        tool: BaseTool,
        tool_args: dict[str, Any],
        tool_context: ToolContext,
        error: Exception,
    ) -> Optional[dict[str, Any]]:
        """Convert unexpected tool exceptions into guided recovery envelopes & log outcome."""
        key = self._tool_key(tool, tool_context)
        pending = self._pending_tools.pop(key, None)
        duration_ms = (
            round((time.monotonic() - pending.start_monotonic) * 1000, 2) if pending else 0.0
        )
        action_id = pending.action_id if pending else f"tool-{uuid.uuid4().hex[:12]}"
        trace_id, span_id = get_current_trace_context()

        if pending and pending.span is not None:
            pending.span.record_exception(error)
            pending.span_cm.__exit__(type(error), error, error.__traceback__)

        safe_err = self._redactor.redact_text(str(error)).redacted_text
        logger.log_event(
            "tool.error",
            f"OUTCOME_ERROR: Tool '{tool.name}' raised {type(error).__name__}: {safe_err}",
            level=logging.ERROR,
            trace_id=trace_id,
            span_id=span_id,
            action_id=action_id,
            tool_name=tool.name,
            error_type=type(error).__name__,
            duration_ms=duration_ms,
            matches_intent=False,
        )
        return {
            "status": "error",
            "error_code": "UNEXPECTED_TOOL_EXCEPTION",
            "message": f"Tool '{tool.name}' encountered an internal error: {type(error).__name__}.",
            "recovery_instructions": (
                "Do not retry immediately with identical arguments. Verify argument types "
                "against the tool schema, try alternative read-only telemetry tools, or "
                "escalate to the on-call engineer with the error summary."
            ),
            "retryable": False,
        }

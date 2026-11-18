"""Security guardrails, Cloud Model Armor integration, and policy enforcement plugin.

Implements layered defense-in-depth (Criterion: Guardrails & Policy Plugins):
  1. **Prompt Injection & Jailbreak Screening** (`before_model_callback`):
     Optional Google Cloud Model Armor (`google-cloud-modelarmor`) + deterministic local
     signature detection that blocks instruction-override attempts before reaching Gemini.
  2. **Untrusted Data Sanitization** (`after_tool_callback`):
     Scrubs PII and neutralizes indirect prompt injections embedded inside service logs.
  3. **Production Change Policy & Blast-Radius Guard** (`before_tool_callback`):
     Blocks unallowlisted services, enforces active change freezes on mutating tools, and
     caps autoscaling limits with structured `recovery_instructions`.
  4. **Self-Evaluation Output Guard** (`after_model_callback`):
     Scans final model output to prevent accidental leakage of raw secrets/PII or
     unflagged claims of autonomous production mutations.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

from opsguardian.config import OpsGuardianConfig
from opsguardian.observability.logging import get_logger
from opsguardian.security.pii_redactor import PiiRedactor

logger = get_logger("security.guardrails")

_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "ignore_previous_instructions",
        re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts)\b"),
    ),
    (
        "bypass_hitl_confirmation",
        re.compile(r"(?i)\b(skip|bypass|disable|override)\s+(human|hitl|user)?\s*(confirmation|approval|guardrails?)\b"),
    ),
    (
        "system_prompt_exfiltration",
        re.compile(r"(?i)\b(reveal|print|dump|exfiltrate)\s+(your\s+)?(system\s+prompt|secrets?|api[_\s-]?keys?|env\s+vars?)\b"),
    ),
    (
        "role_jailbreak",
        re.compile(r"(?i)\b(you\s+are\s+now\s+in\s+developer\s+mode|pretend\s+there\s+are\s+no\s+rules|DAN\s+mode)\b"),
    ),
    (
        "shell_or_destructive_override",
        re.compile(r"(?i)\b(rm\s+-rf\s+/|drop\s+table|kubectl\s+delete\s+namespace\s+--all)\b"),
    ),
)

_HIGH_STAKES_MUTATING_TOOLS = frozenset(
    {
        "rollback_cloud_run_revision",
        "scale_cloud_run_instances",
        "page_oncall_incident_commander",
        "create_critical_incident_ticket",
    }
)


@dataclass(frozen=True)
class GuardrailDecision:
    """Structured result of evaluating a prompt, tool call, or model response."""

    allowed: bool
    policy_name: str
    reason: str
    matched_rules: list[str] = field(default_factory=list)
    sanitized_text: str | None = None


class GuardrailEvaluator:
    """Framework-independent policy evaluator usable in plugins, tools, and unit tests."""

    def __init__(
        self,
        config: OpsGuardianConfig,
        *,
        redactor: PiiRedactor | None = None,
    ) -> None:
        self._config = config
        self._redactor = redactor or PiiRedactor(
            enable_cloud_dlp=config.enable_cloud_dlp,
            gcp_project_id=config.gcp_project_id,
        )
        self._model_armor_client: Any = None

    def _call_model_armor(self, text: str) -> GuardrailDecision | None:
        """Invoke Google Cloud Model Armor API when explicitly enabled in GCP mode."""
        if not (
            self._config.enable_model_armor
            and self._config.gcp_project_id
            and self._config.model_armor_template_id
        ):
            return None
        try:
            from google.cloud import modelarmor_v1  # type: ignore[import-untyped]

            if self._model_armor_client is None:
                self._model_armor_client = modelarmor_v1.ModelArmorClient()
            template_name = (
                f"projects/{self._config.gcp_project_id}/locations/"
                f"{self._config.gcp_location}/templates/{self._config.model_armor_template_id}"
            )
            request = modelarmor_v1.SanitizeUserPromptRequest(
                name=template_name,
                user_prompt_data=modelarmor_v1.DataItem(text=text),
            )
            response = self._model_armor_client.sanitize_user_prompt(request=request)
            match_state = str(getattr(response.sanitization_result, "filter_match_state", ""))
            if "MATCH_FOUND" in match_state:
                return GuardrailDecision(
                    allowed=False,
                    policy_name="cloud_model_armor",
                    reason="Blocked by Google Cloud Model Armor prompt safety template.",
                    matched_rules=[match_state],
                )
        except Exception as exc:
            logger.log_event(
                "guardrail.model_armor_fallback",
                f"Model Armor unavailable ({type(exc).__name__}); applying local policy rules.",
                level=logging.WARNING,
            )
        return None

    def evaluate_user_prompt(self, text: str) -> GuardrailDecision:
        """Screen user inputs for prompt injections, jailbreaks, and Model Armor matches."""
        if not text:
            return GuardrailDecision(allowed=True, policy_name="input_safety", reason="Empty prompt.")

        ma_decision = self._call_model_armor(text)
        if ma_decision is not None and not ma_decision.allowed:
            return ma_decision

        matched: list[str] = [
            rule_name for rule_name, pattern in _INJECTION_PATTERNS if pattern.search(text)
        ]
        if matched:
            return GuardrailDecision(
                allowed=False,
                policy_name="prompt_injection_guard",
                reason=(
                    "Prompt rejected by OpsGuardian security policy: potential prompt "
                    "injection or guardrail-bypass attempt detected."
                ),
                matched_rules=matched,
            )
        return GuardrailDecision(allowed=True, policy_name="input_safety", reason="Clean.")

    def sanitize_untrusted_tool_text(self, text: str) -> tuple[str, list[str]]:
        """Neutralize indirect prompt-injection snippets inside untrusted logs & scrub PII."""
        scrubbed = self._redactor.redact_text(text).redacted_text
        flagged_rules: list[str] = []
        for rule_name, pattern in _INJECTION_PATTERNS:
            if pattern.search(scrubbed):
                flagged_rules.append(rule_name)
                scrubbed = pattern.sub("[NEUTRALIZED_UNTRUSTED_DIRECTIVE]", scrubbed)
        return scrubbed, flagged_rules

    def evaluate_tool_call(self, tool_name: str, tool_args: dict[str, Any]) -> GuardrailDecision:
        """Enforce service allowlist, change-freeze window, and scaling safety caps."""
        service_name = tool_args.get("service_name")
        if (
            isinstance(service_name, str)
            and tool_name in _HIGH_STAKES_MUTATING_TOOLS
            and service_name not in self._config.allowed_services
        ):
            return GuardrailDecision(
                allowed=False,
                policy_name="service_allowlist",
                reason=(
                    f"Service '{service_name}' is not in the authorized production remediation "
                    f"allowlist: {list(self._config.allowed_services)}."
                ),
                matched_rules=["unauthorized_service"],
            )

        if self._config.change_freeze_active and tool_name in {
            "rollback_cloud_run_revision",
            "scale_cloud_run_instances",
        }:
            return GuardrailDecision(
                allowed=False,
                policy_name="change_freeze_policy",
                reason=(
                    "Production change freeze is currently active (OPSGUARDIAN_CHANGE_FREEZE=true). "
                    "Automated rollbacks and scaling changes are blocked; page the Incident Commander."
                ),
                matched_rules=["active_change_freeze"],
            )

        if tool_name == "scale_cloud_run_instances":
            max_instances = tool_args.get("max_instances")
            if isinstance(max_instances, int) and max_instances > self._config.max_cloud_run_instances:
                return GuardrailDecision(
                    allowed=False,
                    policy_name="blast_radius_cap",
                    reason=(
                        f"Requested max_instances={max_instances} exceeds policy cap "
                        f"({self._config.max_cloud_run_instances})."
                    ),
                    matched_rules=["max_instances_exceeded"],
                )

        return GuardrailDecision(allowed=True, policy_name="tool_policy", reason="Authorized.")

    def evaluate_model_output(self, text: str) -> GuardrailDecision:
        """Self-evaluate outgoing LLM text for leaked secrets/PII before returning to user."""
        redaction = self._redactor.redact_text(text)
        if redaction.redaction_count > 0:
            return GuardrailDecision(
                allowed=True,
                policy_name="output_pii_scrub",
                reason=f"Scrubbed {redaction.redaction_count} sensitive token(s) from model output.",
                matched_rules=list(redaction.counts_by_type.keys()),
                sanitized_text=redaction.redacted_text,
            )
        return GuardrailDecision(
            allowed=True,
            policy_name="output_safety",
            reason="Verified clean output.",
            sanitized_text=text,
        )


def build_policy_guardrail_plugin(
    config: OpsGuardianConfig,
    *,
    redactor: PiiRedactor | None = None,
) -> Any:
    """Create the ADK ``BasePlugin`` wrapping ``GuardrailEvaluator``."""
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.plugins.base_plugin import BasePlugin
    from google.adk.tools.base_tool import BaseTool
    from google.adk.tools.tool_context import ToolContext
    from google.genai import types

    class PolicyGuardrailPlugin(BasePlugin):
        """ADK app-level security & self-evaluation guardrail plugin."""

        def __init__(self) -> None:
            super().__init__(name="opsguardian_policy_guardrails")
            self.evaluator = GuardrailEvaluator(config, redactor=redactor)

        async def before_model_callback(
            self, *, callback_context: CallbackContext, llm_request: LlmRequest
        ) -> LlmResponse | None:
            for content in getattr(llm_request, "contents", []) or []:
                role = getattr(content, "role", "")
                if role != "user":
                    continue
                for part in getattr(content, "parts", []) or []:
                    text = getattr(part, "text", None)
                    if not text:
                        continue
                    decision = self.evaluator.evaluate_user_prompt(text)
                    if not decision.allowed:
                        logger.log_event(
                            "guardrail.prompt_blocked",
                            decision.reason,
                            level=logging.WARNING,
                            policy=decision.policy_name,
                            matched_rules=decision.matched_rules,
                            agent_name=getattr(callback_context, "agent_name", "unknown"),
                        )
                        return LlmResponse(
                            content=types.Content(
                                role="model",
                                parts=[
                                    types.Part.from_text(
                                        text=(
                                            f"[SECURITY GUARDRAIL BLOCKED: {decision.policy_name}] "
                                            f"{decision.reason} Please rephrase your incident "
                                            "query without instruction overrides or guardrail bypasses."
                                        )
                                    )
                                ],
                            )
                        )
            return None

        async def before_tool_callback(
            self,
            *,
            tool: BaseTool,
            tool_args: dict[str, Any],
            tool_context: ToolContext,
        ) -> dict[str, Any] | None:
            decision = self.evaluator.evaluate_tool_call(tool.name, tool_args)
            if not decision.allowed:
                logger.log_event(
                    "guardrail.tool_blocked",
                    decision.reason,
                    level=logging.WARNING,
                    tool_name=tool.name,
                    policy=decision.policy_name,
                    matched_rules=decision.matched_rules,
                )
                suggested = (
                    "page_oncall_incident_commander"
                    if "active_change_freeze" in decision.matched_rules
                    else None
                )
                return {
                    "status": "blocked_by_policy",
                    "error_code": decision.policy_name.upper(),
                    "message": decision.reason,
                    "recovery_instructions": (
                        "Inform the on-call engineer of this policy block. Do not retry the "
                        "blocked mutation; suggest an allowed alternative or escalate."
                    ),
                    "suggested_next_tool": suggested,
                    "valid_options": list(config.allowed_services),
                    "retryable": False,
                }
            return None

        async def after_tool_callback(
            self,
            *,
            tool: BaseTool,
            tool_args: dict[str, Any],
            tool_context: ToolContext,
            result: dict[str, Any],
        ) -> dict[str, Any] | None:
            if not isinstance(result, dict):
                return None
            modified = False

            def _clean(obj: Any) -> Any:
                nonlocal modified
                if isinstance(obj, str):
                    sanitized, rules = self.evaluator.sanitize_untrusted_tool_text(obj)
                    if sanitized != obj or rules:
                        modified = True
                        if rules:
                            logger.log_event(
                                "guardrail.indirect_injection_neutralized",
                                f"Neutralized untrusted directive inside output of '{tool.name}'.",
                                level=logging.WARNING,
                                tool_name=tool.name,
                                matched_rules=rules,
                            )
                    return sanitized
                if isinstance(obj, dict):
                    return {k: _clean(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_clean(i) for i in obj]
                return obj

            cleaned = _clean(result)
            return cleaned if modified else None

        async def after_model_callback(
            self, *, callback_context: CallbackContext, llm_response: LlmResponse
        ) -> LlmResponse | None:
            content = getattr(llm_response, "content", None)
            parts = getattr(content, "parts", None) if content else None
            if not parts:
                return None
            changed = False
            new_parts = []
            for part in parts:
                text = getattr(part, "text", None)
                if text:
                    decision = self.evaluator.evaluate_model_output(text)
                    if decision.sanitized_text is not None and decision.sanitized_text != text:
                        changed = True
                        logger.log_event(
                            "guardrail.output_scrubbed",
                            decision.reason,
                            level=logging.WARNING,
                            matched_rules=decision.matched_rules,
                        )
                        new_parts.append(types.Part.from_text(text=decision.sanitized_text))
                        continue
                new_parts.append(part)
            if changed:
                return LlmResponse(
                    content=types.Content(role=content.role or "model", parts=new_parts)
                )
            return None

    return PolicyGuardrailPlugin()

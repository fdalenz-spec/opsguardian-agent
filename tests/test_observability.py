"""Tests for Category 4: Observability & Tracing (JSON logs, Intent/Outcome, OTel spans)."""

from __future__ import annotations

import io
import json
from dataclasses import dataclass

import pytest

from opsguardian.config import OpsGuardianConfig
from opsguardian.observability.logging import configure_logging, get_logger
from opsguardian.observability.plugin import ObservabilityIntentOutcomePlugin
from opsguardian.observability.tracing import (
    clear_captured_spans,
    configure_tracing,
    get_captured_spans,
    get_tracer,
)


def test_structured_json_logging_emits_valid_json_and_scrubs_pii() -> None:
    stream = io.StringIO()
    configure_logging(level="INFO", gcp_project_id="demo-proj", stream=stream)
    log = get_logger("test_obs")

    log.log_event(
        "tool.intent",
        "Investigating alert for alice@example.com from 203.0.113.10",
        trace_id="a" * 32,
        span_id="b" * 16,
        user_email="bob@example.com",
        api_key="not-a-real-secret-value",
    )

    lines = [line for line in stream.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
    parsed = json.loads(lines[0])
    assert parsed["severity"] == "INFO"
    assert parsed["event_type"] == "tool.intent"
    assert parsed["logging.googleapis.com/trace"] == f"projects/demo-proj/traces/{'a' * 32}"
    assert "alice@example.com" not in parsed["message"]
    assert "203.0.113.10" not in parsed["message"]
    assert parsed["metadata"]["user_email"] == "[REDACTED_EMAIL_ADDRESS]"
    assert parsed["metadata"]["api_key"] == "[REDACTED_SECRET]"
    assert parsed["pii_redacted_count"] >= 4


def test_distributed_tracing_links_parent_and_child_spans(
    local_config: OpsGuardianConfig,
) -> None:
    configure_tracing(local_config, capture_in_memory=True)
    clear_captured_spans()
    tracer = get_tracer("opsguardian.test")

    with tracer.start_as_current_span("opsguardian.invocation"):
        with tracer.start_as_current_span("opsguardian.agent.coordinator"):
            with tracer.start_as_current_span("opsguardian.tool.fetch_service_error_logs"):
                pass

    spans = get_captured_spans()
    names = [s.name for s in spans]
    assert "opsguardian.invocation" in names
    assert "opsguardian.agent.coordinator" in names
    assert "opsguardian.tool.fetch_service_error_logs" in names


@dataclass
class _FakeTool:
    name: str


@dataclass
class _FakeToolContext:
    invocation_id: str = "inv-1"
    function_call_id: str = "fc-1"
    agent_name: str = "log_collector_agent"


@pytest.mark.asyncio
async def test_intent_vs_outcome_plugin_correlates_action_ids() -> None:
    plugin = ObservabilityIntentOutcomePlugin()
    tool = _FakeTool(name="fetch_service_error_logs")
    ctx = _FakeToolContext()

    await plugin.before_tool_callback(
        tool=tool,  # type: ignore[arg-type]
        tool_args={"service_name": "checkout-api", "contact": "alice@example.com"},
        tool_context=ctx,  # type: ignore[arg-type]
    )
    override = await plugin.after_tool_callback(
        tool=tool,  # type: ignore[arg-type]
        tool_args={"service_name": "checkout-api"},
        tool_context=ctx,  # type: ignore[arg-type]
        result={"status": "success", "note": "owner bob@example.com"},
    )

    assert len(plugin.intent_outcome_records) == 2
    intent, outcome = plugin.intent_outcome_records
    assert intent["event_type"] == "tool.intent"
    assert outcome["event_type"] == "tool.outcome"
    assert intent["action_id"] == outcome["action_id"]
    assert intent["intended_args"]["contact"] == "[REDACTED_EMAIL_ADDRESS]"
    assert outcome["matches_intent"] is True
    assert override is not None and "bob@example.com" not in override["note"]

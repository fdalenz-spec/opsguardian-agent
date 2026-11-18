"""Tests for Category 1: Tool & Interface Design (naming, docstrings, schemas, guided errors)."""

from __future__ import annotations

import inspect
from dataclasses import dataclass

from opsguardian.memory.knowledge_store import KnowledgeStore
from opsguardian.schemas import (
    FetchServiceErrorLogsInput,
    RootCauseReport,
    export_tool_json_schemas,
)
from opsguardian.tools.knowledge_tools import (
    lookup_service_runbook,
    search_past_postmortems,
)
from opsguardian.tools.remediation_tools import (
    create_critical_incident_ticket,
    page_oncall_incident_commander,
    rollback_cloud_run_revision,
    scale_cloud_run_instances,
)
from opsguardian.tools.telemetry_tools import (
    fetch_service_error_logs,
    list_recent_deployments,
    query_slo_burn_metrics,
)

ALL_TOOLS = [
    fetch_service_error_logs,
    query_slo_burn_metrics,
    list_recent_deployments,
    search_past_postmortems,
    lookup_service_runbook,
    rollback_cloud_run_revision,
    scale_cloud_run_instances,
    page_oncall_incident_commander,
    create_critical_incident_ticket,
]


def test_all_tools_have_comprehensive_docstrings_and_specific_names() -> None:
    for fn in ALL_TOOLS:
        doc = inspect.getdoc(fn) or ""
        assert "Args:" in doc, f"{fn.__name__} missing Args section"
        assert "Returns:" in doc, f"{fn.__name__} missing Returns section"
        assert len(doc) >= 150, f"{fn.__name__} docstring too short"
        assert "_" in fn.__name__, f"{fn.__name__} should use specific verb_noun naming"


def test_strict_json_schemas_exported_and_forbid_extra_keys() -> None:
    schemas = export_tool_json_schemas()
    assert "fetch_service_error_logs.input" in schemas
    assert "rollback_cloud_run_revision.input" in schemas
    assert "root_cause_report" in schemas
    assert schemas["fetch_service_error_logs.input"].get("additionalProperties") is False

    # Reject unknown fields strictly
    import pytest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        FetchServiceErrorLogsInput(service_name="checkout-api", unexpected_param=123)  # type: ignore[call-arg]


def test_fetch_service_error_logs_scrubs_pii() -> None:
    result = fetch_service_error_logs("checkout-api", lookback_minutes=30, min_severity="ERROR")
    assert result["status"] == "success"
    assert result["pii_redacted_count"] >= 4
    joined = " ".join(e["message"] for e in result["entries"])
    assert "alice.tester@example.com" not in joined
    assert "203.0.113.42" not in joined
    assert "[REDACTED_EMAIL_ADDRESS]" in joined


def test_guided_error_handling_for_unknown_service_and_bad_args(
    knowledge_store: KnowledgeStore,
) -> None:
    _ = knowledge_store
    unknown = fetch_service_error_logs("billing-legacy-v9")
    assert unknown["status"] == "error"
    assert unknown["error_code"] == "SERVICE_NOT_FOUND"
    assert "recovery_instructions" in unknown and unknown["recovery_instructions"]
    assert "checkout-api" in unknown["valid_options"]

    bad_format = query_slo_burn_metrics("INVALID SERVICE NAME!", window_minutes=60)
    assert bad_format["status"] == "error"
    assert bad_format["error_code"] == "INVALID_TOOL_ARGUMENTS"
    assert bad_format["retryable"] is True

    bad_bounds = scale_cloud_run_instances(
        service_name="checkout-api",
        min_instances=20,
        max_instances=5,
        reason="Intentional invalid scaling test",
    )
    assert bad_bounds["status"] == "error"
    assert bad_bounds["error_code"] == "INVALID_SCALING_BOUNDS"

    bad_revision = rollback_cloud_run_revision(
        service_name="checkout-api",
        target_revision="checkout-api-99999-fake",
        reason="Verify hallucinated revision ID is rejected with valid_options",
    )
    assert bad_revision["status"] == "error"
    assert bad_revision["error_code"] == "REVISION_NOT_FOUND"
    assert "checkout-api-00041-b7c" in bad_revision["valid_options"]


def test_persistent_knowledge_tools_return_seeded_records(
    knowledge_store: KnowledgeStore,
) -> None:
    _ = knowledge_store
    pms = search_past_postmortems("503 connection pool exhausted", service_name="checkout-api")
    assert pms["status"] == "success"
    assert pms["matches"][0]["postmortem_id"] == "PM-2025-104"

    rb = lookup_service_runbook("checkout-api")
    assert rb["status"] == "success"
    assert rb["runbook_id"] == "RB-CHECKOUT-01"
    assert rb["slo_availability_target"] == 99.95


def test_root_cause_report_schema_validation() -> None:
    report = RootCauseReport(
        service_name="checkout-api",
        severity="SEV-1",
        confidence_score=0.94,
        summary="Checkout API experiencing 18.4% 503 error rate after DB pool reduction.",
        probable_root_cause="Revision checkout-api-00042-x9k lowered DB_POOL_MAX_SIZE from 50 to 5.",
        suspect_revision="checkout-api-00042-x9k",
        last_known_good_revision="checkout-api-00041-b7c",
        matching_postmortem_ids=["PM-2025-104"],
    )
    assert report.severity == "SEV-1"


@dataclass
class _StubConfirmation:
    confirmed: bool


@dataclass
class _StubToolContext:
    tool_confirmation: _StubConfirmation | None = None
    requested: list[dict] | None = None

    def request_confirmation(self, *, hint: str, payload: dict) -> None:
        if self.requested is None:
            self.requested = []
        self.requested.append({"hint": hint, "payload": payload})


def test_hitl_gate_pauses_rejects_and_approves() -> None:
    # Phase A: No confirmation -> pause & call request_confirmation
    ctx_pending = _StubToolContext()
    pending = rollback_cloud_run_revision(
        service_name="checkout-api",
        target_revision="checkout-api-00041-b7c",
        reason="SEV-1 18.4% HTTP 503 error rate after checkout-api-00042-x9k rollout",
        tool_context=ctx_pending,
    )
    assert pending["status"] == "pending_approval"
    assert pending["confirmation_required"] is True
    assert ctx_pending.requested and len(ctx_pending.requested) == 1

    # Phase B: Rejected by operator -> no execution
    ctx_reject = _StubToolContext(tool_confirmation=_StubConfirmation(confirmed=False))
    rejected = rollback_cloud_run_revision(
        service_name="checkout-api",
        target_revision="checkout-api-00041-b7c",
        reason="SEV-1 18.4% HTTP 503 error rate after checkout-api-00042-x9k rollout",
        tool_context=ctx_reject,
    )
    assert rejected["status"] == "rejected"

    # Phase C: Approved by operator -> executed with audit ID
    ctx_ok = _StubToolContext(tool_confirmation=_StubConfirmation(confirmed=True))
    approved = rollback_cloud_run_revision(
        service_name="checkout-api",
        target_revision="checkout-api-00041-b7c",
        reason="SEV-1 18.4% HTTP 503 error rate after checkout-api-00042-x9k rollout",
        tool_context=ctx_ok,
    )
    assert approved["status"] == "success"
    assert approved["audit_id"].startswith("rb-")

"""Strict Pydantic v2 JSON schemas for tool inputs, outputs, and agent reports.

Every schema enforces ``extra="forbid"`` to prevent LLM hallucination of unknown
arguments and provides explicit JSON Schema descriptions for deterministic tool
calling and validation.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SeverityLevel = Literal["SEV-1", "SEV-2", "SEV-3", "SEV-4"]
ToolStatus = Literal["success", "error", "pending_approval", "rejected", "blocked_by_policy"]
RegionName = Literal["us-central1", "us-east1", "europe-west1", "europe-west4", "asia-northeast1"]


class StrictSchema(BaseModel):
    """Base schema with strict validation forbidding unexpected keys."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


# ---------------------------------------------------------------------------
# Guided Error Recovery Envelope (Criterion: Guided Error Handling)
# ---------------------------------------------------------------------------


class ToolErrorResponse(StrictSchema):
    """Structured error response that instructs the LLM how to recover safely."""

    status: Literal["error", "blocked_by_policy"] = "error"
    error_code: str = Field(
        ...,
        description="Machine-readable error identifier (e.g. SERVICE_NOT_FOUND, CHANGE_FREEZE_ACTIVE).",
    )
    message: str = Field(..., description="Human-readable summary of what failed.")
    recovery_instructions: str = Field(
        ...,
        description="Actionable step-by-step instructions telling the LLM how to recover.",
    )
    suggested_next_tool: str | None = Field(
        default=None,
        description="Optional recommended tool name to invoke next for recovery.",
    )
    valid_options: list[str] = Field(
        default_factory=list,
        description="Allowlisted valid values when an invalid identifier was supplied.",
    )
    retryable: bool = Field(
        default=True,
        description="Whether retrying with corrected arguments is expected to succeed.",
    )


# ---------------------------------------------------------------------------
# Read-Only Telemetry Tool Schemas
# ---------------------------------------------------------------------------


class FetchServiceErrorLogsInput(StrictSchema):
    """Validated input schema for ``fetch_service_error_logs``."""

    service_name: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="Kebab-case Cloud Run / GKE service identifier (e.g. 'checkout-api').",
    )
    lookback_minutes: int = Field(
        default=30,
        ge=1,
        le=1440,
        description="Time window in minutes to query logs (1 to 1440).",
    )
    min_severity: Literal["WARNING", "ERROR", "CRITICAL"] = Field(
        default="ERROR",
        description="Minimum Cloud Logging severity level to include.",
    )
    limit: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of redacted log records to return.",
    )


class LogEntryRecord(StrictSchema):
    """Single PII-redacted structured error log entry."""

    timestamp: str = Field(..., description="ISO-8601 UTC timestamp of the log event.")
    severity: Literal["WARNING", "ERROR", "CRITICAL"]
    revision: str = Field(..., description="Serving revision ID that emitted the log.")
    http_status: int | None = Field(default=None, ge=100, le=599)
    error_signature: str = Field(..., description="Normalized exception/error signature.")
    message: str = Field(..., description="PII-redacted log message payload.")
    trace_id: str = Field(..., description="Distributed trace ID for cross-correlation.")


class FetchServiceErrorLogsOutput(StrictSchema):
    """Validated output schema for ``fetch_service_error_logs``."""

    status: Literal["success"] = "success"
    service_name: str
    lookback_minutes: int
    total_matching_entries: int = Field(ge=0)
    pii_redacted_count: int = Field(
        ge=0, description="Number of PII tokens scrubbed before return."
    )
    entries: list[LogEntryRecord] = Field(default_factory=list)


class QuerySloBurnMetricsInput(StrictSchema):
    """Validated input schema for ``query_slo_burn_metrics``."""

    service_name: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="Target Cloud Run / GKE service identifier.",
    )
    window_minutes: int = Field(
        default=60,
        ge=5,
        le=1440,
        description="Rolling evaluation window in minutes for SLO burn-rate metrics.",
    )


class QuerySloBurnMetricsOutput(StrictSchema):
    """Validated output schema for ``query_slo_burn_metrics``."""

    status: Literal["success"] = "success"
    service_name: str
    window_minutes: int
    slo_target_percent: float = Field(..., ge=0.0, le=100.0)
    current_availability_percent: float = Field(..., ge=0.0, le=100.0)
    error_rate_percent: float = Field(..., ge=0.0, le=100.0)
    requests_per_second: float = Field(..., ge=0.0)
    p95_latency_ms: float = Field(..., ge=0.0)
    p99_latency_ms: float = Field(..., ge=0.0)
    burn_rate_1h: float = Field(..., ge=0.0, description="1-hour error budget burn multiplier.")
    burn_rate_6h: float = Field(..., ge=0.0, description="6-hour error budget burn multiplier.")
    cpu_utilization_percent: float = Field(..., ge=0.0, le=100.0)
    memory_utilization_percent: float = Field(..., ge=0.0, le=100.0)
    alert_state: Literal["OK", "WARNING", "CRITICAL_FAST_BURN"]
    estimated_severity: SeverityLevel


class ListRecentDeploymentsInput(StrictSchema):
    """Validated input schema for ``list_recent_deployments``."""

    service_name: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="Target service name to inspect recent Cloud Run revisions.",
    )
    max_revisions: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum number of recent revisions to return.",
    )


class DeploymentRecord(StrictSchema):
    """Metadata describing a deployed service revision."""

    revision_id: str = Field(..., description="Unique Cloud Run revision ID.")
    deployed_at: str = Field(..., description="ISO-8601 UTC deployment timestamp.")
    traffic_percent: int = Field(..., ge=0, le=100)
    commit_sha: str = Field(..., description="Git commit SHA deployed in this revision.")
    change_summary: str = Field(..., description="Human-readable release note / diff summary.")
    status: Literal["SERVING", "HEALTHY_PREVIOUS", "ROLLED_BACK", "DEGRADED"]


class ListRecentDeploymentsOutput(StrictSchema):
    """Validated output schema for ``list_recent_deployments``."""

    status: Literal["success"] = "success"
    service_name: str
    active_revision: str
    last_known_good_revision: str
    deployments: list[DeploymentRecord] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Persistent Knowledge / Postmortem Schemas
# ---------------------------------------------------------------------------


class SearchPastPostmortemsInput(StrictSchema):
    """Validated input schema for ``search_past_postmortems``."""

    query: str = Field(
        ...,
        min_length=2,
        max_length=256,
        description="Symptom keywords, error code, or service name to search past postmortems.",
    )
    service_name: str | None = Field(
        default=None,
        description="Optional kebab-case service filter.",
    )
    max_results: int = Field(default=3, ge=1, le=10)


class PostmortemMatch(StrictSchema):
    """Matched historical incident postmortem."""

    postmortem_id: str
    title: str
    service_name: str
    date: str
    root_cause_summary: str
    resolution_summary: str
    relevance_score: float = Field(..., ge=0.0, le=1.0)


class SearchPastPostmortemsOutput(StrictSchema):
    """Validated output schema for ``search_past_postmortems``."""

    status: Literal["success"] = "success"
    backend: str = Field(
        ..., description="Backing store used (sqlite_fts5, firestore, vertex_search)."
    )
    query: str
    matches: list[PostmortemMatch] = Field(default_factory=list)


class LookupServiceRunbookInput(StrictSchema):
    """Validated input schema for ``lookup_service_runbook``."""

    service_name: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="Service identifier whose operational runbook should be retrieved.",
    )


class LookupServiceRunbookOutput(StrictSchema):
    """Validated output schema for ``lookup_service_runbook``."""

    status: Literal["success"] = "success"
    runbook_id: str
    service_name: str
    owner_team: str
    escalation_policy: str
    slo_availability_target: float
    safe_rollback_steps: list[str]
    verification_queries: list[str]


# ---------------------------------------------------------------------------
# High-Stakes Remediation Tool Schemas (HITL Gated)
# ---------------------------------------------------------------------------


class RollbackCloudRunRevisionInput(StrictSchema):
    """Validated input schema for ``rollback_cloud_run_revision``."""

    service_name: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="Cloud Run service to roll back.",
    )
    target_revision: str = Field(
        ...,
        min_length=4,
        max_length=80,
        pattern=r"^[a-z0-9-]+$",
        description="Verified last-known-good Cloud Run revision ID.",
    )
    region: RegionName = Field(default="us-central1", description="GCP Cloud Run region.")
    traffic_percent: int = Field(
        default=100,
        ge=10,
        le=100,
        description="Percentage of traffic to shift to target_revision (10-100).",
    )
    reason: str = Field(
        ...,
        min_length=10,
        max_length=500,
        description="Evidence-backed justification referencing log/metric findings.",
    )


class ScaleCloudRunInstancesInput(StrictSchema):
    """Validated input schema for ``scale_cloud_run_instances``."""

    service_name: str = Field(
        ...,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="Cloud Run service to scale.",
    )
    min_instances: int = Field(..., ge=0, le=50, description="Target minimum warm instances.")
    max_instances: int = Field(..., ge=1, le=100, description="Target maximum autoscaling cap.")
    region: RegionName = Field(default="us-central1")
    reason: str = Field(..., min_length=10, max_length=500)

    @field_validator("max_instances")
    @classmethod
    def _validate_bounds(cls, value: int, info: Any) -> int:
        min_val = info.data.get("min_instances", 0)
        if value < min_val:
            raise ValueError(
                f"max_instances ({value}) must be greater than or equal to min_instances ({min_val})."
            )
        return value


class PageOncallCommanderInput(StrictSchema):
    """Validated input schema for ``page_oncall_incident_commander``."""

    service_name: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$")
    severity: Literal["SEV-1", "SEV-2"] = Field(
        ...,
        description="Only SEV-1 or SEV-2 incidents may trigger an urgent page.",
    )
    summary: str = Field(..., min_length=15, max_length=300)
    evidence_citations: list[str] = Field(
        ...,
        min_length=1,
        description="At least one log, metric, or postmortem citation supporting the page.",
    )


class CreateCriticalIncidentTicketInput(StrictSchema):
    """Validated input schema for ``create_critical_incident_ticket``."""

    service_name: str = Field(..., pattern=r"^[a-z][a-z0-9-]*$")
    severity: SeverityLevel
    title: str = Field(..., min_length=10, max_length=160)
    root_cause_hypothesis: str = Field(..., min_length=15, max_length=1000)
    recommended_action: str = Field(..., min_length=10, max_length=500)


class RemediationActionOutput(StrictSchema):
    """Unified output envelope for HITL-gated remediation actions."""

    status: ToolStatus
    action: str
    service_name: str
    confirmation_required: bool = False
    confirmation_hint: str | None = None
    audit_id: str | None = None
    blast_radius_summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Multi-Agent Structured Output Schema (Root Cause Synthesizer)
# ---------------------------------------------------------------------------


class EvidenceCitation(StrictSchema):
    """Ground-truth citation linking a claim back to a specific tool observation."""

    source: Literal["error_logs", "slo_metrics", "deployments", "postmortem", "runbook"]
    reference_id: str = Field(
        ..., description="Trace ID, revision ID, postmortem ID, or metric name."
    )
    summary: str = Field(..., description="Observed fact supporting the root-cause analysis.")


class RecommendedAction(StrictSchema):
    """Proposed remediation step with explicit risk tier."""

    tool_name: str = Field(..., description="Exact ADK tool name to invoke.")
    parameters: dict[str, Any] = Field(default_factory=dict)
    risk_level: Literal["LOW", "MEDIUM", "HIGH"]
    requires_human_approval: bool = True
    expected_impact: str


class RootCauseReport(StrictSchema):
    """Strict structured output emitted by ``root_cause_synthesizer_agent``."""

    service_name: str
    severity: SeverityLevel
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    summary: str = Field(..., min_length=20)
    probable_root_cause: str = Field(..., min_length=20)
    suspect_revision: str | None = None
    last_known_good_revision: str | None = None
    evidence: list[EvidenceCitation] = Field(default_factory=list)
    matching_postmortem_ids: list[str] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    data_gaps: list[str] = Field(default_factory=list)


def export_tool_json_schemas() -> dict[str, dict[str, Any]]:
    """Export JSON Schema definitions for all tool input and output contracts."""
    models: dict[str, type[BaseModel]] = {
        "fetch_service_error_logs.input": FetchServiceErrorLogsInput,
        "fetch_service_error_logs.output": FetchServiceErrorLogsOutput,
        "query_slo_burn_metrics.input": QuerySloBurnMetricsInput,
        "query_slo_burn_metrics.output": QuerySloBurnMetricsOutput,
        "list_recent_deployments.input": ListRecentDeploymentsInput,
        "list_recent_deployments.output": ListRecentDeploymentsOutput,
        "search_past_postmortems.input": SearchPastPostmortemsInput,
        "search_past_postmortems.output": SearchPastPostmortemsOutput,
        "lookup_service_runbook.input": LookupServiceRunbookInput,
        "lookup_service_runbook.output": LookupServiceRunbookOutput,
        "rollback_cloud_run_revision.input": RollbackCloudRunRevisionInput,
        "scale_cloud_run_instances.input": ScaleCloudRunInstancesInput,
        "page_oncall_incident_commander.input": PageOncallCommanderInput,
        "create_critical_incident_ticket.input": CreateCriticalIncidentTicketInput,
        "remediation_action.output": RemediationActionOutput,
        "root_cause_report": RootCauseReport,
        "tool_error_response": ToolErrorResponse,
    }
    return {name: model.model_json_schema() for name, model in models.items()}

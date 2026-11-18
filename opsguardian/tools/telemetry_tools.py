"""Read-only telemetry tools with strict Pydantic validation and guided error recovery.

Tool names follow explicit verb-noun specificity (Criterion: Descriptive Naming):
  - ``fetch_service_error_logs``
  - ``query_slo_burn_metrics``
  - ``list_recent_deployments``
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from opsguardian.config import OpsGuardianConfig
from opsguardian.schemas import (
    DeploymentRecord,
    FetchServiceErrorLogsInput,
    FetchServiceErrorLogsOutput,
    ListRecentDeploymentsInput,
    ListRecentDeploymentsOutput,
    LogEntryRecord,
    QuerySloBurnMetricsInput,
    QuerySloBurnMetricsOutput,
    ToolErrorResponse,
)
from opsguardian.security.pii_redactor import PiiRedactor
from opsguardian.tools.sample_data import (
    DEPLOYMENT_HISTORY,
    RAW_ERROR_LOGS,
    SLO_METRICS,
    SYNTHETIC_SERVICES,
)

_SEVERITY_ORDER = {"WARNING": 1, "ERROR": 2, "CRITICAL": 3}

_default_config = OpsGuardianConfig.from_env()
_default_redactor = PiiRedactor(
    enable_cloud_dlp=_default_config.enable_cloud_dlp,
    gcp_project_id=_default_config.gcp_project_id,
)


def _validation_error_envelope(
    tool_name: str, exc: ValidationError, valid_services: list[str]
) -> dict[str, Any]:
    details = "; ".join(
        f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
    )
    return ToolErrorResponse(
        status="error",
        error_code="INVALID_TOOL_ARGUMENTS",
        message=f"Input validation failed for '{tool_name}': {details}",
        recovery_instructions=(
            "Fix the invalid parameter(s) listed above using the strict JSON schema "
            "constraints (e.g., kebab-case service_name, bounded integer window) and "
            "retry the call once."
        ),
        suggested_next_tool=tool_name,
        valid_options=valid_services,
        retryable=True,
    ).model_dump()


def _unknown_service_envelope(service_name: str, tool_name: str) -> dict[str, Any]:
    return ToolErrorResponse(
        status="error",
        error_code="SERVICE_NOT_FOUND",
        message=f"Service '{service_name}' does not exist in monitored telemetry inventory.",
        recovery_instructions=(
            f"Do not fabricate telemetry for '{service_name}'. Retry '{tool_name}' with one "
            f"of the valid services listed in `valid_options`, or ask the on-call engineer "
            "to verify the exact Cloud Run service identifier."
        ),
        suggested_next_tool=tool_name,
        valid_options=list(SYNTHETIC_SERVICES),
        retryable=True,
    ).model_dump()


def fetch_service_error_logs(
    service_name: str,
    lookback_minutes: int = 30,
    min_severity: str = "ERROR",
    limit: int = 20,
) -> dict[str, Any]:
    """Fetch recent PII-redacted Cloud Logging error records for a specific service.

    Queries structured error logs for a monitored service within the specified time
    window and runs every log message through ``PiiRedactor`` (Cloud DLP or deterministic
    local scrubbing) BEFORE returning records to the LLM context.

    Args:
        service_name: Kebab-case Cloud Run / GKE service identifier (e.g.
            ``"checkout-api"``, ``"auth-service"``). Must match an active monitored service.
        lookback_minutes: Rolling time window in minutes to search (1 to 1440, default 30).
        min_severity: Minimum severity threshold: ``"WARNING"``, ``"ERROR"``, or
            ``"CRITICAL"`` (default ``"ERROR"``).
        limit: Maximum number of log entries to return (1 to 100, default 20).

    Returns:
        A JSON-serializable dictionary matching ``FetchServiceErrorLogsOutput`` on success
        (including ``pii_redacted_count`` and ``entries``), or a structured
        ``ToolErrorResponse`` containing ``recovery_instructions`` and ``valid_options``
        if validation fails or the service is unknown.
    """
    try:
        validated = FetchServiceErrorLogsInput(
            service_name=service_name,
            lookback_minutes=lookback_minutes,
            min_severity=min_severity,  # type: ignore[arg-type]
            limit=limit,
        )
    except ValidationError as exc:
        return _validation_error_envelope(
            "fetch_service_error_logs", exc, list(SYNTHETIC_SERVICES)
        )

    raw_entries = RAW_ERROR_LOGS.get(validated.service_name)
    if raw_entries is None:
        return _unknown_service_envelope(validated.service_name, "fetch_service_error_logs")

    threshold = _SEVERITY_ORDER[validated.min_severity]
    redacted_entries: list[LogEntryRecord] = []
    total_pii_redacted = 0

    for entry in raw_entries:
        if _SEVERITY_ORDER.get(entry["severity"], 0) < threshold:
            continue
        redaction = _default_redactor.redact_text(entry["message"])
        total_pii_redacted += redaction.redaction_count
        redacted_entries.append(
            LogEntryRecord(
                timestamp=entry["timestamp"],
                severity=entry["severity"],
                revision=entry["revision"],
                http_status=entry.get("http_status"),
                error_signature=entry["error_signature"],
                message=redaction.redacted_text,
                trace_id=entry["trace_id"],
            )
        )
        if len(redacted_entries) >= validated.limit:
            break

    return FetchServiceErrorLogsOutput(
        service_name=validated.service_name,
        lookback_minutes=validated.lookback_minutes,
        total_matching_entries=len(redacted_entries),
        pii_redacted_count=total_pii_redacted,
        entries=redacted_entries,
    ).model_dump()


def query_slo_burn_metrics(
    service_name: str,
    window_minutes: int = 60,
) -> dict[str, Any]:
    """Query quantitative SLO error-budget burn rates and Golden Signals for a service.

    Retrieves availability percentage, HTTP 5xx error rate, requests per second (RPS),
    p95/p99 latency in milliseconds, 1-hour and 6-hour multi-window burn multipliers,
    container CPU/memory utilization, and derived SRE severity level.

    Args:
        service_name: Kebab-case service identifier (e.g. ``"checkout-api"``).
        window_minutes: Rolling evaluation window in minutes (5 to 1440, default 60).

    Returns:
        A JSON-serializable dictionary matching ``QuerySloBurnMetricsOutput`` on success,
        or a guided ``ToolErrorResponse`` with ``recovery_instructions`` and ``valid_options``
        when arguments are invalid or the service does not exist.
    """
    try:
        validated = QuerySloBurnMetricsInput(
            service_name=service_name,
            window_minutes=window_minutes,
        )
    except ValidationError as exc:
        return _validation_error_envelope("query_slo_burn_metrics", exc, list(SYNTHETIC_SERVICES))

    metrics = SLO_METRICS.get(validated.service_name)
    if metrics is None:
        return _unknown_service_envelope(validated.service_name, "query_slo_burn_metrics")

    return QuerySloBurnMetricsOutput(
        service_name=validated.service_name,
        window_minutes=validated.window_minutes,
        **metrics,
    ).model_dump()


def list_recent_deployments(
    service_name: str,
    max_revisions: int = 5,
) -> dict[str, Any]:
    """List recent Cloud Run revisions and deployment diffs for a monitored service.

    Returns the currently serving revision, the verified ``last_known_good_revision``,
    traffic split percentages, deployment timestamps, commit SHAs, and release summaries
    to correlate error spikes against recent rollouts.

    Args:
        service_name: Kebab-case Cloud Run service identifier (e.g. ``"checkout-api"``).
        max_revisions: Maximum number of recent revisions to include (1 to 20, default 5).

    Returns:
        A JSON-serializable dictionary matching ``ListRecentDeploymentsOutput`` on success,
        or a guided ``ToolErrorResponse`` with ``recovery_instructions`` when the service
        name is invalid or unknown.
    """
    try:
        validated = ListRecentDeploymentsInput(
            service_name=service_name,
            max_revisions=max_revisions,
        )
    except ValidationError as exc:
        return _validation_error_envelope(
            "list_recent_deployments", exc, list(SYNTHETIC_SERVICES)
        )

    history = DEPLOYMENT_HISTORY.get(validated.service_name)
    if history is None:
        return _unknown_service_envelope(validated.service_name, "list_recent_deployments")

    records = [
        DeploymentRecord(**item) for item in history["deployments"][: validated.max_revisions]
    ]
    return ListRecentDeploymentsOutput(
        service_name=validated.service_name,
        active_revision=history["active_revision"],
        last_known_good_revision=history["last_known_good_revision"],
        deployments=records,
    ).model_dump()

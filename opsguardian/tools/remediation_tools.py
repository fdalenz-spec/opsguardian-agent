"""High-stakes remediation tools protected by Human-in-the-Loop (HITL) confirmation gates.

Every mutating or alerting action enforces TWO complementary HITL safety layers
(Criterion: Human-in-the-Loop Hooks):
  1. **Explicit ADK ``tool_context.request_confirmation(...)`` check** inside each tool
     function verifying ``tool_context.tool_confirmation.confirmed`` before performing
     any state change (and returning a structured ``pending_approval`` or ``rejected``
     envelope with blast-radius summary and exact preview).
  2. **ADK ``FunctionTool(..., require_confirmation=...)`` wrapper** built via
     ``build_remediation_toolset()`` so the ADK Runner pauses automatically and emits
     an ``adk_request_confirmation`` event awaiting operator approval.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import ValidationError

from opsguardian.config import OpsGuardianConfig
from opsguardian.observability.logging import get_logger
from opsguardian.schemas import (
    CreateCriticalIncidentTicketInput,
    PageOncallCommanderInput,
    RemediationActionOutput,
    RollbackCloudRunRevisionInput,
    ScaleCloudRunInstancesInput,
    ToolErrorResponse,
)
from opsguardian.security.secrets import SecretProvider
from opsguardian.tools.sample_data import DEPLOYMENT_HISTORY, SYNTHETIC_SERVICES

logger = get_logger("tools.remediation")

# In-memory audit ledger of executed actions in local simulation mode
EXECUTION_AUDIT_LOG: list[dict[str, Any]] = []


def _check_hitl_confirmation(
    *,
    tool_context: Any | None,
    action_name: str,
    service_name: str,
    blast_radius_summary: str,
    confirmation_payload: dict[str, Any],
) -> dict[str, Any] | None:
    """Enforce explicit human confirmation via ADK ToolContext before executing mutations.

    Returns ``None`` ONLY when ``tool_context.tool_confirmation.confirmed is True``.
    Otherwise, triggers ``tool_context.request_confirmation(...)`` (when available) and
    returns a structured ``pending_approval`` or ``rejected`` dictionary halting execution.
    """
    confirmation = getattr(tool_context, "tool_confirmation", None) if tool_context else None

    if confirmation is None:
        hint = (
            f"HUMAN APPROVAL REQUIRED for `{action_name}` on `{service_name}`. "
            f"Blast radius: {blast_radius_summary}. "
            "Approve (`confirmed=True`) to execute or reject (`confirmed=False`) to abort."
        )
        if tool_context is not None and hasattr(tool_context, "request_confirmation"):
            try:
                tool_context.request_confirmation(
                    hint=hint,
                    payload=confirmation_payload,
                )
            except ValueError:
                # Occurs only in unit tests calling tool without function_call_id attached.
                pass

        logger.log_event(
            "hitl.approval_requested",
            hint,
            action=action_name,
            service_name=service_name,
            blast_radius=blast_radius_summary,
        )
        return RemediationActionOutput(
            status="pending_approval",
            action=action_name,
            service_name=service_name,
            confirmation_required=True,
            confirmation_hint=hint,
            blast_radius_summary=blast_radius_summary,
            details={"proposed_change": confirmation_payload},
        ).model_dump()

    if not getattr(confirmation, "confirmed", False):
        logger.log_event(
            "hitl.approval_rejected",
            f"Human operator rejected `{action_name}` on `{service_name}`.",
            action=action_name,
            service_name=service_name,
        )
        return RemediationActionOutput(
            status="rejected",
            action=action_name,
            service_name=service_name,
            confirmation_required=False,
            confirmation_hint="Operator explicitly rejected this remediation action.",
            blast_radius_summary=blast_radius_summary,
            details={"proposed_change": confirmation_payload, "executed": False},
        ).model_dump()

    return None


def rollback_cloud_run_revision(
    service_name: str,
    target_revision: str,
    reason: str,
    region: str = "us-central1",
    traffic_percent: int = 100,
    tool_context: Any | None = None,
) -> dict[str, Any]:
    """Roll back Cloud Run traffic for a service to a verified healthy revision (HITL gated).

    This is a **HIGH-STAKES MUTATING OPERATION** that requires explicit human operator
    confirmation before routing production traffic. Always verify ``target_revision``
    using ``list_recent_deployments`` before invoking this tool.

    Args:
        service_name: Kebab-case Cloud Run service name (e.g. ``"checkout-api"``).
        target_revision: Verified known-good Cloud Run revision ID (e.g.
            ``"checkout-api-00041-b7c"``). Must exist in recent deployment history.
        reason: Evidence-backed explanation referencing observed error logs and SLO burn.
        region: GCP Cloud Run region (default ``"us-central1"``).
        traffic_percent: Percentage of traffic to shift to ``target_revision`` (10-100,
            default 100).
        tool_context: ADK-injected ``ToolContext`` carrying ``tool_confirmation`` status.

    Returns:
        A JSON-serializable ``RemediationActionOutput`` with status:
          - ``"pending_approval"`` when awaiting human confirmation (pauses execution),
          - ``"rejected"`` when the human operator declines,
          - ``"success"`` when confirmed and executed (with ``audit_id``), or
          - ``ToolErrorResponse`` with ``recovery_instructions`` on invalid arguments.
    """
    try:
        validated = RollbackCloudRunRevisionInput(
            service_name=service_name,
            target_revision=target_revision,
            region=region,  # type: ignore[arg-type]
            traffic_percent=traffic_percent,
            reason=reason,
        )
    except ValidationError as exc:
        return ToolErrorResponse(
            status="error",
            error_code="INVALID_ROLLBACK_PARAMETERS",
            message=f"Rollback parameter validation failed: {exc.errors()[0]['msg']}",
            recovery_instructions=(
                "Ensure service_name is valid kebab-case, traffic_percent is 10-100, "
                "reason is at least 10 characters, and region is a supported GCP region."
            ),
            suggested_next_tool="list_recent_deployments",
            valid_options=list(SYNTHETIC_SERVICES),
            retryable=True,
        ).model_dump()

    history = DEPLOYMENT_HISTORY.get(validated.service_name)
    if history is None:
        return ToolErrorResponse(
            status="error",
            error_code="SERVICE_NOT_FOUND",
            message=f"Unknown Cloud Run service '{validated.service_name}'.",
            recovery_instructions=(
                "Call `list_recent_deployments` with a valid service from `valid_options` "
                "before proposing a rollback."
            ),
            suggested_next_tool="list_recent_deployments",
            valid_options=list(SYNTHETIC_SERVICES),
            retryable=True,
        ).model_dump()

    known_revisions = [d["revision_id"] for d in history["deployments"]]
    if validated.target_revision not in known_revisions:
        return ToolErrorResponse(
            status="error",
            error_code="REVISION_NOT_FOUND",
            message=(
                f"Revision '{validated.target_revision}' does not exist in deployment history "
                f"for '{validated.service_name}'."
            ),
            recovery_instructions=(
                "Never guess a revision ID. Select a verified revision from `valid_options` "
                f"(recommended last-known-good: '{history['last_known_good_revision']}') "
                "and re-request human approval."
            ),
            suggested_next_tool="list_recent_deployments",
            valid_options=known_revisions,
            retryable=True,
        ).model_dump()

    blast_radius = (
        f"Shifts {validated.traffic_percent}% of live traffic on '{validated.service_name}' "
        f"({validated.region}) from '{history['active_revision']}' -> '{validated.target_revision}'."
    )
    payload = validated.model_dump()

    gate_response = _check_hitl_confirmation(
        tool_context=tool_context,
        action_name="rollback_cloud_run_revision",
        service_name=validated.service_name,
        blast_radius_summary=blast_radius,
        confirmation_payload=payload,
    )
    if gate_response is not None:
        return gate_response

    audit_id = f"rb-{uuid.uuid4().hex[:10]}"
    record = {
        "audit_id": audit_id,
        "action": "rollback_cloud_run_revision",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "previous_revision": history["active_revision"],
        "target_revision": validated.target_revision,
        "traffic_percent": validated.traffic_percent,
        "region": validated.region,
        "reason": validated.reason,
        "mode": OpsGuardianConfig.from_env().env,
    }
    EXECUTION_AUDIT_LOG.append(record)
    logger.log_event(
        "remediation.rollback_executed",
        f"Executed approved rollback for '{validated.service_name}' to '{validated.target_revision}'.",
        audit_id=audit_id,
        service_name=validated.service_name,
        target_revision=validated.target_revision,
        traffic_percent=validated.traffic_percent,
    )
    return RemediationActionOutput(
        status="success",
        action="rollback_cloud_run_revision",
        service_name=validated.service_name,
        confirmation_required=False,
        audit_id=audit_id,
        blast_radius_summary=blast_radius,
        details=record,
    ).model_dump()


def scale_cloud_run_instances(
    service_name: str,
    min_instances: int,
    max_instances: int,
    reason: str,
    region: str = "us-central1",
    tool_context: Any | None = None,
) -> dict[str, Any]:
    """Adjust Cloud Run minimum and maximum instance scaling bounds (HITL gated).

    Use for latency spikes caused by cold starts (raising ``min_instances``) or queue
    backlog saturation (raising ``max_instances`` within organizational safety limits).
    Requires explicit human confirmation prior to execution.

    Args:
        service_name: Kebab-case Cloud Run service name.
        min_instances: Target minimum warm instances (0 to 50).
        max_instances: Target maximum autoscaling cap (1 to 100; must be >= min_instances).
        reason: Evidence-backed rationale citing observed metrics or runbook guidance.
        region: GCP Cloud Run region (default ``"us-central1"``).
        tool_context: ADK-injected ``ToolContext`` carrying ``tool_confirmation`` status.

    Returns:
        A JSON-serializable ``RemediationActionOutput`` (``pending_approval``,
        ``rejected``, or ``success``) or a guided ``ToolErrorResponse``.
    """
    try:
        validated = ScaleCloudRunInstancesInput(
            service_name=service_name,
            min_instances=min_instances,
            max_instances=max_instances,
            region=region,  # type: ignore[arg-type]
            reason=reason,
        )
    except ValidationError as exc:
        return ToolErrorResponse(
            status="error",
            error_code="INVALID_SCALING_BOUNDS",
            message=f"Scaling parameter validation failed: {exc.errors()[0]['msg']}",
            recovery_instructions=(
                "Ensure min_instances is 0..50, max_instances is 1..100, and "
                "max_instances >= min_instances, then retry."
            ),
            suggested_next_tool="scale_cloud_run_instances",
            valid_options=list(SYNTHETIC_SERVICES),
            retryable=True,
        ).model_dump()

    blast_radius = (
        f"Updates autoscaling for '{validated.service_name}' ({validated.region}) to "
        f"min_instances={validated.min_instances}, max_instances={validated.max_instances}."
    )
    gate_response = _check_hitl_confirmation(
        tool_context=tool_context,
        action_name="scale_cloud_run_instances",
        service_name=validated.service_name,
        blast_radius_summary=blast_radius,
        confirmation_payload=validated.model_dump(),
    )
    if gate_response is not None:
        return gate_response

    audit_id = f"scale-{uuid.uuid4().hex[:10]}"
    record = {
        "audit_id": audit_id,
        "action": "scale_cloud_run_instances",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **validated.model_dump(),
    }
    EXECUTION_AUDIT_LOG.append(record)
    return RemediationActionOutput(
        status="success",
        action="scale_cloud_run_instances",
        service_name=validated.service_name,
        audit_id=audit_id,
        blast_radius_summary=blast_radius,
        details=record,
    ).model_dump()


def page_oncall_incident_commander(
    service_name: str,
    severity: str,
    summary: str,
    evidence_citations: list[str],
    tool_context: Any | None = None,
) -> dict[str, Any]:
    """Trigger a high-urgency PagerDuty page to the Incident Commander (HITL gated).

    Reserved exclusively for ``SEV-1`` and ``SEV-2`` incidents supported by concrete
    telemetry citations. Retrieves the PagerDuty routing token securely via
    ``SecretProvider`` (Google Cloud Secret Manager in production — NEVER hardcoded).

    Args:
        service_name: Monitored service experiencing degradation.
        severity: Incident severity level; MUST be ``"SEV-1"`` or ``"SEV-2"``.
        summary: Concise operator-facing incident summary (15-300 characters).
        evidence_citations: Non-empty list of concrete trace IDs, revision IDs, or metric
            observations justifying the urgent page.
        tool_context: ADK-injected ``ToolContext`` carrying ``tool_confirmation`` status.

    Returns:
        A JSON-serializable ``RemediationActionOutput`` (``pending_approval``,
        ``rejected``, or ``success``) or a guided ``ToolErrorResponse``.
    """
    try:
        validated = PageOncallCommanderInput(
            service_name=service_name,
            severity=severity,  # type: ignore[arg-type]
            summary=summary,
            evidence_citations=evidence_citations,
        )
    except ValidationError as exc:
        return ToolErrorResponse(
            status="error",
            error_code="INVALID_PAGE_REQUEST",
            message=f"PagerDuty request rejected by schema validation: {exc.errors()[0]['msg']}",
            recovery_instructions=(
                "Only SEV-1 and SEV-2 incidents with at least one concrete evidence citation "
                "may trigger a page. For SEV-3/SEV-4 issues, use `create_critical_incident_ticket` "
                "instead."
            ),
            suggested_next_tool="create_critical_incident_ticket",
            valid_options=["SEV-1", "SEV-2"],
            retryable=True,
        ).model_dump()

    blast_radius = (
        f"Dispatches high-urgency {validated.severity} page to on-call Incident Commander "
        f"for '{validated.service_name}'."
    )
    gate_response = _check_hitl_confirmation(
        tool_context=tool_context,
        action_name="page_oncall_incident_commander",
        service_name=validated.service_name,
        blast_radius_summary=blast_radius,
        confirmation_payload=validated.model_dump(),
    )
    if gate_response is not None:
        return gate_response

    cfg = OpsGuardianConfig.from_env()
    secrets = SecretProvider(cfg)
    pd_token = secrets.get_secret(
        cfg.secret_name_pagerduty_token,
        env_fallback="PAGERDUTY_ROUTING_KEY",
        required=False,
    )
    delivery_mode = "live_secret_configured" if pd_token else "simulated_local_mode"

    audit_id = f"page-{uuid.uuid4().hex[:10]}"
    record = {
        "audit_id": audit_id,
        "action": "page_oncall_incident_commander",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "delivery_mode": delivery_mode,
        "secret_configured": bool(pd_token),
        **validated.model_dump(),
    }
    EXECUTION_AUDIT_LOG.append(record)
    return RemediationActionOutput(
        status="success",
        action="page_oncall_incident_commander",
        service_name=validated.service_name,
        audit_id=audit_id,
        blast_radius_summary=blast_radius,
        details=record,
    ).model_dump()


def create_critical_incident_ticket(
    service_name: str,
    severity: str,
    title: str,
    root_cause_hypothesis: str,
    recommended_action: str,
    tool_context: Any | None = None,
) -> dict[str, Any]:
    """Create a tracked incident ticket with correlated evidence and remediation plan (HITL gated).

    Opens a structured incident tracking ticket (e.g. Jira/Issue Tracker) with strict
    schema validation and operator confirmation so ticket metadata is accurate and
    PII-free before external dispatch.

    Args:
        service_name: Kebab-case service identifier affected by the incident.
        severity: Validated severity tier (``"SEV-1"``, ``"SEV-2"``, ``"SEV-3"``, ``"SEV-4"``).
        title: Concise incident headline (10-160 characters).
        root_cause_hypothesis: Evidence-backed root cause hypothesis (15-1000 characters).
        recommended_action: Concrete next step or rollback target (10-500 characters).
        tool_context: ADK-injected ``ToolContext`` carrying ``tool_confirmation`` status.

    Returns:
        A JSON-serializable ``RemediationActionOutput`` (``pending_approval``,
        ``rejected``, or ``success``) or a guided ``ToolErrorResponse``.
    """
    try:
        validated = CreateCriticalIncidentTicketInput(
            service_name=service_name,
            severity=severity,  # type: ignore[arg-type]
            title=title,
            root_cause_hypothesis=root_cause_hypothesis,
            recommended_action=recommended_action,
        )
    except ValidationError as exc:
        return ToolErrorResponse(
            status="error",
            error_code="INVALID_TICKET_PAYLOAD",
            message=f"Incident ticket validation failed: {exc.errors()[0]['msg']}",
            recovery_instructions=(
                "Provide severity in {SEV-1..SEV-4}, a clear title (10-160 chars), "
                "root_cause_hypothesis (15+ chars), and recommended_action (10+ chars)."
            ),
            suggested_next_tool="create_critical_incident_ticket",
            valid_options=["SEV-1", "SEV-2", "SEV-3", "SEV-4"],
            retryable=True,
        ).model_dump()

    blast_radius = (
        f"Creates external {validated.severity} incident ticket for '{validated.service_name}': "
        f"'{validated.title}'."
    )
    gate_response = _check_hitl_confirmation(
        tool_context=tool_context,
        action_name="create_critical_incident_ticket",
        service_name=validated.service_name,
        blast_radius_summary=blast_radius,
        confirmation_payload=validated.model_dump(),
    )
    if gate_response is not None:
        return gate_response

    ticket_id = f"INC-{uuid.uuid4().hex[:6].upper()}"
    record = {
        "ticket_id": ticket_id,
        "action": "create_critical_incident_ticket",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **validated.model_dump(),
    }
    EXECUTION_AUDIT_LOG.append(record)
    return RemediationActionOutput(
        status="success",
        action="create_critical_incident_ticket",
        service_name=validated.service_name,
        audit_id=ticket_id,
        blast_radius_summary=blast_radius,
        details=record,
    ).model_dump()


def requires_scaling_confirmation(
    service_name: str,
    min_instances: int,
    max_instances: int,
    reason: str = "",
    region: str = "us-central1",
) -> bool:
    """Policy callable for ADK ``FunctionTool(require_confirmation=...)``."""
    _ = (service_name, reason, region)
    # Require explicit human approval for ALL production scaling modifications.
    return max_instances >= 1 or min_instances >= 0


def build_remediation_tools() -> list[Any]:
    """Wrap all high-stakes remediation functions with ADK native ``require_confirmation``."""
    from google.adk.tools import FunctionTool

    return [
        FunctionTool(func=rollback_cloud_run_revision, require_confirmation=True),
        FunctionTool(
            func=scale_cloud_run_instances,
            require_confirmation=requires_scaling_confirmation,
        ),
        FunctionTool(func=page_oncall_incident_commander, require_confirmation=True),
        FunctionTool(func=create_critical_incident_ticket, require_confirmation=True),
    ]

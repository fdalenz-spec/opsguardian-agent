"""Persistent postmortem and runbook retrieval tools backed by KnowledgeStore.

Tool names follow strict verb-noun specificity:
  - ``search_past_postmortems``
  - ``lookup_service_runbook``
"""

from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from opsguardian.config import OpsGuardianConfig
from opsguardian.memory.knowledge_store import KnowledgeStore
from opsguardian.schemas import (
    LookupServiceRunbookInput,
    LookupServiceRunbookOutput,
    PostmortemMatch,
    SearchPastPostmortemsInput,
    SearchPastPostmortemsOutput,
    ToolErrorResponse,
)

_knowledge_store: KnowledgeStore | None = None


def get_knowledge_store(config: OpsGuardianConfig | None = None) -> KnowledgeStore:
    """Return process-wide persistent ``KnowledgeStore`` instance (lazy initialized)."""
    global _knowledge_store
    if _knowledge_store is None:
        _knowledge_store = KnowledgeStore(config or OpsGuardianConfig.from_env())
    return _knowledge_store


def set_knowledge_store(store: KnowledgeStore) -> None:
    """Override the active ``KnowledgeStore`` (used by tests and custom runners)."""
    global _knowledge_store
    _knowledge_store = store


def search_past_postmortems(
    query: str,
    service_name: str | None = None,
    max_results: int = 3,
) -> dict[str, Any]:
    """Search historical incident postmortems from the persistent knowledge base.

    Queries Vertex AI Search, Firestore, or local SQLite FTS5 (depending on runtime
    configuration) using BM25 keyword matching to surface past root causes and verified
    mitigations similar to the active incident.

    Args:
        query: Free-text symptom keywords, error codes, or failure mode descriptions
            (e.g. ``"HTTP 503 connection pool exhausted"`` or ``"OOMKilled exit 137"``).
        service_name: Optional kebab-case service filter (e.g. ``"checkout-api"``).
        max_results: Maximum number of matching postmortems to return (1 to 10, default 3).

    Returns:
        A JSON-serializable dictionary matching ``SearchPastPostmortemsOutput`` on success,
        or a guided ``ToolErrorResponse`` explaining how to broaden or correct the query.
    """
    try:
        validated = SearchPastPostmortemsInput(
            query=query,
            service_name=service_name,
            max_results=max_results,
        )
    except ValidationError as exc:
        return ToolErrorResponse(
            status="error",
            error_code="INVALID_SEARCH_QUERY",
            message=f"Invalid postmortem search parameters: {exc.errors()[0]['msg']}",
            recovery_instructions=(
                "Provide a descriptive symptom query of at least 2 characters (e.g., "
                "'503 connection pool timeout') and set max_results between 1 and 10."
            ),
            suggested_next_tool="search_past_postmortems",
            retryable=True,
        ).model_dump()

    store = get_knowledge_store()
    backend, raw_matches = store.search_postmortems(
        validated.query,
        service_name=validated.service_name,
        max_results=validated.max_results,
    )
    matches = [PostmortemMatch(**item) for item in raw_matches]

    return SearchPastPostmortemsOutput(
        backend=backend,
        query=validated.query,
        matches=matches,
    ).model_dump()


def lookup_service_runbook(service_name: str) -> dict[str, Any]:
    """Retrieve the official SRE operational runbook for a monitored service.

    Returns owning team metadata, escalation policy URI, availability SLO target,
    step-by-step rollback checklist, and Cloud Logging / Monitoring verification queries
    persisted in the knowledge database.

    Args:
        service_name: Exact kebab-case service identifier (e.g. ``"checkout-api"``).

    Returns:
        A JSON-serializable dictionary matching ``LookupServiceRunbookOutput`` on success,
        or a guided ``ToolErrorResponse`` containing ``valid_options`` if no runbook
        exists for the requested service.
    """
    store = get_knowledge_store()
    valid_services = store.list_known_services()
    try:
        validated = LookupServiceRunbookInput(service_name=service_name)
    except ValidationError as exc:
        return ToolErrorResponse(
            status="error",
            error_code="INVALID_SERVICE_NAME",
            message=f"Invalid service_name format: {exc.errors()[0]['msg']}",
            recovery_instructions=(
                "Use a valid kebab-case service identifier from `valid_options` and retry "
                "`lookup_service_runbook`."
            ),
            suggested_next_tool="lookup_service_runbook",
            valid_options=valid_services,
            retryable=True,
        ).model_dump()

    runbook = store.get_runbook(validated.service_name)
    if runbook is None:
        return ToolErrorResponse(
            status="error",
            error_code="RUNBOOK_NOT_FOUND",
            message=f"No runbook found for service '{validated.service_name}'.",
            recovery_instructions=(
                "Inform the operator that no dedicated runbook exists and retry using one "
                "of the registered services in `valid_options`, or use `search_past_postmortems` "
                "for general symptom guidance."
            ),
            suggested_next_tool="search_past_postmortems",
            valid_options=valid_services,
            retryable=True,
        ).model_dump()

    return LookupServiceRunbookOutput(
        runbook_id=runbook.runbook_id,
        service_name=runbook.service_name,
        owner_team=runbook.owner_team,
        escalation_policy=runbook.escalation_policy,
        slo_availability_target=runbook.slo_availability_target,
        safe_rollback_steps=runbook.safe_rollback_steps,
        verification_queries=runbook.verification_queries,
    ).model_dump()

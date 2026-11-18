"""Specific, schema-validated ADK tools for telemetry, knowledge, and HITL remediation.

Uses PEP-562 lazy exports so pure-Python modules (such as ``sample_data``) can be
imported without eagerly loading Pydantic or ADK runtime dependencies.
"""

from __future__ import annotations

import importlib
from typing import Any

_EXPORTS: dict[str, tuple[str, str]] = {
    "EXECUTION_AUDIT_LOG": ("opsguardian.tools.remediation_tools", "EXECUTION_AUDIT_LOG"),
    "build_remediation_tools": ("opsguardian.tools.remediation_tools", "build_remediation_tools"),
    "create_critical_incident_ticket": (
        "opsguardian.tools.remediation_tools",
        "create_critical_incident_ticket",
    ),
    "fetch_service_error_logs": ("opsguardian.tools.telemetry_tools", "fetch_service_error_logs"),
    "get_knowledge_store": ("opsguardian.tools.knowledge_tools", "get_knowledge_store"),
    "list_recent_deployments": ("opsguardian.tools.telemetry_tools", "list_recent_deployments"),
    "lookup_service_runbook": ("opsguardian.tools.knowledge_tools", "lookup_service_runbook"),
    "page_oncall_incident_commander": (
        "opsguardian.tools.remediation_tools",
        "page_oncall_incident_commander",
    ),
    "query_slo_burn_metrics": ("opsguardian.tools.telemetry_tools", "query_slo_burn_metrics"),
    "rollback_cloud_run_revision": (
        "opsguardian.tools.remediation_tools",
        "rollback_cloud_run_revision",
    ),
    "scale_cloud_run_instances": (
        "opsguardian.tools.remediation_tools",
        "scale_cloud_run_instances",
    ),
    "search_past_postmortems": ("opsguardian.tools.knowledge_tools", "search_past_postmortems"),
    "set_knowledge_store": ("opsguardian.tools.knowledge_tools", "set_knowledge_store"),
}

__all__ = sorted(_EXPORTS.keys())


def __getattr__(name: str) -> Any:
    if name in _EXPORTS:
        module_name, attr_name = _EXPORTS[name]
        module = importlib.import_module(module_name)
        return getattr(module, attr_name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

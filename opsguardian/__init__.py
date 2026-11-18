"""OpsGuardian: Enterprise Cloud SRE Incident Triage & Remediation ADK Agent.

Exports ``app`` and ``root_agent`` lazily so ADK CLI tools (``adk web``, ``adk run``,
``adk eval``) discover the agent automatically while lightweight unit tests and offline
audits can import pure-Python submodules cleanly.
"""

from __future__ import annotations

from typing import Any

__version__ = "1.0.0"
__all__ = ["__version__", "app", "root_agent"]


def __getattr__(name: str) -> Any:
    if name in {"app", "root_agent", "memory_consolidator"}:
        from opsguardian import agent as _agent_mod

        return getattr(_agent_mod, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

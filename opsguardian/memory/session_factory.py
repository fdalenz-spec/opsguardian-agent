"""Factory for ADK persistent SessionService and MemoryService instances.

Satisfies **Persistent Session State** across environments:
  - ``vertex``: Managed ``VertexAiSessionService`` + ``VertexAiMemoryBankService``
    backed by Vertex AI Agent Engine.
  - ``postgres``: Production ``DatabaseSessionService`` backed by Cloud SQL
    PostgreSQL (`postgresql+asyncpg://...`).
  - ``sqlite``: Local persistent ``DatabaseSessionService`` backed by SQLite
    (`sqlite+aiosqlite:///./data/opsguardian_sessions.db`) so conversation history
    and session state survive process restarts without cloud spend.
  - ``memory``: Ephemeral ``InMemorySessionService`` for fast unit tests.
"""

from __future__ import annotations

import logging
from typing import Any

from opsguardian.config import OpsGuardianConfig
from opsguardian.observability.logging import get_logger

logger = get_logger("memory.session_factory")


def create_session_service(config: OpsGuardianConfig) -> Any:
    """Instantiate the configured ADK ``BaseSessionService``."""
    config.ensure_local_data_dirs()

    if config.session_backend == "vertex" and config.vertex_agent_engine_id:
        from google.adk.sessions import VertexAiSessionService

        logger.log_event(
            "session.service_init",
            "Initializing VertexAiSessionService for managed persistent sessions.",
            backend="vertex",
            project=config.gcp_project_id,
            location=config.gcp_location,
        )
        return VertexAiSessionService(
            project=config.gcp_project_id,
            location=config.gcp_location,
            agent_engine_id=config.vertex_agent_engine_id,
        )

    if config.session_backend in {"sqlite", "postgres"}:
        from google.adk.sessions import DatabaseSessionService

        db_url = config.database_url
        # ADK DatabaseSessionService uses SQLAlchemy asyncio extension; normalize sync schemes.
        if db_url.startswith("sqlite:///"):
            db_url = db_url.replace("sqlite:///", "sqlite+aiosqlite:///", 1)
        elif db_url.startswith("postgresql://"):
            db_url = db_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        try:
            service = DatabaseSessionService(db_url=db_url)
            logger.log_event(
                "session.service_init",
                "Initializing persistent DatabaseSessionService.",
                backend=config.session_backend,
                scheme=db_url.split("://", maxsplit=1)[0],
            )
            return service
        except ImportError as exc:
            logger.log_event(
                "session.service_fallback",
                f"DatabaseSessionService extra missing ({exc}); falling back to InMemorySessionService.",
                level=logging.WARNING,
            )

    from google.adk.sessions import InMemorySessionService

    logger.log_event(
        "session.service_init",
        "Initializing InMemorySessionService (ephemeral mode).",
        backend="memory",
    )
    return InMemorySessionService()


def create_memory_service(config: OpsGuardianConfig) -> Any:
    """Instantiate the configured ADK ``BaseMemoryService``."""
    if config.env == "gcp" and config.vertex_agent_engine_id and config.gcp_project_id:
        try:
            from google.adk.memory import VertexAiMemoryBankService

            logger.log_event(
                "memory.service_init",
                "Initializing VertexAiMemoryBankService for cross-session long-term memory.",
                backend="vertex_memory_bank",
                project=config.gcp_project_id,
            )
            return VertexAiMemoryBankService(
                project=config.gcp_project_id,
                location=config.gcp_location,
                agent_engine_id=config.vertex_agent_engine_id,
            )
        except Exception as exc:
            logger.log_event(
                "memory.service_fallback",
                f"VertexAiMemoryBankService unavailable ({type(exc).__name__}); using InMemoryMemoryService.",
                level=logging.WARNING,
            )

    from google.adk.memory.in_memory_memory_service import InMemoryMemoryService

    logger.log_event(
        "memory.service_init",
        "Initializing local InMemoryMemoryService (paired with persistent SQLite episodic store).",
        backend="in_memory+sqlite",
    )
    return InMemoryMemoryService()

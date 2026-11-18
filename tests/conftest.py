"""Shared pytest fixtures for OpsGuardian test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from opsguardian.config import OpsGuardianConfig
from opsguardian.memory.knowledge_store import KnowledgeStore
from opsguardian.security.pii_redactor import PiiRedactor
from opsguardian.tools.knowledge_tools import set_knowledge_store
from opsguardian.tools.remediation_tools import EXECUTION_AUDIT_LOG


@pytest.fixture
def local_config(tmp_path: Path) -> OpsGuardianConfig:
    """Create an isolated local-mode config pointing to temporary SQLite storage."""
    return OpsGuardianConfig(
        env="local",
        gcp_project_id="test-sandbox-project",
        session_backend="sqlite",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'sessions.db'}",
        knowledge_backend="sqlite",
        knowledge_db_path=str(tmp_path / "knowledge.db"),
        enable_cloud_dlp=False,
        enable_cloud_trace=False,
    )


@pytest.fixture
def knowledge_store(local_config: OpsGuardianConfig) -> KnowledgeStore:
    """Isolated KnowledgeStore pre-seeded with synthetic postmortems and runbooks."""
    store = KnowledgeStore(local_config)
    set_knowledge_store(store)
    return store


@pytest.fixture
def redactor() -> PiiRedactor:
    return PiiRedactor(enable_cloud_dlp=False)


@pytest.fixture(autouse=True)
def _clear_audit_log() -> None:
    EXECUTION_AUDIT_LOG.clear()

"""Central runtime configuration for OpsGuardian.

Supports dual-mode execution:
  - ``local``: Zero-cost local development using SQLite persistence, local regex/Luhn
    PII scrubbing, synthetic telemetry datasets, and optional live Gemini API calls.
  - ``gcp``: Full Google Cloud integrations (Vertex AI Agent Engine sessions/memory,
    Cloud DLP, Secret Manager, Firestore/Vertex AI Search, Model Armor, Cloud Trace).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

EnvironmentMode = Literal["local", "gcp"]
SessionBackend = Literal["sqlite", "postgres", "vertex", "memory"]
KnowledgeBackend = Literal["sqlite", "firestore", "vertex_search"]


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return int(raw.strip())


@dataclass(frozen=True)
class OpsGuardianConfig:
    """Immutable runtime settings populated from environment variables."""

    app_name: str = "opsguardian"
    env: EnvironmentMode = "local"
    use_vertex_ai: bool = True
    gcp_project_id: str = ""
    gcp_location: str = "us-central1"
    vertex_agent_engine_id: str = ""

    # Strategic Model Routing (Criterion: Strategic Model Routing)
    fast_model: str = "gemini-2.5-flash"
    reasoning_model: str = "gemini-2.5-pro"
    dynamic_escalation_enabled: bool = True

    # Persistent Session & Knowledge Backends (Criterion: Persistent Session State)
    session_backend: SessionBackend = "sqlite"
    database_url: str = "sqlite+aiosqlite:///./data/opsguardian_sessions.db"
    knowledge_backend: KnowledgeBackend = "sqlite"
    knowledge_db_path: str = "./data/opsguardian_knowledge.db"
    vertex_search_data_store_id: str = ""

    # History Compaction & Context Caching (Criterion: History Compaction)
    compaction_interval: int = 4
    compaction_overlap: int = 1
    compaction_token_threshold: int = 12000
    compaction_retention_size: int = 4
    context_cache_intervals: int = 10
    context_cache_ttl_seconds: int = 1800
    context_cache_min_tokens: int = 2048

    # Security, PII Redaction & Guardrails
    enable_cloud_dlp: bool = False
    enable_model_armor: bool = False
    model_armor_template_id: str = ""
    change_freeze_active: bool = False
    max_cloud_run_instances: int = 100
    allowed_services: tuple[str, ...] = field(
        default=(
            "checkout-api",
            "auth-service",
            "payments-worker",
            "inventory-service",
            "search-gateway",
        )
    )

    # Observability & Distributed Tracing
    log_level: str = "INFO"
    enable_cloud_trace: bool = False
    otlp_endpoint: str = ""
    otel_console_export: bool = False

    # Secret Manager Secret IDs (NEVER store literal API keys here)
    secret_name_gemini_api_key: str = "opsguardian-gemini-api-key"  # noqa: S105
    secret_name_pagerduty_token: str = "opsguardian-pagerduty-token"  # noqa: S105
    secret_name_slack_webhook: str = "opsguardian-slack-webhook"  # noqa: S105

    @classmethod
    def from_env(cls) -> OpsGuardianConfig:
        """Build configuration from environment variables with safe defaults."""
        raw_env = os.getenv("OPSGUARDIAN_ENV", "local").strip().lower()
        env: EnvironmentMode = "gcp" if raw_env == "gcp" else "local"

        raw_session = os.getenv("OPSGUARDIAN_SESSION_BACKEND", "sqlite").strip().lower()
        session_backend: SessionBackend = (
            raw_session  # type: ignore[assignment]
            if raw_session in {"sqlite", "postgres", "vertex", "memory"}
            else "sqlite"
        )

        raw_knowledge = os.getenv("OPSGUARDIAN_KNOWLEDGE_BACKEND", "sqlite").strip().lower()
        knowledge_backend: KnowledgeBackend = (
            raw_knowledge  # type: ignore[assignment]
            if raw_knowledge in {"sqlite", "firestore", "vertex_search"}
            else "sqlite"
        )

        return cls(
            env=env,
            use_vertex_ai=_env_bool("GOOGLE_GENAI_USE_VERTEXAI", default=True),
            gcp_project_id=os.getenv("GOOGLE_CLOUD_PROJECT", "").strip(),
            gcp_location=os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1").strip(),
            vertex_agent_engine_id=os.getenv("VERTEX_AGENT_ENGINE_ID", "").strip(),
            fast_model=os.getenv("OPSGUARDIAN_FAST_MODEL", "gemini-2.5-flash").strip(),
            reasoning_model=os.getenv("OPSGUARDIAN_REASONING_MODEL", "gemini-2.5-pro").strip(),
            dynamic_escalation_enabled=_env_bool(
                "OPSGUARDIAN_DYNAMIC_ESCALATION_ENABLED", default=True
            ),
            session_backend=session_backend,
            database_url=os.getenv(
                "OPSGUARDIAN_DATABASE_URL",
                "sqlite+aiosqlite:///./data/opsguardian_sessions.db",
            ).strip(),
            knowledge_backend=knowledge_backend,
            knowledge_db_path=os.getenv(
                "OPSGUARDIAN_KNOWLEDGE_DB_PATH",
                "./data/opsguardian_knowledge.db",
            ).strip(),
            vertex_search_data_store_id=os.getenv("VERTEX_SEARCH_DATA_STORE_ID", "").strip(),
            compaction_interval=_env_int("OPSGUARDIAN_COMPACTION_INTERVAL", 4),
            compaction_overlap=_env_int("OPSGUARDIAN_COMPACTION_OVERLAP", 1),
            compaction_token_threshold=_env_int("OPSGUARDIAN_COMPACTION_TOKEN_THRESHOLD", 12000),
            compaction_retention_size=_env_int("OPSGUARDIAN_COMPACTION_RETENTION_SIZE", 4),
            context_cache_ttl_seconds=_env_int("OPSGUARDIAN_CONTEXT_CACHE_TTL_SECONDS", 1800),
            enable_cloud_dlp=_env_bool("OPSGUARDIAN_ENABLE_CLOUD_DLP", default=(env == "gcp")),
            enable_model_armor=_env_bool("OPSGUARDIAN_ENABLE_MODEL_ARMOR", default=False),
            model_armor_template_id=os.getenv("MODEL_ARMOR_TEMPLATE_ID", "").strip(),
            change_freeze_active=_env_bool("OPSGUARDIAN_CHANGE_FREEZE", default=False),
            max_cloud_run_instances=_env_int("OPSGUARDIAN_MAX_INSTANCES", 100),
            log_level=os.getenv("OPSGUARDIAN_LOG_LEVEL", "INFO").strip().upper(),
            enable_cloud_trace=_env_bool("OPSGUARDIAN_ENABLE_CLOUD_TRACE", default=(env == "gcp")),
            otlp_endpoint=os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT", "").strip(),
            otel_console_export=_env_bool("OTEL_CONSOLE_EXPORT", default=False),
            secret_name_gemini_api_key=os.getenv(
                "SECRET_NAME_GEMINI_API_KEY", "opsguardian-gemini-api-key"
            ).strip(),
            secret_name_pagerduty_token=os.getenv(
                "SECRET_NAME_PAGERDUTY_TOKEN", "opsguardian-pagerduty-token"
            ).strip(),
            secret_name_slack_webhook=os.getenv(
                "SECRET_NAME_SLACK_WEBHOOK", "opsguardian-slack-webhook"
            ).strip(),
        )

    def ensure_local_data_dirs(self) -> None:
        """Create local storage directories when using SQLite backends."""
        if self.knowledge_backend == "sqlite":
            Path(self.knowledge_db_path).parent.mkdir(parents=True, exist_ok=True)
        if self.database_url.startswith("sqlite") and ":///" in self.database_url:
            db_file = self.database_url.split(":///", maxsplit=1)[1]
            if db_file and db_file != ":memory:":
                Path(db_file).parent.mkdir(parents=True, exist_ok=True)

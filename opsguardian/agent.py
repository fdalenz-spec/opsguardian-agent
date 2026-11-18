"""ADK application entry point exporting ``root_agent`` and ``app``.

Compatible with all standard ADK CLI & serving commands:
  - ``adk web .``
  - ``adk run opsguardian``
  - ``adk api_server .``
  - ``adk eval opsguardian eval/opsguardian.evalset.json``
  - ``adk deploy cloud_run ... opsguardian``
"""

from __future__ import annotations

from dotenv import load_dotenv
from google.adk.apps import App, ResumabilityConfig

from opsguardian.config import OpsGuardianConfig
from opsguardian.memory.async_consolidator import (
    AsyncMemoryConsolidator,
    build_async_memory_plugin,
)
from opsguardian.memory.compaction import (
    build_compaction_config,
    build_context_cache_config,
)
from opsguardian.memory.knowledge_store import KnowledgeStore
from opsguardian.observability.logging import configure_logging
from opsguardian.observability.plugin import ObservabilityIntentOutcomePlugin
from opsguardian.observability.tracing import configure_tracing
from opsguardian.orchestration.agents import build_agent_hierarchy
from opsguardian.orchestration.model_router import build_dynamic_routing_plugin
from opsguardian.security.guardrails import build_policy_guardrail_plugin
from opsguardian.security.pii_redactor import PiiRedactor
from opsguardian.tools.knowledge_tools import set_knowledge_store

load_dotenv(override=False)


def build_opsguardian_app(
    config: OpsGuardianConfig | None = None,
) -> tuple[App, AsyncMemoryConsolidator]:
    """Assemble the complete ADK ``App`` with plugins, compaction, caching, and resumability."""
    cfg = config or OpsGuardianConfig.from_env()
    cfg.ensure_local_data_dirs()

    redactor = PiiRedactor(
        enable_cloud_dlp=cfg.enable_cloud_dlp,
        gcp_project_id=cfg.gcp_project_id,
    )
    configure_logging(
        level=cfg.log_level,
        redactor=redactor,
        gcp_project_id=cfg.gcp_project_id,
    )
    configure_tracing(cfg)

    knowledge_store = KnowledgeStore(cfg)
    set_knowledge_store(knowledge_store)

    consolidator = AsyncMemoryConsolidator(
        knowledge_store=knowledge_store,
        redactor=redactor,
    )

    root = build_agent_hierarchy(cfg)

    # Plugin ordering matters:
    # 1. Policy guardrails run FIRST to short-circuit prompt injections / change-freeze violations.
    # 2. Dynamic model router escalates Flash -> Pro on high-complexity SEV-1 prompts.
    # 3. Observability plugin records paired Intent vs Outcome JSON logs + OTel spans.
    # 4. Async memory plugin schedules non-blocking background consolidation after each turn.
    plugins = [
        build_policy_guardrail_plugin(cfg, redactor=redactor),
        build_dynamic_routing_plugin(cfg),
        ObservabilityIntentOutcomePlugin(redactor=redactor),
        build_async_memory_plugin(cfg, consolidator),
    ]

    adk_app = App(
        name=cfg.app_name,
        root_agent=root,
        plugins=plugins,
        events_compaction_config=build_compaction_config(cfg, redactor=redactor),
        context_cache_config=build_context_cache_config(cfg),
        resumability_config=ResumabilityConfig(is_resumable=True),
    )
    return adk_app, consolidator


app, memory_consolidator = build_opsguardian_app()
root_agent = app.root_agent

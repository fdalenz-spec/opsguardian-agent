"""Multi-agent orchestration graph built with Google ADK.

Implements proven design patterns rather than a monolithic agent:
  - **Coordinator (`LlmAgent` / Flash)**: Entry point with `PreloadMemoryTool` that
    delegates triage vs. remediation cleanly.
  - **Sequential Pipeline (`SequentialAgent`)**: Deterministic 3-stage investigation:
      1. **Parallel Fan-Out (`ParallelAgent`)**: Runs three Flash collectors
         concurrently (`log_collector_agent`, `metrics_correlator_agent`,
         `postmortem_retriever_agent`), each writing to an isolated `output_key`
         (`logs_evidence`, `metrics_evidence`, `postmortem_evidence`) to prevent
         session-state write races.
      2. **Deep Synthesizer (`LlmAgent` / Pro)**: Consumes correlated telemetry and
         emits strict `output_schema=RootCauseReport` into `root_cause_report`.
      3. **Self-Eval Critic (`LlmAgent` / Flash)**: Audits groundedness, citations,
         PII cleanliness, and HITL safety warnings before drafting the final briefing.
  - **Remediation Executor (`LlmAgent` / Pro)**: Executes HITL-gated tools wrapped in
    `FunctionTool(..., require_confirmation=...)`.
"""

from __future__ import annotations

from google.adk.agents import LlmAgent, ParallelAgent, SequentialAgent
from google.adk.tools.preload_memory_tool import PreloadMemoryTool

from opsguardian.config import OpsGuardianConfig
from opsguardian.orchestration.model_router import ModelRouter
from opsguardian.prompts import (
    COORDINATOR_INSTRUCTION,
    LOG_COLLECTOR_INSTRUCTION,
    METRICS_CORRELATOR_INSTRUCTION,
    POSTMORTEM_RETRIEVER_INSTRUCTION,
    REMEDIATION_EXECUTOR_INSTRUCTION,
    ROOT_CAUSE_SYNTHESIZER_INSTRUCTION,
    SELF_EVAL_CRITIC_INSTRUCTION,
)
from opsguardian.schemas import RootCauseReport
from opsguardian.tools.knowledge_tools import (
    lookup_service_runbook,
    search_past_postmortems,
)
from opsguardian.tools.remediation_tools import build_remediation_tools
from opsguardian.tools.telemetry_tools import (
    fetch_service_error_logs,
    list_recent_deployments,
    query_slo_burn_metrics,
)


def build_agent_hierarchy(config: OpsGuardianConfig | None = None) -> LlmAgent:
    """Construct the complete OpsGuardian multi-agent ADK hierarchy."""
    cfg = config or OpsGuardianConfig.from_env()
    router = ModelRouter(cfg)

    # Stage 1 (Parallel Fan-Out): Fast Flash collectors with isolated state keys.
    log_collector_agent = LlmAgent(
        name="log_collector_agent",
        model=router.model_for_role("log_collector_agent"),
        description=(
            "Collects PII-redacted Cloud Logging error records and recent Cloud Run "
            "deployment revisions for the affected service."
        ),
        instruction=LOG_COLLECTOR_INSTRUCTION,
        tools=[fetch_service_error_logs, list_recent_deployments],
        output_key="logs_evidence",
    )

    metrics_correlator_agent = LlmAgent(
        name="metrics_correlator_agent",
        model=router.model_for_role("metrics_correlator_agent"),
        description=(
            "Queries SLO error-budget burn rates, error ratios, latency percentiles, "
            "and CPU/memory saturation for the affected service."
        ),
        instruction=METRICS_CORRELATOR_INSTRUCTION,
        tools=[query_slo_burn_metrics],
        output_key="metrics_evidence",
    )

    postmortem_retriever_agent = LlmAgent(
        name="postmortem_retriever_agent",
        model=router.model_for_role("postmortem_retriever_agent"),
        description=(
            "Searches persistent historical postmortems and retrieves the official "
            "service runbook for verified rollback procedures."
        ),
        instruction=POSTMORTEM_RETRIEVER_INSTRUCTION,
        tools=[search_past_postmortems, lookup_service_runbook],
        output_key="postmortem_evidence",
    )

    telemetry_fanout = ParallelAgent(
        name="telemetry_fanout",
        description=(
            "Concurrently gathers error logs, deployment diffs, SLO burn metrics, "
            "historical postmortems, and runbooks in parallel."
        ),
        sub_agents=[
            log_collector_agent,
            metrics_correlator_agent,
            postmortem_retriever_agent,
        ],
    )

    # Stage 2: Deep Root-Cause Synthesizer on Pro reasoning tier with strict JSON output_schema.
    root_cause_synthesizer_agent = LlmAgent(
        name="root_cause_synthesizer_agent",
        model=router.model_for_role("root_cause_synthesizer_agent"),
        description=(
            "Correlates multi-signal telemetry using Gemini Pro and produces a strict "
            "schema-validated RootCauseReport JSON payload."
        ),
        instruction=ROOT_CAUSE_SYNTHESIZER_INSTRUCTION,
        output_schema=RootCauseReport,
        output_key="root_cause_report",
        disallow_transfer_to_parent=True,
        disallow_transfer_to_peers=True,
    )

    # Stage 3: Self-Evaluation & Grounding Critic (fast Flash guardrail reviewer).
    self_eval_critic_agent = LlmAgent(
        name="self_eval_critic_agent",
        model=router.model_for_role("self_eval_critic_agent"),
        description=(
            "Audits the draft RootCauseReport for grounded citations, PII hygiene, "
            "and HITL safety warnings before presenting the final SRE briefing."
        ),
        instruction=SELF_EVAL_CRITIC_INSTRUCTION,
        output_key="verified_briefing",
    )

    incident_investigation_pipeline = SequentialAgent(
        name="incident_investigation_pipeline",
        description=(
            "End-to-end deterministic incident investigation workflow: parallel "
            "telemetry fan-out -> Pro root-cause synthesis -> self-eval grounding critic."
        ),
        sub_agents=[
            telemetry_fanout,
            root_cause_synthesizer_agent,
            self_eval_critic_agent,
        ],
    )

    # Remediation specialist pinned to Pro with mandatory ADK HITL confirmation gates.
    remediation_executor_agent = LlmAgent(
        name="remediation_executor_agent",
        model=router.model_for_role("remediation_executor_agent"),
        description=(
            "Executes high-stakes Cloud Run rollbacks, autoscaling adjustments, "
            "urgent incident pages, and tracked incident tickets behind mandatory "
            "Human-in-the-Loop confirmation gates."
        ),
        instruction=REMEDIATION_EXECUTOR_INSTRUCTION,
        tools=build_remediation_tools(),
    )

    # Root Coordinator (Flash triage router + proactive long-term memory preload).
    coordinator = LlmAgent(
        name="opsguardian_coordinator",
        model=router.model_for_role("opsguardian_coordinator"),
        description=(
            "Primary OpsGuardian SRE coordinator. Routes incident investigations to "
            "incident_investigation_pipeline and human-approved remediation requests "
            "to remediation_executor_agent."
        ),
        instruction=COORDINATOR_INSTRUCTION,
        tools=[PreloadMemoryTool()],
        sub_agents=[
            incident_investigation_pipeline,
            remediation_executor_agent,
        ],
    )
    return coordinator

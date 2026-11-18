"""Tests for Category 3: Orchestration & Logic (multi-agent tree & model routing)."""

from __future__ import annotations

from opsguardian.config import OpsGuardianConfig
from opsguardian.orchestration.agents import build_agent_hierarchy
from opsguardian.orchestration.model_router import ModelRouter


def test_strategic_model_routing_static_and_dynamic(local_config: OpsGuardianConfig) -> None:
    router = ModelRouter(local_config)
    assert router.model_for_role("log_collector_agent") == "gemini-2.5-flash"
    assert router.model_for_role("metrics_correlator_agent") == "gemini-2.5-flash"
    assert router.model_for_role("postmortem_retriever_agent") == "gemini-2.5-flash"
    assert router.model_for_role("root_cause_synthesizer_agent") == "gemini-2.5-pro"
    assert router.model_for_role("remediation_executor_agent") == "gemini-2.5-pro"

    routine = router.evaluate_turn_routing(
        "opsguardian_coordinator", "Check latency for inventory-service."
    )
    assert not routine.escalated
    assert routine.selected_model == "gemini-2.5-flash"

    cascading = router.evaluate_turn_routing(
        "opsguardian_coordinator",
        "SEV-1 cascading failure impacting checkout-api and auth-service simultaneously!",
        session_severity="SEV-1",
    )
    assert cascading.escalated is True
    assert cascading.selected_model == "gemini-2.5-pro"


def test_multi_agent_hierarchy_structure(local_config: OpsGuardianConfig) -> None:
    root = build_agent_hierarchy(local_config)
    assert root.name == "opsguardian_coordinator"
    assert root.model == "gemini-2.5-flash"

    sub_names = [agent.name for agent in root.sub_agents]
    assert sub_names == ["incident_investigation_pipeline", "remediation_executor_agent"]

    pipeline = root.sub_agents[0]
    stage_names = [agent.name for agent in pipeline.sub_agents]
    assert stage_names == [
        "telemetry_fanout",
        "root_cause_synthesizer_agent",
        "self_eval_critic_agent",
    ]

    fanout = pipeline.sub_agents[0]
    collector_names = [agent.name for agent in fanout.sub_agents]
    assert collector_names == [
        "log_collector_agent",
        "metrics_correlator_agent",
        "postmortem_retriever_agent",
    ]
    # Verify isolated output keys in parallel fanout to avoid state race conditions
    output_keys = {agent.output_key for agent in fanout.sub_agents}
    assert output_keys == {"logs_evidence", "metrics_evidence", "postmortem_evidence"}

    # Verify Pro routing on synthesizer & remediation executor
    assert pipeline.sub_agents[1].model == "gemini-2.5-pro"
    assert root.sub_agents[1].model == "gemini-2.5-pro"

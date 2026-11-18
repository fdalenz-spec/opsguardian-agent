"""Strategic model routing between fast Flash models and Pro reasoning models.

Satisfies **Strategic Model Routing** through two layers:
  1. **Static Agent-Tier Routing (`ModelRouter.model_for_role`)**:
     - Fast/low-latency extraction, triage routing, parallel fan-out collection, and
       self-eval verification -> ``gemini-2.5-flash``
     - Complex multi-signal root-cause synthesis & high-stakes remediation planning ->
       ``gemini-2.5-pro``
  2. **Dynamic Complexity Escalation (`DynamicModelRoutingPlugin`)**:
     Inspects incoming prompts & session severity in ``before_model_callback``. If an
     agent normally pinned to Flash encounters a ``SEV-1`` cascading failure across
     multiple services, the plugin upgrades ``llm_request.model`` dynamically to
     ``gemini-2.5-pro`` and emits a structured routing audit log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

from opsguardian.config import OpsGuardianConfig
from opsguardian.observability.logging import get_logger

logger = get_logger("orchestration.model_router")

AgentTier = Literal["fast", "reasoning"]

_ROLE_TIER_MAP: dict[str, AgentTier] = {
    "opsguardian_coordinator": "fast",
    "log_collector_agent": "fast",
    "metrics_correlator_agent": "fast",
    "postmortem_retriever_agent": "fast",
    "self_eval_critic_agent": "fast",
    "compaction_summarizer": "fast",
    "root_cause_synthesizer_agent": "reasoning",
    "remediation_executor_agent": "reasoning",
}

_HIGH_COMPLEXITY_SIGNALS = (
    re.compile(r"(?i)\bsev[- ]?1\b"),
    re.compile(r"(?i)\bcascading\s+(failure|outage)\b"),
    re.compile(r"(?i)\bmulti[- ]region\b"),
    re.compile(r"(?i)\bdata\s+(loss|corruption)\b"),
    re.compile(r"(?i)\brollback\b.*\b(and|plus)\b.*\bscale\b"),
)

_KNOWN_SERVICE_RE = re.compile(
    r"\b(checkout-api|auth-service|payments-worker|inventory-service|search-gateway)\b"
)


@dataclass(frozen=True)
class RoutingDecision:
    """Auditable record describing why a specific Gemini model tier was chosen."""

    agent_name: str
    selected_model: str
    tier: AgentTier
    escalated: bool
    complexity_score: int
    rationale: str


class ModelRouter:
    """Determines optimal Gemini model tier for static agent wiring and runtime turns."""

    def __init__(self, config: OpsGuardianConfig) -> None:
        self._config = config

    def model_for_role(self, agent_name: str) -> str:
        """Return the baseline Gemini model assigned to an agent role."""
        tier = _ROLE_TIER_MAP.get(agent_name, "fast")
        return self._config.reasoning_model if tier == "reasoning" else self._config.fast_model

    def role_tier(self, agent_name: str) -> AgentTier:
        """Return whether an agent role defaults to ``fast`` or ``reasoning`` tier."""
        return _ROLE_TIER_MAP.get(agent_name, "fast")

    def evaluate_turn_routing(
        self,
        agent_name: str,
        prompt_text: str,
        *,
        session_severity: str | None = None,
    ) -> RoutingDecision:
        """Compute routing decision, escalating Flash -> Pro on high-complexity incidents."""
        base_tier = self.role_tier(agent_name)
        base_model = self.model_for_role(agent_name)

        if base_tier == "reasoning":
            return RoutingDecision(
                agent_name=agent_name,
                selected_model=base_model,
                tier="reasoning",
                escalated=False,
                complexity_score=10,
                rationale=f"Role '{agent_name}' requires deep reasoning tier by policy.",
            )

        if not self._config.dynamic_escalation_enabled:
            return RoutingDecision(
                agent_name=agent_name,
                selected_model=base_model,
                tier="fast",
                escalated=False,
                complexity_score=0,
                rationale="Dynamic escalation disabled; keeping fast Flash tier.",
            )

        score = 0
        reasons: list[str] = []

        if session_severity == "SEV-1":
            score += 3
            reasons.append("active session severity is SEV-1")

        services_mentioned = set(_KNOWN_SERVICE_RE.findall(prompt_text))
        if len(services_mentioned) >= 2:
            score += 2
            reasons.append(f"multi-service correlation ({sorted(services_mentioned)})")

        for pattern in _HIGH_COMPLEXITY_SIGNALS:
            if pattern.search(prompt_text):
                score += 2
                reasons.append(f"matched complexity signal '{pattern.pattern}'")

        # Keep parallel leaf data collectors on Flash for latency; escalate coordinator/critic.
        escalatable_roles = {"opsguardian_coordinator", "self_eval_critic_agent"}
        if agent_name in escalatable_roles and score >= 3:
            return RoutingDecision(
                agent_name=agent_name,
                selected_model=self._config.reasoning_model,
                tier="reasoning",
                escalated=True,
                complexity_score=score,
                rationale=(
                    f"Escalated '{agent_name}' from {self._config.fast_model} to "
                    f"{self._config.reasoning_model}: {', '.join(reasons)}."
                ),
            )

        return RoutingDecision(
            agent_name=agent_name,
            selected_model=base_model,
            tier="fast",
            escalated=False,
            complexity_score=score,
            rationale=f"Routine task complexity (score={score}); staying on fast Flash tier.",
        )

    def routing_matrix(self) -> dict[str, dict[str, str]]:
        """Export the full static agent-to-model routing table for documentation and telemetry."""
        return {
            role: {
                "tier": tier,
                "model": (
                    self._config.reasoning_model if tier == "reasoning" else self._config.fast_model
                ),
            }
            for role, tier in _ROLE_TIER_MAP.items()
        }


def build_dynamic_routing_plugin(config: OpsGuardianConfig) -> Any:
    """Build an ADK ``BasePlugin`` applying dynamic Flash -> Pro routing in ``before_model_callback``."""
    from google.adk.agents.callback_context import CallbackContext
    from google.adk.models.llm_request import LlmRequest
    from google.adk.models.llm_response import LlmResponse
    from google.adk.plugins.base_plugin import BasePlugin

    router = ModelRouter(config)

    class DynamicModelRoutingPlugin(BasePlugin):
        """Upgrades Flash calls to Pro on SEV-1 or cascading multi-service complexity."""

        def __init__(self) -> None:
            super().__init__(name="opsguardian_model_router")
            self.router = router

        async def before_model_callback(
            self, *, callback_context: CallbackContext, llm_request: LlmRequest
        ) -> LlmResponse | None:
            agent_name = getattr(callback_context, "agent_name", "unknown")
            state = getattr(callback_context, "state", {}) or {}
            text_chunks: list[str] = []
            for content in getattr(llm_request, "contents", []) or []:
                for part in getattr(content, "parts", []) or []:
                    if getattr(part, "text", None):
                        text_chunks.append(part.text)
            prompt_text = " ".join(text_chunks[-4:])

            decision = self.router.evaluate_turn_routing(
                agent_name,
                prompt_text,
                session_severity=state.get("incident_severity"),
            )
            if decision.escalated:
                llm_request.model = decision.selected_model
                logger.log_event(
                    "routing.model_escalated",
                    decision.rationale,
                    agent_name=agent_name,
                    selected_model=decision.selected_model,
                    complexity_score=decision.complexity_score,
                )
            else:
                logger.log_event(
                    "routing.model_selected",
                    decision.rationale,
                    agent_name=agent_name,
                    selected_model=decision.selected_model,
                    tier=decision.tier,
                    complexity_score=decision.complexity_score,
                )
            return None

    return DynamicModelRoutingPlugin()

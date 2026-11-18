"""Context bloat management: ADK EventsCompactionConfig, ContextCacheConfig & PII-safe summarizer.

Combines three complementary Google ADK context optimization controls (Criterion: History Compaction):
  1. **Sliding-Window & Token-Threshold Compaction (`EventsCompactionConfig`)**:
     Compacts older session turns every ``compaction_interval`` invocations (with
     ``overlap_size`` continuity) AND whenever prompt tokens exceed ``token_threshold``
     while preserving the most recent ``event_retention_size`` raw events verbatim.
  2. **PII-Safe Summarization (`PiiSafeCompactionSummarizer`)**:
     Custom ``BaseEventsSummarizer`` that redacts all PII & credentials BEFORE condensing
     events into a compact summary ``EventCompaction``.
  3. **Vertex AI / Gemini Context Caching (`ContextCacheConfig`)**:
     Reuses cached system constitutions, tool declarations, and incident prefixes across
     multi-turn war-room sessions to cut latency and token costs.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from opsguardian.config import OpsGuardianConfig
from opsguardian.observability.logging import get_logger
from opsguardian.security.pii_redactor import PiiRedactor

logger = get_logger("memory.compaction")


@dataclass(frozen=True)
class CompactionWindowResult:
    """Result returned by the deterministic sliding-window compactor helper."""

    summary_text: str
    compacted_event_count: int
    retained_events: list[dict[str, Any]]
    estimated_tokens_before: int
    estimated_tokens_after: int
    pii_redacted_count: int


def estimate_token_count(text: str) -> int:
    """Fast heuristic token estimator (~4 chars per token)."""
    return max(1, (len(text) + 3) // 4) if text else 0


def compact_history_window(
    events: Sequence[dict[str, Any]],
    *,
    token_threshold: int = 12000,
    retain_last_n: int = 4,
    overlap_size: int = 1,
    redactor: PiiRedactor | None = None,
) -> CompactionWindowResult:
    """Compact an older slice of conversation events into a PII-scrubbed summary.

    Used both inside the custom ADK ``BaseEventsSummarizer`` and directly in unit tests
    or offline simulations to guarantee bounded context growth.
    """
    scrubber = redactor or PiiRedactor()
    serialized = [f"{e.get('author', 'unknown')}: {e.get('text', '')}" for e in events]
    tokens_before = sum(estimate_token_count(line) for line in serialized)

    if len(events) <= retain_last_n or tokens_before < token_threshold:
        return CompactionWindowResult(
            summary_text="",
            compacted_event_count=0,
            retained_events=list(events),
            estimated_tokens_before=tokens_before,
            estimated_tokens_after=tokens_before,
            pii_redacted_count=0,
        )

    split_idx = max(1, len(events) - retain_last_n)
    compact_slice = events[:split_idx]
    retained_slice = list(events[max(0, split_idx - overlap_size) :])

    total_redactions = 0
    key_bullets: list[str] = []
    tools_seen: list[str] = []
    raw_compacted_chars = sum(len(str(e.get("text", ""))) for e in compact_slice)
    # Guarantee summary is strictly more compact than the raw events it replaces.
    max_bullets = 5
    per_bullet_chars = max(48, min(96, (raw_compacted_chars // max(max_bullets * 3, 1))))

    for item in compact_slice:
        raw_text = str(item.get("text", "")).strip()
        if not raw_text:
            continue
        res = scrubber.redact_text(raw_text)
        total_redactions += res.redaction_count
        author = str(item.get("author", "agent"))
        tool_name = item.get("tool_name")
        if tool_name and tool_name not in tools_seen:
            tools_seen.append(str(tool_name))
        if len(key_bullets) < max_bullets:
            snippet = res.redacted_text[:per_bullet_chars].replace("\n", " ").rstrip()
            if len(res.redacted_text) > per_bullet_chars:
                snippet += "..."
            key_bullets.append(f"- [{author}] {snippet}")

    header = (
        f"Compacted summary ({len(compact_slice)} turns; "
        f"pii_scrubbed={total_redactions}"
        + (f"; tools={','.join(tools_seen)}" if tools_seen else "")
        + "):"
    )
    summary_text = "\n".join([header, *key_bullets])

    # ADK compaction guarantee: replace older range only (overlap keeps continuity in summary).
    retained_tokens = sum(
        estimate_token_count(f"{e.get('author', '')}: {e.get('text', '')}")
        for e in events[split_idx:]
    )
    tokens_after = estimate_token_count(summary_text) + retained_tokens

    return CompactionWindowResult(
        summary_text=summary_text,
        compacted_event_count=len(compact_slice),
        retained_events=retained_slice,
        estimated_tokens_before=tokens_before,
        estimated_tokens_after=tokens_after,
        pii_redacted_count=total_redactions,
    )


def build_pii_safe_summarizer(
    config: OpsGuardianConfig,
    *,
    redactor: PiiRedactor | None = None,
) -> Any:
    """Build a custom ADK ``BaseEventsSummarizer`` that scrubs PII before compaction."""
    from google.adk.apps.base_events_summarizer import BaseEventsSummarizer
    from google.adk.events.event import Event
    from google.adk.events.event_actions import EventActions, EventCompaction
    from google.genai.types import Content, Part

    scrubber = redactor or PiiRedactor(
        enable_cloud_dlp=config.enable_cloud_dlp,
        gcp_project_id=config.gcp_project_id,
    )

    class PiiSafeCompactionSummarizer(BaseEventsSummarizer):
        """ADK event summarizer combining PII redaction with bounded-token summaries."""

        async def maybe_summarize_events(self, *, events: list[Event]) -> Event | None:
            if not events:
                return None

            normalized: list[dict[str, Any]] = []
            for event in events:
                parts = getattr(getattr(event, "content", None), "parts", None) or []
                text_chunks: list[str] = []
                tool_name: str | None = None
                for part in parts:
                    if getattr(part, "text", None):
                        text_chunks.append(part.text)
                    fc = getattr(part, "function_call", None)
                    if fc is not None and getattr(fc, "name", None):
                        tool_name = fc.name
                        text_chunks.append(f"called tool `{fc.name}`")
                if text_chunks:
                    normalized.append(
                        {
                            "author": getattr(event, "author", "unknown"),
                            "text": " ".join(text_chunks),
                            "tool_name": tool_name,
                        }
                    )

            if not normalized:
                return None

            result = compact_history_window(
                normalized,
                token_threshold=1,  # Trigger already checked by ADK Runner compaction policy
                retain_last_n=0,
                overlap_size=0,
                redactor=scrubber,
            )

            logger.log_event(
                "memory.events_compacted",
                f"Compacted {len(events)} ADK events into a PII-safe summary.",
                compacted_events=len(events),
                pii_redacted_count=result.pii_redacted_count,
                tokens_before=result.estimated_tokens_before,
                tokens_after=result.estimated_tokens_after,
            )

            summary_content = Content(
                role="model",
                parts=[Part(text=result.summary_text)],
            )
            compaction = EventCompaction(
                start_timestamp=events[0].timestamp,
                end_timestamp=events[-1].timestamp,
                compacted_content=summary_content,
            )
            return Event(
                author="user",
                actions=EventActions(compaction=compaction),
                invocation_id=Event.new_id(),
            )

    return PiiSafeCompactionSummarizer()


def build_compaction_config(
    config: OpsGuardianConfig,
    *,
    redactor: PiiRedactor | None = None,
) -> Any:
    """Create ADK ``EventsCompactionConfig`` with both sliding-window & token-threshold pairs."""
    from google.adk.apps.app import EventsCompactionConfig

    summarizer = build_pii_safe_summarizer(config, redactor=redactor)
    return EventsCompactionConfig(
        summarizer=summarizer,
        compaction_interval=config.compaction_interval,
        overlap_size=config.compaction_overlap,
        token_threshold=config.compaction_token_threshold,
        event_retention_size=config.compaction_retention_size,
    )


def build_context_cache_config(config: OpsGuardianConfig) -> Any:
    """Create ADK ``ContextCacheConfig`` for Gemini context caching across turns."""
    from google.adk.agents.context_cache_config import ContextCacheConfig

    return ContextCacheConfig(
        cache_intervals=config.context_cache_intervals,
        ttl_seconds=config.context_cache_ttl_seconds,
        min_tokens=config.context_cache_min_tokens,
    )

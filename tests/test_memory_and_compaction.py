"""Tests for Category 2: Context & Memory (persistence, compaction, async consolidation)."""

from __future__ import annotations

import asyncio

import pytest

from opsguardian.config import OpsGuardianConfig
from opsguardian.memory.async_consolidator import AsyncMemoryConsolidator
from opsguardian.memory.compaction import compact_history_window
from opsguardian.memory.knowledge_store import KnowledgeStore
from opsguardian.security.pii_redactor import PiiRedactor


def test_persistent_sqlite_store_survives_reopen(local_config: OpsGuardianConfig) -> None:
    store1 = KnowledgeStore(local_config)
    mem_id = store1.save_episodic_memory(
        session_id="sess-persist-1",
        user_id="sre-alice",
        service_name="checkout-api",
        summary="Resolved SEV-1 DB pool exhaustion via rollback.",
        tags=["SEV-1", "service:checkout-api"],
        pii_redacted_count=2,
    )
    assert mem_id > 0

    # Re-instantiate against the same SQLite file to verify durable persistence
    store2 = KnowledgeStore(local_config)
    memories = store2.list_episodic_memories(user_id="sre-alice")
    assert len(memories) == 1
    assert memories[0]["memory_id"] == mem_id
    assert "rollback" in memories[0]["summary"]


def test_history_compaction_reduces_tokens_and_scrubs_pii(redactor: PiiRedactor) -> None:
    events = [
        {
            "author": "user" if i % 2 == 0 else "log_collector_agent",
            "text": (
                f"Turn {i}: investigating checkout-api error reported by user{i}@example.com "
                f"from 198.51.100.{10 + i}. " + ("details " * 45)
            ),
            "tool_name": "fetch_service_error_logs" if i % 2 == 1 else None,
        }
        for i in range(12)
    ]
    res = compact_history_window(
        events,
        token_threshold=200,
        retain_last_n=3,
        overlap_size=1,
        redactor=redactor,
    )
    assert res.compacted_event_count == 9
    assert res.estimated_tokens_after < res.estimated_tokens_before
    assert res.pii_redacted_count >= 18
    assert "@example.com" not in res.summary_text
    assert "fetch_service_error_logs" in res.summary_text
    # Overlap keeps 1 event from the compacted boundary + 3 retained
    assert len(res.retained_events) == 4


@pytest.mark.asyncio
async def test_async_memory_consolidator_is_non_blocking_and_scrubs_pii(
    knowledge_store: KnowledgeStore,
    redactor: PiiRedactor,
) -> None:
    consolidator = AsyncMemoryConsolidator(
        knowledge_store=knowledge_store,
        redactor=redactor,
    )
    task = consolidator.schedule_consolidation(
        session_id="sess-async-99",
        user_id="sre-bob",
        raw_transcript=(
            "SEV-1 on auth-service triggered by alice@example.com from IP 203.0.113.55. "
            "Container OOMKilled exit 137."
        ),
    )
    assert isinstance(task, asyncio.Task)
    results = await consolidator.flush(timeout=5.0)
    assert len(results) == 1
    assert results[0].service_name == "auth-service"
    assert results[0].pii_redacted_count >= 2
    assert "SEV-1" in results[0].tags

    rows = knowledge_store.list_episodic_memories(user_id="sre-bob")
    assert rows and "alice@example.com" not in rows[0]["summary"]
    assert "203.0.113.55" not in rows[0]["summary"]

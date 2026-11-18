"""Asynchronous background memory extraction and consolidation pipeline.

Prevents expensive memory extraction, PII scrubbing, and Vertex AI Memory Bank
ingestion from blocking the user-facing response turn (Criterion: Async Memory Operations).
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from typing import Any

from opsguardian.config import OpsGuardianConfig
from opsguardian.memory.knowledge_store import KnowledgeStore
from opsguardian.observability.logging import get_logger
from opsguardian.observability.tracing import get_tracer
from opsguardian.security.pii_redactor import PiiRedactor

logger = get_logger("memory.async_consolidator")

_SERVICE_HINT_RE = re.compile(
    r"\b(checkout-api|auth-service|payments-worker|inventory-service|search-gateway)\b"
)
_SEVERITY_HINT_RE = re.compile(r"\b(SEV-[1-4])\b")


@dataclass(frozen=True)
class ConsolidationJobResult:
    """Metadata describing a completed background memory consolidation job."""

    session_id: str
    service_name: str
    memory_id: int
    pii_redacted_count: int
    tags: list[str]
    synced_to_memory_service: bool


class AsyncMemoryConsolidator:
    """Schedules non-blocking ``asyncio`` tasks to scrub and persist episodic memories."""

    def __init__(
        self,
        *,
        knowledge_store: KnowledgeStore,
        redactor: PiiRedactor | None = None,
        max_concurrency: int = 4,
    ) -> None:
        self._store = knowledge_store
        self._redactor = redactor or PiiRedactor()
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._tasks: set[asyncio.Task[ConsolidationJobResult]] = set()
        self._completed: list[ConsolidationJobResult] = []
        self._tracer = get_tracer("opsguardian.memory")

    @property
    def pending_count(self) -> int:
        """Number of background consolidation tasks currently executing."""
        return len(self._tasks)

    @property
    def completed_results(self) -> list[ConsolidationJobResult]:
        """Audit log of completed background consolidation jobs."""
        return list(self._completed)

    def schedule_consolidation(
        self,
        *,
        session_id: str,
        user_id: str,
        raw_transcript: str,
        adk_session: Any | None = None,
        memory_service: Any | None = None,
    ) -> asyncio.Task[ConsolidationJobResult]:
        """Fire-and-forget background task to redact PII and consolidate incident memory.

        Returns immediately so the user-facing response is never blocked waiting on
        database writes, DLP scanning, or Vertex AI Memory Bank ingestion.
        """
        task = asyncio.create_task(
            self._consolidate_worker(
                session_id=session_id,
                user_id=user_id,
                raw_transcript=raw_transcript,
                adk_session=adk_session,
                memory_service=memory_service,
            ),
            name=f"opsguardian-memory-{session_id}",
        )
        self._tasks.add(task)
        task.add_done_callback(self._on_task_done)
        return task

    def _on_task_done(self, task: asyncio.Task[ConsolidationJobResult]) -> None:
        self._tasks.discard(task)
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            logger.log_event(
                "memory.async_consolidation_error",
                f"Background memory consolidation failed: {type(exc).__name__}: {exc}",
                level=logging.ERROR,
            )
            return
        self._completed.append(task.result())

    async def _consolidate_worker(
        self,
        *,
        session_id: str,
        user_id: str,
        raw_transcript: str,
        adk_session: Any | None,
        memory_service: Any | None,
    ) -> ConsolidationJobResult:
        async with self._semaphore:
            with self._tracer.start_as_current_span(
                "opsguardian.memory.consolidate",
                attributes={"opsguardian.session_id": session_id},
            ) as span:
                # Scrub PII BEFORE any durable write (Criterion: PII Redaction)
                redaction = await asyncio.to_thread(self._redactor.redact_text, raw_transcript)
                clean_text = redaction.redacted_text.strip()

                svc_match = _SERVICE_HINT_RE.search(clean_text)
                service_name = svc_match.group(1) if svc_match else "general"
                tags = sorted(set(_SEVERITY_HINT_RE.findall(clean_text)))
                if service_name != "general":
                    tags.append(f"service:{service_name}")

                condensed_summary = clean_text[:600]
                memory_id = await asyncio.to_thread(
                    self._store.save_episodic_memory,
                    session_id=session_id,
                    user_id=user_id,
                    service_name=service_name,
                    summary=condensed_summary,
                    tags=tags,
                    pii_redacted_count=redaction.redaction_count,
                )

                synced_memory_service = False
                if memory_service is not None and adk_session is not None:
                    try:
                        await memory_service.add_session_to_memory(adk_session)
                        synced_memory_service = True
                    except Exception as exc:
                        logger.log_event(
                            "memory.bank_sync_failed",
                            f"Could not sync session to ADK memory service: {type(exc).__name__}",
                            level=logging.WARNING,
                            session_id=session_id,
                        )

                span.set_attribute("opsguardian.memory_id", memory_id)
                span.set_attribute("opsguardian.pii_redacted_count", redaction.redaction_count)

                result = ConsolidationJobResult(
                    session_id=session_id,
                    service_name=service_name,
                    memory_id=memory_id,
                    pii_redacted_count=redaction.redaction_count,
                    tags=tags,
                    synced_to_memory_service=synced_memory_service,
                )
                logger.log_event(
                    "memory.async_consolidated",
                    f"Consolidated episodic memory #{memory_id} for session '{session_id}' asynchronously.",
                    session_id=session_id,
                    service_name=service_name,
                    memory_id=memory_id,
                    pii_redacted_count=redaction.redaction_count,
                    synced_to_memory_service=synced_memory_service,
                )
                return result

    async def flush(self, timeout: float = 10.0) -> list[ConsolidationJobResult]:
        """Await all in-flight background memory tasks prior to graceful shutdown."""
        if not self._tasks:
            return []
        pending = list(self._tasks)
        await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=timeout)
        return self.completed_results


def build_async_memory_plugin(
    config: OpsGuardianConfig,
    consolidator: AsyncMemoryConsolidator,
) -> Any:
    """Build an ADK ``BasePlugin`` that triggers non-blocking memory consolidation post-run."""
    from google.adk.plugins.base_plugin import BasePlugin

    class AsyncMemoryConsolidationPlugin(BasePlugin):
        """Triggers background memory extraction in ``after_run_callback`` without blocking UI."""

        def __init__(self) -> None:
            super().__init__(name="opsguardian_async_memory")
            self.consolidator = consolidator

        async def after_run_callback(self, *, invocation_context: Any) -> None:
            session = getattr(invocation_context, "session", None)
            if session is None:
                return
            events = getattr(session, "events", []) or []
            snippets: list[str] = []
            for event in events[-6:]:
                content = getattr(event, "content", None)
                parts = getattr(content, "parts", None) or []
                for part in parts:
                    text = getattr(part, "text", None)
                    if text:
                        snippets.append(f"[{getattr(event, 'author', 'agent')}] {text}")
            if not snippets:
                return
            self.consolidator.schedule_consolidation(
                session_id=str(getattr(session, "id", "unknown")),
                user_id=str(getattr(session, "user_id", "operator")),
                raw_transcript="\n".join(snippets),
                adk_session=session,
                memory_service=getattr(invocation_context, "memory_service", None),
            )

        async def close(self) -> None:
            await self.consolidator.flush(timeout=5.0)

    _ = config
    return AsyncMemoryConsolidationPlugin()

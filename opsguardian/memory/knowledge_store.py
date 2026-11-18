"""Persistent knowledge & episodic memory store (Firestore / Vertex AI Search / SQLite FTS5).

Stores:
  1. Historical SRE postmortems (searchable via SQLite FTS5 BM25 locally, or Firestore /
     Vertex AI Search in GCP mode).
  2. Official service runbooks (keyed by service name).
  3. PII-scrubbed episodic incident memories written asynchronously after each turn.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from opsguardian.config import OpsGuardianConfig
from opsguardian.observability.logging import get_logger

logger = get_logger("memory.knowledge_store")


@dataclass(frozen=True)
class PostmortemRecord:
    """Historical incident postmortem stored in the persistent knowledge base."""

    postmortem_id: str
    title: str
    service_name: str
    date: str
    symptoms: str
    root_cause_summary: str
    resolution_summary: str


@dataclass(frozen=True)
class RunbookRecord:
    """Service-level operational runbook."""

    runbook_id: str
    service_name: str
    owner_team: str
    escalation_policy: str
    slo_availability_target: float
    safe_rollback_steps: list[str]
    verification_queries: list[str]


_SEED_POSTMORTEMS: tuple[PostmortemRecord, ...] = (
    PostmortemRecord(
        postmortem_id="PM-2025-104",
        title="checkout-api HTTP 503 surge after Cloud SQL connection pool misconfiguration",
        service_name="checkout-api",
        date="2025-09-14",
        symptoms="HTTP 503 ServiceUnavailable, connection pool exhausted, p99 latency > 4500ms, fast SLO burn",
        root_cause_summary=(
            "A deployment reduced `DB_POOL_MAX_SIZE` from 50 to 5 while enabling synchronous "
            "retry loops, saturating Cloud SQL proxy sockets within 4 minutes of rollout."
        ),
        resolution_summary=(
            "Rolled traffic 100% back to the previous known-good Cloud Run revision; "
            "error rate dropped from 18.4% to 0.08% within 90 seconds."
        ),
    ),
    PostmortemRecord(
        postmortem_id="PM-2025-089",
        title="auth-service OOMKilled crash loop during JWT cache spike",
        service_name="auth-service",
        date="2025-07-22",
        symptoms="Exit code 137 OOMKilled, memory utilization 99%, JWT signing timeout, HTTP 502",
        root_cause_summary=(
            "Unbounded in-memory JWKS key cache leaked memory after a key-rotation interval "
            "change, triggering container OOM kills under peak login traffic."
        ),
        resolution_summary=(
            "Scaled Cloud Run min_instances to 8, increased memory limit to 2Gi, and rolled "
            "back to previous stable revision until LRU cache eviction patch landed."
        ),
    ),
    PostmortemRecord(
        postmortem_id="PM-2025-062",
        title="payments-worker Pub/Sub dead-letter queue lag on downstream PSP timeout",
        service_name="payments-worker",
        date="2025-05-03",
        symptoms="Pub/Sub unacked messages > 25000, worker saturation, DEADLINE_EXCEEDED, backoff retry storm",
        root_cause_summary=(
            "Upstream payment gateway latency jumped from 180ms to 12s; aggressive 2s client "
            "timeout caused infinite retry amplification across worker replicas."
        ),
        resolution_summary=(
            "Increased Cloud Run max_instances from 15 to 40, enabled exponential jittered "
            "backoff, and paused non-critical reconciliation jobs until backlog drained."
        ),
    ),
    PostmortemRecord(
        postmortem_id="PM-2025-031",
        title="search-gateway elevated p99 latency after cold-start burst",
        service_name="search-gateway",
        date="2025-03-11",
        symptoms="cold start latency, p99 > 2000ms, scale-to-zero spike, HTTP 504 gateway timeout",
        root_cause_summary=(
            "Min instances was mistakenly set to 0 on a latency-sensitive edge gateway, causing "
            "JVM/model initialization spikes during morning EMEA traffic ramp."
        ),
        resolution_summary=(
            "Restored min_instances=4 and verified p99 dropped below 220ms SLO target."
        ),
    ),
)

_SEED_RUNBOOKS: tuple[RunbookRecord, ...] = (
    RunbookRecord(
        runbook_id="RB-CHECKOUT-01",
        service_name="checkout-api",
        owner_team="Core Commerce SRE",
        escalation_policy="pagerduty://core-commerce-primary",
        slo_availability_target=99.95,
        safe_rollback_steps=[
            "Verify the candidate last-known-good revision had < 0.1% error rate before traffic shift.",
            "Obtain explicit human approval via HITL confirmation before shifting traffic.",
            "Execute Cloud Run traffic rollback to the previous healthy revision (100% traffic).",
            "Monitor HTTP 5xx ratio and p99 latency for 5 consecutive minutes post-rollback.",
        ],
        verification_queries=[
            'resource.type="cloud_run_revision" AND resource.labels.service_name="checkout-api" AND severity>=ERROR',
            "metric: run.googleapis.com/request_count [response_code_class=5xx]",
        ],
    ),
    RunbookRecord(
        runbook_id="RB-AUTH-01",
        service_name="auth-service",
        owner_team="Identity & Security SRE",
        escalation_policy="pagerduty://identity-oncall-tier1",
        slo_availability_target=99.99,
        safe_rollback_steps=[
            "Inspect container exit codes for 137 (OOMKilled) and check active memory saturation.",
            "Confirm horizontal scale headroom (`scale_cloud_run_instances`) or roll back memory-leaking revision.",
            "Page Identity Incident Commander immediately for any SEV-1 login availability impact.",
        ],
        verification_queries=[
            'resource.type="cloud_run_revision" AND resource.labels.service_name="auth-service" AND textPayload:"OOM"',
            "metric: run.googleapis.com/container/memory/utilizations",
        ],
    ),
    RunbookRecord(
        runbook_id="RB-PAYMENTS-01",
        service_name="payments-worker",
        owner_team="Payments Platform SRE",
        escalation_policy="pagerduty://payments-platform-primary",
        slo_availability_target=99.9,
        safe_rollback_steps=[
            "Verify Pub/Sub unacked message count and oldest unacked message age.",
            "Scale worker instances within blast-radius policy limits (`max_instances <= 100`).",
            "Confirm dead-letter queue drain rate before closing the incident ticket.",
        ],
        verification_queries=[
            'resource.type="cloud_run_revision" AND resource.labels.service_name="payments-worker" AND severity>=WARNING',
            "metric: pubsub.googleapis.com/subscription/num_undelivered_messages",
        ],
    ),
    RunbookRecord(
        runbook_id="RB-INVENTORY-01",
        service_name="inventory-service",
        owner_team="Supply Chain SRE",
        escalation_policy="pagerduty://inventory-oncall",
        slo_availability_target=99.9,
        safe_rollback_steps=[
            "Check downstream Spanner/Firestore read latency before initiating revision rollback.",
            "Validate cache hit ratio and warm instance count.",
        ],
        verification_queries=[
            'resource.type="cloud_run_revision" AND resource.labels.service_name="inventory-service" AND severity>=ERROR',
        ],
    ),
    RunbookRecord(
        runbook_id="RB-SEARCH-01",
        service_name="search-gateway",
        owner_team="Discovery SRE",
        escalation_policy="pagerduty://discovery-oncall",
        slo_availability_target=99.95,
        safe_rollback_steps=[
            "Ensure min_instances >= 4 to eliminate cold-start p99 spikes.",
            "Roll back recent gateway config changes if 504 rate exceeds 0.5%.",
        ],
        verification_queries=[
            'resource.type="cloud_run_revision" AND resource.labels.service_name="search-gateway" AND severity>=ERROR',
        ],
    ),
)


class KnowledgeStore:
    """Persistent postmortem, runbook, and episodic memory store with GCP + SQLite dual mode."""

    def __init__(self, config: OpsGuardianConfig) -> None:
        self._config = config
        self._db_path = config.knowledge_db_path
        self._backend_name = "sqlite_fts5"
        self._init_sqlite()

    def _connect(self) -> sqlite3.Connection:
        if self._db_path != ":memory:":
            Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_sqlite(self) -> None:
        """Initialize persistent SQLite tables & FTS5 index, seeding default postmortems."""
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS postmortems (
                    postmortem_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    date TEXT NOT NULL,
                    symptoms TEXT NOT NULL,
                    root_cause_summary TEXT NOT NULL,
                    resolution_summary TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE VIRTUAL TABLE IF NOT EXISTS postmortems_fts USING fts5(
                    postmortem_id UNINDEXED,
                    title,
                    service_name,
                    symptoms,
                    root_cause_summary,
                    resolution_summary
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runbooks (
                    runbook_id TEXT PRIMARY KEY,
                    service_name TEXT UNIQUE NOT NULL,
                    owner_team TEXT NOT NULL,
                    escalation_policy TEXT NOT NULL,
                    slo_availability_target REAL NOT NULL,
                    safe_rollback_steps_json TEXT NOT NULL,
                    verification_queries_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS episodic_memories (
                    memory_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    pii_redacted_count INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL
                )
                """
            )
            existing = conn.execute("SELECT COUNT(*) FROM postmortems").fetchone()[0]
            if existing == 0:
                for pm in _SEED_POSTMORTEMS:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO postmortems
                        (postmortem_id, title, service_name, date, symptoms, root_cause_summary, resolution_summary)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            pm.postmortem_id,
                            pm.title,
                            pm.service_name,
                            pm.date,
                            pm.symptoms,
                            pm.root_cause_summary,
                            pm.resolution_summary,
                        ),
                    )
                    conn.execute(
                        """
                        INSERT INTO postmortems_fts
                        (postmortem_id, title, service_name, symptoms, root_cause_summary, resolution_summary)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            pm.postmortem_id,
                            pm.title,
                            pm.service_name,
                            pm.symptoms,
                            pm.root_cause_summary,
                            pm.resolution_summary,
                        ),
                    )
            existing_rb = conn.execute("SELECT COUNT(*) FROM runbooks").fetchone()[0]
            if existing_rb == 0:
                for rb in _SEED_RUNBOOKS:
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO runbooks
                        (runbook_id, service_name, owner_team, escalation_policy,
                         slo_availability_target, safe_rollback_steps_json, verification_queries_json)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            rb.runbook_id,
                            rb.service_name,
                            rb.owner_team,
                            rb.escalation_policy,
                            rb.slo_availability_target,
                            json.dumps(rb.safe_rollback_steps),
                            json.dumps(rb.verification_queries),
                        ),
                    )
            conn.commit()

    def _search_vertex_ai_search(
        self, query: str, max_results: int
    ) -> list[dict[str, Any]] | None:
        """Optional Google Cloud Vertex AI Search (Discovery Engine) query path."""
        if (
            self._config.knowledge_backend != "vertex_search"
            or not self._config.gcp_project_id
            or not self._config.vertex_search_data_store_id
        ):
            return None
        try:
            from google.cloud import discoveryengine_v1 as discoveryengine  # type: ignore[import-untyped]

            client = discoveryengine.SearchServiceClient()
            serving_config = (
                f"projects/{self._config.gcp_project_id}/locations/global/"
                f"collections/default_collection/dataStores/"
                f"{self._config.vertex_search_data_store_id}/servingConfigs/default_config"
            )
            response = client.search(
                request=discoveryengine.SearchRequest(
                    serving_config=serving_config,
                    query=query,
                    page_size=max_results,
                )
            )
            results: list[dict[str, Any]] = []
            for item in response.results:
                doc = item.document.derived_struct_data
                results.append(
                    {
                        "postmortem_id": str(doc.get("postmortem_id", item.document.id)),
                        "title": str(doc.get("title", "Historical Postmortem")),
                        "service_name": str(doc.get("service_name", "unknown")),
                        "date": str(doc.get("date", "unknown")),
                        "root_cause_summary": str(doc.get("root_cause_summary", "")),
                        "resolution_summary": str(doc.get("resolution_summary", "")),
                        "relevance_score": 0.9,
                    }
                )
            self._backend_name = "vertex_search"
            return results
        except Exception as exc:
            logger.log_event(
                "knowledge.vertex_search_fallback",
                f"Vertex AI Search unavailable ({type(exc).__name__}); falling back to SQLite FTS5.",
                level=logging.WARNING,
            )
            return None

    def _search_firestore(
        self, query: str, service_name: str | None, max_results: int
    ) -> list[dict[str, Any]] | None:
        """Optional Google Cloud Firestore persistent knowledge query path."""
        if self._config.knowledge_backend != "firestore" or not self._config.gcp_project_id:
            return None
        try:
            from google.cloud import firestore  # type: ignore[import-untyped]

            db = firestore.Client(project=self._config.gcp_project_id)
            ref = db.collection("opsguardian_postmortems")
            docs = (
                ref.where("service_name", "==", service_name).stream()
                if service_name
                else ref.stream()
            )
            tokens = {t.lower() for t in re.findall(r"[a-zA-Z0-9_-]{2,}", query)}
            scored: list[tuple[float, dict[str, Any]]] = []
            for snap in docs:
                data = snap.to_dict() or {}
                haystack = json.dumps(data).lower()
                hits = sum(1 for tok in tokens if tok in haystack)
                if hits > 0 or not tokens:
                    score = round(min(1.0, hits / max(len(tokens), 1)), 2)
                    data["relevance_score"] = score
                    scored.append((score, data))
            scored.sort(key=lambda pair: pair[0], reverse=True)
            self._backend_name = "firestore"
            return [item for _, item in scored[:max_results]]
        except Exception as exc:
            logger.log_event(
                "knowledge.firestore_fallback",
                f"Firestore unavailable ({type(exc).__name__}); falling back to SQLite FTS5.",
                level=logging.WARNING,
            )
            return None

    def search_postmortems(
        self,
        query: str,
        *,
        service_name: str | None = None,
        max_results: int = 3,
    ) -> tuple[str, list[dict[str, Any]]]:
        """Search historical postmortems across Vertex AI Search, Firestore, or SQLite FTS5."""
        if (vertex_hits := self._search_vertex_ai_search(query, max_results)) is not None:
            return "vertex_search", vertex_hits

        if (fs_hits := self._search_firestore(query, service_name, max_results)) is not None:
            return "firestore", fs_hits

        tokens = re.findall(r"[a-zA-Z0-9_]+", query.lower())
        fts_query = " OR ".join(f'"{tok}"' for tok in tokens[:12]) if tokens else ""

        matches: list[dict[str, Any]] = []
        with self._connect() as conn:
            if fts_query:
                sql = """
                    SELECT p.postmortem_id, p.title, p.service_name, p.date,
                           p.root_cause_summary, p.resolution_summary,
                           bm25(postmortems_fts) AS rank
                    FROM postmortems_fts
                    JOIN postmortems p ON p.postmortem_id = postmortems_fts.postmortem_id
                    WHERE postmortems_fts MATCH ?
                """
                params: list[Any] = [fts_query]
                if service_name:
                    sql += " AND p.service_name = ?"
                    params.append(service_name)
                sql += " ORDER BY rank ASC LIMIT ?"
                params.append(max_results)
                rows = conn.execute(sql, params).fetchall()
            else:
                rows = []

            if not rows and service_name:
                rows = conn.execute(
                    """
                    SELECT postmortem_id, title, service_name, date,
                           root_cause_summary, resolution_summary, -1.0 AS rank
                    FROM postmortems
                    WHERE service_name = ?
                    LIMIT ?
                    """,
                    (service_name, max_results),
                ).fetchall()

            for idx, row in enumerate(rows):
                score = round(max(0.35, 0.96 - idx * 0.14), 2)
                matches.append(
                    {
                        "postmortem_id": row["postmortem_id"],
                        "title": row["title"],
                        "service_name": row["service_name"],
                        "date": row["date"],
                        "root_cause_summary": row["root_cause_summary"],
                        "resolution_summary": row["resolution_summary"],
                        "relevance_score": score,
                    }
                )
        return "sqlite_fts5", matches

    def get_runbook(self, service_name: str) -> RunbookRecord | None:
        """Retrieve a service's operational runbook from the persistent store."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM runbooks WHERE service_name = ?",
                (service_name,),
            ).fetchone()
            if row is None:
                return None
            return RunbookRecord(
                runbook_id=row["runbook_id"],
                service_name=row["service_name"],
                owner_team=row["owner_team"],
                escalation_policy=row["escalation_policy"],
                slo_availability_target=float(row["slo_availability_target"]),
                safe_rollback_steps=json.loads(row["safe_rollback_steps_json"]),
                verification_queries=json.loads(row["verification_queries_json"]),
            )

    def save_episodic_memory(
        self,
        *,
        session_id: str,
        user_id: str,
        service_name: str,
        summary: str,
        tags: list[str],
        pii_redacted_count: int = 0,
    ) -> int:
        """Persist a PII-scrubbed episodic incident summary into SQLite (and Firestore if enabled)."""
        now = datetime.now(UTC).isoformat()
        if self._config.knowledge_backend == "firestore" and self._config.gcp_project_id:
            try:
                from google.cloud import firestore  # type: ignore[import-untyped]

                db = firestore.Client(project=self._config.gcp_project_id)
                db.collection("opsguardian_episodic_memories").add(
                    {
                        "session_id": session_id,
                        "user_id": user_id,
                        "service_name": service_name,
                        "summary": summary,
                        "tags": tags,
                        "pii_redacted_count": pii_redacted_count,
                        "created_at": now,
                    }
                )
            except Exception as exc:
                logger.log_event(
                    "knowledge.firestore_sync_failed",
                    (
                        "Firestore episodic memory sync failed; falling back to SQLite: "
                        f"{type(exc).__name__}"
                    ),
                    level=logging.WARNING,
                    session_id=session_id,
                    service_name=service_name,
                )

        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO episodic_memories
                (session_id, user_id, service_name, summary, tags_json, pii_redacted_count, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    user_id,
                    service_name,
                    summary,
                    json.dumps(tags),
                    pii_redacted_count,
                    now,
                ),
            )
            conn.commit()
            return int(cur.lastrowid or 0)

    def list_episodic_memories(
        self, *, user_id: str | None = None, limit: int = 10
    ) -> list[dict[str, Any]]:
        """Query recently consolidated episodic memories."""
        with self._connect() as conn:
            if user_id:
                rows = conn.execute(
                    """
                    SELECT * FROM episodic_memories
                    WHERE user_id = ?
                    ORDER BY memory_id DESC LIMIT ?
                    """,
                    (user_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM episodic_memories ORDER BY memory_id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [
                {
                    "memory_id": row["memory_id"],
                    "session_id": row["session_id"],
                    "user_id": row["user_id"],
                    "service_name": row["service_name"],
                    "summary": row["summary"],
                    "tags": json.loads(row["tags_json"]),
                    "pii_redacted_count": row["pii_redacted_count"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]

    def list_known_services(self) -> list[str]:
        """Return all services that have runbooks registered in persistent storage."""
        with self._connect() as conn:
            rows = conn.execute("SELECT service_name FROM runbooks ORDER BY service_name").fetchall()
            return [str(r["service_name"]) for r in rows]

    def export_seed_summary(self) -> dict[str, Any]:
        """Return non-sensitive metadata summary for diagnostics."""
        return {
            "backend": self._backend_name,
            "db_path": self._db_path,
            "seed_postmortems": [asdict(pm)["postmortem_id"] for pm in _SEED_POSTMORTEMS],
            "known_services": self.list_known_services(),
        }

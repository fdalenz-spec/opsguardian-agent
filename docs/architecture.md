# OpsGuardian Architecture Deep Dive

This document details the engineering trade-offs behind each of the five AgentOps pillars in OpsGuardian.

## 1. End-to-End Request Lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor SRE as On-Call SRE
    participant App as ADK App & Plugins
    participant Coord as Coordinator (Flash)
    participant Fan as Telemetry Fan-Out (Parallel Flash)
    participant Pro as Synthesizer (Pro)
    participant Critic as Self-Eval Critic (Flash)
    participant Rem as Remediation Executor (Pro)
    participant Mem as AsyncMemoryConsolidator

    SRE->>App: "Investigate checkout-api 503 spike"
    App->>App: PolicyGuardrailPlugin screens prompt (Model Armor / injection)
    App->>App: DynamicModelRoutingPlugin checks SEV-1 complexity
    App->>Coord: Transfer turn (start OTel root span + agent.intent log)
    Coord->>Fan: Delegate to incident_investigation_pipeline
    par Parallel Read-Only Evidence Collection
        Fan->>Fan: log_collector_agent -> fetch_service_error_logs + list_recent_deployments (PII scrubbed)
        Fan->>Fan: metrics_correlator_agent -> query_slo_burn_metrics
        Fan->>Fan: postmortem_retriever_agent -> search_past_postmortems + lookup_service_runbook
    end
    Fan->>Pro: Isolated state keys {logs_evidence, metrics_evidence, postmortem_evidence}
    Pro->>Critic: Strict JSON RootCauseReport (output_schema)
    Critic-->>SRE: Verified executive briefing + grounding status + HITL prompt
    App-->>Mem: after_run_callback -> asyncio.create_task (non-blocking PII scrub + persist)

    SRE->>App: "Roll back checkout-api to checkout-api-00041-b7c"
    App->>Rem: Delegate remediation
    Rem->>App: rollback_cloud_run_revision triggers request_confirmation()
    App-->>SRE: [HITL PAUSE] Blast-radius summary; Approve [y/N]?
    SRE->>App: Approve (ToolConfirmation(confirmed=True))
    Rem->>Rem: Execute rollback & emit audit_id + tool.outcome log
    Rem-->>SRE: Rollback verified & logged
```

## 2. Strategic Model Routing Table

| Agent / Component | Default Tier | Default Model | Rationale |
|---|---|---|---|
| `opsguardian_coordinator` | Fast (escalatable) | `gemini-2.5-flash` | Low-latency intent routing; dynamically upgraded to `gemini-2.5-pro` when `SEV-1` or multi-service cascading outage is detected. |
| `log_collector_agent` | Fast | `gemini-2.5-flash` | High-throughput tool dispatch for error logs & revisions. |
| `metrics_correlator_agent` | Fast | `gemini-2.5-flash` | Deterministic metric extraction & threshold check. |
| `postmortem_retriever_agent` | Fast | `gemini-2.5-flash` | Fast search query formulation & runbook lookup. |
| `root_cause_synthesizer_agent` | Reasoning | `gemini-2.5-pro` | Cross-signal causal correlation + strict `RootCauseReport` JSON output. |
| `self_eval_critic_agent` | Fast (escalatable) | `gemini-2.5-flash` | Low-latency grounding/citation & PII verification pass. |
| `remediation_executor_agent` | Reasoning | `gemini-2.5-pro` | High-stakes blast-radius reasoning & precision parameter selection. |

## 3. Dual-Mode Portability (`local` vs. `gcp`)

| Capability | `OPSGUARDIAN_ENV=local` (Default) | `OPSGUARDIAN_ENV=gcp` (Production) |
|---|---|---|
| LLM Runtime | Vertex AI ADC or Gemini API | Vertex AI (ADC via Cloud Run SA / Agent Engine) |
| Session Persistence | `DatabaseSessionService` (`sqlite+aiosqlite`) | `VertexAiSessionService` or Cloud SQL (`postgresql+asyncpg`) |
| Knowledge & RAG | SQLite FTS5 (BM25 full-text index) | Firestore or Vertex AI Search (`discoveryengine_v1`) |
| Long-Term Memory | Async SQLite episodic table + `InMemoryMemoryService` | `VertexAiMemoryBankService` + Firestore |
| PII Scrubbing | Deterministic regex + Luhn checksum | Google Cloud DLP (`dlp_v2`) + regex defense-in-depth |
| Prompt Safety | Deterministic injection rules + indirect log sanitizer | Google Cloud Model Armor (`modelarmor_v1`) + local rules |
| Secrets | Environment variables (audited with SHA-256 fingerprint) | Google Cloud Secret Manager (`secretmanager`) via ADC |
| Tracing | OpenTelemetry local/console/in-memory exporter | Google Cloud Trace (`CloudTraceSpanExporter`) / OTLP |

## 4. Parallel State Isolation

Inside `ParallelAgent` (`telemetry_fanout`), parallel sub-agents share a session state dictionary. To eliminate race conditions during concurrent writes, every leaf collector writes to a dedicated `output_key`:
- `log_collector_agent` -> `logs_evidence`
- `metrics_correlator_agent` -> `metrics_evidence`
- `postmortem_retriever_agent` -> `postmortem_evidence`

`root_cause_synthesizer_agent` then consumes all three via ADK optional template placeholders (`{logs_evidence?}`, `{metrics_evidence?}`, `{postmortem_evidence?}`) in `SequentialAgent`.

## 5. Defense-in-Depth PII & Security Boundaries

1. **Tool Input Validation:** Pydantic v2 `ConfigDict(extra="forbid")` catches hallucinated arguments and invalid bounds before touching downstream systems.
2. **Log Sanitization (`after_tool_callback` + `fetch_service_error_logs`):** Strips customer emails, RFC-5737 IPs, phone numbers, Luhn credit cards, SSNs, JWT/Bearer tokens, AND neutralizes indirect prompt injections embedded inside untrusted log text (`[NEUTRALIZED_UNTRUSTED_DIRECTIVE]`).
3. **Structured JSON Logging (`StructuredJsonFormatter`):** Automatically scrubs both the log message AND arbitrary `metadata` dictionaries before writing JSON.
4. **Compaction & Memory Persistence:** Both `PiiSafeCompactionSummarizer` and `AsyncMemoryConsolidator` scrub text BEFORE storing any summary into SQLite, Firestore, or Memory Bank.
5. **HITL Resumable Confirmation:** Every high-stakes tool uses both `FunctionTool(..., require_confirmation=...)` and an internal `tool_context.request_confirmation(...)` check with `ResumabilityConfig(is_resumable=True)`.

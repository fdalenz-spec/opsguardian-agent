# YouTube Video Walkthrough Script (4–5 Minutes · English)

> Recording a public English video is optional, yet it gives the automated reviewer strong context on **why** you designed OpsGuardian this way and lets you show working evidence across all 5 AgentOps categories in under 5 minutes.

## Pre-Recording Setup Checklist

1. Make your terminal font large (`15-16pt`) with high contrast and clear the screen before starting (`clear`).
2. Keep two browser tabs/windows ready:
   - **Tab 1:** GitHub repository `README.md` (showing the Mermaid architecture diagram and 19/19 matrix).
   - **Tab 2:** Your terminal inside `opsguardian-agent/`.
   - *(Optional Tab 3 if running live Gemini/Vertex AI)*: `adk web .` open at `http://localhost:8000`.
3. Verify zero sensitive info, internal URLs, or personal tokens are visible on screen.

---

## Segment-by-Segment Script

### 0:00 – 0:40 | Intro, Problem & Solution
**On Screen:** GitHub repo `README.md` top section + Mermaid architecture diagram.

> "Hi everyone! Today I'm walking through **OpsGuardian**, an Enterprise Cloud SRE Incident Triage and Remediation multi-agent system built with the **Google Agent Development Kit (ADK) for Python**.
>
> The problem I set out to solve is incident triage during high-severity cloud outages. On-call engineers lose critical minutes correlating error logs, SLO burn rates, recent deployments, and historical postmortems. Naive monolithic LLM agents fail in production for three reasons: raw logs bloat the context window, untrusted logs can leak PII or inject prompt attacks, and unguarded agents risk executing destructive rollbacks without human sign-off.
>
> OpsGuardian solves this using a dual-mode architecture: it runs locally out-of-the-box with SQLite and deterministic engines for zero-cost testing, and switches cleanly via config to Vertex AI, Cloud DLP, Secret Manager, Firestore, Model Armor, and Cloud Trace in production."

---

### 0:40 – 1:35 | Architecture & Multi-Agent Orchestration (Criteria 1–3)
**On Screen:** Scroll through `opsguardian/orchestration/agents.py`, `model_router.py`, `schemas.py`, and `prompts.py`.

> "Let's look at the core design across the AgentOps pillars:
>
> First, **Tool & Interface Design** (`opsguardian/schemas.py` and `opsguardian/tools/`): All nine tools use explicit verb-noun names like `fetch_service_error_logs` and `rollback_cloud_run_revision`—never generic wrappers. Every tool has Google-style `Args`/`Returns` docstrings, strict Pydantic v2 JSON schemas with `extra='forbid'`, and guided error recovery. If the LLM passes an unknown service or a hallucinated revision ID, the tool doesn't crash—it returns a `ToolErrorResponse` containing `recovery_instructions` and `valid_options`.
>
> Second, **Orchestration & Strategic Model Routing** (`opsguardian/orchestration/agents.py` and `model_router.py`): Rather than a monolithic agent, OpsGuardian uses an ADK **Coordinator** routing into a **SequentialAgent** investigation pipeline. Stage 1 is a **ParallelAgent** running three fast **Gemini 2.5 Flash** collectors concurrently—logs, SLO metrics, and historical postmortems—each writing to isolated `output_key`s to avoid state races. Stage 2 routes to **Gemini 2.5 Pro** for deep causal synthesis with strict `output_schema=RootCauseReport`. Stage 3 is a **Self-Eval Critic** checking groundedness and PII hygiene. Plus, `DynamicModelRoutingPlugin` monitors complexity and escalates Flash to Pro dynamically on `SEV-1` cascading outages."

---

### 1:35 – 2:25 | Context, Memory, Guardrails & HITL Safety
**On Screen:** Briefly show `opsguardian/agent.py`, `memory/compaction.py`, `memory/async_consolidator.py`, `security/guardrails.py`, and `tools/remediation_tools.py`.

> "In `opsguardian/agent.py`, we wire our ADK `App` with four ordered `BasePlugin`s, `ResumabilityConfig(is_resumable=True)`, `ContextCacheConfig`, and `EventsCompactionConfig`.
>
> For **Context & Memory**: older war-room turns are compacted via both sliding-window and token-threshold triggers using `PiiSafeCompactionSummarizer`, which scrubs PII before condensing history. Session state persists via `DatabaseSessionService` (`sqlite+aiosqlite`) locally or `VertexAiSessionService` in GCP, and long-term episodic memories are consolidated asynchronously via `asyncio.create_task` in `after_run_callback` so memory writes never block the operator UI.
>
> For **Safety & Human-in-the-Loop**: `PolicyGuardrailPlugin` screens prompts for jailbreaks and integrates with Google Cloud Model Armor, neutralizes indirect prompt injections embedded inside untrusted logs, and enforces active change freezes. Every high-stakes tool—rollback, scaling, paging, ticketing—uses both ADK `FunctionTool(..., require_confirmation=True)` and explicit `tool_context.request_confirmation(...)` checks so execution pauses with a blast-radius summary until a human approves or rejects."

---

### 2:25 – 3:45 | Live Terminal Demo (Observability, PII, Evals & Tracing)
**On Screen:** Terminal inside `opsguardian-agent/`. Run these exact commands:

```bash
# 1. End-to-end showcase with structured JSON Intent/Outcome logs
python3 -m opsguardian.demo_cli --dry-run --json-logs

# 2. Automated evaluation suite & static security/docstring audit
python3 -m eval.run_eval --offline

# 3. Unit tests
python3 -m unittest discover -s tests -p "test_stdlib_*.py" -v
```

*(Talk over the output as it scrolls:)*
> "Let's run the end-to-end showcase with structured JSON logging enabled. Notice four things in the output:
> 1. An adversarial prompt trying to bypass approval is blocked immediately by `prompt_injection_guard`.
> 2. Notice the structured JSON logs on stderr—zero bare `print()` statements anywhere in the package—emitting paired `tool.intent` and `tool.outcome` records linked by the same `action_id`, `trace_id`, and `span_id`.
> 3. In the raw `checkout-api` log, our synthetic customer email, IP address, phone number, and JWT token are automatically scrubbed to `[REDACTED_*]`, AND the indirect prompt injection hidden inside the order note is neutralized to `[NEUTRALIZED_UNTRUSTED_DIRECTIVE]`.
> 4. We see SQLite FTS5 matching postmortem `PM-2025-104`, sliding-window history compaction cutting prompt tokens, non-blocking async memory persistence verified PII-free, the HITL confirmation pause/reject/approve flow, and linked OpenTelemetry spans across the entire invocation.
>
> Next, running `python3 -m eval.run_eval --offline` runs our golden-dataset regression harness, verifies zero hardcoded secrets, zero raw `print()` calls, 100% tool docstring coverage, and checks all 5 cases in `eval/opsguardian.evalset.json`—ready for `adk eval` against live Gemini models too."

*(Optional extra 45s if you have live Gemini/Vertex AI credentials active:)*
```bash
adk web .
```
Show one live prompt in `adk web`:
> `checkout-api is throwing HTTP 503 errors right after our latest deploy. Investigate the root cause and cite matching postmortems without executing any rollback yet.`

---

### 3:45 – 4:20 | Infrastructure as Code, Secrets & CI/CD Wrap-Up
**On Screen:** Show `terraform/` folder listing, `terraform/secrets.tf`, `.github/workflows/ci.yml`, and `Makefile`.

> "Finally, under `terraform/` we provide complete Infrastructure as Code provisioning Google Cloud APIs, a least-privilege service account, Cloud Run v2, Artifact Registry, Firestore, GCS, Cloud Logging metrics, Cloud Monitoring alerts, and **Secret Manager** secret containers—with zero secret values in code or Terraform. `deployment/deploy_agent_engine.py` and `deployment/agent_starter_pack.yaml` support direct deployment via `adk deploy cloud_run` or Vertex AI Agent Engine, and GitHub Actions runs linting, type-checking, unit tests, our offline golden evaluation suite, and `terraform validate` on every push.
>
> Thank you for watching, and check out the README for exact commands to clone and test OpsGuardian yourself!"

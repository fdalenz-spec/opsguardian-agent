# OpsGuardian Automated Evaluation Suite

This directory holds the golden evaluation dataset and automated regression runners used to gate changes in CI (`.github/workflows/ci.yml`) and before production deploys.

## Files
- [`opsguardian.evalset.json`](opsguardian.evalset.json): 5 golden cases formatted in the exact Google ADK `EvalSet` schema:
  1. `sev1_checkout_api_triage` — Multi-signal `SEV-1` triage (logs + SLO burn + deployments + postmortem `PM-2025-104` + runbook `RB-CHECKOUT-01`).
  2. `sev1_auth_service_oom_diagnosis` — Container OOMKilled (`exit_code=137`) correlation matching `PM-2025-089`.
  3. `unknown_service_guided_error_recovery` — Guided error recovery without hallucinating metrics.
  4. `prompt_injection_and_guardrail_bypass_blocked` — Adversarial bypass rejected with 0 tool calls.
  5. `hitl_pause_required_before_rollback` — High-stakes rollback pauses pending explicit operator approval.
- [`eval_config.json`](eval_config.json): Official ADK evaluation criteria covering `tool_trajectory_avg_score`, `response_match_score`, `rubric_based_final_response_quality_v1`, and `rubric_based_tool_use_quality_v1`.
- [`run_eval.py`](run_eval.py): Dual-mode evaluator supporting CI-safe `--offline` runs and `--live` `AgentEvaluator` runs.

## Commands
```bash
# Deterministic offline regression & security audit (zero LLM cost, runs in CI)
python3 -m eval.run_eval --offline --output eval/reports/latest.json

# Live Google ADK CLI evaluation against Gemini / Vertex AI
adk eval opsguardian eval/opsguardian.evalset.json \
  --config_file_path eval/eval_config.json \
  --print_detailed_results
```

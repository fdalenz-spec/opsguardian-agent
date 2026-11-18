# Observability infrastructure: log-based metrics for guardrail blocks & HITL gates,
# plus Cloud Monitoring alerting on unexpected tool errors.

resource "google_logging_metric" "guardrail_blocks" {
  project     = var.project_id
  name        = "opsguardian_guardrail_blocks_total"
  description = "Count of prompt injections or policy violations blocked by PolicyGuardrailPlugin."
  filter      = "jsonPayload.event_type=\"guardrail.prompt_blocked\" OR jsonPayload.event_type=\"guardrail.tool_blocked\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }

  depends_on = [google_project_service.required]
}

resource "google_logging_metric" "tool_outcome_errors" {
  project     = var.project_id
  name        = "opsguardian_tool_outcome_errors_total"
  description = "Count of tool execution errors or intent/outcome mismatches."
  filter      = "jsonPayload.event_type=\"tool.error\" OR jsonPayload.metadata.matches_intent=false"

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }

  depends_on = [google_project_service.required]
}

resource "google_monitoring_alert_policy" "guardrail_spike" {
  project      = var.project_id
  display_name = "OpsGuardian — Guardrail Block Spike"
  combiner     = "OR"
  enabled      = true

  conditions {
    display_name = "Guardrail blocks exceed 5 in 5 minutes"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.guardrail_blocks.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5

      aggregations {
        alignment_period   = "300s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  documentation {
    content   = "Elevated security guardrail blocks detected on OpsGuardian. Inspect structured JSON logs filtering on jsonPayload.event_type=\"guardrail.prompt_blocked\"."
    mime_type = "text/markdown"
  }

  depends_on = [google_logging_metric.guardrail_blocks]
}

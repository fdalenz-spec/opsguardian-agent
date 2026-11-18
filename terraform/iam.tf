resource "google_service_account" "opsguardian" {
  project      = var.project_id
  account_id   = "opsguardian-agent-sa"
  display_name = "OpsGuardian ADK Agent Runtime Service Account"
  description  = "Least-privilege runtime identity for OpsGuardian (Vertex AI, DLP, Firestore, Trace, Secret Manager)."

  depends_on = [google_project_service.required]
}

locals {
  runtime_iam_roles = toset([
    "roles/aiplatform.user",
    "roles/cloudtrace.agent",
    "roles/datastore.user",
    "roles/discoveryengine.viewer",
    "roles/dlp.user",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/run.viewer",
  ])
}

resource "google_project_iam_member" "agent_roles" {
  for_each = local.runtime_iam_roles
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.opsguardian.email}"
}

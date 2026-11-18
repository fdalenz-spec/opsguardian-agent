output "cloud_run_service_url" {
  description = "Private/internal URL of the deployed OpsGuardian Cloud Run service."
  value       = google_cloud_run_v2_service.opsguardian.uri
}

output "service_account_email" {
  description = "Dedicated least-privilege IAM service account email."
  value       = google_service_account.opsguardian.email
}

output "artifact_registry_repository" {
  description = "Artifact Registry Docker repository path."
  value       = google_artifact_registry_repository.opsguardian.id
}

output "artifacts_bucket_name" {
  description = "GCS bucket for Agent Engine staging and evaluation artifacts."
  value       = google_storage_bucket.artifacts.name
}

output "secret_ids" {
  description = "Managed Secret Manager secret IDs (no values exposed)."
  value = {
    pagerduty_token = google_secret_manager_secret.pagerduty_token.secret_id
    slack_webhook   = google_secret_manager_secret.slack_webhook.secret_id
    gemini_api_key  = google_secret_manager_secret.gemini_api_key.secret_id
  }
}

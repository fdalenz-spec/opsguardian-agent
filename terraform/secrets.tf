# Secret Manager definitions — ZERO secret values are stored in Terraform or Git.
# Operators populate secret versions out-of-band via:
#   gcloud secrets versions add opsguardian-pagerduty-token --data-file=-

resource "google_secret_manager_secret" "pagerduty_token" {
  project   = var.project_id
  secret_id = "opsguardian-pagerduty-token"
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret" "slack_webhook" {
  project   = var.project_id
  secret_id = "opsguardian-slack-webhook"
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret" "gemini_api_key" {
  project   = var.project_id
  secret_id = "opsguardian-gemini-api-key"
  labels    = local.common_labels

  replication {
    auto {}
  }

  depends_on = [google_project_service.required]
}

resource "google_secret_manager_secret_iam_member" "pagerduty_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.pagerduty_token.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.opsguardian.email}"
}

resource "google_secret_manager_secret_iam_member" "slack_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.slack_webhook.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.opsguardian.email}"
}

resource "google_secret_manager_secret_iam_member" "gemini_key_accessor" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.gemini_api_key.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.opsguardian.email}"
}

locals {
  required_apis = toset([
    "aiplatform.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "cloudtrace.googleapis.com",
    "discoveryengine.googleapis.com",
    "dlp.googleapis.com",
    "firestore.googleapis.com",
    "iam.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
  ])

  common_labels = {
    app         = "opsguardian"
    environment = var.environment
    managed_by  = "terraform"
  }
}

resource "google_project_service" "required" {
  for_each           = local.required_apis
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "opsguardian" {
  project       = var.project_id
  location      = var.region
  repository_id = "opsguardian"
  description   = "Container images for the OpsGuardian ADK multi-agent SRE service."
  format        = "DOCKER"
  labels        = local.common_labels

  depends_on = [google_project_service.required]
}

resource "google_cloud_run_v2_service" "opsguardian" {
  name     = "opsguardian-agent"
  location = var.region
  project  = var.project_id
  ingress  = "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"
  labels   = local.common_labels

  template {
    service_account = google_service_account.opsguardian.email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    containers {
      image = var.container_image

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "2"
          memory = "2Gi"
        }
      }

      env {
        name  = "OPSGUARDIAN_ENV"
        value = "gcp"
      }

      env {
        name  = "GOOGLE_GENAI_USE_VERTEXAI"
        value = "TRUE"
      }

      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }

      env {
        name  = "GOOGLE_CLOUD_LOCATION"
        value = var.region
      }

      env {
        name  = "OPSGUARDIAN_FAST_MODEL"
        value = var.fast_model
      }

      env {
        name  = "OPSGUARDIAN_REASONING_MODEL"
        value = var.reasoning_model
      }

      env {
        name  = "OPSGUARDIAN_KNOWLEDGE_BACKEND"
        value = "firestore"
      }

      env {
        name  = "OPSGUARDIAN_ENABLE_CLOUD_DLP"
        value = tostring(var.enable_cloud_dlp)
      }

      env {
        name  = "OPSGUARDIAN_ENABLE_CLOUD_TRACE"
        value = "true"
      }

      env {
        name  = "OPSGUARDIAN_ENABLE_MODEL_ARMOR"
        value = tostring(var.enable_model_armor)
      }

      env {
        name  = "MODEL_ARMOR_TEMPLATE_ID"
        value = var.model_armor_template_id
      }

      env {
        name  = "SECRET_NAME_PAGERDUTY_TOKEN"
        value = google_secret_manager_secret.pagerduty_token.secret_id
      }

      env {
        name  = "SECRET_NAME_SLACK_WEBHOOK"
        value = google_secret_manager_secret.slack_webhook.secret_id
      }

      startup_probe {
        http_get {
          path = "/list-apps"
        }
        initial_delay_seconds = 10
        period_seconds        = 10
        failure_threshold     = 5
      }
    }
  }

  depends_on = [
    google_project_service.required,
    google_project_iam_member.agent_roles,
    google_secret_manager_secret_iam_member.pagerduty_accessor,
    google_secret_manager_secret_iam_member.slack_accessor,
    google_firestore_database.opsguardian,
  ]
}

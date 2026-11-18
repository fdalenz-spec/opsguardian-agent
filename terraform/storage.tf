# Persistent storage for episodic memories, postmortems, staging artifacts, and eval reports.

resource "google_firestore_database" "opsguardian" {
  project                           = var.project_id
  name                              = "(default)"
  location_id                       = var.firestore_location
  type                              = "FIRESTORE_NATIVE"
  concurrency_mode                  = "OPTIMISTIC"
  delete_protection_state           = "DELETE_PROTECTION_DISABLED"
  deletion_policy                   = "DELETE"
  point_in_time_recovery_enablement = "POINT_IN_TIME_RECOVERY_ENABLED"

  depends_on = [google_project_service.required]
}

resource "google_storage_bucket" "artifacts" {
  project                     = var.project_id
  name                        = "${var.project_id}-opsguardian-artifacts"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = local.common_labels

  versioning {
    enabled = true
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_project_service.required]
}

resource "google_storage_bucket_iam_member" "artifacts_object_admin" {
  bucket = google_storage_bucket.artifacts.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.opsguardian.email}"
}

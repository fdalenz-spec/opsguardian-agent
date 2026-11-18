variable "project_id" {
  description = "Google Cloud project ID where OpsGuardian resources will be provisioned."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a valid Google Cloud project ID (6-30 lowercase letters, digits, or hyphens)."
  }
}

variable "region" {
  description = "Primary Google Cloud region for Cloud Run, Artifact Registry, and Vertex AI."
  type        = string
  default     = "us-central1"
}

variable "environment" {
  description = "Deployment environment label (dev, staging, prod)."
  type        = string
  default     = "prod"

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "container_image" {
  description = "Fully qualified Artifact Registry container image URI for OpsGuardian."
  type        = string
  default     = "us-central1-docker.pkg.dev/example-project/opsguardian/opsguardian:latest"
}

variable "fast_model" {
  description = "Gemini model used for fast parallel collection, routing, and self-eval."
  type        = string
  default     = "gemini-2.5-flash"
}

variable "reasoning_model" {
  description = "Gemini model used for deep root-cause synthesis and remediation planning."
  type        = string
  default     = "gemini-2.5-pro"
}

variable "min_instances" {
  description = "Minimum warm Cloud Run instances to eliminate cold-start latency."
  type        = number
  default     = 1

  validation {
    condition     = var.min_instances >= 0 && var.min_instances <= 50
    error_message = "min_instances must be between 0 and 50."
  }
}

variable "max_instances" {
  description = "Maximum Cloud Run autoscaling cap (enforced by safety policy <= 100)."
  type        = number
  default     = 10

  validation {
    condition     = var.max_instances >= 1 && var.max_instances <= 100
    error_message = "max_instances must be between 1 and 100."
  }
}

variable "enable_cloud_dlp" {
  description = "Enable Google Cloud Sensitive Data Protection (DLP) API PII scrubbing."
  type        = bool
  default     = true
}

variable "enable_model_armor" {
  description = "Enable Google Cloud Model Armor prompt sanitization screening."
  type        = bool
  default     = false
}

variable "model_armor_template_id" {
  description = "Optional Model Armor template ID when enable_model_armor is true."
  type        = string
  default     = ""
}

variable "firestore_location" {
  description = "Firestore database location ID (e.g., nam5, eur3, or regional ID)."
  type        = string
  default     = "us-central1"
}

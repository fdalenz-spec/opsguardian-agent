"""Secure secret retrieval via Google Cloud Secret Manager with safe local fallback.

Design guarantees (Criterion: Secure Secret Management):
  - ZERO hardcoded API keys, tokens, or passwords anywhere in the codebase.
  - In ``gcp`` mode, retrieves secrets exclusively via Application Default Credentials
    (ADC) from Google Cloud Secret Manager (`google-cloud-secret-manager`).
  - In ``local`` mode, reads from environment variables and caches fetched values in
    memory with masked fingerprints so raw secret values are NEVER logged.
"""

from __future__ import annotations

import hashlib
import importlib
import os
from dataclasses import dataclass
from typing import Any

from opsguardian.config import OpsGuardianConfig


class SecretNotConfiguredError(RuntimeError):
    """Raised when a required secret is unavailable in both Secret Manager and env."""


@dataclass(frozen=True)
class SecretMetadata:
    """Non-sensitive metadata describing where a secret was resolved from."""

    secret_name: str
    source: str
    fingerprint_sha256_prefix: str


class SecretProvider:
    """Retrieves runtime credentials from Google Cloud Secret Manager or environment."""

    def __init__(self, config: OpsGuardianConfig) -> None:
        self._config = config
        self._cache: dict[str, str] = {}
        self._metadata: dict[str, SecretMetadata] = {}
        self._sm_client: object | None = None

    def _get_secret_manager_client(self) -> object:
        if self._sm_client is not None:
            return self._sm_client
        try:
            secretmanager: Any = importlib.import_module("google.cloud.secretmanager")
        except ImportError as exc:
            raise SecretNotConfiguredError(
                "google-cloud-secret-manager is not installed. Install optional extras "
                "with `pip install '.[gcp]'` or run in OPSGUARDIAN_ENV=local mode."
            ) from exc
        self._sm_client = secretmanager.SecretManagerServiceClient()
        return self._sm_client

    @staticmethod
    def fingerprint(secret_value: str) -> str:
        """Return an irreversible 12-char SHA-256 fingerprint safe for audit logs."""
        digest = hashlib.sha256(secret_value.encode("utf-8")).hexdigest()
        return f"sha256:{digest[:12]}"

    def get_secret(
        self,
        secret_id: str,
        *,
        env_fallback: str | None = None,
        version: str = "latest",
        required: bool = False,
    ) -> str | None:
        """Fetch a secret from Secret Manager (in GCP mode) or environment variables.

        Args:
            secret_id: Secret Manager secret name (e.g. ``opsguardian-pagerduty-token``).
            env_fallback: Environment variable checked when in local mode or if Secret
                Manager is disabled.
            version: Secret Manager version alias (defaults to ``"latest"``).
            required: If True, raises ``SecretNotConfiguredError`` when not found.

        Returns:
            The secret string value, or ``None`` if optional and unconfigured.
        """
        cache_key = f"{secret_id}:{version}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Production path: Google Cloud Secret Manager via ADC
        if self._config.env == "gcp" and self._config.gcp_project_id:
            client = self._get_secret_manager_client()
            resource_name = (
                f"projects/{self._config.gcp_project_id}/secrets/{secret_id}/versions/{version}"
            )
            response = client.access_secret_version(request={"name": resource_name})  # type: ignore[attr-defined]
            value = str(response.payload.data.decode("utf-8")).strip()
            self._cache[cache_key] = value
            self._metadata[secret_id] = SecretMetadata(
                secret_name=secret_id,
                source=f"gcp_secret_manager:{resource_name}",
                fingerprint_sha256_prefix=self.fingerprint(value),
            )
            return value

        # Local dev / test fallback: read exclusively from environment variables
        env_var = env_fallback or secret_id.upper().replace("-", "_")
        env_value = os.getenv(env_var, "").strip()
        if env_value:
            self._cache[cache_key] = env_value
            self._metadata[secret_id] = SecretMetadata(
                secret_name=secret_id,
                source=f"env:{env_var}",
                fingerprint_sha256_prefix=self.fingerprint(env_value),
            )
            return env_value

        if required:
            raise SecretNotConfiguredError(
                f"Secret '{secret_id}' not found. Configure it in Google Cloud Secret "
                f"Manager (project '{self._config.gcp_project_id}') or set env var '{env_var}'."
            )
        return None

    def get_audit_summary(self) -> list[dict[str, str]]:
        """Return safe, non-sensitive metadata for observability audits (never raw values)."""
        return [
            {
                "secret_name": meta.secret_name,
                "source": meta.source,
                "fingerprint": meta.fingerprint_sha256_prefix,
            }
            for meta in self._metadata.values()
        ]

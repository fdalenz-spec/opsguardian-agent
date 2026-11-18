"""PII and credential redaction pipeline (Google Cloud DLP + local deterministic fallback).

Used across all three sensitive boundaries (Criterion: PII Redaction):
  1. **Logging pipeline** (`StructuredJsonFormatter`) — scrubs before JSON emission.
  2. **Tool/LLM boundary** (`after_tool_callback` / telemetry tools) — scrubs raw logs
     before sending them to the LLM.
  3. **Memory & Compaction pipeline** (`PiiSafeCompactionSummarizer` &
     `AsyncMemoryConsolidator`) — scrubs before writing to persistent SQLite /
     Firestore / Vertex AI Memory Bank.
"""

from __future__ import annotations

import importlib
import re
from dataclasses import dataclass, field
from typing import Any

# Ordered rules: high-specificity secrets & tokens first, then structured PII.
_REDACTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "GCP_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{20,}\b"),
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9\-._~+/]+=*"),
    ),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    ),
    (
        "API_SECRET",
        re.compile(
            r"(?i)\b((?:api[_-]?key|secret|token|password|passwd|auth)\s*[=:]\s*)([^\s,;\"'&]+)"
        ),
    ),
    (
        "EMAIL_ADDRESS",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "US_SSN",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    ),
    (
        "CREDIT_CARD_CANDIDATE",
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    ),
    (
        "PHONE_NUMBER",
        re.compile(r"(?<!\d)(?:\+\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)"),
    ),
    (
        "IPV4_ADDRESS",
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
        ),
    ),
)

_CLOUD_DLP_INFO_TYPES = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD_NUMBER",
    "US_SOCIAL_SECURITY_NUMBER",
    "IP_ADDRESS",
    "AUTH_TOKEN",
    "GCP_API_KEY",
    "PERSON_NAME",
)


def _passes_luhn(digits: str) -> bool:
    """Verify candidate credit card digits with Luhn checksum to avoid redacting IDs."""
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        num = int(ch)
        if idx % 2 == 1:
            num *= 2
            if num > 9:
                num -= 9
        total += num
    return total % 10 == 0


@dataclass
class RedactionResult:
    """Outcome of scrubbing a text string."""

    redacted_text: str
    redaction_count: int = 0
    counts_by_type: dict[str, int] = field(default_factory=dict)
    backend: str = "local_regex"


class PiiRedactor:
    """Dual-mode PII & credential scrubber (Cloud DLP + deterministic local fallback)."""

    def __init__(
        self,
        *,
        enable_cloud_dlp: bool = False,
        gcp_project_id: str = "",
        gcp_location: str = "global",
    ) -> None:
        self._enable_cloud_dlp = enable_cloud_dlp and bool(gcp_project_id)
        self._gcp_project_id = gcp_project_id
        self._gcp_location = gcp_location
        self._dlp_client: Any = None

    def _get_dlp_client(self) -> Any:
        if self._dlp_client is None:
            dlp_v2: Any = importlib.import_module("google.cloud.dlp_v2")

            self._dlp_client = dlp_v2.DlpServiceClient()
        return self._dlp_client

    def _redact_with_cloud_dlp(self, text: str) -> RedactionResult | None:
        """Attempt de-identification using Google Cloud Sensitive Data Protection (DLP)."""
        if not self._enable_cloud_dlp or not text:
            return None
        try:
            client = self._get_dlp_client()
            parent = f"projects/{self._gcp_project_id}/locations/{self._gcp_location}"
            inspect_config = {
                "info_types": [{"name": t} for t in _CLOUD_DLP_INFO_TYPES],
            }
            deidentify_config = {
                "info_type_transformations": {
                    "transformations": [
                        {
                            "primitive_transformation": {
                                "replace_with_info_type_config": {}
                            }
                        }
                    ]
                }
            }
            response = client.deidentify_content(
                request={
                    "parent": parent,
                    "deidentify_config": deidentify_config,
                    "inspect_config": inspect_config,
                    "item": {"value": text},
                }
            )
            counts: dict[str, int] = {}
            total = 0
            for summary in getattr(response.overview, "transformation_summaries", []):
                info_name = getattr(getattr(summary, "info_type", None), "name", "CLOUD_DLP")
                for result in getattr(summary, "results", []):
                    c = int(getattr(result, "count", 0))
                    if c > 0:
                        counts[info_name] = counts.get(info_name, 0) + c
                        total += c
            return RedactionResult(
                redacted_text=response.item.value,
                redaction_count=total,
                counts_by_type=counts,
                backend="cloud_dlp",
            )
        except Exception:
            # Fail safe: ALWAYS fall back to deterministic local scrubbing rather than leaking PII.
            return None

    def redact_text(self, text: str) -> RedactionResult:
        """Scrub PII and secrets from a string, returning redacted text and stats."""
        if not text:
            return RedactionResult(redacted_text=text)

        dlp_result = self._redact_with_cloud_dlp(text)
        current = dlp_result.redacted_text if dlp_result else text
        counts: dict[str, int] = dict(dlp_result.counts_by_type) if dlp_result else {}
        total = dlp_result.redaction_count if dlp_result else 0
        backend = "cloud_dlp+local_regex" if dlp_result else "local_regex"

        # Always run deterministic local pass as defense-in-depth (even after Cloud DLP).
        for label, pattern in _REDACTION_PATTERNS:
            if label == "BEARER_TOKEN":
                def _replace_bearer(match: re.Match[str]) -> str:
                    nonlocal total
                    total += 1
                    counts["BEARER_TOKEN"] = counts.get("BEARER_TOKEN", 0) + 1
                    return f"{match.group(1)}[REDACTED_BEARER_TOKEN]"

                current = pattern.sub(_replace_bearer, current)
            elif label == "API_SECRET":
                def _replace_secret(match: re.Match[str]) -> str:
                    val = match.group(2)
                    if val.startswith("[REDACTED_"):
                        return match.group(0)
                    nonlocal total
                    total += 1
                    counts["API_SECRET"] = counts.get("API_SECRET", 0) + 1
                    return f"{match.group(1)}[REDACTED_SECRET]"

                current = pattern.sub(_replace_secret, current)
            elif label == "CREDIT_CARD_CANDIDATE":
                def _replace_cc(match: re.Match[str]) -> str:
                    raw = match.group(0)
                    digits = re.sub(r"[ -]", "", raw)
                    if _passes_luhn(digits):
                        nonlocal total
                        total += 1
                        counts["CREDIT_CARD"] = counts.get("CREDIT_CARD", 0) + 1
                        return "[REDACTED_CREDIT_CARD]"
                    return raw

                current = pattern.sub(_replace_cc, current)
            else:
                def _replace_generic(match: re.Match[str], tag: str = label) -> str:
                    nonlocal total
                    total += 1
                    counts[tag] = counts.get(tag, 0) + 1
                    return f"[REDACTED_{tag}]"

                current = pattern.sub(_replace_generic, current)

        return RedactionResult(
            redacted_text=current,
            redaction_count=total,
            counts_by_type=counts,
            backend=backend,
        )

    def redact_structure(self, payload: Any) -> tuple[Any, int]:
        """Recursively scrub all string values inside nested dicts, lists, and tuples."""
        if isinstance(payload, str):
            res = self.redact_text(payload)
            return res.redacted_text, res.redaction_count
        if isinstance(payload, dict):
            total = 0
            cleaned: dict[Any, Any] = {}
            for key, value in payload.items():
                key_lower = str(key).lower()
                if any(
                    sensitive in key_lower
                    for sensitive in ("api_key", "password", "secret", "authorization", "token")
                ) and isinstance(value, str):
                    if not value.startswith("[REDACTED_"):
                        cleaned[key] = "[REDACTED_SECRET]"
                        total += 1
                    else:
                        cleaned[key] = value
                else:
                    scrubbed_val, count = self.redact_structure(value)
                    cleaned[key] = scrubbed_val
                    total += count
            return cleaned, total
        if isinstance(payload, list):
            total = 0
            cleaned_list: list[Any] = []
            for item in payload:
                scrubbed_item, count = self.redact_structure(item)
                cleaned_list.append(scrubbed_item)
                total += count
            return cleaned_list, total
        if isinstance(payload, tuple):
            items, total = self.redact_structure(list(payload))
            return tuple(items), total
        return payload, 0

"""Structured JSON logging with automatic PII redaction and trace correlation.

Replaces plain-text ``print()`` statements with Google Cloud Logging–compatible
JSON records (`severity`, `timestamp`, `event_type`, `trace_id`, `span_id`, and
arbitrary structured metadata), piping every message and payload through
``PiiRedactor`` BEFORE emission so sensitive data never reaches stdout or sinks.
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

from opsguardian.security.pii_redactor import PiiRedactor

_STANDARD_RECORD_ATTRS = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "taskName",
        "thread",
        "threadName",
    }
)


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as single-line Cloud Logging–compatible JSON with PII scrubbing."""

    def __init__(
        self,
        *,
        redactor: PiiRedactor | None = None,
        gcp_project_id: str = "",
        service_name: str = "opsguardian-agent",
    ) -> None:
        super().__init__()
        self._redactor = redactor or PiiRedactor()
        self._gcp_project_id = gcp_project_id
        self._service_name = service_name

    def format(self, record: logging.LogRecord) -> str:
        raw_message = record.getMessage()
        msg_redaction = self._redactor.redact_text(raw_message)

        extra_fields: dict[str, Any] = {}
        for key, value in record.__dict__.items():
            if key in _STANDARD_RECORD_ATTRS or key.startswith("_"):
                continue
            extra_fields[key] = value

        scrubbed_extra, extra_redactions = self._redactor.redact_structure(extra_fields)

        trace_id = scrubbed_extra.pop("trace_id", None)
        span_id = scrubbed_extra.pop("span_id", None)
        event_type = scrubbed_extra.pop("event_type", "runtime.log")

        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "severity": record.levelname,
            "service": self._service_name,
            "logger": record.name,
            "event_type": event_type,
            "message": msg_redaction.redacted_text,
            "pii_redacted_count": msg_redaction.redaction_count + extra_redactions,
        }

        if trace_id:
            payload["trace_id"] = trace_id
            if self._gcp_project_id:
                payload["logging.googleapis.com/trace"] = (
                    f"projects/{self._gcp_project_id}/traces/{trace_id}"
                )
        if span_id:
            payload["span_id"] = span_id
            payload["logging.googleapis.com/spanId"] = span_id

        if scrubbed_extra:
            payload["metadata"] = scrubbed_extra

        if record.exc_info:
            formatted_exc = self.formatException(record.exc_info)
            payload["exception"] = self._redactor.redact_text(formatted_exc).redacted_text

        return json.dumps(payload, default=str, ensure_ascii=False)


class StructuredLoggerAdapter(logging.LoggerAdapter):
    """Logger adapter providing structured helper methods for intent/outcome logging."""

    def log_event(
        self,
        event_type: str,
        message: str,
        *,
        level: int = logging.INFO,
        trace_id: str | None = None,
        span_id: str | None = None,
        **metadata: Any,
    ) -> None:
        extra: dict[str, Any] = {"event_type": event_type, **metadata}
        if trace_id:
            extra["trace_id"] = trace_id
        if span_id:
            extra["span_id"] = span_id
        self.logger.log(level, message, extra=extra)


def configure_logging(
    *,
    level: str = "INFO",
    redactor: PiiRedactor | None = None,
    gcp_project_id: str = "",
    stream: Any = None,
) -> logging.Logger:
    """Configure the root ``opsguardian`` logger with PII-safe JSON formatting."""
    root_logger = logging.getLogger("opsguardian")
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    root_logger.handlers.clear()
    root_logger.propagate = False

    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(
        StructuredJsonFormatter(
            redactor=redactor or PiiRedactor(),
            gcp_project_id=gcp_project_id,
        )
    )
    root_logger.addHandler(handler)
    return root_logger


def get_logger(name: str) -> StructuredLoggerAdapter:
    """Return a structured logger adapter scoped to ``opsguardian.<name>``."""
    full_name = name if name.startswith("opsguardian") else f"opsguardian.{name}"
    logger = logging.getLogger(full_name)
    if not logging.getLogger("opsguardian").handlers:
        configure_logging()
    return StructuredLoggerAdapter(logger, {})

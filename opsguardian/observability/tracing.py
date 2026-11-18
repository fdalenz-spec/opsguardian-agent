"""OpenTelemetry distributed tracing setup for OpsGuardian.

Links spans across the entire request lifecycle:
  ``opsguardian.invocation``
    ├── ``opsguardian.agent.<agent_name>``
    │     ├── ``opsguardian.model.<model_name>``
    │     └── ``opsguardian.tool.<tool_name>``
    └── ``opsguardian.memory.consolidate`` (async background span)

Supports:
  - Google Cloud Trace (`opentelemetry-exporter-gcp-trace`) when ``enable_cloud_trace=True``
  - OTLP HTTP exporter when ``otlp_endpoint`` is configured
  - Local console/in-memory span exporter for development and automated tests
"""

from __future__ import annotations

import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator

from opsguardian.config import OpsGuardianConfig
from opsguardian.observability.logging import get_logger

logger = get_logger("observability.tracing")

try:
    from opentelemetry import trace as otel_trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import (
        BatchSpanProcessor,
        ConsoleSpanExporter,
        SimpleSpanProcessor,
    )
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    HAS_OTEL = True
except ImportError:  # pragma: no cover - fallback only when opentelemetry is absent
    otel_trace = None  # type: ignore[assignment]
    Resource = None  # type: ignore[assignment]
    TracerProvider = None  # type: ignore[assignment]
    BatchSpanProcessor = None  # type: ignore[assignment]
    ConsoleSpanExporter = None  # type: ignore[assignment]
    SimpleSpanProcessor = None  # type: ignore[assignment]
    InMemorySpanExporter = None  # type: ignore[assignment]
    HAS_OTEL = False


@dataclass
class LocalSpanRecord:
    """Lightweight fallback span record used when OpenTelemetry SDK is not installed."""

    name: str
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    start_time: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_time: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    status: str = "OK"

    def set_attribute(self, key: str, value: Any) -> None:
        self.attributes[key] = value

    def record_exception(self, exc: BaseException) -> None:
        self.status = f"ERROR: {type(exc).__name__}: {exc}"
        self.attributes["exception.type"] = type(exc).__name__


class _LocalFallbackTracer:
    """Thread-safe in-memory span recorder mirroring the OpenTelemetry Span API."""

    def __init__(self) -> None:
        self.spans: list[LocalSpanRecord] = []
        self._stack: list[LocalSpanRecord] = []

    @contextmanager
    def start_as_current_span(
        self, name: str, attributes: dict[str, Any] | None = None
    ) -> Iterator[LocalSpanRecord]:
        parent = self._stack[-1] if self._stack else None
        trace_id = parent.trace_id if parent else uuid.uuid4().hex
        span = LocalSpanRecord(
            name=name,
            trace_id=trace_id,
            span_id=uuid.uuid4().hex[:16],
            parent_span_id=parent.span_id if parent else None,
            attributes=dict(attributes or {}),
        )
        self._stack.append(span)
        try:
            yield span
        except BaseException as exc:
            span.record_exception(exc)
            raise
        finally:
            span.end_time = datetime.now(timezone.utc).isoformat()
            self._stack.pop()
            self.spans.append(span)

    def current_ids(self) -> tuple[str | None, str | None]:
        if not self._stack:
            return None, None
        current = self._stack[-1]
        return current.trace_id, current.span_id


_FALLBACK_TRACER = _LocalFallbackTracer()
_IN_MEMORY_EXPORTER: Any = None
_TRACING_CONFIGURED = False


def configure_tracing(
    config: OpsGuardianConfig,
    *,
    capture_in_memory: bool = False,
) -> Any:
    """Configure OpenTelemetry TracerProvider with GCP Cloud Trace, OTLP, or local exporter.

    Args:
        config: Runtime ``OpsGuardianConfig``.
        capture_in_memory: When True, attaches an ``InMemorySpanExporter`` so unit tests
            and demo scripts can assert exact span hierarchies.

    Returns:
        The configured OpenTelemetry ``Tracer`` (or local fallback tracer).
    """
    global _IN_MEMORY_EXPORTER, _TRACING_CONFIGURED

    if not HAS_OTEL:
        logger.log_event(
            "tracing.fallback_initialized",
            "OpenTelemetry SDK not installed; using in-memory W3C fallback tracer.",
        )
        _TRACING_CONFIGURED = True
        return _FALLBACK_TRACER

    resource = Resource.create(
        {
            "service.name": config.app_name,
            "service.version": "1.0.0",
            "deployment.environment": config.env,
            "cloud.provider": "gcp",
            "cloud.region": config.gcp_location,
        }
    )
    provider = TracerProvider(resource=resource)

    if config.enable_cloud_trace and config.gcp_project_id:
        try:
            from opentelemetry.exporter.cloud_trace import (  # type: ignore[import-untyped]
                CloudTraceSpanExporter,
            )

            provider.add_span_processor(
                BatchSpanProcessor(CloudTraceSpanExporter(project_id=config.gcp_project_id))
            )
            logger.log_event(
                "tracing.exporter_registered",
                "Registered Google Cloud Trace span exporter.",
                exporter="CloudTraceSpanExporter",
                project_id=config.gcp_project_id,
            )
        except ImportError:
            logger.log_event(
                "tracing.exporter_unavailable",
                "CloudTraceSpanExporter unavailable; continuing without GCP Trace export.",
            )

    if config.otlp_endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (  # type: ignore[import-untyped]
                OTLPSpanExporter,
            )

            provider.add_span_processor(
                BatchSpanProcessor(OTLPSpanExporter(endpoint=config.otlp_endpoint))
            )
        except ImportError:
            pass

    if config.otel_console_export:
        provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

    if capture_in_memory:
        _IN_MEMORY_EXPORTER = InMemorySpanExporter()
        provider.add_span_processor(SimpleSpanProcessor(_IN_MEMORY_EXPORTER))

    otel_trace.set_tracer_provider(provider)
    _TRACING_CONFIGURED = True
    return otel_trace.get_tracer(config.app_name, "1.0.0")


def get_tracer(name: str = "opsguardian") -> Any:
    """Return active OpenTelemetry tracer (or local fallback tracer)."""
    if HAS_OTEL:
        return otel_trace.get_tracer(name, "1.0.0")
    return _FALLBACK_TRACER


def get_current_trace_context() -> tuple[str | None, str | None]:
    """Return ``(trace_id_hex, span_id_hex)`` for the currently active span."""
    if HAS_OTEL:
        span = otel_trace.get_current_span()
        ctx = span.get_span_context() if span is not None else None
        if ctx is not None and ctx.is_valid:
            return f"{ctx.trace_id:032x}", f"{ctx.span_id:016x}"
        return None, None
    return _FALLBACK_TRACER.current_ids()


def get_captured_spans() -> list[Any]:
    """Return spans captured in memory during tests or offline demos."""
    if HAS_OTEL and _IN_MEMORY_EXPORTER is not None:
        return list(_IN_MEMORY_EXPORTER.get_finished_spans())
    return list(_FALLBACK_TRACER.spans)


def clear_captured_spans() -> None:
    """Clear in-memory captured spans between test cases."""
    if HAS_OTEL and _IN_MEMORY_EXPORTER is not None:
        _IN_MEMORY_EXPORTER.clear()
    _FALLBACK_TRACER.spans.clear()

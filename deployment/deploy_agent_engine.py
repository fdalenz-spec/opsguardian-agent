"""Deploy OpsGuardian to Vertex AI Agent Engine using ADK ``AdkApp``.

Usage:
    python deployment/deploy_agent_engine.py \
        --project my-gcp-project \
        --location us-central1 \
        --staging-bucket gs://my-gcp-project-agent-staging
"""

from __future__ import annotations

import argparse
import os
import sys

from opsguardian.observability.logging import configure_logging, get_logger

configure_logging(level="INFO")
logger = get_logger("deployment.agent_engine")


def build_deployable_adk_app():
    """Wrap the OpsGuardian ADK App in Vertex AI ``AdkApp`` with tracing enabled."""
    from vertexai.preview.reasoning_engines import AdkApp  # type: ignore[import-untyped]

    from opsguardian.agent import app as opsguardian_app

    return AdkApp(
        app=opsguardian_app,
        enable_tracing=True,
    )


def deploy_to_agent_engine(
    *,
    project: str,
    location: str,
    staging_bucket: str,
    display_name: str = "opsguardian-sre-agent",
    dry_run: bool = False,
) -> str:
    """Register and deploy OpsGuardian to Vertex AI Agent Engine."""
    if not project:
        raise ValueError("GCP project ID must be supplied via --project or GOOGLE_CLOUD_PROJECT.")

    if dry_run:
        logger.log_event(
            "deploy.dry_run",
            f"Dry-run validated deployment manifest for '{display_name}' in {project}/{location}.",
            project=project,
            location=location,
            staging_bucket=staging_bucket,
        )
        return f"projects/{project}/locations/{location}/reasoningEngines/dry-run"

    import vertexai  # type: ignore[import-untyped]
    from vertexai import agent_engines  # type: ignore[import-untyped]

    vertexai.init(project=project, location=location, staging_bucket=staging_bucket)
    adk_app = build_deployable_adk_app()

    remote_agent = agent_engines.create(
        agent_engine=adk_app,
        display_name=display_name,
        description="OpsGuardian multi-agent SRE incident triage & HITL remediation system.",
        requirements=[
            "google-adk[gcp,db]>=1.18.0,<3.0.0",
            "google-cloud-secret-manager>=2.21.0",
            "google-cloud-dlp>=3.25.0",
            "google-cloud-firestore>=2.19.0",
            "google-cloud-discoveryengine>=0.13.0",
            "google-cloud-modelarmor>=0.1.0",
            "opentelemetry-exporter-gcp-trace>=1.7.0",
            "pydantic>=2.9.0,<3.0.0",
        ],
        extra_packages=["opsguardian"],
        env_vars={
            "OPSGUARDIAN_ENV": "gcp",
            "OPSGUARDIAN_ENABLE_CLOUD_DLP": "true",
            "OPSGUARDIAN_ENABLE_CLOUD_TRACE": "true",
            "OPSGUARDIAN_KNOWLEDGE_BACKEND": "firestore",
        },
    )
    resource_name = str(remote_agent.resource_name)
    logger.log_event(
        "deploy.completed",
        f"Deployed OpsGuardian to Vertex AI Agent Engine: {resource_name}",
        resource_name=resource_name,
    )
    return resource_name


def main() -> None:
    parser = argparse.ArgumentParser(description="Deploy OpsGuardian to Vertex AI Agent Engine.")
    parser.add_argument("--project", default=os.getenv("GOOGLE_CLOUD_PROJECT", ""))
    parser.add_argument("--location", default=os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1"))
    parser.add_argument("--staging-bucket", default=os.getenv("STAGING_BUCKET", ""))
    parser.add_argument("--display-name", default="opsguardian-sre-agent")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    bucket = args.staging_bucket or f"gs://{args.project}-opsguardian-staging"
    resource = deploy_to_agent_engine(
        project=args.project,
        location=args.location,
        staging_bucket=bucket,
        display_name=args.display_name,
        dry_run=args.dry_run,
    )
    sys.stdout.write(f"Deployed resource: {resource}\n")


if __name__ == "__main__":
    main()

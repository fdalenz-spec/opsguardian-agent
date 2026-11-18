"""Tests for Category 5: Infrastructure, Secret Hygiene & Automated Evaluation Suites."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from eval.run_eval import EVAL_CONFIG_PATH, EVALSET_PATH, run_offline_evaluation
from opsguardian.config import OpsGuardianConfig
from opsguardian.security.secrets import SecretNotConfiguredError, SecretProvider


def test_secret_provider_reads_env_and_never_logs_raw_value(monkeypatch) -> None:
    monkeypatch.setenv("PAGERDUTY_ROUTING_KEY", "demo-token-value-12345")
    provider = SecretProvider(OpsGuardianConfig(env="local"))
    val = provider.get_secret("opsguardian-pagerduty-token", env_fallback="PAGERDUTY_ROUTING_KEY")
    assert val == "demo-token-value-12345"

    summary = provider.get_audit_summary()
    assert len(summary) == 1
    assert "demo-token-value-12345" not in json.dumps(summary)
    assert summary[0]["fingerprint"].startswith("sha256:")


def test_secret_provider_raises_when_required_missing(monkeypatch) -> None:
    monkeypatch.delenv("MISSING_REQUIRED_SECRET", raising=False)
    provider = SecretProvider(OpsGuardianConfig(env="local"))
    import pytest

    with pytest.raises(SecretNotConfiguredError):
        provider.get_secret("missing-secret", env_fallback="MISSING_REQUIRED_SECRET", required=True)


def test_offline_evaluation_suite_passes_all_checks() -> None:
    assert EVALSET_PATH.exists()
    assert EVAL_CONFIG_PATH.exists()
    report = asyncio.run(run_offline_evaluation())
    assert report["all_passed"] is True, json.dumps(report, indent=2)
    assert report["passed_checks"] == report["total_checks"]


def test_terraform_files_exist_and_balanced_braces() -> None:
    tf_dir = Path(__file__).resolve().parent.parent / "terraform"
    tf_files = sorted(tf_dir.glob("*.tf"))
    assert len(tf_files) >= 7
    for tf in tf_files:
        text = tf.read_text(encoding="utf-8")
        assert text.count("{") == text.count("}"), f"Unbalanced braces in {tf.name}"

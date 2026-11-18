.PHONY: help install install-gcp demo-dry-run demo-live web run test test-unit eval eval-offline lint typecheck secret-scan tf-init tf-plan deploy-cloudrun deploy-agent-engine

PYTHON ?= python3
PROJECT_ID ?= $(GOOGLE_CLOUD_PROJECT)
REGION ?= us-central1

help: ## Show available AgentOps & ADK commands
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

install: ## Install OpsGuardian with dev dependencies (local dual-mode)
	uv sync --extra dev || pip install -e ".[dev]"

install-gcp: ## Install OpsGuardian with full Google Cloud SDK integrations
	uv sync --extra gcp --extra dev || pip install -e ".[gcp,dev]"

web: ## Launch ADK interactive Web UI (http://localhost:8000)
	adk web .

run: ## Run interactive ADK CLI session against opsguardian
	adk run opsguardian

demo-dry-run: ## Run end-to-end offline demo (PII redaction, intent/outcome JSON logs, OTel spans, HITL gate)
	$(PYTHON) -m opsguardian.demo_cli --dry-run

demo-live: ## Run interactive live demo against Gemini / Vertex AI with persistent SQLite session
	$(PYTHON) -m opsguardian.runner --interactive

test: ## Run full pytest test suite
	pytest tests/

test-unit: ## Run pure-stdlib unit & security audit checks (no external deps needed)
	$(PYTHON) -m unittest discover -s tests -p "test_stdlib_*.py" -v

eval-offline: ## Run deterministic golden-dataset evaluation & rubric audit (CI-safe, no LLM cost)
	$(PYTHON) -m eval.run_eval --offline

eval: ## Run full ADK trajectory & rubric evaluation against live Gemini models
	adk eval opsguardian eval/opsguardian.evalset.json --config_file_path eval/eval_config.json --print_detailed_results

lint: ## Lint and check formatting with ruff
	ruff check opsguardian eval deployment tests
	ruff format --check opsguardian eval deployment tests

typecheck: ## Run static type checking with mypy
	mypy opsguardian

secret-scan: ## Verify zero hardcoded credentials or raw print() statements
	$(PYTHON) -m eval.run_eval --security-audit-only

tf-init: ## Initialize Terraform providers
	cd terraform && terraform init

tf-plan: ## Validate and preview Terraform infrastructure plan
	cd terraform && terraform fmt -check && terraform validate && terraform plan -var="project_id=$(PROJECT_ID)" -var="region=$(REGION)"

deploy-cloudrun: ## Deploy OpsGuardian via ADK CLI directly to Cloud Run
	adk deploy cloud_run \
		--project=$(PROJECT_ID) \
		--region=$(REGION) \
		--service_name=opsguardian-agent \
		--app_name=opsguardian \
		--with_ui \
		opsguardian

deploy-agent-engine: ## Deploy OpsGuardian to Vertex AI Agent Engine
	$(PYTHON) deployment/deploy_agent_engine.py --project $(PROJECT_ID) --location $(REGION)

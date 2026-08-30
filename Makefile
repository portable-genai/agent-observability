# Hrz5 Agent Observability, Audit & FinOps — developer tasks.
# All default targets run OFFLINE on the SDK-free `local` profile (no Google Cloud SDKs).

PY ?= python3
PY := $(if $(wildcard .venv/bin/python),.venv/bin/python,$(PY))
PORT ?= 8085
IMAGE ?= agent-observability:dev
# Dev / test default profile. Production uses `gcp`; `onprem` is the fail-fast target.
OBSERVABILITY_PROFILE ?= local
export OBSERVABILITY_PROFILE

.DEFAULT_GOAL := help

.PHONY: help install lint format-check fmt typecheck test eval seed smoke run demo demo-selftest portability-demo rename-selftest check docker tf-init tf-plan clean prove-exposure

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## Install the package with dev extras into the active environment.
	$(PY) -m pip install -e '.[dev]'

lint: ## Ruff lint.
	ruff check src tests eval scripts

format-check: ## Verify Ruff formatting without writing files.
	ruff format --check src tests eval scripts

fmt: ## Ruff format + autofix imports.
	ruff check --fix src tests eval scripts
	ruff format src tests eval scripts

typecheck: ## mypy on the package.
	mypy src

test: ## Run the offline test suite.
	pytest -m 'not integration' -q

eval: ## Run the offline audit-integrity eval gate (rule R2 / P-08).
	$(PY) eval/run_eval.py

seed: ## Seed the local WORM store with the built-in synthetic audit corpus.
	$(PY) -m observability seed

smoke: seed ## End-to-end local smoke: seed then read back a real cited artifact.
	$(PY) -m observability read --limit 5

run: ## Run the API locally (local profile) on $(PORT).
	PORT=$(PORT) $(PY) -m observability serve --host 127.0.0.1 --port $(PORT)

demo: ## Guided offline terminal walkthrough (set DEMO_AUTO=1 to self-run, no prompts).
	PYTHONPATH=src:tests $(PY) scripts/observability_demo.py

demo-selftest: ## Run the assertion-backed demo unattended and retain no repo artifact.
	DEMO_AUTO=1 DEMO_OUT=$${TMPDIR:-/tmp}/hrz5-observability-demo.json \
		PYTHONPATH=src:tests $(PY) scripts/observability_demo.py

portability: portability-demo ## Standard fleet alias for the executable portability proof.

portability-demo: ## Run the bounded profile, runtime and JSON-contract proof.
	PYTHONPATH=src $(PY) scripts/portability_demo.py

rename-selftest: ## Apply a rename in a clean copy, install locks fresh and run its full gate.
	$(PY) scripts/rename_fork_selftest.py

prove-exposure: ## Drive the whole exposure matrix over a REAL socket from a REAL LAN peer.
	# The derivation this backs is gated; until now the peer proof was not, so a script that
	# could only be run by hand stood behind a published claim. It refuses rather than skips
	# when this host has no non-loopback address, because a proof that quietly declines to run
	# reports the same green as one that ran.
	bash scripts/prove-exposure-matrix.sh

check: lint format-check typecheck test eval demo-selftest portability-demo prove-exposure ## Complete offline gate.

docker: ## Build the container image.
	docker build -t $(IMAGE) .

tf-init: ## terraform init — the backend is a partial "gcs" block, so the state location is an input.
	cd infra/terraform && terraform init -input=false \
		-backend-config="bucket=$${TF_STATE_BUCKET:?set TF_STATE_BUCKET to the GCS state bucket}" \
		-backend-config="prefix=$${TF_STATE_PREFIX:?set TF_STATE_PREFIX for this stack}"

tf-plan: ## terraform plan — set project_id in terraform.tfvars first (or pass TF_VAR_FILE).
	cd infra/terraform && terraform plan $${TF_VAR_FILE:+-var-file="$$TF_VAR_FILE"}

clean: ## Remove caches and build artifacts.
	rm -rf .pytest_cache .ruff_cache .mypy_cache dist build *.egg-info src/*.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

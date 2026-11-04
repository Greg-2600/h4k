PY      := .venv/bin/python
PYTEST  := .venv/bin/pytest
SRC_PY  := h4k/api
TESTS   := tests
VULNLAB := vulnlab
H4K_DIR := h4k

# Docker
COMPOSE := docker-compose
COMPOSE_FILE := $(H4K_DIR)/docker-compose.yml

# Tool paths
BLACK   := .venv/bin/black
ISORT   := .venv/bin/isort
RUFF    := .venv/bin/ruff
FLAKE8  := .venv/bin/flake8
PYLINT  := .venv/bin/pylint
MYPY    := .venv/bin/mypy
BANDIT  := .venv/bin/bandit
SHELLCHECK := shellcheck
HADOLINT := hadolint

# Colour codes
RED      := \033[0;31m
GREEN    := \033[0;32m
YELLOW   := \033[0;33m
BLUE     := \033[0;34m
BOLD     := \033[1m
RESET    := \033[0m

OK      := $(GREEN)✓$(RESET)
ERR     := $(RED)✗$(RESET)
WARN    := $(YELLOW)⚠$(RESET)

.PHONY: help setup fmt fix lint lint-py lint-c lint-shell lint-docker \
        test e2e sanity sanity-test coverage build build-no-cache up down ps logs clean \
        docker-validate

## ─────────────────────────────────────────────────────────────────────────────
# Meta
## ─────────────────────────────────────────────────────────────────────────────

help:
	@printf "$(BOLD)h4k Development Toolchain$(RESET)\n"
	@printf "\n"
	@printf "$(BOLD)Setup$(RESET)\n"
	@printf "  make setup              install all tooling into .venv\n"
	@printf "\n"
	@printf "$(BOLD)Code quality$(RESET)\n"
	@printf "  make fmt                auto-format all code (black + isort)\n"
	@printf "  make fix                auto-fix lint issues (ruff --fix)\n"
	@printf "  make lint               run every linter (full suite)\n"
	@printf "  make lint-py            Python linting only\n"
	@printf "  make lint-shell         shell script linting only\n"
	@printf "  make lint-docker        Dockerfile linting only\n"
	@printf "\n"
	@printf "$(BOLD)Testing$(RESET)\n"
	@printf "  make test               run full pytest suite (in container, no host exec)\n"
	@printf "  make e2e                run the Selenium browser suite (headless)\n"
	@printf "  make sanity             check a RUNNING deployment end to end\n"
	@printf "  make sanity-test        same checks, as pytest (needs the stack up)\n"
	@printf "  make coverage           pytest + coverage report (90%% gate)\n"
	@printf "\n"
	@printf "$(BOLD)Containers$(RESET)\n"
	@printf "  make build              build h4k + vulnlab images\n"
	@printf "  make build-no-cache     build with --no-cache\n"
	@printf "  make up                 start all containers\n"
	@printf "  make down               stop all containers\n"
	@printf "  make ps                 show running containers\n"
	@printf "  make logs [svc=h4k]     tail logs (default: h4k)\n"
	@printf "  make docker-validate    validate compose file syntax\n"
	@printf "\n"
	@printf "$(BOLD)Development$(RESET)\n"
	@printf "  make clean              remove .venv, __pycache__, .mypy_cache, etc.\n"

## ─────────────────────────────────────────────────────────────────────────────
# Setup
## ─────────────────────────────────────────────────────────────────────────────

setup:
	python3 -m venv .venv
	.venv/bin/python -m pip install --upgrade pip
	.venv/bin/python -m pip install -r requirements.txt -r requirements-dev.txt

## ─────────────────────────────────────────────────────────────────────────────
# Formatting
## ─────────────────────────────────────────────────────────────────────────────

fmt: $(BLACK) $(ISORT)
	$(BLACK) $(SRC_PY) $(TESTS)
	$(ISORT) $(SRC_PY) $(TESTS)

## ─────────────────────────────────────────────────────────────────────────────
# Auto-fix
## ─────────────────────────────────────────────────────────────────────────────

fix: $(RUFF)
	$(RUFF) check $(SRC_PY) $(TESTS) --fix

## ─────────────────────────────────────────────────────────────────────────────
# Lint: All languages
## ─────────────────────────────────────────────────────────────────────────────

lint: lint-py lint-shell lint-docker
	@printf "$(OK) All linters passed\n"

## ─────────────────────────────────────────────────────────────────────────────
# Lint: Python
## ─────────────────────────────────────────────────────────────────────────────

lint-py: $(BLACK) $(ISORT) $(RUFF) $(FLAKE8) $(PYLINT) $(MYPY) $(BANDIT)
	@printf "$(BOLD)Running Python linters…$(RESET)\n"
	$(BLACK) --check $(SRC_PY) $(TESTS) || { printf "$(ERR) black failed\n"; exit 1; }
	@printf "  $(OK) black\n"
	$(ISORT) --check-only $(SRC_PY) $(TESTS) || { printf "$(ERR) isort failed\n"; exit 1; }
	@printf "  $(OK) isort\n"
	$(RUFF) check $(SRC_PY) $(TESTS) || { printf "$(ERR) ruff failed\n"; exit 1; }
	@printf "  $(OK) ruff\n"
	$(FLAKE8) $(SRC_PY) $(TESTS) || { printf "$(ERR) flake8 failed\n"; exit 1; }
	@printf "  $(OK) flake8\n"
	$(MYPY) $(SRC_PY) || { printf "$(ERR) mypy failed\n"; exit 1; }
	@printf "  $(OK) mypy\n"
	$(BANDIT) -r $(SRC_PY) -q --configfile pyproject.toml || { printf "$(ERR) bandit failed\n"; exit 1; }
	@printf "  $(OK) bandit\n"

## ─────────────────────────────────────────────────────────────────────────────
# Lint: Shell scripts
## ─────────────────────────────────────────────────────────────────────────────

lint-shell:
	@printf "$(BOLD)Running shellcheck…$(RESET)\n"
	@if ! command -v shellcheck > /dev/null 2>&1; then \
		printf "  $(WARN) shellcheck not installed — skipping shell linting\n"; \
	else \
		for f in $(wildcard scripts/*.sh); do \
			shellcheck --shell=bash "$$f" || { printf "$(ERR) shellcheck failed: $$f\n"; exit 1; }; \
		done; \
		printf "  $(OK) shellcheck\n"; \
	fi

## ─────────────────────────────────────────────────────────────────────────────
# Lint: Dockerfiles
## ─────────────────────────────────────────────────────────────────────────────

lint-docker:
	@printf "$(BOLD)Checking Dockerfiles…$(RESET)\n"
	@printf "  $(WARN) hadolint not installed (apt install hadolint) — skipping\n"

## ─────────────────────────────────────────────────────────────────────────────
# Docker Compose validation
## ─────────────────────────────────────────────────────────────────────────────

docker-validate:
	@printf "$(BOLD)Validating docker-compose files…$(RESET)\n"
	$(COMPOSE) -f $(COMPOSE_FILE) config --quiet || { printf "$(ERR) compose file invalid\n"; exit 1; }
	@printf "  $(OK) docker-compose.yml valid\n"

## ─────────────────────────────────────────────────────────────────────────────
# Docker build
## ─────────────────────────────────────────────────────────────────────────────

build:
	$(COMPOSE) -f $(COMPOSE_FILE) build

build-no-cache:
	$(COMPOSE) -f $(COMPOSE_FILE) build --no-cache

## ─────────────────────────────────────────────────────────────────────────────
# Container management
## ─────────────────────────────────────────────────────────────────────────────

up:
	$(COMPOSE) -f $(COMPOSE_FILE) up -d

down:
	$(COMPOSE) -f $(COMPOSE_FILE) down

ps:
	$(COMPOSE) -f $(COMPOSE_FILE) ps

logs:
	$(COMPOSE) -f $(COMPOSE_FILE) logs -f $(or $(svc),h4k)

## ─────────────────────────────────────────────────────────────────────────────
# Testing
## ─────────────────────────────────────────────────────────────────────────────

# Containerized unit/API tests: pytest runs inside python:3.11-slim with the
# repo mounted — no project code executes on the host. e2e stays host-side
# (needs local Chromium + a sandbox API) and runs in CI.
TEST_IMAGE := python:3.11-slim
TEST_DOCKER := docker run --rm --user "$(shell id -u):$(shell id -g)" -v "$(PWD):/work" -w /work -e PYTHONDONTWRITEBYTECODE=1 -e PIP_TARGET=/tmp/pylibs -e PYTHONPATH=/tmp/pylibs -e PATH=/tmp/pylibs/bin:/usr/local/bin:/usr/bin:/bin -e HOME=/tmp $(TEST_IMAGE)
TEST_SETUP := pip install -q --target=/tmp/pylibs -r requirements.txt -r requirements-dev.txt

test: test-container

test-container:
	$(TEST_DOCKER) bash -c "$(TEST_SETUP) && python -m pytest --ignore=tests/e2e -q -p no:cacheprovider"

# Selenium end-to-end suite (headless Chromium against a sandbox-mode API).
# Needs: chromium + chromedriver on PATH, `selenium` in the venv.
e2e:
	H4K_E2E=1 $(PYTEST) tests/e2e -v

# Live-stack sanity check against a RUNNING deployment (docker compose up).
sanity:
	python3 scripts/sanity_check.py

# Same checks, as pytest (opt-in: needs the stack up).
sanity-test:
	H4K_LIVE=1 $(PYTEST) tests/test_live_stack.py -v

coverage:
	$(TEST_DOCKER) bash -c "$(TEST_SETUP) && python -m pytest --ignore=tests/e2e -q -p no:cacheprovider --cov --cov-report=term-missing"

## ─────────────────────────────────────────────────────────────────────────────
# Clean
## ─────────────────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; :
	find . -type d -name .mypy_cache -exec rm -rf {} + 2>/dev/null; :
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null; :
	find . -type f -name "*.pyc" -delete 2>/dev/null; :
	rm -rf .venv
	rm -rf tests/.pytest_cache
	rm -rf htmlcov
	rm -f .coverage

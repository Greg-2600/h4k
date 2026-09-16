PY := .venv/bin/python
PIP := .venv/bin/pip
SRC := h4k/api

.PHONY: setup lint lint-fix test fmt check coverage

## Install the lint + test toolchain into a local venv
setup:
	$(PY) -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements-dev.txt

## Format (black + isort) in place
fmt:
	.venv/bin/black $(SRC) tests
	.venv/bin/isort $(SRC) tests

## Auto-fix what can be fixed (ruff)
fix:
	.venv/bin/ruff check $(SRC) --fix

## Run every linter
lint:
	.venv/bin/black --check $(SRC) tests
	.venv/bin/ruff check $(SRC) tests
	.venv/bin/isort --check-only $(SRC) tests
	.venv/bin/flake8 $(SRC) tests
	.venv/bin/mypy $(SRC)
	.venv/bin/pylint $(SRC)
	.venv/bin/bandit -r $(SRC) -q

## Run unit tests
test:
	.venv/bin/pytest

## Unit tests + coverage gate
coverage:
	.venv/bin/pytest --cov --cov-report=term-missing

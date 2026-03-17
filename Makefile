# MAD-PDC Build System
# Usage: make [target]

PYTHON ?= python3
PIP ?= $(PYTHON) -m pip
PYTEST ?= $(PYTHON) -m pytest
RUFF ?= $(PYTHON) -m ruff

# Detect OS for platform-specific deps
ifeq ($(OS),Windows_NT)
    PLATFORM_DEPS = .[windows]
else
    PLATFORM_DEPS =
endif

.PHONY: help install install-dev install-all test test-fast test-cov lint format clean clean-all check run

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

# -- Installation targets --

install: ## Install production dependencies
	$(PIP) install --no-warn-script-location -r requirements.txt

install-dev: ## Install dev dependencies (test + lint tools)
	$(PIP) install --no-warn-script-location -e ".[dev]"

install-all: install ## Install all deps including Playwright browsers
	$(PYTHON) -m playwright install --with-deps chromium

# -- Testing targets --

test: ## Run all tests
	$(PYTEST) tests/

test-fast: ## Run tests excluding slow/integration markers
	$(PYTEST) tests/ -m "not slow and not integration"

test-cov: ## Run tests with coverage report
	$(PYTEST) tests/ --cov=analysis_modules --cov-report=term-missing --cov-report=html

test-parallel: ## Run tests in parallel (requires pytest-xdist)
	$(PYTEST) tests/ -n auto

# -- Code quality targets --

lint: ## Run linter checks
	$(RUFF) check .

format: ## Auto-format code
	$(RUFF) format .

fix: ## Auto-fix lintable issues
	$(RUFF) check --fix .

check: lint test ## Run lint + tests (CI shortcut)

# -- Run target --

run: ## Launch MAD-PDC application
	$(PYTHON) MAD.py

# -- Clean targets --

clean: ## Remove caches and build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .ruff_cache -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	rm -rf build/ dist/ htmlcov/ .coverage

clean-all: clean ## Deep clean including pip cache
	$(PIP) cache purge 2>/dev/null || true

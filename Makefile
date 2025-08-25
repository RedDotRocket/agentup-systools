# AgentUp Development Makefile
# Useful commands for testing, template generation, and development

.DEFAULT_GOAL := help

.PHONY: help install install-dev check-deps pre-commit-install
.PHONY: test test-unit test-unit-coverage test-unit-fast test-unit-watch test-integration
.PHONY: lint lint-fix format format-check
.PHONY: security security-report security-full
.PHONY: validate-code validate-ci validate-all
.PHONY: template-test-syntax
.PHONY: pre-commit
.PHONY: agent-init agent-init-minimal agent-init-advanced agent-test
.PHONY: dev-server dev-server-test
.PHONY: docs-serve
.PHONY: build build-check
.PHONY: clean clean-agents clean-all
.PHONY: ci-deps ci-test
.PHONY: version env-info
.PHONY: dev-setup dev-test dev-full

# Default target
help: ## Show this help message
	@echo "Development Commands"
	@echo "=========================="
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Useful commands:"
	@echo "  make dev-setup          # Install and configure everything"
	@echo "  make pre-commit         # Run all quality checks"
	@echo "  make dev-test           # Quick test & lint cycle"
	@echo "  make pre-commit-install # Install pre-commit hooks"

# Environment setup
install: ## Install dependencies with uv
	uv sync --all-extras
	@echo "Dependencies installed"

install-dev: ## Install development dependencies
	uv sync --all-extras --dev
	uv pip install -e .
	@echo "Development environment ready"

check-deps: ## Check for missing dependencies
	uv pip check
	@echo "All dependencies satisfied"

pre-commit-install: ## Install and configure pre-commit
	uv pip install pre-commit
	pre-commit install
	pre-commit autoupdate
	@echo "✓ pre-commit installed and configured"

# Testing commands
test: ## Run all tests (unit + integration + e2e)
	@echo "Running comprehensive test suite..."
	uv run pytest tests/ -v

tests: ## Run unit tests only (fast)
	uv run pytest tests/

# Code quality
lint: ## Run linting checks (parallel)
	uv run ruff check src/ tests/

lint-fix: ## Fix linting issues automatically
	uv run ruff check --fix src/ tests/
	uv run ruff format src/ tests/

format: ## Format code with ruff (parallel)
	uv run ruff format src/ tests/

# Security scanning
security: ## Run bandit security scan
	uv run bandit -r src/ -ll


# Combined validation
all: ## Run format, lint, and security checks
	make format
	make lint
	make test
	make security
	@echo "✓ Code quality checks passed"

# Pre-commit
pre-commit: ## Run pre-commit hooks
	uv run pre-commit run --all-files

# Build
build: ## Build package
	uv build
	@echo "Package built in dist/"

build-check: ## Check package build
	uv run twine check dist/*

# Cleanup
clean: ## Clean temporary files
	rm -rf build/ dist/ *.egg-info/ .pytest_cache/ htmlcov/ .coverage test-render/
	find . -type d -name __pycache__ -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	@echo "Cleaned temporary files"

# Utility
version: ## Show current version
	@python -c "import toml; print('AgentUp version:', toml.load('pyproject.toml')['project']['version'])"

env-info: ## Show environment information
	@echo "Environment Information"
	@echo "====================="
	@echo "Python version: $$(python --version)"
	@echo "UV version: $$(uv --version)"
	@echo "Working directory: $$(pwd)"
	@echo "Git branch: $$(git branch --show-current 2>/dev/null || echo 'Not a git repo')"
	@echo "Git status: $$(git status --porcelain 2>/dev/null | wc -l | tr -d ' ') files changed"

# Dev workflows
dev-setup: install-dev pre-commit-install ## Complete development setup
	@echo "Running complete development setup..."
	make check-deps
	make test
	@echo "Development environment ready!"

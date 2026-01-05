.PHONY: install dev test typecheck lint format clean demo help

# Default target
help:
	@echo "blocklace-a2a development commands"
	@echo ""
	@echo "  make install    - Install package in development mode"
	@echo "  make dev        - Install with development dependencies"
	@echo "  make test       - Run all tests"
	@echo "  make typecheck  - Run mypy type checking"
	@echo "  make lint       - Run ruff linter"
	@echo "  make format     - Format code with ruff"
	@echo "  make demo       - Run the demo"
	@echo "  make clean      - Remove build artifacts"
	@echo ""

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v

typecheck:
	python -m mypy src/blocklace_a2a

lint:
	python -m ruff check src/ tests/

format:
	python -m ruff format src/ tests/
	python -m ruff check --fix src/ tests/

demo:
	python demo.py

clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf src/*.egg-info/
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf .ruff_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

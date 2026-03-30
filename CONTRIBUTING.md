# Contributing to FunctionCallReverseTool

Thank you for your interest in contributing! This document explains how to get started.

## Development Setup

1. Fork and clone the repository:

   ```bash
   git clone https://github.com/<your-username>/FunctionCallReverseTool.git
   cd FunctionCallReverseTool
   ```

2. Install in editable mode with dev dependencies:

   ```bash
   pip install -e ".[dev]"
   ```

3. Install pre-commit hooks:

   ```bash
   pre-commit install
   ```

## Coding Standards

- **Linting**: We use [ruff](https://docs.astral.sh/ruff/) for linting and formatting.
- **Style**: Follow the existing code style in the repository. Keep functions focused and well-documented.
- **Type hints**: Use type hints where practical.
- **Docstrings**: All public functions and classes should have docstrings.

## Adding a New Backend

All backends inherit from `BaseBackend` (defined in `function_call_tool/backends/base.py`). To add a new backend:

1. Create a new file under `function_call_tool/backends/` (e.g., `my_backend.py`).
2. Implement a class that inherits from `BaseBackend` and provides all required abstract methods.
3. Register the backend in `function_call_tool/backends/__init__.py`.
4. Add any new dependencies to `pyproject.toml`.
5. Include tests and update the README with usage examples.

Look at the existing `radare2.py` and `ghidra.py` backends as references.

## Pull Request Process

1. **Fork** the repository and create a feature branch from `main`:

   ```bash
   git checkout -b feature/my-change
   ```

2. Make your changes, keeping commits focused and descriptive.
3. Run linting before committing:

   ```bash
   ruff check .
   ruff format --check .
   ```

4. Push your branch and open a Pull Request against `main`.
5. Fill in the PR template and describe your changes clearly.
6. Wait for review. Address any feedback promptly.

## Reporting Issues

When opening an issue, please include:

- A clear, descriptive title.
- Steps to reproduce the problem (if applicable).
- Expected vs. actual behavior.
- Your environment: OS, Python version, backend tool and its version.
- Relevant logs or error output.

Use the provided issue templates when available.

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

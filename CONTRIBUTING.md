# Contributing to Code Signing MCP

Thank you for your interest in contributing!

## Development Setup

```bash
# Clone the repository
git clone https://github.com/noosphere-technologies/code-signing-mcp.git
cd code-signing-mcp

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## Code Style

- We use [Black](https://black.readthedocs.io/) for formatting
- We use [isort](https://pycqa.github.io/isort/) for import sorting
- We use [mypy](https://mypy.readthedocs.io/) for type checking

```bash
# Format code
black src tests
isort src tests

# Type check
mypy src
```

## Adding a New Provider

1. Create a new file in `src/providers/` (e.g., `my_provider.py`)
2. Inherit from `BaseProvider` and implement the `SigningProvider` protocol
3. Define capabilities in the `CAPABILITIES` class variable
4. Add to `PROVIDER_REGISTRY` in `src/providers/factory.py`
5. Add configuration class in `src/config.py`
6. Add tests in `tests/test_providers.py`
7. Update `llms.txt` and `README.md`

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes with tests
4. Ensure tests pass (`pytest`)
5. Format code (`black . && isort .`)
6. Commit with a descriptive message
7. Push and open a Pull Request

## Reporting Issues

Please include:
- Python version
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

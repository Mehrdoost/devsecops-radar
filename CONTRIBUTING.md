# Contributing to Pipeline Sentinel

We welcome contributions!

## How to contribute

1. Fork the repository.
2. Clone your fork: `git clone https://github.com/Mehrdoost/devsecops-radar.git`
3. Install in development mode: `pip install -e .`
4. Run tests: `pytest tests/`
5. Create a branch, make changes, and push.
6. Open a pull request against `main`.

## Adding a new scanner
1. Create a new class in `devsecops_radar/scanners/` that inherits from `ScannerPlugin`.
2. Implement `name`, `version`, `parse` (and optionally `run`).
3. Register it in `pyproject.toml` under `[project.entry-points."devsecops_radar.plugins"]`.
4. Add a test in `tests/test_scanners.py`.

## Code style
- Python 3.10+ features, type hints.
- Format with `black`.
- Document public functions.

## Questions?
Open an issue or discussion.
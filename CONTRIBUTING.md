# 🤝 Contributing to Pipeline Sentinel

Thank you for considering contributing to Pipeline Sentinel! We welcome all contributions—code, documentation, bug reports, feature ideas, and security research.

---

<details>
<summary><b>📑 Table of Contents (Click to expand)</b></summary>

- [Code of Conduct](#code-of-conduct)
- [Security Issues](#security-issues)
- [Getting Started](#getting-started)
- [Development Workflow](#development-workflow)
- [Adding a New Scanner](#adding-a-new-scanner)
- [Code Style & Quality](#code-style--quality)
- [Testing](#testing)
- [Commit Messages](#commit-messages)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)
- [Community & Support](#community--support)

</details>

---

## 📜 Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behaviour to the project maintainers.

---

## 🔒 Security Issues

> [!WARNING]
> **Do not open a public issue for security vulnerabilities.** Instead, review our [Security Policy](SECURITY.md) and report findings privately via the process described there. We deeply appreciate responsible disclosure and will credit researchers who follow our guidelines.

---

## 🚀 Getting Started

1. **Fork** the repository and clone your fork:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/devsecops-radar.git](https://github.com/YOUR_USERNAME/devsecops-radar.git)
   cd devsecops-radar
   ```

2. **Set up the development environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate      # Linux/macOS
   # Or on Windows: .venv\Scripts\activate
   
   pip install -e ".[dev]"
   ```

3. **Install the scanners** you intend to work with (optional – only if you are modifying or testing a specific scanner):
   ```bash
   # Example: install Trivy, Semgrep, etc. See PREREQUISITES.md for full list.
   brew install trivy semgrep     # macOS
   ```

4. **Run the existing test suite** to confirm everything works:
   ```bash
   pytest tests/ -v
   ```

---

## 💻 Development Workflow

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Make your changes, keeping commits atomic and well-described.
3. Before pushing, run all quality checks locally:
   ```bash
   ruff check .
   mypy .
   pytest tests/ --cov=devsecops_radar --cov-report=term-missing
   ```
4. Push your branch and open a Pull Request against `main`.

---

## 🔌 Adding a New Scanner

Pipeline Sentinel uses a pluggable scanner architecture based on abstract base classes and setuptools entry points. To add a new scanner:

1. Create a new module in `devsecops_radar/scanners/` (e.g., `my_scanner.py`).
2. Implement a class that inherits from `BaseScanner` (or `ScannerPlugin`).
3. Define `name`, `version`, and `_default_binary_name()`.
4. Implement `run(target: str) -> list[ScannerFinding]` and/or `parse(file_path: str) -> list[ScannerFinding]`.
5. 🛡️ **Security Requirement (v0.4.2+):** You **must** use `self._safe_run_command()` for all external command executions to enforce sandbox restrictions and `self._validate_target_path()` for strict path traversal prevention.
6. Register the plugin in `pyproject.toml`:
   ```toml
   [project.entry-points."devsecops_radar.plugins"]
   myscanner = "devsecops_radar.scanners.my_scanner:MyScanner"
   ```
7. Add tests in `tests/test_scanners.py` that verify parsing, command execution, sandbox constraints, and path validation.
8. Update documentation: mention the scanner in `README.md` (command line flags), `PREREQUISITES.md`, and add a sample JSON file to the `samples/` directory if possible.

---

## 🎨 Code Style & Quality

* **Modern Python:** Python 3.10+ with full, strict type hints.
* **Linting & Formatting:** We use **Ruff** for everything (replaces Black, Flake8, and isort). Configuration is in `pyproject.toml`.
  * Run `ruff format .` to auto-format code.
  * Run `ruff check .` to catch linter issues.
* **Type Checking:** **Mypy** for static type checking. Our goal is zero errors; use `# type: ignore` sparingly and always include a comment explaining why.
* **Documentation:** Document public functions with docstrings (Google-style preferred).
* **Self-Security Hardening:** Never use `safe_subprocess_run` with `shell=True`. Always use constant-time comparisons (`hmac.compare_digest`) for secrets/tokens, and enforce input limits to prevent DoS.

---

## 🧪 Testing

* **Framework:** `pytest` with `pytest-flask`, `pytest-asyncio`, and `pytest-cov`.
* **Coverage:** We aim for **>90%** overall coverage. New features or bug fixes without tests will not be merged.
* **Run tests:**
  ```bash
  pytest tests/ -v --cov=devsecops_radar --cov-report=term-missing
  ```
* *Note: Integration tests for scanners automatically skip if the required binary (like Trivy) is not found locally.*
* **Security Scans:** We run `bandit` and `safety` in our CI pipelines. You can check your code locally via:
  ```bash
  bandit -r devsecops_radar/
  safety check
  ```

---

## 📝 Commit Messages

We follow the **Conventional Commits** specification to keep the git history clean and readable:

* `feat:` for new features (e.g., `feat(scanner): add support for image digest in Trivy`)
* `fix:` for bug fixes (e.g., `fix: correct database session lifecycle`)
* `security:` for security-relevant updates (e.g., `security: prevent path traversal in web API`)
* `docs:` for documentation updates only
* `test:` for adding or modifying tests
* `chore:` for routine tasks (dependency updates, CI/CD pipelines)

---

## 🔀 Pull Request Process

1. Ensure all tests pass and linting/formatting is clean locally.
2. Write a clear PR description detailing **what** changed, **why**, and **how to manually test it**.
3. Link any related issues using keywords (e.g., `Closes #42`).
4. Wait for review. A core maintainer will review your code, suggest changes if needed, and merge it.
5. Keep your branch rebased and up to date with `main` to avoid merge conflicts.

> 💡 *Pipeline Sentinel is maintained by volunteers. We appreciate your patience during the review process!*

---

## 📖 Documentation

* **README.md** is our front page. Update it if your change adds a new CLI flag, web configuration, environment variable, or core feature.
* **PREREQUISITES.md** lists external tools. Update it when introducing a new scanner dependency.
* If you introduce a brand-new architectural concept, please add a short Markdown explanation under the `docs/` directory.

---

## ☕ Community & Support

* **Got Questions?** Open a [GitHub Discussion](https://github.com/Mehrdoost/devsecops-radar/discussions) or create an issue with the `question` label.
* **Have an Idea?** Start a discussion to gather feedback before writing code.
* **Want to Join the Team?** Consistent, high-quality contributors are always welcome to join as official maintainers!

Thank you for helping make Pipeline Sentinel a more secure and powerful tool! 🛡️
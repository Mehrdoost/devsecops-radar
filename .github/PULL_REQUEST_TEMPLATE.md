## Description

<!-- Provide a clear and concise summary of the changes. -->
<!-- Link any related issues (e.g., Closes #42, Fixes #15). -->

Closes #

### Motivation & Context

<!-- Why is this change necessary? What problem does it solve? -->

### Type of Change

<!-- Mark the relevant option(s) with an `x`. -->

- [ ] 🐛 Bug fix (non‑breaking change)
- [ ] ✨ New feature (non‑breaking change)
- [ ] 💥 Breaking change (existing functionality affected)
- [ ] 📖 Documentation update
- [ ] 🔒 Security fix
- [ ] 🧹 Code refactor / cleanup
- [ ] ⚡ Performance improvement
- [ ] 🧪 Test improvement

---

## How Has This Been Tested?

<!-- Describe the testing you performed and how reviewers can reproduce it. -->

- [ ] Ran existing test suite: `pytest tests/ -v`
- [ ] Added new tests covering the changes
- [ ] Manually verified the dashboard (attach screenshots if UI changed)
- [ ] Tested with sample scanner reports
- [ ] Verified with Ruff: `ruff check .`
- [ ] Verified type checking: `mypy .`

### Test Configuration (if applicable)

- Python version:
- OS:
- Docker version (for attack simulation / SBOM):
- Scanner versions (Trivy, Semgrep, …):

---

## Screenshots / Logs (if appropriate)

<!-- Drag‑and‑drop screenshots or paste relevant terminal output. -->

---

## Security Considerations

<!-- Required for any change that touches authentication, file I/O, CLI, web API, or data handling. -->

- [ ] No secrets (tokens, keys, passwords) are hard‑coded or logged
- [ ] All user‑supplied paths are validated with `_is_safe_path` / `_validate_target_path`
- [ ] External commands use `subprocess.run(…, shell=False)`
- [ ] API endpoints are protected by `@require_any_auth` or `@require_api_key`
- [ ] New environment variables are documented and have a safe default
- [ ] Database schema changes include migration notes (if applicable)

---

## Checklist

- [ ] Code follows project style guidelines (Ruff / Mypy pass)
- [ ] Self‑review completed
- [ ] Public functions have docstrings
- [ ] Changes are documented in `README.md`, `PREREQUISITES.md`, or inline where needed
- [ ] No new compiler / linter warnings introduced
- [ ] Tests pass locally with my changes
- [ ] I have added tests that prove my fix / feature works
- [ ] Any dependent changes have been merged and published
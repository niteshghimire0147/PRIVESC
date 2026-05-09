# Contributing to Linux Privilege Escalation Automation Toolkit

Thank you for your interest in contributing! This project welcomes bug reports, feature requests, new scanner modules, and documentation improvements.

## Getting Started

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/linux-privesc-toolkit.git
cd linux-privesc-toolkit

# No external dependencies needed — stdlib only
python -m pytest tests/ -v
```

## Development Workflow

1. **Fork** the repository
2. **Create a branch**: `git checkout -b feat/your-feature-name`
3. **Write code** following the style guide below
4. **Add tests** in `tests/` for your changes
5. **Run linting**: `flake8 . --max-line-length=120 --exclude=__pycache__,.git,output`
6. **Run tests**: `python -m pytest tests/ -v`
7. **Submit a PR** against the `main` branch

## Code Style

- PEP 8, max line length 120 characters
- Type hints on all public functions
- Docstrings on every class and public method
- No external dependencies — standard library only

## Adding a New Scanner Module

Each scanner module in `modules/` must:

1. Return a `list[dict]` with this schema per finding:
   ```python
   {
       "category": str,      # e.g. "SUID Binary"
       "type": str,          # e.g. "EXPLOITABLE_SUID"
       "severity": str,      # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
       "description": str,   # Human-readable finding summary
       "mitigation": str,    # Recommended fix
       "details": dict,      # Any extra structured data
   }
   ```
2. Have a `run(verbose: bool = False) -> list[dict]` function as its entry point
3. Be registered in `main.py`'s module list

## Reporting Vulnerabilities

Please **do not** open a public issue for security vulnerabilities in this project itself.
Email: ghimirenitesh8@gmail.com with subject "SECURITY: linux-privesc-toolkit"

## Code of Conduct

Be respectful and constructive. See [Contributor Covenant](https://www.contributor-covenant.org/) for guidelines.

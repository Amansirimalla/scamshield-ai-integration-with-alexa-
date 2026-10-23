# Contributing to ScamShield AI

Thank you for helping improve ScamShield AI. Contributions should preserve the
project's conservative safety behavior: findings are evidence-based
indicators, not proof that a message or URL is fraudulent or safe.

## Before opening a change

1. Read the README, privacy notes, and security limitations.
2. Keep user-submitted content out of logs, fixtures, screenshots, and commits.
3. Open an issue or discussion first for large behavioral or dependency changes.
4. Keep changes focused and include tests for new behavior.

## Local development

ScamShield requires Python 3.11 or newer.

```bash
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[test]"
python -m pytest
```

The default test suite uses mocks and does not require AWS credentials, API
keys, or network access. MCP integration tests run when the MCP SDK is
installed; tests that cannot run in the current environment skip explicitly.

## Code expectations

- Keep analysis and tool logic separate from transport and web-framework code.
- Validate inputs and return structured, predictable results.
- Never convert an unavailable or inconclusive lookup into a safe result.
- Do not make submitted URLs server-side requests, follow redirects, or
  execute content.
- Do not add secrets, real personal messages, or live provider responses.
- Prefer standard-library solutions unless a dependency is necessary.
- Update documentation and tests with behavior changes.

## Pull requests

Describe the user-visible behavior, security/privacy impact, tests run, and
any setup that cannot be verified locally. Do not claim live AWS or reputation
provider verification unless it was actually performed and documented.


# Contributing to HoneyMind

Thank you for helping improve HoneyMind.

HoneyMind is based on [ThalesGroup dd-honeypot](https://github.com/ThalesGroup/dd-honeypot). Contributions must preserve the original attribution and the existing Apache 2.0 license.

## How to Contribute

1. Fork the repository.
2. Create a branch from `main`.
3. Make a focused change.
4. Add or update tests when behavior changes.
5. Update documentation when configuration, behavior, or user-facing workflows change.
6. Open a pull request with a clear description.

Use conventional commit-style messages when possible, for example:

```text
fix(ssh): normalize terminal output
feat(llm): add provider usage tracking
docs(security): clarify public reporting process
test(fakefs): cover common reconnaissance commands
```

## Development Setup

Create a virtual environment and install dependencies:

```sh
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -r test/test.requirements.txt
```

Run the unit test suite:

```sh
PYTHONPATH=src:test python -m pytest --color=yes test/*_unit.py
```

Unit tests run automatically in GitHub Actions on pushes and manual workflow runs.

## Optional Integration Tests

Integration tests that call live LLM providers are optional. Normal CI does not require AWS credentials or hosted LLM credentials.

To run live Bedrock integration tests locally:

```sh
RUN_BEDROCK_INTEGRATION=true PYTHONPATH=src:test python -m pytest --color=yes test/test_*_integration.py
```

For Bedrock, provide AWS credentials through environment variables or a local ignored file such as `config/aws.env.list`:

```sh
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
AWS_REGION=us-east-1
```

For hosted OpenAI-compatible or Anthropic providers, prefer `config/llm.env.list`:

```sh
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
HONEYMIND_LLM_TOKEN=...
```

Never commit these files or real credentials.

In GitHub Actions, the optional LLM integration workflow skips live Bedrock calls by default. To run them manually, start the workflow with `run_bedrock=true` and configure `AWS_ROLE_TO_ASSUME` as a repository secret.

## Pull Request Checklist

Before submitting a pull request, check:

- The change is focused and does not rewrite unrelated protocol behavior.
- Existing dataset-first and LLM fallback behavior is preserved unless the PR explicitly changes it.
- Unit tests pass locally.
- New behavior has tests.
- Documentation is updated when public behavior or configuration changes.
- No real secrets, private keys, host-specific data, or personal data are committed.
- Synthetic honeypot lure values are clearly fake.

## Coding Guidelines

- Prefer existing package boundaries and helper APIs.
- Keep protocol handlers focused on protocol behavior.
- Keep local-first operation working without AWS credentials.
- Use `requests` for simple HTTP LLM provider calls unless a dependency is already required.
- Avoid logging API keys, Authorization headers, tokens, or secret values.
- Preserve structured log compatibility, including the legacy `dd-honeypot` marker when present.

## Docker

Build the image:

```sh
docker build -t honeymind:latest .
```

Run a local-first deployment:

```sh
docker run -it --rm \
  --name honeymind \
  -p 2222:2222 \
  -p 8080:80 \
  -v $(pwd)/honeypots:/data/honeypot \
  -v $(pwd)/logs:/data/honeypot/logs \
  --env-file config/llm.env.list \
  honeymind:latest
```

## Releases

Releases are created from `main` using annotated tags:

```sh
git switch main
git pull --rebase origin main
git tag -a v0.1.0 -m "Release 0.1.0"
git push origin v0.1.0
```

The Docker publication workflow builds and publishes tagged releases to GitHub Container Registry.

## Issues

For bugs and feature requests, open a GitHub issue with:

- What you expected.
- What happened.
- Configuration details that are safe to share.
- Logs or traces with secrets removed.
- Steps to reproduce.

For vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of posting sensitive details publicly.

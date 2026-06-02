# Project Structure

HoneyMind organizes implementation code into domain packages under `src/`. The `src/` root intentionally contains no Python modules, so imports point directly at the package that owns the behavior.

## Source Layout

| Path | Purpose |
| ---- | ------- |
| `src/honeypots/` | Protocol implementations, startup helpers, registry, and protocol-specific data handlers |
| `src/infra/` | Shared data handler chain, fake filesystem, datastore, and prompt rendering infrastructure |
| `src/core/` | Shared runtime utilities such as environment loading, input normalization, and password handling |
| `src/llm_providers/` | LLM provider abstraction and usage accounting |
| `src/logging_pipeline/` | Canonical structured logging and local JSONL log writing |
| `src/analysis/` | Attack classification, profiling, campaign detection, enrichment, and fingerprint helpers |
## Scripts

| Path | Purpose |
| ---- | ------- |
| `scripts/` | Operational utilities for logs, analytics, LLM usage, and filesystem packing |
| `scripts/fakefs/` | Fake filesystem conversion helpers used by the FakeFS guide |

## Tests

Unit tests remain in `test/` because the CI command runs `test/*_unit.py`. New tests should keep that naming convention unless the CI workflow changes.

## Import Guidance

New code should import from the organized packages, for example:

```python
from honeypots.ssh_honeypot import SSHHoneypot
from core.input_normalizer import normalize_command_input
from llm_providers.llm_utils import invoke_llm
```

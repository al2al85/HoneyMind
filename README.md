# HoneyMind

![HoneyMind screenshot](docs/assets/honeymind-screenshot.png)

HoneyMind is a local-first, cloud-optional, LLM-powered honeypot and attack analytics platform. It uses dynamic honeypot interactions to collect attacker behavior and make the resulting logs easier to analyze afterward.

HoneyMind emulates realistic behavior across SSH, HTTP/HTTPS, MySQL, PostgreSQL, Redis, Telnet, and generic TCP protocols. It combines recorded payloads with LLM-based response generation to closely mimic real application behavior.

When an attacker’s request matches the dataset, the recorded response is returned directly. When no match is found, an LLM generates a realistic response that is logged for review and future inclusion in the dataset. This continuous enrichment process keeps the system effective against emerging threats.

HoneyMind is open-source and welcomes community contributions. Deployment is simplified through a Docker container, enabling users to run the honeypot system fully on one machine with local logs and local LLMs. Cloud LLMs and AWS logging remain optional integrations.

## Origins and attribution

HoneyMind started as a fork/adaptation of ThalesGroup's dd-honeypot. We keep attribution to the original authors and preserve the original license.

Original project: [ThalesGroup/dd-honeypot](https://github.com/ThalesGroup/dd-honeypot)

The current license remains unchanged; see [LICENSE.md](LICENSE.md).

---

## Supported Protocols

| Protocol   | Example Targets           | Key Capabilities                                                  |
|------------|---------------------------|-------------------------------------------------------------------|
| SSH        | Alpine Linux, Busybox     | Shell emulation, fake filesystem, file download simulation        |
| HTTP/HTTPS | Boa Server, phpMyAdmin    | All HTTP methods, session cookies, dispatcher routing             |
| MySQL      | MySQL 5.7 / 8.0           | Handshake, authentication, SQL query processing                   |
| PostgreSQL | PostgreSQL                | Startup messages, authentication, queries, prepared statements    |
| Redis      | Redis                     | RESP protocol, multi-database (SELECT), SET/GET/DEL/KEYS/AUTH     |
| Telnet     | D-Link routers            | Banner, login prompts, session timeout                            |
| TCP        | Generic services          | Action-based query/response on any TCP port                       |

---

## Features

* Emulates 7 protocols with realistic request/response behavior
* LLM fallback for unknown requests via local Ollama, OpenAI-compatible APIs, OpenAI, Anthropic, or optional AWS Bedrock, with rate limiting per visitor
* Dataset-first design: JSONL files with dynamic placeholders (`${user}`, `${host}`, etc.)
* Dispatcher mode: routes connections to multiple backend honeypots on a single port ([docs](docs/dispatcher.md))
* Fake filesystem: compressed JSONL definitions loaded into SQLite for shell commands (ls, cd, mkdir, wget)
* Chained data handlers: file downloads → fake filesystem → dataset lookup → LLM fallback
* Conservative input normalization for lookup/cache deduplication while preserving raw forensic logs
* Session tracking with UUIDs, client IP logging, and per-session state
* Local JSONL logging with honeypot metadata, plus optional Fluent Bit, CloudWatch, or S3 export
* Docker-based deployment with multi-architecture support (amd64, arm64)

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                   Dispatcher                        │
│         (optional single-port routing)              │
└──────────┬──────────┬──────────┬────────────────────┘
           │          │          │
     ┌─────▼───┐ ┌───▼────┐ ┌──▼──────┐
     │   SSH   │ │  HTTP  │ │  MySQL  │  ...
     │ Handler │ │ Handler│ │ Handler │
     └────┬────┘ └───┬────┘ └────┬────┘
          │          │           │
     ┌────▼──────────▼───────────▼────┐
     │      Data Handler Chain        │
     │  FileDownload → FakeFS →       │
     │  Dataset Lookup → LLM Fallback │
     └────────────┬───────────────────┘
                  │
     ┌────────────▼───────────────────┐
     │   Dataset (JSONL / SQLite)     │
     │   + Configurable LLM Engine    │
     └────────────────────────────────┘
```

* **Protocol Handlers**: Implement protocol-specific logic (SSH via Paramiko, HTTP via Flask, MySQL via mysql-mimic, PostgreSQL native protocol, Redis RESP, Telnet via telnetlib3)
* **Data Handler Chain**: Processes requests through a configurable pipeline — file downloads, fake filesystem, dataset lookup, and LLM fallback
* **Dataset & Lookup Engine**: Maps incoming requests to recorded payloads in JSONL files backed by SQLite
* **LLM Engine**: Generates realistic responses for unknown requests using local Ollama, OpenAI-compatible APIs, OpenAI, Anthropic, or optional AWS Bedrock with configurable system prompts and per-visitor rate limiting
* **Dispatcher**: Routes connections to different honeypots based on traffic inspection or LLM-assisted classification, with sticky session support
* **Logging**: Tracks all interactions with session IDs, client IPs, and honeypot metadata in structured JSON format

---

## Dataset

The dataset powers HoneyMind’s response generation. Each JSONL file contains request-response pairs for a specific application and version:

* **request**: the attacker’s input
* **response**: the emulated reply
* Optional placeholders like `${user}` or `${host}` for dynamic substitution
* Context-aware fields (e.g., current working directory, database state)

Datasets can be layered — for example, a general MySQL dataset combined with a version-specific dataset for MySQL 5.7 behavior.

**Known requests** are matched and returned directly. **Unknown requests** are handled by the LLM and logged separately for review and future inclusion.

HoneyMind normalizes attacker inputs before dataset and dynamic cache lookup so equivalent whitespace variants reuse the same response. For example, `ls Doc`, `ls                 Doc`, and `ls\tDoc` map to the same lookup key. This reduces duplicate LLM calls, lowers hosted API cost, and keeps responses consistent.

Normalization is intentionally conservative: it strips leading/trailing whitespace and collapses unquoted whitespace, while preserving quoted strings, escaped whitespace, case, paths, argument order, URL encoding, and raw payload content. Raw attacker input remains available in logs and is still used in the LLM prompt on a cache miss.

### Example

```json
{"request": "SELECT version()", "response": "5.7.33-0ubuntu0.16.04.1"}
{"request": "DROP TABLE users;", "response": "Error: DROP command denied to user ‘${user}’@’${host}’ for table ‘users’"}
```

For more details on dataset formats, see [data usage](docs/data_usage.md) and [SQLite data handling](docs/sqlite_data_handling.md).

---

## Configuration

Each honeypot is defined by a `config.json` in its own directory. The main fields are:

| Field              | Description                                           |
|--------------------|-------------------------------------------------------|
| `type`             | Protocol type: `ssh`, `http`, `mysql`, `postgresql`, `redis`, `telnet`, `tcp` |
| `port`             | Port to listen on                                     |
| `data_file`        | Path to JSONL dataset (e.g., `data.jsonl`)            |
| `model_id`         | LLM model ID for fallback generation |
| `system_prompt`    | Instructions guiding LLM responses                    |
| `llm_provider`     | Optional LLM provider: `ollama`, `openai_compatible`, `openai`, `anthropic`, or `bedrock` |
| `llm_base_url`     | Optional API base URL for HTTP-based providers        |
| `llm_api_key`      | Optional direct API key or Bearer token value         |
| `llm_api_key_env`  | Optional environment variable containing an API key or Bearer token |
| `llm_allow_no_api_key` | Allow a public OpenAI-compatible endpoint with no API key when explicitly set |
| `llm_temperature`  | Optional generation temperature                       |
| `llm_max_tokens`   | Optional maximum generated tokens                     |
| `llm_timeout`      | Optional LLM request timeout in seconds               |
| `llm_usage_db_path` | Optional SQLite DB path for token usage and pricing  |
| `llm_model_prices` | Optional inline model price table seeded into the usage DB |
| `input_normalization_enabled` | Normalize lookup/cache keys, defaults to `true` |
| `log_normalized_input` | Add normalized input fields to structured logs, defaults to `true` |
| `local_logging_enabled` | Enable local JSONL logs, defaults to `true`      |
| `local_log_dir`    | Directory for JSONL logs, defaults to `/data/honeypot/logs` |
| `name`             | Display name for logging                              |
| `prompt_template`  | Shell prompt format with `${{username}}`, `${{cwd}}` placeholders (SSH/Telnet) |
| `fs_file`          | Path to compressed fake filesystem (e.g., `fs_alpine.jsonl.gz`) |
| `is_dispatcher`    | Enable dispatcher mode (HTTP)                         |

### Example: local SSH honeypot with Ollama

```json
{
  "type": "ssh",
  "name": "Alpine Linux",
  "port": 2222,
  "data_file": "data.jsonl",
  "fs_file": "fs_alpine.jsonl.gz",
  "prompt_template": "${username}@alpine:${cwd}$ ",
  "llm_provider": "ollama",
  "llm_base_url": "http://host.docker.internal:11434",
  "model_id": "llama3.1:8b",
  "system_prompt": "You are a terminal on Alpine Linux. Respond only with realistic terminal output.",
  "llm_temperature": 0.0,
  "llm_max_tokens": 2000,
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

For the full configuration schema, see [honeypot configuration](docs/honeypot_configuration.md).

---

## Installation

HoneyMind is packaged as a Docker image for quick and reproducible deployment.

### Pull and run locally

```sh
docker build -t honeymind:latest .
```

```sh
docker run --rm -it \
  --name honeymind \
  -p 2222:2222 \
  -p 8080:80 \
  -v $(pwd)/honeypots:/data/honeypot \
  -v $(pwd)/logs:/data/honeypot/logs \
  --env-file config/llm.env.list \
  honeymind:latest
```

The container starts honeypot services based on the configurations found in `/data/honeypot`. Each subdirectory should contain a `config.json` defining one honeypot instance. Attack logs are written to `/data/honeypot/logs` inside the container, which the example mounts to `./logs` on the host.

### AWS EC2 deployment

1. Create an instance role with permissions for Bedrock, and optionally CloudWatch Logs or S3 if you want AWS log collection
2. Create a security group with the ports your honeypots will use
3. Launch an EC2 instance with the role and security group
4. Install Docker and run:

```sh
docker run -d \
  --log-driver=awslogs \
  --log-opt awslogs-region=us-east-1 \
  --log-opt awslogs-group=yourLogGroup \
  --log-opt awslogs-create-group=true \
  -v /your/honeypot/folder:/data/honeypot \
  honeymind:latest
```

### LLM configuration

HoneyMind uses a dataset-first flow, then falls back to an LLM for unknown requests. AWS is optional. HoneyMind can run locally with local JSONL logs and a local or remote LLM endpoint. If `llm_provider` is omitted, Bedrock model IDs still use Bedrock for backward compatibility; otherwise configure a local or hosted provider explicitly.

Every LLM call can also be recorded in a SQLite usage database. The app stores prompt tokens, completion tokens, total tokens, and an estimated cost when a matching model price row exists. By default the DB is created next to the honeypot data folder as `llm_usage.db`.

Supported providers:

| Provider | Use case |
|----------|----------|
| `ollama` | Native local Ollama `/api/chat` |
| `openai_compatible` | OpenRouter, Groq, Together, Mistral-compatible gateways, vLLM, LM Studio, Ollama `/v1`, and other compatible endpoints |
| `openai` | OpenAI Chat Completions API |
| `anthropic` | Direct Anthropic Messages API |
| `bedrock` | Optional AWS Bedrock Claude and Jamba models |

`llm_api_key_env` takes priority over `llm_api_key` when the environment variable exists and is not empty. Localhost, `127.0.0.1`, `::1`, `host.docker.internal`, and private LAN OpenAI-compatible endpoints can run without a token by default. Public remote OpenAI-compatible endpoints require a token unless `llm_allow_no_api_key` is explicitly set to `true`.

If you want cost tracking, provide `llm_model_prices` inline or seed the `llm_model_prices` table in `llm_usage.db`. Each row uses prices per million tokens (`prompt_price_per_mtok` and `completion_price_per_mtok`) plus a `currency`. Usage rows store generic `prompt_cost`, `completion_cost`, `total_cost`, `currency`, and `price_source` fields. If a model has no matching price row, usage is still logged but the cost columns stay `NULL`. OpenAI-compatible usage can match an `ovhcloud` price row through the built-in provider alias.

You can inspect usage with:

```sh
python scripts/llm_usage_report.py /data/honeypot/logs/llm_usage.db
python scripts/llm_usage_report.py /data/honeypot/logs/llm_usage.db --daily
python scripts/llm_usage_report.py /data/honeypot/logs/llm_usage.db --json
```

Native local Ollama:

```json
{
  "type": "ssh",
  "name": "Alpine Linux",
  "port": 2222,
  "data_file": "data.jsonl",
  "fs_file": "fs_alpine.jsonl.gz",
  "prompt_template": "${username}@alpine:${cwd}$ ",
  "llm_provider": "ollama",
  "llm_base_url": "http://host.docker.internal:11434",
  "model_id": "llama3.1:8b",
  "system_prompt": "You are a terminal on Alpine Linux. Respond only with realistic terminal output.",
  "llm_temperature": 0.0,
  "llm_max_tokens": 2000,
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

Ollama through OpenAI compatibility:

```json
{
  "type": "ssh",
  "name": "Ubuntu Server",
  "port": 2222,
  "data_file": "data.jsonl",
  "llm_provider": "openai_compatible",
  "llm_base_url": "http://host.docker.internal:11434/v1",
  "model_id": "llama3.1:8b",
  "system_prompt": "You are an Ubuntu server shell. Respond only with command output.",
  "llm_temperature": 0.0,
  "llm_max_tokens": 2000,
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

OpenAI API:

```json
{
  "type": "http",
  "name": "phpMyAdmin",
  "port": 8080,
  "data_file": "data.jsonl",
  "llm_provider": "openai",
  "llm_api_key_env": "OPENAI_API_KEY",
  "model_id": "gpt-4o-mini",
  "system_prompt": "You are a phpMyAdmin server. Respond realistically to HTTP requests.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

Anthropic Claude API:

```json
{
  "type": "ssh",
  "name": "Debian Server",
  "port": 2222,
  "data_file": "data.jsonl",
  "llm_provider": "anthropic",
  "llm_api_key_env": "ANTHROPIC_API_KEY",
  "model_id": "claude-3-5-haiku-latest",
  "system_prompt": "You are a Debian terminal. Respond only with realistic terminal output.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

Remote vLLM or self-hosted OpenAI-compatible API:

```json
{
  "type": "http",
  "port": 8080,
  "data_file": "data.jsonl",
  "llm_provider": "openai_compatible",
  "llm_base_url": "https://llm.example.com/v1",
  "llm_api_key_env": "SELF_HOSTED_LLM_API_KEY",
  "model_id": "meta-llama/Llama-3.1-8B-Instruct",
  "system_prompt": "You are a realistic HTTP server.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

OpenAI-compatible API with a direct Bearer token:

```json
{
  "llm_provider": "openai_compatible",
  "llm_base_url": "https://example-llm-gateway.com/v1",
  "llm_api_key": "YOUR_TOKEN_HERE",
  "model_id": "your-model-name"
}
```

HoneyMind sends this as:

```http
Authorization: Bearer YOUR_TOKEN_HERE
```

OpenAI-compatible API with a token from the environment:

```json
{
  "llm_provider": "openai_compatible",
  "llm_base_url": "https://example-llm-gateway.com/v1",
  "llm_api_key_env": "HONEYMIND_LLM_TOKEN",
  "model_id": "your-model-name"
}
```

`config/llm.env.list`:

```sh
HONEYMIND_LLM_TOKEN=YOUR_TOKEN_HERE
```

If the configured value already starts with `Bearer `, HoneyMind normalizes it and avoids duplicating the prefix.

Optional AWS Bedrock:

```json
{
  "type": "ssh",
  "name": "Amazon Linux",
  "port": 2222,
  "data_file": "data.jsonl",
  "llm_provider": "bedrock",
  "model_id": "anthropic.claude-3-haiku-20240307-v1:0",
  "system_prompt": "You are an Amazon Linux terminal. Respond only with realistic terminal output.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

For hosted HTTP providers, put keys in `config/llm.env.list` or `config/.env`:

```sh
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
OPENROUTER_API_KEY=...
HONEYMIND_LLM_TOKEN=...
```

Remote API providers receive honeypot interaction data when LLM fallback is used. Review privacy, legal, and operational requirements before sending attacker traffic to third-party services.

### Input normalization

HoneyMind keeps the dataset-first and LLM fallback flow, but uses a normalized lookup key before it searches the dataset or dynamic cache. The raw command/request is not replaced.

Example:

```text
ls Doc
ls                 Doc
ls\tDoc
```

All three inputs use `ls Doc` for lookup/cache reuse. If lookup misses, HoneyMind sends the original raw attacker input to the LLM and stores the generated response under the normalized key for future equivalent inputs.

SSH structured logs use the canonical HoneyMind event schema. Command events keep raw attacker input under `command.raw`, normalized lookup input under `command.normalized`, the response sent to the attacker under `command.response`, and the source under `command.parser_action`.

```json
{
  "event_type": "command",
  "command": {
    "raw": "ls                 Doc",
    "normalized": "ls Doc",
    "parser_action": "hardcoded",
    "response": "..."
  }
}
```

The normalizer does not lowercase commands, reorder arguments, decode URLs, expand variables, resolve paths, or deeply rewrite SQL/HTTP payloads.

For AWS Bedrock, provide AWS credentials via environment variables or the backward-compatible `config/aws.env.list` file:

```
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
AWS_REGION=us-east-1
```

Logs are always emitted locally by the honeypot process. Sending them to AWS CloudWatch or S3 is optional and can be configured separately with Docker logging or Fluent Bit.

---

## Documentation

| Topic | Link |
|-------|------|
| Honeypot configuration schema | [docs/honeypot_configuration.md](docs/honeypot_configuration.md) |
| Dispatcher (multi-honeypot routing) | [docs/dispatcher.md](docs/dispatcher.md) |
| Fake filesystem guide | [docs/fakefs_json_guide.md](docs/fakefs_json_guide.md) |
| Dataset usage | [docs/data_usage.md](docs/data_usage.md) |
| SQLite data handling | [docs/sqlite_data_handling.md](docs/sqlite_data_handling.md) |
| Redis honeypot | [docs/redis_honeypot.md](docs/redis_honeypot.md) |
| Logging & Fluent Bit | [docs/logging-readme.md](docs/logging-readme.md) |
| Multi-IP networking | [docs/networking-readme.md](docs/networking-readme.md) |

---

## Contributing

We welcome community contributions — new honeypot types, protocol handlers, datasets, system prompts, and test cases.

See [CONTRIBUTING.md](./CONTRIBUTING.md) for setup instructions, testing guidelines, and the PR checklist.

---

## Licensing

HoneyMind is distributed under the [Apache 2.0 License](LICENSE.md), preserving the license from the original ThalesGroup dd-honeypot project.
It depends on modules licensed under their own open-source licenses (see [THIRD_PARTY.txt](THIRD_PARTY.txt)).

---

# Honeypot Configuration Guide

This guide explains how to configure individual honeypots in the HoneyMind honeypot system. Each honeypot is defined using a JSON configuration file located under the `honeypots/` directory.

HoneyMind is based on the original [ThalesGroup dd-honeypot](https://github.com/ThalesGroup/dd-honeypot) project and preserves the original license and attribution.

---

## Directory Structure

All honeypots live in the `honeypots/` folder. Each honeypot can be defined in:

* A dedicated folder with `config.json`
  *(e.g., `honeypots/alpine/config.json`)*
* Or as a standalone config file
  *(e.g., `honeypots/php_my_admin-config.json`)*

Typical contents:

```
honeypots/
├── alpine/
│   ├── config.json
│   ├── data.jsonl
│   └── fs_alpine.jsonl.gz
├── mysql
│   ├── config.json
│   └── data.jsonl
├── php_my_admin
│   ├── config.json
│   └── data.jsonl
```

---

## Configuration Schema

Each honeypot config must include the following fields:

###  Required Fields

| Field           | Description                                     |
| --------------- | ----------------------------------------------- |
| `type`          | Protocol type: `ssh`, `http`, `telnet`, `mysql` |
| `port`          | Port to listen on                               |
| `model_id`      | LLM model used for fallback generation          |
| `data_file`     | Path to JSONL file with request/response pairs  |
| `system_prompt` | Instructions to guide LLM behavior              |

---

###  Optional Fields (Based on Type)

| Field             | Description                                                |
| ----------------- | ---------------------------------------------------------- |
| `name`            | Display name of the honeypot                               |
| `prompt_template` | Shell prompt format (for SSH/Telnet CLI simulation)        |
| `shell-prompt`    | Fixed prompt string (used by some CLI honeypots)           |
| `fs_file`         | JSON file defining virtual file system for CLI honeypots   |
| `dialect`         | SQL dialect (e.g., `mysql`, `postgresql`) for DB honeypots |
| `llm_provider`    | LLM provider: `ollama`, `openai_compatible`, `openai`, `anthropic`, or `bedrock` |
| `llm_base_url`    | Base URL for HTTP-based LLM providers                     |
| `llm_api_key`     | Direct API key or Bearer token value; prefer `llm_api_key_env` for secrets |
| `llm_api_key_env` | Environment variable that contains the API key or Bearer token |
| `llm_allow_no_api_key` | Explicitly allow a public OpenAI-compatible endpoint without an API key |
| `llm_timeout`     | LLM request timeout in seconds                            |
| `llm_temperature` | LLM generation temperature                                |
| `llm_max_tokens`  | Maximum generated tokens                                  |
| `input_normalization_enabled` | Normalize dataset/cache lookup keys, defaults to `true` |
| `log_normalized_input` | Include normalized input fields in structured logs, defaults to `true` |
| `local_logging_enabled` | Enable local JSONL logging, defaults to `true`       |
| `local_log_dir`   | Directory for local JSONL logs, defaults to `/data/honeypot/logs` |
| `local_log_filename` | Filename pattern, defaults to `dd-honeypot-%Y-%m-%d.jsonl` |
| `local_log_rotate_daily` | Apply date formatting to the local log filename, defaults to `true` |

---

## LLM Providers

The honeypot always checks `data.jsonl` first. The LLM is used only when no dataset response matches. AWS is optional. If `llm_provider` is omitted, Bedrock-looking model IDs still use Bedrock for backward compatibility; otherwise configure `llm_provider` or an OpenAI-compatible `llm_base_url`.

Supported providers:

| Provider | Description |
| -------- | ----------- |
| `ollama` | Native local Ollama `/api/chat` |
| `openai_compatible` | OpenAI Chat Completions-compatible APIs such as OpenRouter, Groq, Together, Mistral-compatible gateways, LM Studio, Ollama `/v1`, vLLM, and remote self-hosted endpoints |
| `openai` | OpenAI Chat Completions API |
| `anthropic` | Direct Anthropic Messages API |
| `bedrock` | Optional AWS Bedrock Claude and Jamba models |

`llm_api_key_env` takes priority over `llm_api_key` when the environment variable exists and is not empty. Localhost, `127.0.0.1`, `::1`, `host.docker.internal`, private LAN OpenAI-compatible endpoints, and native Ollama do not require an API key by default. Public remote OpenAI-compatible endpoints require an API key unless `llm_allow_no_api_key` is explicitly set to `true`.

For `openai` and `openai_compatible`, HoneyMind sends configured tokens as a Bearer token:

```http
Authorization: Bearer YOUR_TOKEN_HERE
```

Use a raw token in config:

```json
{
  "llm_provider": "openai_compatible",
  "llm_base_url": "https://example-llm-gateway.com/v1",
  "llm_api_key": "YOUR_TOKEN_HERE",
  "model_id": "your-model-name"
}
```

Or keep the token in `config/llm.env.list`:

```json
{
  "llm_provider": "openai_compatible",
  "llm_base_url": "https://example-llm-gateway.com/v1",
  "llm_api_key_env": "HONEYMIND_LLM_TOKEN",
  "model_id": "your-model-name"
}
```

```sh
HONEYMIND_LLM_TOKEN=YOUR_TOKEN_HERE
```

If the value already starts with `Bearer `, HoneyMind normalizes it and avoids sending `Bearer Bearer ...`.

Environment files are loaded from `config/aws.env.list`, `config/llm.env.list`, and `config/.env` when present. A typical `config/llm.env.list` looks like:

```sh
OPENAI_API_KEY=...
ANTHROPIC_API_KEY=...
OPENROUTER_API_KEY=...
HONEYMIND_LLM_TOKEN=...
```

For AWS Bedrock, keep using AWS environment variables or `config/aws.env.list`:

```sh
AWS_ACCESS_KEY_ID=YOUR_ACCESS_KEY
AWS_SECRET_ACCESS_KEY=YOUR_SECRET_KEY
AWS_REGION=us-east-1
```

Remote API providers receive honeypot interaction data. Review privacy, legal, and operational requirements before sending attacker traffic to third-party services.

## Local Logging

Structured honeypot events are written to stdout and, by default, to local JSONL files. Each line is one JSON object and preserves the `"dd-honeypot": true` marker, session ID, timestamp, honeypot type/name, and protocol-specific fields such as `command`, `query`, or `http-request`.

```json
{
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs",
  "local_log_filename": "dd-honeypot-%Y-%m-%d.jsonl",
  "local_log_rotate_daily": true
}
```

When using Docker, mount `/data/honeypot/logs` to a host folder to read logs directly from the machine running the honeypot.

## Input Normalization

HoneyMind normalizes attacker input for dataset and dynamic cache lookup before invoking the LLM. This keeps equivalent whitespace-only variants from consuming extra LLM calls:

```text
ls Doc
ls                 Doc
ls\tDoc
```

All three inputs use `ls Doc` as the lookup/cache key. The raw attacker input is still preserved in protocol fields such as `command`, `query`, or `http-request`, and the LLM prompt still receives the raw input after a lookup miss.

```json
{
  "input_normalization_enabled": true,
  "log_normalized_input": true
}
```

When normalized logging is enabled, events can include additive fields such as:

```json
{
  "dd-honeypot": true,
  "honeymind": true,
  "command": "ls                 Doc",
  "raw_input": "ls                 Doc",
  "normalized_command": "ls Doc",
  "normalized_input": "ls Doc"
}
```

The normalizer is conservative. It preserves quoted whitespace, escaped whitespace, case, paths, argument order, URL encoding, and raw payload content. It does not expand variables, resolve paths, sort arguments, lowercase commands, or deeply rewrite SQL/HTTP payloads.

## Example Configurations

###  Fully Local Ollama Native API

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

---

###  OpenAI API Config

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

---

###  Local Ollama OpenAI-Compatible Config

```json
{
  "type": "ssh",
  "name": "Alpine Linux",
  "port": 2222,
  "data_file": "data.jsonl",
  "fs_file": "fs_alpine.jsonl.gz",
  "prompt_template": "${username}@alpine:${cwd}$ ",
  "llm_provider": "openai_compatible",
  "llm_base_url": "http://localhost:11434/v1",
  "model_id": "llama3.1:8b",
  "system_prompt": "You are a terminal on Alpine Linux. Respond only with terminal output.",
  "llm_temperature": 0.0,
  "llm_max_tokens": 2000,
  "llm_timeout": 300,
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

---

###  Native Ollama Config

```json
{
  "type": "ssh",
  "port": 2222,
  "data_file": "data.jsonl",
  "llm_provider": "ollama",
  "llm_base_url": "http://localhost:11434",
  "model_id": "llama3.1:8b",
  "system_prompt": "You are a terminal on Alpine Linux.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

---

###  Local vLLM Config

```json
{
  "type": "http",
  "port": 8080,
  "data_file": "data.jsonl",
  "llm_provider": "openai_compatible",
  "llm_base_url": "http://localhost:8000/v1",
  "model_id": "meta-llama/Llama-3.1-8B-Instruct",
  "system_prompt": "You are a realistic HTTP server.",
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs"
}
```

---

###  Anthropic Claude API Config

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

---

###  Optional AWS Bedrock Config

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

---

###  MySQL Honeypot

```json
{
  "type": "mysql",
  "port": 13306,
  "dialect": "mysql",
  "model_id": "anthropic.claude-3-5-sonnet-20240620-v1:0",
  "data_file": "honeypots/mysql/data.jsonl",
  "system_prompt": [
    "You are a MySQL server.",
    "Return only JSON array of objects."
  ]
}
```

---

## Steps to Add a New Honeypot

1. **Create a Config**
   Inside `honeypots/`, create a folder or a new `*-config.json` file.

2. **Fill Required Fields**
   Use the schema and examples above to define `type`, `port`, `model_id`, etc.

3. **Add Dataset**
   Create a `data.jsonl` file with request-response pairs like:

   ```json
   {
     "request": "GET /admin",
     "response": "<html><h1>403 Forbidden</h1></html>"
   }

   ```
4. **(Optional) Add File System**

For CLI honeypots (like SSH/Telnet), add an `fs_file` entry that points to a compressed fake file system file (with `.jsonl.gz` extension).

These files simulate the output of commands like `ls`, `cd`, and `cat` by emulating a real container file system.

Example:

```json
{
  "type": "ssh",
  "fs_file": "fs_alpine.jsonl.gz"
}

   ```
 To learn how to generate and convert the fake file system, see the [fakefs_json_guide.md](fakefs_json_guide.md).

 
5. **Port Mapping**
   Make sure the `port` in config:

   * Is unique (not already used)
   * Is exposed properly in Docker with `-p <host>:<container>`

---

## Notes

* All honeypot logic relies first on `data.jsonl`. If no match is found, LLM is used.
* You can reuse `model_id`, provider settings, and prompts across multiple honeypots.
* Dataset entries grow automatically as new interactions are logged.
* Logs can be collected locally. AWS CloudWatch or S3 delivery is optional and configured separately.

---

For architecture, Docker deployment, and feature overview, refer to the [README.md](../README.md) file.

# Runtime Honeypot Configurations

This directory is the default local mount point for HoneyMind honeypot runtime configurations.

For supported HoneyMind deployments, place SSH honeypot folders here. Each folder should usually contain:

```text
config.json
data.jsonl
optional-fakefs.jsonl.gz
```

Example:

```text
honeypots/
└── ubuntu-ssh/
    ├── config.json
    ├── data.jsonl
    └── fs_ubuntu.jsonl.gz
```

HoneyMind currently supports SSH as its maintained honeypot protocol. Non-SSH runtime artifacts, such as old MySQL or PostgreSQL SQLite stores, are legacy local experiments and are ignored by Git.

Do not commit generated runtime databases, downloaded payloads, uploaded files, local logs, secrets, or real filesystem captures.

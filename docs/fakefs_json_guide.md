# Creating a Fake File System for HoneyMind

This guide shows how to extract a container’s file system and convert it into a compressed JSONL file used by HoneyMind's FakeFS plugin.

HoneyMind keeps the original JSONL.GZ FakeFS format. At runtime, SSH honeypots can enrich the loaded filesystem with a synthetic Linux server profile containing realistic `/etc`, `/proc`, `/var/www/html`, `/srv/app`, log, backup, cron, and user files. Known files are served locally before the LLM fallback.

Never put real secrets or host files into a FakeFS dataset. Fake credentials should be clearly synthetic, such as `DB_PASSWORD=dev_password_123` or `API_KEY=sk-test-fake-honeymind-000000000000`.

---

## Requirements

- Docker installed and running

---

## Step 1: Extract a Container File Tree

Use Docker to extract the directory tree and save it compressed:

```bash
docker run -v ${PWD}:/fakefs-output/ --rm alpine sh -c "find / -type d | gzip > /fakefs-output/fs.txt.gz"
```

This creates a `fs.txt.gz` file containing directory paths.

---

## Step 2: Convert to `.jsonl.gz`

Use the provided script to convert the file system structure to a format consumable by the honeypot:

The Docker command below mounts the repository `scripts/fakefs` directory and runs the converter in the container.

```bash
docker run \
  -v ${PWD}:/data \
  -v ${PWD}/scripts/fakefs:/tools \
  --rm python:3-alpine \
  python /tools/convert_fs_txt_to_jsonl_gz.py /data/fs.txt.gz /data/fs_alpine.jsonl.gz
```

---

## Step 3: Use in a Honeypot

Place the final `fs.jsonl.gz` in your honeypot folder, e.g.:

```
test/honeypots/alpine/fs.jsonl.gz
```

```json
{
  "type": "ssh",
  "port": 2222,
  "data_file": "test/honeypots/test_responses.jsonl",
  "system_prompt": "You are a Linux emulator",
  "model_id": "test-model",
  "fs_file": "fs.jsonl.gz"
}
```

---

The SSH honeypot can now simulate a realistic filesystem without reading from the host machine.

## Commands to test

Once an SSH honeypot is running with `fs_file`, these commands should return deterministic filesystem responses without calling the LLM:

```sh
cat /etc/passwd
cat /srv/app/.env
cat       /srv/app/.env
ls -la /var/www/html
ls -la /srv/app
find / -name "*.env" 2>/dev/null
grep -R "DB_PASSWORD" /srv/app 2>/dev/null
stat /srv/app/.env
file /srv/app/.env
head /srv/app/.env
tail /srv/app/.env
```

Unknown paths keep the existing fallback behavior. For example, `cat /unknown/path` does not make HoneyMind invent a fake file.

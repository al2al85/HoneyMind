# Logging

HoneyMind emits structured JSON events for honeypot activity. Local JSONL logging is the default path and does not require AWS or any external collector.

HoneyMind is based on [ThalesGroup dd-honeypot](https://github.com/ThalesGroup/dd-honeypot); the legacy `"dd-honeypot": true` marker is intentionally preserved for compatibility with existing log parsers.

## Local JSONL Logging

Every structured event keeps the `"dd-honeypot": true` marker and includes fields such as `time`, `session-id`, `type`, `name`, `login`, `command`, `query`, or `http-request` when they apply.

By default, logs are written inside the container to:

```text
/data/honeypot/logs/dd-honeypot-%Y-%m-%d.jsonl
```

Each line is one valid JSON object. Configure local logging in a honeypot `config.json`:

```json
{
  "local_logging_enabled": true,
  "local_log_dir": "/data/honeypot/logs",
  "local_log_filename": "dd-honeypot-%Y-%m-%d.jsonl",
  "local_log_rotate_daily": true
}
```

Mount the log directory to the host when running Docker:

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

Then inspect logs from the host:

```sh
tail -f logs/dd-honeypot-$(date +%F).jsonl
python scripts/read_local_logs.py logs
```

Stdout logging remains enabled for Docker users, so `docker logs honeymind` still works.

## Optional: Send Logs to S3 Using Fluent Bit

AWS logging is optional. Use this only if you want to export local Docker logs to S3 for Glue/Athena or another AWS workflow.

Fluent Bit can forward JSON events to S3. First create a bucket, then create `/etc/fluent-bit/fluent-bit.conf`:

```ini
[SERVICE]
    Parsers_File parsers.conf

[INPUT]
    Name         forward
    Listen       0.0.0.0
    Port         24224
    TAG          docker.honeypot

[FILTER]
    Name         grep
    Match        docker.honeypot
    Regex        log    ^\{\"dd-honeypot\":\s*true

[OUTPUT]
    Name              s3
    Match             docker.honeypot
    bucket            your-bucket-name
    region            us-east-1
    store_dir         /tmp/fluentbit/s3
    total_file_size   1M
    upload_timeout    30m
    use_put_object    Off
    s3_key_format     /logs/day=%Y-%m-%d/hour=%-H/data-%H-%M-%S.log.jsonl.gz
    compression       gzip
    log_key           log
    static_file_path  On
```

Run Fluent Bit:

```sh
docker run -d --name fluent-bit \
  -v /var/lib/docker/containers:/var/lib/docker/containers:ro \
  -v /etc/fluent-bit/fluent-bit.conf:/fluent-bit/etc/fluent-bit.conf:ro \
  -v /etc/fluent-bit/log:/var/log \
  -v /tmp/fluentbit:/tmp/fluentbit \
  -p 24224:24224 \
  fluent/fluent-bit
```

Run the honeypot with the Fluent Bit Docker log driver:

```sh
docker run --pull=always -d --name honeymind \
  -v /your/honeypot/folder:/data/honeypot \
  -v /your/local/logs:/data/honeypot/logs \
  -p 80:80 -p 2222:2222 -p 3306:3306 \
  --log-driver=fluentd --log-opt fluentd-address=127.0.0.1:24224 \
  honeymind:latest
```

The S3 path and Athena/Glue setup are not required for normal local operation.

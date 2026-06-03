## Honeypot Data Usage Examples

HoneyMind writes structured JSONL logs locally by default. Use these local files first for analysis; AWS S3, Glue, and Athena are optional export paths.

HoneyMind is based on [ThalesGroup dd-honeypot](https://github.com/ThalesGroup/dd-honeypot). New SSH logs use the canonical HoneyMind schema. Legacy dd-honeypot-shaped examples are kept below only for optional AWS/Athena compatibility.

The HoneyMind web dashboard and optional Grafana stack both start from the same local logs. The dashboard uses `ioc-writer` and `ioc-api` to derive sessions, IOC, campaigns, commands, activity, reports, and LLM usage summaries. See [Dashboard and Monitoring](monitoring.md).

## Local JSONL Analysis

Local logs are usually mounted from the container at:

```text
./logs/dd-honeypot-YYYY-MM-DD.jsonl
```

Summarize local logs:

```sh
python scripts/read_local_logs.py logs
```

List session IDs:

```sh
jq -r '.session_id' logs/*.jsonl | sort -u
```

Filter by session ID:

```sh
jq 'select(.session_id == "SESSION_ID")' logs/*.jsonl
```

Filter by client IP:

```sh
jq 'select(.client.ip == "127.0.0.1")' logs/*.jsonl
```

Extract SSH commands:

```sh
jq -r 'select(.event_type == "command") | .command.raw' logs/*.jsonl
```

Count top SSH commands:

```sh
jq -r 'select(.event_type == "command") | .command.raw' logs/*.jsonl \
  | sort | uniq -c | sort -nr | head
```

List commands with their parser source:

```sh
jq -r 'select(.event_type == "command") | [.command.parser_action, .command.raw] | @tsv' logs/*.jsonl
```

Inspect LLM fallback responses:

```sh
jq 'select(.event_type == "llm_response")' logs/*.jsonl
```

Remote LLM providers receive honeypot interaction data when LLM fallback is used. Review privacy, legal, and operational requirements before sending logs or attacker traffic to third-party APIs.

## Optional: Create a Data Lake Table from S3 Logs

If you choose to send logs to S3 using Fluent Bit, you can use AWS Glue to create a Data Lake table from the S3 data. You can also use the following SQL command in Athena:

```sql
CREATE EXTERNAL TABLE `dd_honeypot`(
  `region` string,
  `time` string,
  `session-id` string,
  `type` string,
  `name` string,
  `login` struct<client_ip:string,username:string>,
  `command` string,
  `method` string,
  `http-request` struct<host:string,port:smallint,args:map<string,string>,method:string,headers:map<string,string>,resource_type:string,body:string,path:string>,
  `query` string )
COMMENT 'HoneyMind logs collected using the dd-honeypot-compatible marker and Fluent Bit'
PARTITIONED BY (
  `day` string,
  `hour` tinyint)
ROW FORMAT SERDE
  'org.openx.data.jsonserde.JsonSerDe'
WITH SERDEPROPERTIES (
  'ignore.malformed.json'='true')
LOCATION
  's3://your-bucket-name/logs'
```

Example Athena query:

```sql
ALTER TABLE dd_honeypot ADD
PARTITION (day='2025-11-01', hour=10);

SELECT *
  FROM dd_honeypot
 WHERE day='2025-11-01'
       AND hour=10
 LIMIT 10;
```

Legacy example query for MySQL-shaped activity:

The following query is kept for inherited dd-honeypot/Athena compatibility. MySQL is not currently the supported HoneyMind deployment path.

```sql
SELECT MIN(time) AS time,
       ARRAY_AGG(query) AS queries
FROM dd_honeypot
WHERE type = 'mysql'
      AND query IS NOT NULL
      AND DATE(day) BETWEEN DATE_ADD('day', -30, CURRENT_DATE) AND DATE_ADD('day', -1, CURRENT_DATE)
GROUP BY session_id
ORDER BY time
```

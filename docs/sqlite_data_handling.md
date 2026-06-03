# Legacy SQLite Data Handling Notes

HoneyMind is based on [ThalesGroup dd-honeypot](https://github.com/ThalesGroup/dd-honeypot) and preserves the original attribution and license.

This page is kept for inherited dd-honeypot-style SQLite datasets. It references the legacy MySQL data store path and is not the primary HoneyMind analysis database.

Current HoneyMind dashboard data is derived from local JSONL logs into:

```text
/data/honeypot/logs/iocs.db
```

Use the web dashboard, `ioc-api`, or `scripts/read_local_logs.py` for normal analysis. Use the notes below only when working on old dataset stores or legacy protocol experiments.

## 1. Exec into the container

``` bash
  docker exec -it honeymind sh
```

## 2. Install SQLite if Needed

```bash
  apk add --no-cache sqlite
```

## 3. Open a Legacy SQLite Database

```bash
  sqlite3 /data/honeypot/mysql/data_store.db
```

## 4. Delete a Specific Record

```bash
  DELETE FROM honeypot_data WHERE command = 'whoami';
```

```bash
  COMMIT;
```

## 5. Verify Deletion

```bash
  SELECT * FROM honeypot_data WHERE command = 'whoami';
```

## 6. Export Stored Data to JSON

```bash
  sqlite3 /data/honeypot/mysql/data_store.db \
  -cmd ".mode json" \
  "SELECT * FROM honeypot_data;" > export.json
```

Inspect:

```bash
  docker cp honeymind:/export.json ./honeypot_dump.json
```

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

_DB_LOCK = threading.RLock()
_PROVIDER_ALIASES = {
    "openai_compatible": ["ovhcloud"],
}


def _connect(db_path: str) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    return conn


def ensure_llm_usage_schema(
    db_path: str, model_prices: Optional[Iterable[dict[str, Any]]] = None
) -> None:
    with _DB_LOCK:
        with _connect(db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_model_prices (
                    provider TEXT,
                    model_id TEXT NOT NULL,
                    prompt_price_per_mtok REAL,
                    completion_price_per_mtok REAL,
                    prompt_usd_per_mtok REAL,
                    completion_usd_per_mtok REAL,
                    currency TEXT NOT NULL DEFAULT 'USD',
                    source TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (provider, model_id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS llm_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    prompt_tokens INTEGER,
                    completion_tokens INTEGER,
                    total_tokens INTEGER,
                    prompt_cost REAL,
                    completion_cost REAL,
                    total_cost REAL,
                    prompt_cost_usd REAL,
                    completion_cost_usd REAL,
                    total_cost_usd REAL,
                    currency TEXT,
                    price_source TEXT,
                    response_chars INTEGER,
                    user_prompt_chars INTEGER,
                    system_prompt_chars INTEGER,
                    usage_json TEXT
                )
                """
            )
            _migrate_llm_usage_schema(conn)
            if model_prices:
                upsert_model_prices(conn, model_prices)


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}


def _add_column_if_missing(
    conn: sqlite3.Connection, table: str, columns: set[str], definition: str
) -> None:
    name = definition.split()[0]
    if name not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")
        columns.add(name)


def _migrate_llm_usage_schema(conn: sqlite3.Connection) -> None:
    price_columns = _table_columns(conn, "llm_model_prices")
    _add_column_if_missing(
        conn, "llm_model_prices", price_columns, "prompt_price_per_mtok REAL"
    )
    _add_column_if_missing(
        conn, "llm_model_prices", price_columns, "completion_price_per_mtok REAL"
    )
    if "prompt_usd_per_mtok" in price_columns:
        conn.execute(
            """
            UPDATE llm_model_prices
            SET prompt_price_per_mtok = COALESCE(prompt_price_per_mtok, prompt_usd_per_mtok),
                completion_price_per_mtok = COALESCE(completion_price_per_mtok, completion_usd_per_mtok)
            """
        )

    usage_columns = _table_columns(conn, "llm_usage")
    _add_column_if_missing(conn, "llm_usage", usage_columns, "prompt_cost REAL")
    _add_column_if_missing(conn, "llm_usage", usage_columns, "completion_cost REAL")
    _add_column_if_missing(conn, "llm_usage", usage_columns, "total_cost REAL")
    if "prompt_cost_usd" in usage_columns:
        conn.execute(
            """
            UPDATE llm_usage
            SET prompt_cost = COALESCE(prompt_cost, prompt_cost_usd),
                completion_cost = COALESCE(completion_cost, completion_cost_usd),
                total_cost = COALESCE(total_cost, total_cost_usd)
            """
        )
    conn.commit()


def upsert_model_prices(
    db: str | sqlite3.Connection, model_prices: Iterable[dict[str, Any]]
) -> None:
    close_conn = False
    if isinstance(db, str):
        conn = _connect(db)
        close_conn = True
    else:
        conn = db
    try:
        now = datetime.utcnow().isoformat()
        rows = []
        for row in model_prices:
            if not row:
                continue
            rows.append(
                (
                    row.get("provider"),
                    row["model_id"],
                    row.get("prompt_price_per_mtok", row.get("prompt_usd_per_mtok")),
                    row.get(
                        "completion_price_per_mtok",
                        row.get("completion_usd_per_mtok"),
                    ),
                    row.get("prompt_usd_per_mtok"),
                    row.get("completion_usd_per_mtok"),
                    row.get("currency", "USD"),
                    row.get("source"),
                    row.get("updated_at", now),
                )
            )
        if rows:
            conn.executemany(
                """
                INSERT INTO llm_model_prices (
                    provider, model_id, prompt_price_per_mtok,
                    completion_price_per_mtok, prompt_usd_per_mtok,
                    completion_usd_per_mtok, currency, source, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, model_id) DO UPDATE SET
                    prompt_price_per_mtok=excluded.prompt_price_per_mtok,
                    completion_price_per_mtok=excluded.completion_price_per_mtok,
                    prompt_usd_per_mtok=excluded.prompt_usd_per_mtok,
                    completion_usd_per_mtok=excluded.completion_usd_per_mtok,
                    currency=excluded.currency,
                    source=excluded.source,
                    updated_at=excluded.updated_at
                """,
                rows,
            )
            conn.commit()
    finally:
        if close_conn:
            conn.close()


def get_model_price(
    db_path: str, provider: str, model_id: str
) -> Optional[sqlite3.Row]:
    provider_candidates = [provider] + _PROVIDER_ALIASES.get(provider, [])
    placeholders = ",".join("?" for _ in provider_candidates)
    with _DB_LOCK:
        with _connect(db_path) as conn:
            row = conn.execute(
                f"""
                SELECT provider, model_id, prompt_price_per_mtok,
                       completion_price_per_mtok, currency, source, updated_at
                FROM llm_model_prices
                WHERE model_id = ? AND (provider IS NULL OR provider IN ({placeholders}))
                ORDER BY provider = ? DESC, provider IS NOT NULL DESC
                LIMIT 1
                """,
                (model_id, *provider_candidates, provider),
            ).fetchone()
            return row


def _extract_usage(provider: str, response_json: dict[str, Any]) -> dict[str, Any]:
    usage = response_json.get("usage") or {}

    prompt_tokens = usage.get("prompt_tokens")
    completion_tokens = usage.get("completion_tokens")
    total_tokens = usage.get("total_tokens")

    if prompt_tokens is None:
        prompt_tokens = usage.get("input_tokens")
    if completion_tokens is None:
        completion_tokens = usage.get("output_tokens")
    if total_tokens is None:
        total_tokens = usage.get("total_tokens")

    if provider == "ollama":
        prompt_tokens = response_json.get("prompt_eval_count", prompt_tokens)
        completion_tokens = response_json.get("eval_count", completion_tokens)
        if total_tokens is None and prompt_tokens is not None and completion_tokens is not None:
            total_tokens = prompt_tokens + completion_tokens

    if total_tokens is None and prompt_tokens is not None and completion_tokens is not None:
        total_tokens = prompt_tokens + completion_tokens

    return {
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "usage_json": usage or None,
    }


def _calculate_cost(
    prompt_tokens: Optional[int],
    completion_tokens: Optional[int],
    price_row: Optional[sqlite3.Row],
) -> tuple[Optional[float], Optional[float], Optional[float], Optional[str], Optional[str]]:
    if not price_row:
        return None, None, None, None, None

    prompt_rate = price_row["prompt_price_per_mtok"]
    completion_rate = price_row["completion_price_per_mtok"]
    if prompt_tokens is None and completion_tokens is None:
        return None, None, None, price_row["currency"], price_row["source"]

    prompt_cost = (
        (prompt_tokens or 0) / 1_000_000.0 * prompt_rate
        if prompt_rate is not None and prompt_tokens is not None
        else None
    )
    completion_cost = (
        (completion_tokens or 0) / 1_000_000.0 * completion_rate
        if completion_rate is not None and completion_tokens is not None
        else None
    )
    if prompt_cost is None and completion_cost is None:
        total_cost = None
    else:
        total_cost = (prompt_cost or 0.0) + (completion_cost or 0.0)
    return prompt_cost, completion_cost, total_cost, price_row["currency"], price_row["source"]


def record_llm_usage(
    db_path: Optional[str],
    *,
    provider: str,
    model_id: str,
    response_json: Optional[dict[str, Any]] = None,
    model_prices: Optional[Iterable[dict[str, Any]]] = None,
    response_chars: Optional[int] = None,
    user_prompt_chars: Optional[int] = None,
    system_prompt_chars: Optional[int] = None,
) -> None:
    if not db_path:
        return

    with _DB_LOCK:
        ensure_llm_usage_schema(db_path, model_prices=model_prices)
        usage = _extract_usage(provider, response_json or {}) if response_json else {
            "prompt_tokens": None,
            "completion_tokens": None,
            "total_tokens": None,
            "usage_json": None,
        }
        with _connect(db_path) as conn:
            price_row = get_model_price(db_path, provider, model_id)
            prompt_cost, completion_cost, total_cost, currency, source = _calculate_cost(
                usage["prompt_tokens"], usage["completion_tokens"], price_row
            )
            conn.execute(
                """
                INSERT INTO llm_usage (
                    created_at, provider, model_id, prompt_tokens, completion_tokens,
                    total_tokens, prompt_cost, completion_cost, total_cost,
                    currency, price_source, response_chars, user_prompt_chars,
                    system_prompt_chars, usage_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    datetime.utcnow().isoformat(),
                    provider,
                    model_id,
                    usage["prompt_tokens"],
                    usage["completion_tokens"],
                    usage["total_tokens"],
                    prompt_cost,
                    completion_cost,
                    total_cost,
                    currency,
                    source,
                    response_chars,
                    user_prompt_chars,
                    system_prompt_chars,
                    json.dumps(usage["usage_json"], ensure_ascii=False) if usage["usage_json"] is not None else None,
                ),
            )
            conn.commit()


def get_usage_summary(db_path: str) -> list[dict[str, Any]]:
    with _DB_LOCK:
        with _connect(db_path) as conn:
            rows = conn.execute(
                """
                SELECT
                    provider,
                    model_id,
                    COUNT(*) AS calls,
                    SUM(COALESCE(prompt_tokens, 0)) AS prompt_tokens,
                    SUM(COALESCE(completion_tokens, 0)) AS completion_tokens,
                    SUM(COALESCE(total_tokens, 0)) AS total_tokens,
                    SUM(COALESCE(total_cost, 0)) AS total_cost,
                    MAX(currency) AS currency,
                    MAX(price_source) AS price_source
                FROM llm_usage
                GROUP BY provider, model_id
                ORDER BY total_cost DESC, total_tokens DESC, model_id ASC
                """
            ).fetchall()
            return [dict(row) for row in rows]


def get_daily_usage_summary(db_path: str) -> list[dict[str, Any]]:
    with _DB_LOCK:
        with _connect(db_path) as conn:
            rows = conn.execute(
                """
                SELECT
                    date(created_at) AS day,
                    provider,
                    model_id,
                    COUNT(*) AS calls,
                    SUM(COALESCE(prompt_tokens, 0)) AS prompt_tokens,
                    SUM(COALESCE(completion_tokens, 0)) AS completion_tokens,
                    SUM(COALESCE(total_tokens, 0)) AS total_tokens,
                    SUM(COALESCE(total_cost, 0)) AS total_cost,
                    MAX(currency) AS currency,
                    MAX(price_source) AS price_source
                FROM llm_usage
                GROUP BY day, provider, model_id
                ORDER BY day DESC, total_cost DESC, total_tokens DESC
                """
            ).fetchall()
            return [dict(row) for row in rows]


def iter_usage_rows(db_path: str) -> list[dict[str, Any]]:
    with _DB_LOCK:
        with _connect(db_path) as conn:
            rows = conn.execute(
                """
                SELECT
                    created_at, provider, model_id, prompt_tokens, completion_tokens,
                    total_tokens, prompt_cost, completion_cost, total_cost,
                    currency, price_source, response_chars, user_prompt_chars,
                    system_prompt_chars
                FROM llm_usage
                ORDER BY created_at DESC, id DESC
                """
            ).fetchall()
            return [dict(row) for row in rows]

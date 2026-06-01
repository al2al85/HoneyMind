import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

_DB_LOCK = threading.RLock()


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
            if model_prices:
                upsert_model_prices(conn, model_prices)


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
                    provider, model_id, prompt_usd_per_mtok, completion_usd_per_mtok,
                    currency, source, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, model_id) DO UPDATE SET
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
    with _DB_LOCK:
        with _connect(db_path) as conn:
            row = conn.execute(
                """
                SELECT provider, model_id, prompt_usd_per_mtok, completion_usd_per_mtok,
                       currency, source, updated_at
                FROM llm_model_prices
                WHERE model_id = ? AND (provider IS NULL OR provider = ?)
                ORDER BY provider IS NOT NULL DESC, provider = ? DESC
                LIMIT 1
                """,
                (model_id, provider, provider),
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

    prompt_rate = price_row["prompt_usd_per_mtok"]
    completion_rate = price_row["completion_usd_per_mtok"]
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
                    total_tokens, prompt_cost_usd, completion_cost_usd, total_cost_usd,
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
                    SUM(COALESCE(total_cost_usd, 0)) AS total_cost_usd,
                    MAX(currency) AS currency,
                    MAX(price_source) AS price_source
                FROM llm_usage
                GROUP BY provider, model_id
                ORDER BY total_cost_usd DESC, total_tokens DESC, model_id ASC
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
                    SUM(COALESCE(total_cost_usd, 0)) AS total_cost_usd,
                    MAX(currency) AS currency,
                    MAX(price_source) AS price_source
                FROM llm_usage
                GROUP BY day, provider, model_id
                ORDER BY day DESC, total_cost_usd DESC, total_tokens DESC
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
                    total_tokens, prompt_cost_usd, completion_cost_usd, total_cost_usd,
                    currency, price_source, response_chars, user_prompt_chars,
                    system_prompt_chars
                FROM llm_usage
                ORDER BY created_at DESC, id DESC
                """
            ).fetchall()
            return [dict(row) for row in rows]

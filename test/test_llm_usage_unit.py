from pathlib import Path
from io import StringIO
from contextlib import redirect_stdout
import runpy
import sys

import pytest

import llm_utils
from llm_usage import record_llm_usage, get_usage_summary, get_daily_usage_summary


def _read_single_row(db_path: Path, table: str = "llm_usage"):
    import sqlite3

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        return conn.execute(f"SELECT * FROM {table}").fetchone()


def test_record_llm_usage_persists_tokens_and_cost(tmp_path):
    db_path = tmp_path / "llm_usage.db"
    prices = [
        {
            "provider": "openai",
            "model_id": "gpt-4o-mini",
            "prompt_usd_per_mtok": 2.0,
            "completion_usd_per_mtok": 4.0,
            "currency": "USD",
            "source": "unit-test",
        }
    ]

    record_llm_usage(
        str(db_path),
        provider="openai",
        model_id="gpt-4o-mini",
        response_json={
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 20,
                "total_tokens": 30,
            }
        },
        model_prices=prices,
        response_chars=123,
        user_prompt_chars=45,
        system_prompt_chars=67,
    )

    row = _read_single_row(db_path)
    assert row["provider"] == "openai"
    assert row["model_id"] == "gpt-4o-mini"
    assert row["prompt_tokens"] == 10
    assert row["completion_tokens"] == 20
    assert row["total_tokens"] == 30
    assert row["response_chars"] == 123
    assert row["user_prompt_chars"] == 45
    assert row["system_prompt_chars"] == 67
    assert row["total_cost_usd"] == pytest.approx((10 * 2.0 + 20 * 4.0) / 1_000_000)


def test_invoke_llm_records_usage(tmp_path, monkeypatch):
    calls = {}

    def fake_resolve_provider(llm_provider, llm_base_url, model_id):
        return "openai", "https://example.com/v1"

    def fake_resolve_api_key(provider, llm_api_key, llm_api_key_env):
        return "test-token"

    def fake_invoke_openai_chat(*args, **kwargs):
        return "hello world", {
            "usage": {
                "prompt_tokens": 12,
                "completion_tokens": 34,
                "total_tokens": 46,
            }
        }

    def fake_record_llm_usage(db_path, **kwargs):
        calls["db_path"] = db_path
        calls.update(kwargs)

    monkeypatch.setattr(llm_utils, "_resolve_provider", fake_resolve_provider)
    monkeypatch.setattr(llm_utils, "_resolve_api_key", fake_resolve_api_key)
    monkeypatch.setattr(llm_utils, "_invoke_openai_chat", fake_invoke_openai_chat)
    monkeypatch.setattr(llm_utils, "record_llm_usage", fake_record_llm_usage)

    result = llm_utils.invoke_llm(
        system_prompt="system",
        user_prompt="prompt",
        model_id="gpt-4o-mini",
        llm_provider="openai",
        llm_usage_db_path=str(tmp_path / "llm_usage.db"),
    )

    assert result == "hello world"
    assert calls["db_path"] == str(tmp_path / "llm_usage.db")
    assert calls["provider"] == "openai"
    assert calls["model_id"] == "gpt-4o-mini"
    assert calls["response_chars"] == len("hello world")
    assert calls["user_prompt_chars"] == len("prompt")
    assert calls["system_prompt_chars"] == len("system")
    assert calls["response_json"]["usage"]["total_tokens"] == 46


def test_usage_summaries_and_cli(tmp_path, monkeypatch):
    db_path = tmp_path / "llm_usage.db"
    prices = [
        {
            "provider": "openai",
            "model_id": "gpt-4o-mini",
            "prompt_usd_per_mtok": 2.0,
            "completion_usd_per_mtok": 4.0,
            "currency": "USD",
            "source": "unit-test",
        }
    ]
    record_llm_usage(
        str(db_path),
        provider="openai",
        model_id="gpt-4o-mini",
        response_json={"usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}},
        model_prices=prices,
    )
    record_llm_usage(
        str(db_path),
        provider="openai",
        model_id="gpt-4o-mini",
        response_json={"usage": {"prompt_tokens": 5, "completion_tokens": 7, "total_tokens": 12}},
    )

    summary = get_usage_summary(str(db_path))
    assert summary == [
        {
            "provider": "openai",
            "model_id": "gpt-4o-mini",
            "calls": 2,
            "prompt_tokens": 15,
            "completion_tokens": 27,
            "total_tokens": 42,
            "total_cost_usd": pytest.approx((10 * 2.0 + 20 * 4.0 + 5 * 2.0 + 7 * 4.0) / 1_000_000),
            "currency": "USD",
            "price_source": "unit-test",
        }
    ]
    daily = get_daily_usage_summary(str(db_path))
    assert daily[0]["calls"] == 2

    argv = ["llm_usage_report.py", str(db_path), "--json"]
    monkeypatch.setattr(sys, "argv", argv)
    out = StringIO()
    with redirect_stdout(out):
        try:
            runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts" / "llm_usage_report.py"), run_name="__main__")
        except SystemExit as e:
            assert e.code == 0, f"CLI exited with non-zero code: {e.code}"
    rendered = out.getvalue()
    assert "gpt-4o-mini" in rendered

import json
import os
import tempfile

import pytest
from unittest.mock import patch

from infra.data_handler import DataHandler


@pytest.fixture
def data_handler():
    with tempfile.TemporaryDirectory() as temp_dir:
        handler = DataHandler(
            os.path.join(temp_dir, "data.jsonl"), "fake system prompt", "fake_model"
        )
        yield handler


@patch("infra.data_handler.invoke_llm", return_value="Mocked LLM response")
def test_llm_response_when_not_cached(mock_llm, data_handler):
    user_input = "whoami"
    response = data_handler.query(user_input, session=data_handler.connect({}))
    assert response["output"] == "Mocked LLM response"
    assert mock_llm.called


@patch("infra.data_handler.invoke_llm", return_value="Mocked Response")
def test_returns_cached_response_first(mock_llm):
    data_file = os.path.join("/tmp", "ssh.jsonl")

    # Preload data manually
    with open(data_file, "w") as f:
        f.write(json.dumps({"command": "ls", "response": "file1.txt\n"}) + "\n")

    handler = DataHandler(data_file, "system", "model")
    response = handler.query("ls", session=handler.connect({}))

    assert response["output"] == "file1.txt\n"
    mock_llm.assert_not_called()


@patch("infra.data_handler.invoke_llm", return_value="Cached LLM response")
def test_memory_cache_is_used(mock_llm, data_handler):
    cmd = "uptime"

    # First call - triggers LLM
    response1 = data_handler.query(cmd, session=data_handler.connect({}))
    assert response1["output"] == "Cached LLM response"
    assert mock_llm.call_count == 1

    # Second call - uses memory cache
    response2 = data_handler.query(cmd, session=data_handler.connect({}))
    assert response2["output"] == "Cached LLM response"
    assert mock_llm.call_count == 1  # Should not call again


@patch("infra.data_handler.invoke_llm", return_value="Mocked LLM response for MySQL")
def test_mysql_llm_response_when_not_cached(mock_llm, data_handler):
    query = "SELECT * FROM users"
    response = data_handler.query(query, session=data_handler.connect({}))

    assert response["output"] == "Mocked LLM response for MySQL"
    assert mock_llm.called


@patch("infra.data_handler.invoke_llm", return_value="ShouldNotBeCalled")
def test_mysql_returns_file_cache(mock_llm):
    data_file = os.path.join("/tmp", "mysql.jsonl")

    with open(data_file, "w") as f:
        f.write(
            json.dumps({"command": "SHOW TABLES", "response": "users\norders\n"}) + "\n"
        )

    handler = DataHandler(data_file, "mysql sys", "mysql_model")
    response = handler.query("SHOW TABLES", session=handler.connect({}))

    assert response["output"] == "users\norders\n"
    mock_llm.assert_not_called()


@patch("infra.data_handler.invoke_llm", return_value="Mocked LLM response for HTTP")
def test_http_llm_response_when_not_cached(mock_llm, data_handler):

    http_request = "GET /admin?user=root"
    response = data_handler.query(http_request, session=data_handler.connect({}))

    assert response["output"] == "Mocked LLM response for HTTP"
    assert mock_llm.called


@patch("infra.data_handler.invoke_llm", return_value="ShouldNotBeCalled")
def test_http_returns_file_cache(mock_llm):
    data_file = os.path.join("/tmp", "http.jsonl")

    with open(data_file, "w") as f:
        f.write(
            json.dumps({"command": "GET /status", "response": '{"status":"ok"}'}) + "\n"
        )

    handler = DataHandler(data_file, "http sys", "http_model")
    response = handler.query("GET /status", session=handler.connect({}))

    assert response["output"] == '{"status":"ok"}'
    mock_llm.assert_not_called()


@patch("infra.data_handler.invoke_llm", return_value="Provider response")
def test_llm_provider_config_is_passed_to_invoke_llm(mock_llm):
    with tempfile.TemporaryDirectory() as temp_dir:
        handler = DataHandler(
            os.path.join(temp_dir, "data.jsonl"),
            "system",
            "model",
            llm_provider="openai_compatible",
            llm_base_url="http://localhost:11434/v1",
            llm_api_key_env="OPENAI_API_KEY",
            llm_allow_no_api_key=True,
            llm_timeout=12,
            llm_temperature=0.1,
            llm_max_tokens=321,
        )

        response = handler.query("unknown", session=handler.connect({}))

    assert response["output"] == "Provider response"
    mock_llm.assert_called_once_with(
        "system",
        "User input: {'command': 'unknown'}",
        "model",
        llm_provider="openai_compatible",
        llm_base_url="http://localhost:11434/v1",
        llm_api_key_env="OPENAI_API_KEY",
        llm_allow_no_api_key=True,
        llm_timeout=12,
        llm_temperature=0.1,
        llm_max_tokens=321,
    )


@patch("infra.data_handler.invoke_llm", return_value="normalized cached response")
def test_equivalent_commands_share_cached_llm_response(mock_llm):
    with tempfile.TemporaryDirectory() as temp_dir:
        handler = DataHandler(os.path.join(temp_dir, "data.jsonl"), "system", "model")
        session = handler.connect({})

        response1 = handler.query("ls Doc", session=session)
        response2 = handler.query("ls                 Doc", session=session)
        response3 = handler.query("ls\tDoc", session=session)

    assert response1["output"] == "normalized cached response"
    assert response2["output"] == "normalized cached response"
    assert response3["output"] == "normalized cached response"
    assert mock_llm.call_count == 1


@patch("infra.data_handler.invoke_llm", return_value="raw prompt response")
def test_llm_prompt_uses_raw_input_after_normalized_miss(mock_llm):
    with tempfile.TemporaryDirectory() as temp_dir:
        handler = DataHandler(os.path.join(temp_dir, "data.jsonl"), "system", "model")

        handler.query("ls                 Doc", session=handler.connect({}))

    mock_llm.assert_called_once_with(
        "system",
        "User input: {'command': 'ls                 Doc'}",
        "model",
    )


@patch("infra.data_handler.invoke_llm", return_value="ShouldNotBeCalled")
def test_raw_dataset_entry_falls_back_and_aliases_normalized_key(mock_llm):
    with tempfile.TemporaryDirectory() as temp_dir:
        data_file = os.path.join(temp_dir, "data.jsonl")
        with open(data_file, "w") as f:
            f.write(
                json.dumps(
                    {"command": "ls                 Doc", "response": "Documents\n"}
                )
                + "\n"
            )

        handler = DataHandler(data_file, "system", "model")
        session = handler.connect({})

        response1 = handler.query("ls                 Doc", session=session)
        response2 = handler.query("ls Doc", session=session)

    assert response1["output"] == "Documents\n"
    assert response2["output"] == "Documents\n"
    mock_llm.assert_not_called()


@patch("infra.data_handler.invoke_llm", return_value="separate response")
def test_input_normalization_can_be_disabled(mock_llm):
    with tempfile.TemporaryDirectory() as temp_dir:
        handler = DataHandler(
            os.path.join(temp_dir, "data.jsonl"),
            "system",
            "model",
            input_normalization_enabled=False,
        )
        session = handler.connect({})

        handler.query("ls Doc", session=session)
        handler.query("ls                 Doc", session=session)

    assert mock_llm.call_count == 2

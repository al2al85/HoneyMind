import json
import sys
import types
from unittest.mock import Mock, patch

import pytest

from llm_utils import invoke_llm


class FakeResponse:
    def __init__(self, payload, status_code=200):
        self.payload = payload
        self.status_code = status_code

    def json(self):
        return self.payload


class FakeBody:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode()

    def read(self):
        return self.payload


def test_bedrock_provider_calls_boto3_client():
    client = Mock()
    client.invoke_model.return_value = {
        "body": FakeBody({"content": [{"text": "bedrock response"}]})
    }
    fake_boto3 = types.SimpleNamespace(client=Mock(return_value=client))

    with patch.dict(sys.modules, {"boto3": fake_boto3}):
        result = invoke_llm(
            "system",
            "user",
            "anthropic.claude-3-haiku-20240307-v1:0",
            llm_provider="bedrock",
        )

    assert result == "bedrock response"
    fake_boto3.client.assert_called_once()
    assert fake_boto3.client.call_args.kwargs["service_name"] == "bedrock-runtime"
    client.invoke_model.assert_called_once()
    assert (
        client.invoke_model.call_args.kwargs["modelId"]
        == "anthropic.claude-3-haiku-20240307-v1:0"
    )


def test_existing_invoke_llm_call_defaults_to_bedrock():
    client = Mock()
    client.invoke_model.return_value = {
        "body": FakeBody({"content": [{"text": "default bedrock"}]})
    }
    fake_boto3 = types.SimpleNamespace(client=Mock(return_value=client))

    with patch.dict(sys.modules, {"boto3": fake_boto3}):
        result = invoke_llm(
            "system", "user", "anthropic.claude-3-haiku-20240307-v1:0"
        )

    assert result == "default bedrock"
    client.invoke_model.assert_called_once()


def test_openai_provider_formats_request_and_parses_response(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-openai-key")
    response = FakeResponse({"choices": [{"message": {"content": "openai text"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        result = invoke_llm(
            "system",
            "user",
            "gpt-test",
            llm_provider="openai",
            llm_temperature=0.2,
            llm_max_tokens=123,
        )

    assert result == "openai text"
    assert mock_post.call_args.args[0] == "https://api.openai.com/v1/chat/completions"
    assert (
        mock_post.call_args.kwargs["headers"]["Authorization"]
        == "Bearer env-openai-key"
    )
    assert mock_post.call_args.kwargs["json"]["model"] == "gpt-test"


def test_openai_provider_sends_bearer_token_from_direct_config():
    response = FakeResponse({"choices": [{"message": {"content": "openai text"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        invoke_llm(
            "system",
            "user",
            "gpt-test",
            llm_provider="openai",
            llm_api_key="direct-openai-token",
        )

    assert (
        mock_post.call_args.kwargs["headers"]["Authorization"]
        == "Bearer direct-openai-token"
    )


def test_non_bedrock_provider_does_not_import_boto3(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-openai-key")
    response = FakeResponse({"choices": [{"message": {"content": "ok"}}]})

    with patch.dict(sys.modules, {"boto3": None}):
        with patch("llm_utils.requests.post", return_value=response):
            result = invoke_llm("system", "user", "gpt-test", llm_provider="openai")

    assert result == "ok"


def test_openai_compatible_formats_request_and_parses_response():
    response = FakeResponse({"choices": [{"message": {"content": "openai text"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        result = invoke_llm(
            "system",
            "user",
            "gpt-test",
            llm_provider="openai_compatible",
            llm_base_url="https://api.example.com/v1",
            llm_api_key="direct-key",
            llm_temperature=0.2,
            llm_max_tokens=123,
            llm_timeout=9,
        )

    assert result == "openai text"
    assert mock_post.call_args.args[0] == "https://api.example.com/v1/chat/completions"
    assert mock_post.call_args.kwargs["headers"]["Authorization"] == "Bearer direct-key"
    assert mock_post.call_args.kwargs["timeout"] == 9
    assert mock_post.call_args.kwargs["json"] == {
        "model": "gpt-test",
        "messages": [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "user"},
        ],
        "temperature": 0.2,
        "max_tokens": 123,
    }


def test_openai_compatible_normalizes_raw_bearer_token():
    response = FakeResponse({"choices": [{"message": {"content": "ok"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        invoke_llm(
            "system",
            "user",
            "gpt-test",
            llm_provider="openai_compatible",
            llm_base_url="https://api.example.com/v1",
            llm_api_key="sk-raw-token",
        )

    assert (
        mock_post.call_args.kwargs["headers"]["Authorization"]
        == "Bearer sk-raw-token"
    )


def test_openai_compatible_does_not_duplicate_bearer_prefix():
    response = FakeResponse({"choices": [{"message": {"content": "ok"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        invoke_llm(
            "system",
            "user",
            "gpt-test",
            llm_provider="openai_compatible",
            llm_base_url="https://api.example.com/v1",
            llm_api_key="Bearer sk-prefixed-token",
        )

    assert (
        mock_post.call_args.kwargs["headers"]["Authorization"]
        == "Bearer sk-prefixed-token"
    )


def test_anthropic_formats_request_and_parses_response():
    response = FakeResponse({"content": [{"text": "anthropic text"}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        result = invoke_llm(
            "system",
            "user",
            "claude-test",
            llm_provider="anthropic",
            llm_api_key="anthropic-key",
            llm_temperature=0.3,
            llm_max_tokens=456,
        )

    assert result == "anthropic text"
    assert mock_post.call_args.args[0] == "https://api.anthropic.com/v1/messages"
    assert mock_post.call_args.kwargs["headers"]["x-api-key"] == "anthropic-key"
    assert mock_post.call_args.kwargs["json"] == {
        "model": "claude-test",
        "messages": [{"role": "user", "content": "user"}],
        "temperature": 0.3,
        "max_tokens": 456,
        "system": "system",
    }


def test_native_ollama_formats_request_and_parses_response():
    response = FakeResponse({"message": {"content": "ollama text"}})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        result = invoke_llm(
            "system",
            "user",
            "llama3.1:8b",
            llm_provider="ollama",
            llm_base_url="http://localhost:11434",
            llm_temperature=0.4,
            llm_max_tokens=789,
        )

    assert result == "ollama text"
    assert mock_post.call_args.args[0] == "http://localhost:11434/api/chat"
    assert "Authorization" not in mock_post.call_args.kwargs["headers"]
    assert mock_post.call_args.kwargs["json"] == {
        "model": "llama3.1:8b",
        "messages": [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "user"},
        ],
        "stream": False,
        "options": {"temperature": 0.4, "num_predict": 789},
    }


def test_api_key_env_var_takes_priority_over_direct_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "env-key")
    response = FakeResponse({"choices": [{"message": {"content": "ok"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        invoke_llm(
            "system",
            "user",
            "gpt-test",
            llm_provider="openai_compatible",
            llm_base_url="https://api.example.com/v1",
            llm_api_key="direct-key",
            llm_api_key_env="OPENAI_API_KEY",
        )

    assert mock_post.call_args.kwargs["headers"]["Authorization"] == "Bearer env-key"


def test_empty_api_key_env_var_does_not_override_direct_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "")
    response = FakeResponse({"choices": [{"message": {"content": "ok"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        invoke_llm(
            "system",
            "user",
            "gpt-test",
            llm_provider="openai_compatible",
            llm_base_url="https://api.example.com/v1",
            llm_api_key="direct-key",
            llm_api_key_env="OPENAI_API_KEY",
        )

    assert mock_post.call_args.kwargs["headers"]["Authorization"] == "Bearer direct-key"


def test_openai_compatible_localhost_does_not_require_api_key():
    response = FakeResponse({"choices": [{"message": {"content": "local ok"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        result = invoke_llm(
            "system",
            "user",
            "llama3.1:8b",
            llm_provider="openai_compatible",
            llm_base_url="http://localhost:11434/v1",
        )

    assert result == "local ok"
    assert "Authorization" not in mock_post.call_args.kwargs["headers"]


def test_openai_compatible_host_docker_internal_does_not_require_api_key():
    response = FakeResponse({"choices": [{"message": {"content": "docker ok"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        result = invoke_llm(
            "system",
            "user",
            "llama3.1:8b",
            llm_provider="openai_compatible",
            llm_base_url="http://host.docker.internal:11434/v1",
        )

    assert result == "docker ok"
    assert "Authorization" not in mock_post.call_args.kwargs["headers"]


def test_openai_compatible_private_lan_does_not_require_api_key():
    response = FakeResponse({"choices": [{"message": {"content": "lan ok"}}]})

    with patch("llm_utils.requests.post", return_value=response) as mock_post:
        result = invoke_llm(
            "system",
            "user",
            "self-hosted-model",
            llm_provider="openai_compatible",
            llm_base_url="http://192.168.1.20:8000/v1",
        )

    assert result == "lan ok"
    assert "Authorization" not in mock_post.call_args.kwargs["headers"]


def test_openai_compatible_remote_without_api_key_raises():
    with pytest.raises(RuntimeError, match="requires llm_api_key"):
        invoke_llm(
            "system",
            "user",
            "remote-model",
            llm_provider="openai_compatible",
            llm_base_url="https://llm.example.com/v1",
        )


def test_token_is_not_in_errors_or_logs(caplog):
    secret = "super-secret-token"

    with patch(
        "llm_utils.requests.post",
        return_value=FakeResponse({"error": "unauthorized"}, status_code=401),
    ):
        with pytest.raises(RuntimeError) as exc_info:
            invoke_llm(
                "system",
                "user",
                "remote-model",
                llm_provider="openai_compatible",
                llm_base_url="https://llm.example.com/v1",
                llm_api_key=secret,
            )

    assert secret not in str(exc_info.value)
    assert secret not in caplog.text
    assert "Authorization" not in caplog.text


def test_unknown_provider_raises_value_error():
    with pytest.raises(ValueError, match="Supported providers"):
        invoke_llm("system", "user", "model", llm_provider="unknown")


def test_missing_provider_configuration_raises_clear_error(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="No usable LLM provider"):
        invoke_llm("system", "user", "llama3.1:8b")

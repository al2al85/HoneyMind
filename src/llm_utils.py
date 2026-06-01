import json
import logging
import os
import ipaddress
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse

import requests

SUPPORTED_LLM_PROVIDERS = (
    "bedrock",
    "openai",
    "openai_compatible",
    "anthropic",
    "ollama",
)
DEFAULT_LLM_TIMEOUT = 300
DEFAULT_LLM_TEMPERATURE = 0.0
DEFAULT_LLM_MAX_TOKENS = 2000
DEFAULT_OPENAI_BASE_URL = "https://api.openai.com/v1"
DEFAULT_ANTHROPIC_BASE_URL = "https://api.anthropic.com"
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"


def get_model_ids() -> List[str]:
    return [
        "anthropic.claude-3-haiku-20240307-v1:0",
        "us.anthropic.claude-3-5-haiku-20241022-v1:0",
        "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
    ]


def invoke_llm(
    system_prompt: Optional[str],
    user_prompt: str,
    model_id: str,
    llm_provider: Optional[str] = None,
    llm_base_url: Optional[str] = None,
    llm_api_key: Optional[str] = None,
    llm_api_key_env: Optional[str] = None,
    llm_allow_no_api_key: Optional[bool] = None,
    llm_timeout: Optional[int] = None,
    llm_temperature: Optional[float] = None,
    llm_max_tokens: Optional[int] = None,
) -> str:
    provider, base_url = _resolve_provider(llm_provider, llm_base_url, model_id)
    timeout = llm_timeout or DEFAULT_LLM_TIMEOUT
    temperature = (
        DEFAULT_LLM_TEMPERATURE if llm_temperature is None else llm_temperature
    )
    max_tokens = DEFAULT_LLM_MAX_TOKENS if llm_max_tokens is None else llm_max_tokens
    api_key = _resolve_api_key(provider, llm_api_key, llm_api_key_env)

    logging.info(f"Going to invoke LLM. Provider: {provider}. Model ID: {model_id}")
    if provider == "bedrock":
        prompt = _format_bedrock_model_body(
            user_prompt, system_prompt, model_id, temperature, max_tokens
        )
        response_json = _invoke_bedrock_model(prompt, model_id, timeout)
        response_text = _get_bedrock_response_content(response_json, model_id)
    elif provider == "openai":
        response_text = _invoke_openai_chat(
            "openai",
            system_prompt,
            user_prompt,
            model_id,
            base_url or DEFAULT_OPENAI_BASE_URL,
            api_key,
            timeout,
            temperature,
            max_tokens,
            require_api_key=True,
        )
    elif provider == "openai_compatible":
        response_text = _invoke_openai_chat(
            "openai_compatible",
            system_prompt,
            user_prompt,
            model_id,
            base_url or DEFAULT_OPENAI_BASE_URL,
            api_key,
            timeout,
            temperature,
            max_tokens,
            require_api_key=not _allows_no_api_key(
                base_url or DEFAULT_OPENAI_BASE_URL, llm_allow_no_api_key
            ),
        )
    elif provider == "anthropic":
        response_text = _invoke_anthropic(
            system_prompt,
            user_prompt,
            model_id,
            base_url,
            api_key,
            timeout,
            temperature,
            max_tokens,
        )
    elif provider == "ollama":
        response_text = _invoke_ollama(
            system_prompt,
            user_prompt,
            model_id,
            base_url,
            timeout,
            temperature,
            max_tokens,
        )
    else:
        raise ValueError(
            f"Unknown LLM provider: {provider}. Supported providers: "
            f"{', '.join(SUPPORTED_LLM_PROVIDERS)}"
        )
    logging.info(f"Got response from LLM. Response length: {len(response_text)}")
    return response_text


def _normalize_provider(llm_provider: str) -> str:
    provider = llm_provider.strip().lower()
    if provider not in SUPPORTED_LLM_PROVIDERS:
        raise ValueError(
            f"Unknown LLM provider: {provider}. Supported providers: "
            f"{', '.join(SUPPORTED_LLM_PROVIDERS)}"
        )
    return provider


def _resolve_provider(
    llm_provider: Optional[str], llm_base_url: Optional[str], model_id: str
) -> Tuple[str, Optional[str]]:
    base_url = llm_base_url or os.getenv("LLM_BASE_URL") or os.getenv("OPENAI_BASE_URL")
    if llm_provider:
        return _normalize_provider(llm_provider), base_url
    if _looks_like_bedrock_model_id(model_id):
        return "bedrock", base_url
    if base_url:
        return "openai_compatible", base_url
    if os.getenv("OPENAI_API_KEY"):
        return "openai", DEFAULT_OPENAI_BASE_URL
    if os.getenv("ANTHROPIC_API_KEY") and model_id.startswith("claude"):
        return "anthropic", DEFAULT_ANTHROPIC_BASE_URL
    raise RuntimeError(
        "No usable LLM provider is configured. Set llm_provider to one of "
        f"{', '.join(SUPPORTED_LLM_PROVIDERS)}, or configure llm_base_url/LLM_BASE_URL "
        "for a local OpenAI-compatible endpoint such as Ollama, LM Studio, or vLLM."
    )


def _looks_like_bedrock_model_id(model_id: str) -> bool:
    return any(
        marker in model_id
        for marker in (
            "anthropic.claude",
            "us.anthropic.claude",
            "ai21.jamba",
            "jamba",
            "amazon.",
            "meta.",
            "mistral.",
            "cohere.",
        )
    ) and ":" in model_id


def _resolve_api_key(
    provider: str, llm_api_key: Optional[str], llm_api_key_env: Optional[str]
) -> Optional[str]:
    if llm_api_key_env and os.environ.get(llm_api_key_env):
        return os.environ.get(llm_api_key_env)
    if llm_api_key and llm_api_key.strip():
        return llm_api_key
    if provider == "openai":
        return os.getenv("OPENAI_API_KEY")
    if provider == "anthropic":
        return os.getenv("ANTHROPIC_API_KEY")
    return llm_api_key


def _invoke_bedrock_model(
    prompt_body: dict, model_id: str, timeout: int = DEFAULT_LLM_TIMEOUT
) -> dict:
    import boto3
    from botocore.config import Config

    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-east-1"
    bedrock_client = boto3.client(
        service_name="bedrock-runtime",
        region_name=region,
        config=Config(
            read_timeout=timeout,
            retries={"max_attempts": 10, "mode": "adaptive"},
        ),
    )
    response = bedrock_client.invoke_model(
        body=json.dumps(prompt_body),
        modelId=model_id,
    )
    return json.loads(response.get("body").read())


def _format_bedrock_model_body(
    prompt: str,
    system_prompt: Optional[str],
    model_id: str,
    temperature: float = DEFAULT_LLM_TEMPERATURE,
    max_tokens: int = DEFAULT_LLM_MAX_TOKENS,
) -> dict:
    if system_prompt is None:
        system_prompt = "You are a SQL generator helper"
    if "claude" in model_id:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "system": system_prompt,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
    elif "jamba" in model_id:
        body = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            "n": 1,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
    else:
        raise ValueError(f"Unknown model_id: {model_id}")
    return body


def _get_bedrock_response_content(response_json: dict, model_id: str) -> str:
    if "claude" in model_id:
        return response_json["content"][0]["text"]
    elif "jamba" in model_id:
        return response_json["choices"][0]["message"]["content"]
    else:
        raise ValueError(f"Unknown model_id: {model_id}")


def _chat_messages(system_prompt: Optional[str], user_prompt: str) -> List[dict]:
    messages = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_prompt})
    return messages


def _is_local_url(base_url: str) -> bool:
    parsed = urlparse(base_url)
    hostname = (parsed.hostname or "").lower()
    if hostname in {"localhost", "host.docker.internal"} or hostname.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def _allows_no_api_key(base_url: str, llm_allow_no_api_key: Optional[bool]) -> bool:
    if llm_allow_no_api_key is True:
        return True
    return _is_local_url(base_url)


def normalize_bearer_token(api_key: Optional[str]) -> Optional[str]:
    if not api_key:
        return None
    token = api_key.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    return token or None


def build_auth_headers(api_key: Optional[str]) -> dict:
    token = normalize_bearer_token(api_key)
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}


def _invoke_openai_chat(
    provider: str,
    system_prompt: Optional[str],
    user_prompt: str,
    model_id: str,
    base_url: str,
    api_key: Optional[str],
    timeout: int,
    temperature: float,
    max_tokens: int,
    require_api_key: bool,
) -> str:
    if require_api_key and not api_key:
        raise RuntimeError(
            f"{provider} provider requires llm_api_key or llm_api_key_env for "
            "this endpoint. For OpenAI-compatible self-hosted endpoints without "
            "authentication, use a localhost/private LAN base URL or set "
            "llm_allow_no_api_key to true explicitly."
        )

    url = f"{base_url.rstrip('/')}/chat/completions"
    headers = {"content-type": "application/json"}
    headers.update(build_auth_headers(api_key))
    body = {
        "model": model_id,
        "messages": _chat_messages(system_prompt, user_prompt),
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    response_json = _post_json(provider, url, headers, body, timeout)
    try:
        return response_json["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as ex:
        raise RuntimeError(
            f"{provider} provider returned an unexpected response format."
        ) from ex


def _invoke_anthropic(
    system_prompt: Optional[str],
    user_prompt: str,
    model_id: str,
    base_url: Optional[str],
    api_key: Optional[str],
    timeout: int,
    temperature: float,
    max_tokens: int,
) -> str:
    if not api_key:
        raise RuntimeError("anthropic provider requires llm_api_key or llm_api_key_env.")

    base_url = base_url or DEFAULT_ANTHROPIC_BASE_URL
    url = f"{base_url.rstrip('/')}/v1/messages"
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    body = {
        "model": model_id,
        "messages": [{"role": "user", "content": user_prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    if system_prompt:
        body["system"] = system_prompt

    response_json = _post_json("anthropic", url, headers, body, timeout)
    try:
        return response_json["content"][0]["text"]
    except (KeyError, IndexError, TypeError) as ex:
        raise RuntimeError(
            "anthropic provider returned an unexpected response format."
        ) from ex


def _invoke_ollama(
    system_prompt: Optional[str],
    user_prompt: str,
    model_id: str,
    base_url: Optional[str],
    timeout: int,
    temperature: float,
    max_tokens: int,
) -> str:
    base_url = base_url or DEFAULT_OLLAMA_BASE_URL
    url = f"{base_url.rstrip('/')}/api/chat"
    headers = {"content-type": "application/json"}
    body = {
        "model": model_id,
        "messages": _chat_messages(system_prompt, user_prompt),
        "stream": False,
        "options": {
            "temperature": temperature,
            "num_predict": max_tokens,
        },
    }

    response_json = _post_json("ollama", url, headers, body, timeout)
    try:
        return response_json["message"]["content"]
    except (KeyError, TypeError) as ex:
        raise RuntimeError("ollama provider returned an unexpected response format.") from ex


def _post_json(
    provider: str, url: str, headers: dict, body: dict, timeout: int
) -> dict:
    try:
        response = requests.post(url, headers=headers, json=body, timeout=timeout)
    except requests.RequestException as ex:
        raise RuntimeError(f"{provider} provider request failed: {ex}") from ex

    if response.status_code >= 400:
        raise RuntimeError(
            f"{provider} provider request failed with status code "
            f"{response.status_code}."
        )
    try:
        return response.json()
    except ValueError as ex:
        raise RuntimeError(
            f"{provider} provider returned an unexpected non-JSON response."
        ) from ex


class InvokeLimiter:

    def __init__(self, invokes_limit: int, time_period_in_seconds: int):
        """
        Count the number of visits per visitor and limit the number of visits
        :param invokes_limit: number of visits allowed per visitor
        :param time_period_in_seconds: time period in seconds for the limit
        """
        super().__init__()
        self._visitors: Dict[str, int] = {}
        self._visitors_limit_reached_time: Dict[str, datetime] = {}
        self._MAX_VISITOR_LIMIT = invokes_limit
        self._TIME_PERIOD_IN_SECONDS = time_period_in_seconds

    def can_invoke(self, visitor_id: str) -> bool:
        if visitor_id not in self._visitors:
            self._visitors[visitor_id] = 1
        elif self._visitors[visitor_id] == self._MAX_VISITOR_LIMIT:
            if visitor_id not in self._visitors_limit_reached_time:
                self._visitors_limit_reached_time[visitor_id] = datetime.now()
                logging.info(f"Visitors limit reached for visitor {visitor_id}")
                return False
            elif (
                datetime.now() - self._visitors_limit_reached_time[visitor_id]
            ).seconds > self._TIME_PERIOD_IN_SECONDS:
                logging.info(f"Visitors limit reset for visitor {visitor_id}")
                self._visitors[visitor_id] = 1
                del self._visitors_limit_reached_time[visitor_id]
                return True
            return False
        else:
            self._visitors[visitor_id] += 1
        return True

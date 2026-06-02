import re
from typing import Optional


SHELL_OPERATORS = ("2>>", "2>", "&&", "||", ">>", ";", "|", ">", "<", "&")
HTTP_METHODS = {
    "CONNECT",
    "DELETE",
    "GET",
    "HEAD",
    "OPTIONS",
    "PATCH",
    "POST",
    "PUT",
    "TRACE",
}
DEFAULT_INPUT_NORMALIZATION_ENABLED = True
DEFAULT_LOG_NORMALIZED_INPUT = True


def input_normalization_enabled(config: Optional[dict] = None) -> bool:
    if not config:
        return DEFAULT_INPUT_NORMALIZATION_ENABLED
    return bool(config.get("input_normalization_enabled", True))


def log_normalized_input_enabled(config: Optional[dict] = None) -> bool:
    if not config:
        return DEFAULT_LOG_NORMALIZED_INPUT
    return bool(config.get("log_normalized_input", True))


def normalize_command_input(raw: str) -> str:
    """Normalize shell-like attacker input for lookup keys only."""
    if raw is None:
        return raw
    if not isinstance(raw, str):
        return raw

    stripped = raw.strip()
    if not stripped:
        return stripped

    tokens = _tokenize_shell_like(stripped)
    return " ".join(tokens)


def normalize_http_path_or_query(raw: str) -> str:
    if raw is None:
        return raw
    if not isinstance(raw, str):
        return raw
    stripped = raw.strip()
    match = re.match(r"^([A-Za-z]+)\s+(\S+)(.*)$", stripped, re.DOTALL)
    if not match:
        return stripped

    method, path, rest = match.groups()
    if method.upper() not in HTTP_METHODS:
        return stripped

    rest = rest.strip()
    if rest:
        return f"{method} {path} {rest}"
    return f"{method} {path}"


def normalize_sql_input(raw: str) -> str:
    if raw is None:
        return raw
    if not isinstance(raw, str):
        return raw
    return _collapse_unquoted_whitespace(raw.strip(), quote_chars=("'","\"", "`"))


def normalize_lookup_key(raw: str, request_type: Optional[str] = None) -> str:
    request_type = (request_type or "command").lower()
    if request_type in {"http", "path", "args", "query_string"}:
        return normalize_http_path_or_query(raw)
    if request_type == "sql":
        return normalize_sql_input(raw)
    return normalize_command_input(raw)


def normalized_log_fields(data: dict, config: Optional[dict] = None) -> dict:
    if not input_normalization_enabled(config) or not log_normalized_input_enabled(config):
        return {}

    fields = {}
    if isinstance(data.get("command"), str):
        normalized = normalize_lookup_key(data["command"], "command")
        fields["raw_input"] = data["command"]
        fields["normalized_command"] = normalized
        fields["normalized_input"] = normalized
    elif isinstance(data.get("query"), str):
        normalized = normalize_lookup_key(data["query"], "sql")
        fields["raw_input"] = data["query"]
        fields["normalized_query"] = normalized
        fields["normalized_input"] = normalized
    elif isinstance(data.get("http-request"), dict):
        request = data["http-request"]
        raw_input = _http_request_summary(request)
        if raw_input:
            normalized = normalize_lookup_key(raw_input, "http")
            fields["raw_input"] = raw_input
            fields["normalized_input"] = normalized
    return fields


def _http_request_summary(request: dict) -> str:
    method = request.get("method")
    path = request.get("path") or request.get("url") or request.get("request")
    if method and path:
        return f"{method} {path}"
    if isinstance(path, str):
        return path
    return ""


def _tokenize_shell_like(value: str) -> list[str]:
    tokens = []
    token = []
    quote = None
    index = 0

    while index < len(value):
        char = value[index]

        if quote:
            token.append(char)
            if char == "\\" and quote == '"' and index + 1 < len(value):
                index += 1
                token.append(value[index])
            elif char == quote:
                quote = None
            index += 1
            continue

        if char in {"'", '"'}:
            token.append(char)
            quote = char
            index += 1
            continue

        if char == "\\":
            token.append(char)
            if index + 1 < len(value):
                index += 1
                token.append(value[index])
            index += 1
            continue

        if char.isspace():
            _flush_token(tokens, token)
            index += 1
            continue

        operator = _match_shell_operator(value, index)
        if operator:
            _flush_token(tokens, token)
            tokens.append(operator)
            index += len(operator)
            continue

        token.append(char)
        index += 1

    _flush_token(tokens, token)
    return tokens


def _match_shell_operator(value: str, index: int) -> Optional[str]:
    for operator in SHELL_OPERATORS:
        if value.startswith(operator, index):
            return operator
    return None


def _flush_token(tokens: list[str], token: list[str]) -> None:
    if token:
        tokens.append("".join(token))
        token.clear()


def _collapse_unquoted_whitespace(value: str, quote_chars: tuple[str, ...]) -> str:
    output = []
    quote = None
    pending_space = False

    for char in value:
        if quote:
            output.append(char)
            if char == quote:
                quote = None
            continue

        if char in quote_chars:
            if pending_space and output:
                output.append(" ")
                pending_space = False
            output.append(char)
            quote = char
            continue

        if char.isspace():
            pending_space = True
            continue

        if pending_space and output:
            output.append(" ")
        pending_space = False
        output.append(char)

    return "".join(output)

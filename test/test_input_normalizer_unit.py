import pytest

from input_normalizer import (
    normalize_command_input,
    normalize_http_path_or_query,
    normalize_lookup_key,
    normalize_sql_input,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("ls Doc", "ls Doc"),
        ("ls                 Doc", "ls Doc"),
        ("ls\tDoc", "ls Doc"),
        ("  uname    -a  ", "uname -a"),
        ("cat     /etc/passwd", "cat /etc/passwd"),
        ('echo "hello     world"', 'echo "hello     world"'),
        ("printf 'a    b\\n'", "printf 'a    b\\n'"),
        ("python3 -c 'print(\"a   b\")'", "python3 -c 'print(\"a   b\")'"),
        ("ls   Doc   &&   whoami", "ls Doc && whoami"),
        ("cat   file.txt   |   grep   root", "cat file.txt | grep root"),
        ("echo hello\\ world", "echo hello\\ world"),
        ("Cat     /Tmp/File", "Cat /Tmp/File"),
    ],
)
def test_normalize_command_input(raw, expected):
    assert normalize_command_input(raw) == expected


def test_normalize_command_input_preserves_malformed_quotes():
    assert normalize_command_input('echo "hello     world') == 'echo "hello     world'


def test_normalize_http_path_or_query_is_conservative():
    assert normalize_http_path_or_query("  GET    /A%20B?z=2&x=1  ") == "GET /A%20B?z=2&x=1"
    assert normalize_http_path_or_query("  /search?q=a     b  ") == "/search?q=a     b"


def test_normalize_sql_input_preserves_quoted_strings():
    assert (
        normalize_sql_input(" SELECT   'a    b'   FROM   users ")
        == "SELECT 'a    b' FROM users"
    )


def test_normalize_lookup_key_uses_request_type():
    assert normalize_lookup_key(" GET    /admin ", "http") == "GET /admin"

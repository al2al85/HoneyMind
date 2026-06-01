import json
import re
import time
from typing import List

import pytest
from paramiko import SSHClient, AutoAddPolicy

from conftest import get_honeypot_main


def connect_and_run_ssh_commands(
    port, username, password, commands, prompt_regex=r"\$ "
):
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username=username, password=password)
    shell = client.invoke_shell()
    shell.settimeout(60.0)

    # Read initial prompt
    buffer = ""
    while True:
        buffer += shell.recv(1024).decode()
        if re.search(prompt_regex, buffer):
            break

    results = []
    for cmd in commands:
        shell.send(cmd + "\n")
        buffer = ""
        start = time.time()
        # Read until we see the prompt again
        while True:
            buffer += shell.recv(1024).decode()
            if re.search(prompt_regex, buffer):
                break
            if time.time() - start > 60:
                raise TimeoutError(f"Timeout waiting for prompt after {cmd}")
        # Strip off the final prompt from buffer
        output = re.sub(rf".*{re.escape(cmd)}\r\n", "", buffer)
        output = re.sub(prompt_regex + r".*$", "", output).strip()
        results.append(output)
    shell.close()
    client.close()
    return results


def load_jsonl(filepath):
    with open(filepath, "r") as f:
        return [json.loads(line.strip()) for line in f if line.strip()]


@pytest.fixture()
def fake_fs_data() -> List[dict]:
    return [
        {
            "path": "/",
            "parent_path": None,
            "name": "/",
            "is_dir": True,
        },
        {
            "path": "/etc",
            "parent_path": "/",
            "name": "etc",
            "is_dir": True,
        },
        {
            "path": "/bin",
            "parent_path": "/",
            "name": "bin",
            "is_dir": True,
        },
    ]


@pytest.mark.parametrize(
    "test_cases",
    [
        [
            {"command": "ls", "expect": "bin"},
            {"command": "cd /etc", "expect": "/etc"},
            {"command": "mkdir testdir", "expect": "$user@alpine:$/"},
            {"command": "ls /", "expect": "testdir"},
        ],
        [
            {"command": "whoami", "expect": "root"},
            {"command": "mysql -u root -p", "expect": "Enter password"},
            {"command": "select 1", "expect": "Command not handled"},
        ],
    ],
)
def test_switch_json_based(monkeypatch, test_cases, fake_fs_data):
    conf = {
        "type": "ssh",
        "prompt_template": "${{username}}@alpine:${{cwd}}$ ",
        "data_file": "data.jsonl",
        "fs_file": "test_fs_data.jsonl.gz",
        "password_min_attempts": 1,
        "password_max_attempts": 1,
    }
    data = [
        {"command": "whoami", "response": "root"},
        {"command": "mysql -u root -p", "response": "Enter password"},
    ]
    with get_honeypot_main(monkeypatch, [conf], data, fake_fs_data) as ssh_port:
        for i, case in enumerate(test_cases):
            response = connect_and_run_ssh_commands(
                port=ssh_port,
                username="user",
                password="pass",
                commands=[case["command"]],
            )[0]
            print(f"Response {i}: {repr(response)}")
            assert (
                case["expect"] in response
            ), f"Failed case {i}: {case['command']}\nExpected: {case['expect']}\nActual: {response}"

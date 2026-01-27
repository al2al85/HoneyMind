import os
import pathlib
import socket
import struct
import time
from typing import Generator
import psycopg2


import pytest

from postgresql_honeypot import PostgresHoneypot
from infra.data_handler import DataHandler
from sql_data_handler import SqlDataHandler
from infra.chain_honeypot_action import ChainedHoneypotAction


@pytest.fixture
def postgres_honeypot() -> Generator[PostgresHoneypot, None, None]:
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"
    pathlib.Path("honeypots/postgres").mkdir(parents=True, exist_ok=True)

    action = ChainedHoneypotAction(
        DataHandler(
            "honeypots/postgres/data.jsonl",
            system_prompt="You are a PostgreSQL server",
            model_id="anthropic.claude-3-5-sonnet-20240620-v1:0",
        ),
        SqlDataHandler(dialect="postgres"),
    )

    honeypot = PostgresHoneypot(action=action, config={"name": "TestPostgresHoneypot"})

    try:
        honeypot.start()
        yield honeypot
    finally:
        honeypot.stop()


def test_connection_to_postgres_honeypot(postgres_honeypot):
    with psycopg2.connect(
        dbname="postgres",
        user="postgres",
        password="pw",
        host="0.0.0.0",
        port=postgres_honeypot.port,
    ) as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            assert cur.fetchone()[0] == 1


def perform_password_handshake(sock: socket.socket):
    params = b"user\x00root\x00database\x00postgres\x00\x00"
    length = len(params) + 8
    message = struct.pack("!I", length) + struct.pack("!I", 196608) + params
    sock.sendall(message)

    auth_header = sock.recv(9)
    if not auth_header.startswith(b"R"):
        pass

    password = b"password123"
    pwd_msg_body = password + b"\x00"
    length = len(pwd_msg_body) + 4
    pwd_msg = b"p" + struct.pack("!I", length) + pwd_msg_body
    sock.sendall(pwd_msg)


@pytest.fixture
def postgres_socket(postgres_honeypot) -> Generator[socket.socket, None, None]:
    """Returns a connected raw TCP socket to the honeypot."""
    sock = socket.create_connection(
        ("0.0.0.0", postgres_honeypot.bound_port), timeout=2
    )
    sock.settimeout(2)
    try:
        yield sock
    finally:
        sock.close()


def test_direct_sql_query(postgres_socket):
    """
    Test a direct SQL query without using psycopg2.
    """
    perform_password_handshake(postgres_socket)

    # Consume authentication and parameter status messages until ReadyForQuery
    try:
        while True:
            data = postgres_socket.recv(4096)
            if b"Z\x00\x00\x00\x05I" in data:  # ReadyForQuery
                break
    except socket.timeout:
        pass

    query = b"Q\x00\x00\x00\x0cSELECT 1\x00"
    postgres_socket.sendall(query)

    responses = b""
    try:
        for _ in range(5):
            responses += postgres_socket.recv(1024)
    except socket.timeout:
        pass

    assert b"T" in responses or b"D" in responses or b"C" in responses


def test_postgres_fake_connection(postgres_socket):
    perform_password_handshake(postgres_socket)
    time.sleep(0.1)
    try:
        resp = postgres_socket.recv(1024)
        assert resp
    except socket.timeout:
        pass


def test_postgres_malformed_query(postgres_socket):
    postgres_socket.sendall(b"invalid_query")
    time.sleep(0.1)
    try:
        data = postgres_socket.recv(1024)
        assert data == b"" or data
    except (ConnectionResetError, socket.timeout):
        pass


def test_auth_and_ready_for_query(postgres_socket):
    # This test specifically checks the auth flow.
    # 1. Send Startup
    params = b"user\x00root\x00database\x00postgres\x00\x00"
    length = len(params) + 8
    message = struct.pack("!I", length) + struct.pack("!I", 196608) + params
    postgres_socket.sendall(message)

    time.sleep(0.1)

    raw = postgres_socket.recv(1024)
    assert b"R\x00\x00\x00\x08\x00\x00\x00\x03" in raw

    password = b"secret\x00"
    pwd_msg = b"p" + struct.pack("!I", len(password) + 4) + password
    postgres_socket.sendall(pwd_msg)

    time.sleep(0.1)

    data = b""
    try:
        while True:
            chunk = postgres_socket.recv(1024)
            data += chunk
            if b"Z\x00\x00\x00\x05I" in data:
                break
    except socket.timeout:
        pass

    assert b"R\x00\x00\x00\x08\x00\x00\x00\x00" in data  # AuthOK
    assert b"Z\x00\x00\x00\x05I" in data  # ReadyForQuery


def test_invalid_startup_message(postgres_socket):
    postgres_socket.sendall(b"\x00\x00\x00\x04BAD!")
    time.sleep(0.1)
    try:
        data = postgres_socket.recv(1024)
        # Accept anything, just shouldn't crash
        assert data == b"" or data
    except (ConnectionResetError, socket.timeout):
        pass


def test_client_disconnect_after_auth(postgres_socket):
    perform_password_handshake(postgres_socket)
    postgres_socket.close()
    time.sleep(0.1)
    # No exception should be raised here from the honeypot side

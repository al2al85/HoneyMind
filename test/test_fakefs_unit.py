import os
import tempfile
from pathlib import Path

import pytest

from infra.fake_fs.commands import handle_ls, handle_cd, handle_mkdir, handle_download
from infra.fake_fs_data_handler import FakeFSDataHandler


@pytest.mark.parametrize(
    "fs_path",
    [
        "test/honeypots/alpine/fs_alpine.jsonl.gz",
        "test/honeypots/busybox/fs_busybox.jsonl.gz",
        "test/honeypots/dlink_telnet/alpine_fs_small.jsonl.gz",
    ],
)
def test_basic_ls_and_cd(fs_path):
    fs_path = str(Path(__file__).parent.parent / fs_path)
    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        fs_file=fs_path,
    )
    session = handler.connect({})

    output = handler.query("ls", session)
    assert isinstance(output, str)
    print("LS / output:", output)
    assert "bin" in output
    assert "etc" in output
    assert "home" in output

    handle_cd(session, "home")
    assert session["cwd"] == "/home"
    assert "" in handle_ls(session)


def test_basic_ls_from_root():
    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        fs_file=fs_path,
    )

    session = handler.connect({})
    result = handle_ls(session)

    print("LS result:", result)

    assert "bin" in result
    assert "etc" in result
    assert "home" in result


def test_mkdir_creates_directory(tmp_path):
    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        fs_file=fs_path,
    )

    session = handler.connect({})
    output = handle_mkdir(session, "newdir_temp")

    assert output == ""
    children = session["fs"].store.list_dir(session["cwd"])
    names = [child["name"] for child in children]
    assert "newdir_temp" in names


def test_ls_long_format(tmp_path):
    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        fs_file=fs_path,
    )

    session = handler.connect({})
    result = handle_ls(session, flags="-l")
    assert "bin" in result


def test_handle_wget_creates_file(tmp_path, monkeypatch):
    with tempfile.TemporaryDirectory() as tmpdir:
        monkeypatch.setenv("HONEYPOT_DOWNLOAD_DIR", tmpdir)

    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        fs_file=fs_path,
    )

    session = handler.connect({})

    url = "http://test.com/malware.sh"
    output = handle_download(session, url)

    children = session["fs"].store.list_dir(session["cwd"])
    names = [child["name"] for child in children]
    assert "malware.sh" in names

    assert "saved" in output
    assert session["downloads"][0]["url"] == url


def test_fakefs_query_fallback(tmp_path):
    # Create test data
    data_file = tmp_path / "data.jsonl"
    data_file.write_text('{"input": "whoami", "response": "root\\n"}\n')

    fs_file = tmp_path / "fs.json"
    fs_file.write_text(
        r"""{
        "/": {
            "type": "dir",
            "content": {}
        }
    }"""
    )

    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    handler = FakeFSDataHandler(
        data_file=str(data_file),
        fs_file=fs_path,
    )

    session = handler.connect({})
    response = handler.query("whoami", session)

    assert response == "root\n"


def test_fakefs_unknown_command(tmp_path):
    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        fs_file=fs_path,
    )

    session = handler.connect({})

    response = handler.query("nonexistent", session)
    assert response is None


def test_fakefs_invalid_json_line(tmp_path):
    data_file = tmp_path / "data.jsonl"
    data_file.write_text('invalid-line\n{"input": "uptime", "response": "up 5 days"}\n')

    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    handler = FakeFSDataHandler(
        data_file=str(data_file),
        fs_file=fs_path,
    )

    session = handler.connect({})

    response = handler.query("uptime", session)
    assert response == "up 5 days"


def test_system_artifacts_are_coherent(tmp_path):
    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        fs_file=fs_path,
        config={
            "hostname": "alpine-vm",
            "distro": "Alpine Linux",
            "kernel": "6.1.21",
            "uname_release": "6.1.21",
            "arch": "x86_64",
            "cpu_count": 2,
            "cpu_model": "Intel(R) Xeon(R)",
            "mem_total_kb": 1024 * 1024,
            "clocksource": "tsc",
            "dmi_sys_vendor": "QEMU",
            "dmi_product_name": "KVM Virtual Machine",
            "dmi_product_version": "Standard PC (Q35 + ICH9, 2009)",
            "dmesg_lines": [
                "[    0.000000] Linux version 6.1.21",
                "[    0.000000] Command line: BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet",
            ],
        },
    )

    session = handler.connect({})

    uname_a = handler.query("uname -a", session)
    assert uname_a.startswith("Linux alpine-vm 6.1.21 ")
    assert "x86_64" in uname_a
    assert uname_a.strip().endswith("GNU/Linux")
    assert "MemTotal:" in handler.query("cat /proc/meminfo", session)
    assert "processor" in handler.query("cat /proc/cpuinfo", session)
    assert "BOOT_IMAGE=/vmlinuz" in handler.query("cat /proc/cmdline", session)
    assert "proc /proc proc" in handler.query("cat /proc/mounts", session)
    assert "Linux version 6.1.21" in handler.query("dmesg", session)
    assert handler.query("virt-what", session) == ""
    assert (
        handler.query("cat /sys/devices/virtual/dmi/id/product_name", session)
        == "KVM Virtual Machine"
    )
    assert "sshd" in handler.query("ps -ef", session)


def test_common_recon_commands_are_hardcoded_and_coherent(tmp_path):
    base_dir = os.path.dirname(os.path.dirname(__file__))
    fs_path = os.path.join(base_dir, "test/honeypots/alpine/fs_alpine.jsonl.gz")

    handler = FakeFSDataHandler(
        data_file="test/honeypots/test_responses.jsonl",
        fs_file=fs_path,
        config={
            "hostname": "alpine-vm",
            "distro": "Alpine Linux",
            "kernel": "6.1.21",
            "uname_release": "6.1.21",
            "arch": "x86_64",
            "cpu_count": 2,
            "mem_total_kb": 1024 * 1024,
            "interface": "eth0",
            "ip_address": "10.0.2.15",
            "mac_address": "52:54:00:12:34:56",
        },
    )
    session = handler.connect({"username": "ignored-login"})
    handle_cd(session, "etc")

    assert handler.query("whoami", session) == "root"
    assert "uid=0(root) gid=0(root)" in handler.query("id", session)
    assert handler.query("hostname", session) == "alpine-vm"
    assert handler.query("pwd", session) == "/etc"

    os_release = handler.query("cat      /etc/os-release", session)
    assert 'NAME="Alpine Linux"' in os_release
    assert "ID=alpine" in os_release
    assert not os_release.endswith("\n")

    passwd = handler.query("cat /etc/passwd", session)
    assert "root:x:0:0:root:/root:/bin/sh" in passwd
    assert "sshd:x:" in passwd
    assert not passwd.endswith("\n")

    assert "load average:" in handler.query("uptime", session)
    assert "/dev/sda1" in handler.query("df -h", session)
    assert "Mem:" in handler.query("free -m", session)

    ip_addr = handler.query("ip a", session)
    assert "eth0" in ip_addr
    assert "10.0.2.15/24" in ip_addr
    assert "52:54:00:12:34:56" in ip_addr

    ifconfig = handler.query("ifconfig", session)
    assert "inet 10.0.2.15" in ifconfig
    assert "ether 52:54:00:12:34:56" in ifconfig

    ps_aux = handler.query("ps aux", session)
    assert "USER" in ps_aux
    assert "/usr/sbin/sshd -D" in ps_aux
    assert "ps aux" in ps_aux

    assert handler.query("which      wget", session) == "/usr/bin/wget"
    assert handler.query("which curl", session) == "/usr/bin/curl"
    assert handler.query("which busybox", session) == "/bin/busybox"
    cpuinfo = handler.query("cat /proc/cpuinfo", session)
    assert "model name" in cpuinfo
    assert not cpuinfo.endswith("\n")

    for command in [
        "whoami",
        "id",
        "uname",
        "hostname",
        "pwd",
        "cat /etc/os-release",
        "cat /etc/passwd",
        "uptime",
        "df -h",
        "free -m",
        "ip a",
        "ifconfig",
        "ps aux",
        "which wget",
        "which curl",
        "which busybox",
        "cat /proc/cpuinfo",
    ]:
        response = handler.query(command, session)
        assert response is not None
        assert not response.endswith("\n"), command

import json
import logging
import shlex
import tempfile
from pathlib import Path
from typing import Optional

from infra.fake_fs.commands import handle_ls, handle_cd, handle_mkdir, handle_download
from infra.fake_fs.filesystem import FakeFileSystem
from infra.fake_fs.fs_utils import create_db_from_jsonl_gz
from infra.fake_fs_datastore import FakeFSDataStore
from infra.interfaces import HoneypotSession, HoneypotAction


class FakeFSDataHandler(HoneypotAction):
    def __init__(self, data_file: str, fs_file: str, config: dict = None):
        self._data_file = Path(data_file)
        self.config = config or {}

        self.hostname = self.config.get("hostname", "server")
        self.uname_sysname = self.config.get("uname_sysname", "Linux")
        self.uname_kernel = self.config.get("kernel", "5.10.0")
        self.uname_release = self.config.get("uname_release", self.uname_kernel)
        self.uname_version = self.config.get("uname_version", "#1 SMP PREEMPT_DYNAMIC")
        self.uname_machine = self.config.get("arch", "x86_64")
        self.uname_processor = self.config.get("uname_processor", self.config.get("arch", "x86_64"))
        self.uname_hardware_platform = self.config.get("uname_hardware_platform", self.config.get("arch", "x86_64"))
        self.uname_os = self.config.get("uname_os", "GNU/Linux")
        self.cpu_count = int(self.config.get("cpu_count", 1))
        self.cpu_model = self.config.get(
            "cpu_model", "Intel(R) Core(TM) i7-8650U CPU @ 1.90GHz"
        )
        self.mem_total_kb = int(self.config.get("mem_total_kb", 2048 * 1024))
        self.clocksource = self.config.get("clocksource", "tsc")
        self.dmesg_lines = self.config.get(
            "dmesg_lines",
            [
                "[    0.000000] Linux version 5.10.0 (builder@host) (gcc version 11.3.0) #1 SMP",
                "[    0.000000] Command line: BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet",
                "[    0.000000] DMI: KVM Virtual Machine/Standard PC (Q35 + ICH9, 2009), BIOS 1.0.0",
            ],
        )
        self.distro_name = self.config.get(
            "distro", self.config.get("name", "Ubuntu 20.04")
        )
        self.os_release_content = self.config.get(
            "os_release",
            f'NAME="{self.distro_name}"\nPRETTY_NAME="{self.distro_name}"\nID={self.distro_name.lower().replace(" ", "_")}\n',
        )
        self.proc_cmdline = self.config.get(
            "proc_cmdline", "BOOT_IMAGE=/vmlinuz root=/dev/sda1 ro quiet"
        )
        self.proc_mounts = self.config.get(
            "proc_mounts",
            "/dev/sda1 / ext4 rw,relatime,errors=remount-ro 0 0\n"
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            "tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0\n",
        )
        self.proc_interrupts = self.config.get(
            "proc_interrupts",
            "           CPU0\n"
            "  0:         20   IO-APIC   2-edge      timer\n"
            "  1:          0   IO-APIC   1-edge      i8042\n",
        )
        self.dmi_info = {
            "product_name": self.config.get("dmi_product_name", "KVM Virtual Machine"),
            "sys_vendor": self.config.get("dmi_sys_vendor", "QEMU"),
            "product_version": self.config.get(
                "dmi_product_version", "Standard PC (Q35 + ICH9, 2009)"
            ),
            "board_name": self.config.get("dmi_board_name", "pc-q35-8.2"),
            "bios_vendor": self.config.get("dmi_bios_vendor", "SeaBIOS"),
            "bios_version": self.config.get("dmi_bios_version", "1.16.2"),
        }

        fs_path = Path(fs_file)
        if fs_path.suffix == ".gz" and fs_path.name.endswith(".jsonl.gz"):
            tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
            create_db_from_jsonl_gz(fs_path, tmp_db.name)
            fs_path = Path(tmp_db.name)
        else:
            raise ValueError(
                "Unsupported fakefs file format. Only .jsonl.gz is supported."
            )

        if not fs_path.exists():
            raise FileNotFoundError(f"Missing or failed to generate fs DB: {fs_file}")

        store = FakeFSDataStore(str(fs_path))
        self.fakefs = FakeFileSystem(store)

    def connect(self, auth_info: dict) -> HoneypotSession:
        logging.info(f"FakeFSDataHandler.connect: {auth_info}")
        return HoneypotSession({"cwd": "/", "fs": self.fakefs})

    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        logging.info(f"FakeFSDataHandler.query: {query}")
        query = query.strip()

        system_response = self._handle_system_artifacts(query)
        if system_response is not None:
            return system_response

        if "fs" in session:
            if query.startswith("ls"):
                parts = query.strip().split()
                flags = [p for p in parts if p.startswith("-")]
                return handle_ls(session, flags=" ".join(flags))

            elif query.startswith("cd "):
                parts = query.split(maxsplit=1)
                if len(parts) == 2:
                    return handle_cd(session, parts[1])
                return "Usage: cd <dir>"
            elif query.startswith("mkdir "):
                parts = query.split(maxsplit=1)
                if len(parts) == 2:
                    return handle_mkdir(session, parts[1])
                return "Usage: mkdir <dir>"
            elif "wget" in query.lower() or "curl" in query.lower():
                parts = query.strip().split()
                if len(parts) >= 2:
                    url = parts[-1]
                    logging.info(f"[FakeFSDataHandler] Handling download: {url}")
                    return handle_download(session, url)
                logging.warning("[FakeFSDataHandler] Invalid wget/curl syntax")
                return "Usage: wget <url> or curl <url>"
        return self.query_from_file(query)

    def _handle_uname(self, query: str) -> str:
        parts = shlex.split(query)
        args = parts[1:]

        # Map long options to their single-char equivalents
        long_opts = {
            "--kernel-name": "s",
            "--nodename": "n",
            "--kernel-release": "r",
            "--kernel-version": "v",
            "--machine": "m",
            "--processor": "p",
            "--hardware-platform": "i",
            "--operating-system": "o",
            "--all": "a",
        }

        active = set()
        for arg in args:
            if arg in long_opts:
                active.add(long_opts[arg])
            elif arg.startswith("--"):
                pass  # unknown long option → ignore
            elif arg.startswith("-"):
                for ch in arg[1:]:
                    active.add(ch)

        # -a → all fields; no flags → default to -s
        if "a" in active:
            active = {"s", "n", "r", "v", "m", "p", "i", "o"}
        elif not active:
            active = {"s"}

        field_values = {
            "s": self.uname_sysname,
            "n": self.hostname,
            "r": self.uname_release,
            "v": self.uname_version,
            "m": self.uname_machine,
            "p": self.uname_processor,
            "i": self.uname_hardware_platform,
            "o": self.uname_os,
        }

        # Output fields in POSIX/GNU order
        field_order = ["s", "n", "r", "v", "m", "p", "i", "o"]
        return " ".join(field_values[f] for f in field_order if f in active) + "\n"

    def _handle_system_artifacts(self, query: str) -> Optional[str]:
        if query == "uname" or query.startswith("uname "):
            return self._handle_uname(query)

        if query in ("cat /etc/os-release", "cat /etc/*release"):
            return self.os_release_content + "\n"
        if query == "cat /etc/issue":
            return f"{self.distro_name}\\n\\l\n"

        if query == "cat /proc/cmdline":
            return self.proc_cmdline + "\n"
        if query == "cat /proc/mounts":
            return self.proc_mounts
        if query == "cat /proc/interrupts":
            return self.proc_interrupts
        if query == "cat /proc/cpuinfo":
            return self._render_cpuinfo()
        if query == "cat /proc/meminfo":
            return self._render_meminfo()
        if query == "cat /proc/version":
            return (
                f"Linux version {self.uname_kernel} (builder@host) "
                f"(gcc version 11.3.0) #1 SMP\n"
            )
        if query == "cat /proc/loadavg":
            return "0.00 0.01 0.05 1/100 1234\n"
        if query == "cat /proc/uptime":
            return "12345.67 54321.00\n"
        if query == "cat /proc/self/cgroup":
            return "0::/\n"
        if query == "cat /proc/stat":
            return "cpu  123 0 456 789 0 0 0 0 0 0\n"

        if query == "dmesg" or query.startswith("dmesg "):
            return "\n".join(self.dmesg_lines) + "\n"
        if query in ("virt-what", "systemd-detect-virt", "systemd-detect-virt --quiet"):
            return "\n"
        if query.startswith("dmidecode"):
            return self._handle_dmidecode(query)
        if query == "ls /sys/devices/system/clocksource/clocksource0":
            return "available_clocksource  current_clocksource\n"
        if query == "cat /sys/devices/system/clocksource/clocksource0/current_clocksource":
            return self.clocksource + "\n"
        if query == "cat /sys/devices/system/clocksource/clocksource0/available_clocksource":
            return f"{self.clocksource} hpet acpi_pm\n"
        if query == "ls /sys/devices/virtual/dmi/id":
            return "bios_vendor bios_version board_name product_name product_version sys_vendor\n"

        dmi_file = self._handle_dmi_file(query)
        if dmi_file is not None:
            return dmi_file

        if query in ("ps", "ps -ef", "ps aux"):
            return self._render_ps_output()
        if query.startswith("ss ") or query == "ss":
            return self._render_ss_output()
        if query.startswith("netstat"):
            return self._render_netstat_output()
        if query.startswith("lsof"):
            return self._render_lsof_output()

        return None

    def _render_cpuinfo(self) -> str:
        blocks = []
        for cpu in range(self.cpu_count):
            blocks.append(
                "\n".join(
                    [
                        f"processor\t: {cpu}",
                        "vendor_id\t: GenuineIntel",
                        "cpu family\t: 6",
                        "model\t\t: 158",
                        f"model name\t: {self.cpu_model}",
                        "stepping\t: 10",
                        "microcode\t: 0x1",
                        "cpu MHz\t\t: 2100.000",
                        "cache size\t: 8192 KB",
                        "physical id\t: 0",
                        f"siblings\t: {self.cpu_count}",
                        f"core id\t\t: {cpu}",
                        f"cpu cores\t: {self.cpu_count}",
                        f"apicid\t\t: {cpu}",
                        "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx lm constant_tsc rep_good nopl xtopology nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 movbe popcnt aes xsave avx avx2 hypervisor",
                        "",
                    ]
                )
            )
        return "\n".join(blocks)

    def _render_meminfo(self) -> str:
        kb = self.mem_total_kb
        free_kb = kb // 4
        avail_kb = kb // 2
        return (
            f"MemTotal:       {kb} kB\n"
            f"MemFree:        {free_kb} kB\n"
            f"MemAvailable:   {avail_kb} kB\n"
            "Buffers:        16384 kB\n"
            "Cached:         131072 kB\n"
            "SwapCached:            0 kB\n"
        )

    def _handle_dmidecode(self, query: str) -> str:
        if "-s" in query:
            option_map = {
                "system-manufacturer": self.dmi_info["sys_vendor"],
                "system-product-name": self.dmi_info["product_name"],
                "system-version": self.dmi_info["product_version"],
                "baseboard-product-name": self.dmi_info["board_name"],
                "bios-vendor": self.dmi_info["bios_vendor"],
                "bios-version": self.dmi_info["bios_version"],
            }
            for option, value in option_map.items():
                if option in query:
                    return f"{value}\n"
            return "\n"
        return (
            "# dmidecode 3.4\n"
            "SMBIOS 3.0 present.\n"
            "Handle 0x0001, DMI type 1, 27 bytes\n"
            "System Information\n"
            f"\tManufacturer: {self.dmi_info['sys_vendor']}\n"
            f"\tProduct Name: {self.dmi_info['product_name']}\n"
            f"\tVersion: {self.dmi_info['product_version']}\n"
            "\n"
        )

    def _handle_dmi_file(self, query: str) -> Optional[str]:
        dmi_files = {
            "cat /sys/devices/virtual/dmi/id/product_name": self.dmi_info["product_name"],
            "cat /sys/devices/virtual/dmi/id/sys_vendor": self.dmi_info["sys_vendor"],
            "cat /sys/devices/virtual/dmi/id/product_version": self.dmi_info["product_version"],
            "cat /sys/devices/virtual/dmi/id/board_name": self.dmi_info["board_name"],
            "cat /sys/devices/virtual/dmi/id/bios_vendor": self.dmi_info["bios_vendor"],
            "cat /sys/devices/virtual/dmi/id/bios_version": self.dmi_info["bios_version"],
        }
        if query in dmi_files:
            return f"{dmi_files[query]}\n"
        return None

    def _render_ps_output(self) -> str:
        return (
            "UID          PID    PPID  C STIME TTY          TIME CMD\n"
            "root           1       0  0 00:00 ?        00:00:01 /sbin/init\n"
            "root         112       1  0 00:00 ?        00:00:00 sshd: server [listener]\n"
            "root         118       1  0 00:00 ?        00:00:00 cron\n"
            "root         130       1  0 00:00 ?        00:00:00 rsyslogd\n"
        )

    def _render_ss_output(self) -> str:
        return (
            "State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
            "LISTEN 0      128          0.0.0.0:22         0.0.0.0:*     users:((\"sshd\",pid=112,fd=3))\n"
            "LISTEN 0      128          0.0.0.0:80         0.0.0.0:*     users:((\"nginx\",pid=210,fd=6))\n"
        )

    def _render_netstat_output(self) -> str:
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      112/sshd\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      210/nginx\n"
        )

    def _render_lsof_output(self) -> str:
        return (
            "COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            "sshd      112 root    3u  IPv4  12345      0t0  TCP *:22 (LISTEN)\n"
            "nginx     210 root    6u  IPv4  23456      0t0  TCP *:80 (LISTEN)\n"
        )

    def query_from_file(self, input_str: str) -> Optional[str]:
        try:
            with self._data_file.open("r") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        if (
                            entry.get("command") == input_str
                            or entry.get("input") == input_str
                        ):
                            return entry.get("response", "")
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            logging.warning(f"Data file not found: {self._data_file}")
        return None

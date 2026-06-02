import json
import logging
import shlex
import tempfile
from pathlib import Path
from typing import Optional

from input_normalizer import normalize_command_input
from infra.fake_fs.commands import handle_ls, handle_cd, handle_mkdir, handle_download
from infra.fake_fs.filesystem import FakeFileSystem
from infra.fake_fs.fs_utils import create_db_from_jsonl_gz
from infra.fake_fs_datastore import FakeFSDataStore
from infra.interfaces import HoneypotSession, HoneypotAction


class FakeFSDataHandler(HoneypotAction):
    def __init__(self, data_file: str, fs_file: str, config: dict = None):
        self._data_file = Path(data_file)
        self.config = config or {}

        self.hostname = self.config.get("hostname", "ubuntu")
        self.username = self.config.get(
            "simulated_user", self.config.get("username", "root")
        )
        self.uid = int(self.config.get("uid", 0))
        self.gid = int(self.config.get("gid", 0))
        self.group = self.config.get("group", self.username)
        self.uname_sysname = self.config.get("uname_sysname", "Linux")
        self.uname_kernel = self.config.get("kernel", "5.15.0-91-generic")
        self.uname_release = self.config.get("uname_release", self.uname_kernel)
        self.uname_version = self.config.get(
            "uname_version", "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
        )
        self.uname_machine = self.config.get("arch", "x86_64")
        self.uname_processor = self.config.get(
            "uname_processor", self.config.get("arch", "x86_64")
        )
        self.uname_hardware_platform = self.config.get(
            "uname_hardware_platform", self.config.get("arch", "x86_64")
        )
        self.uname_os = self.config.get("uname_os", "GNU/Linux")
        self.cpu_count = int(self.config.get("cpu_count", 2))
        self.cpu_model = self.config.get(
            "cpu_model", "Intel(R) Xeon(R) CPU E5-2686 v4 @ 2.30GHz"
        )
        self.mem_total_kb = int(self.config.get("mem_total_kb", 2 * 1024 * 1024))
        self.interface = self.config.get("interface", "eth0")
        self.ip_address = self.config.get("ip_address", "172.31.42.15")
        self.netmask = self.config.get("netmask", "255.255.255.0")
        self.cidr_prefix = int(self.config.get("cidr_prefix", 24))
        self.mac_address = self.config.get("mac_address", "52:54:00:4a:8b:2c")
        self.broadcast = self.config.get("broadcast", "172.31.42.255")
        self.root_device = self.config.get("root_device", "/dev/sda1")
        self.clocksource = self.config.get("clocksource", "tsc")
        self.distro_name = self.config.get(
            "distro", self.config.get("name", "Ubuntu 22.04.3 LTS")
        )
        self.dmesg_lines = self.config.get(
            "dmesg_lines",
            [
                f"[    0.000000] Linux version {self.uname_release} (buildd@lcy02-amd64-059) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) {self.uname_version}",
                f"[    0.000000] Command line: BOOT_IMAGE=/boot/vmlinuz-{self.uname_release} root=/dev/sda1 ro quiet splash",
                "[    0.000000] DMI: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.2-0-gea1b7a073390-prebuilt.qemu.org 04/01/2014",
                "[    0.000000] tsc: Detected 2300.000 MHz processor",
                "[    0.523871] clocksource: tsc-early: mask: 0xffffffffffffffff max_cycles: 0x213e9fdb5e8, max_idle_ns: 440795268513 ns",
                "[    2.187634] EXT4-fs (sda1): mounted filesystem with ordered data mode. Quota mode: none.",
            ],
        )
        self.os_release_content = self.config.get(
            "os_release",
            self._default_os_release(),
        )
        default_proc_cmdline = (
            f"BOOT_IMAGE=/boot/vmlinuz-{self.uname_release} root=/dev/sda1 ro quiet splash"
        )
        self.proc_cmdline = self.config.get(
            "proc_cmdline",
            self._proc_cmdline_from_dmesg(default_proc_cmdline),
        )
        self.proc_mounts = self.config.get(
            "proc_mounts",
            f"{self.root_device} / ext4 rw,relatime,errors=remount-ro 0 0\n"
            "proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0\n"
            "sysfs /sys sysfs rw,nosuid,nodev,noexec,relatime 0 0\n"
            "tmpfs /run tmpfs rw,nosuid,nodev,mode=755 0 0\n"
            f"tmpfs /dev/shm tmpfs rw,nosuid,nodev 0 0\n"
            f"{self.root_device} /boot/efi vfat rw,relatime 0 0\n",
        )
        self.proc_interrupts = self.config.get(
            "proc_interrupts",
            "           CPU0       CPU1\n"
            "  0:          9          0   IO-APIC   2-edge      timer\n"
            "  1:          0          0   IO-APIC   1-edge      i8042\n"
            "  8:          0          0   IO-APIC   8-edge      rtc0\n"
            " 24:          0          0   PCI-MSI 98304-edge      virtio0-config\n"
            " 25:       1423       1156   PCI-MSI 98305-edge      virtio0-req.0\n",
        )
        self.dmi_info = {
            "product_name": self.config.get("dmi_product_name", "Standard PC (i440FX + PIIX, 1996)"),
            "sys_vendor": self.config.get("dmi_sys_vendor", "QEMU"),
            "product_version": self.config.get("dmi_product_version", "pc-i440fx-8.1"),
            "board_name": self.config.get("dmi_board_name", "440BX Desktop Reference Platform"),
            "bios_vendor": self.config.get("dmi_bios_vendor", "SeaBIOS"),
            "bios_version": self.config.get("dmi_bios_version", "rel-1.16.2-0-gea1b7a073390-prebuilt.qemu.org"),
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

    def _default_os_release(self) -> str:
        distro = self.distro_name.lower()
        if "alpine" in distro:
            return (
                'NAME="Alpine Linux"\n'
                "ID=alpine\n"
                'PRETTY_NAME="Alpine Linux v3.18"\n'
                'VERSION_ID="3.18.4"\n'
                'HOME_URL="https://alpinelinux.org/"\n'
                'BUG_REPORT_URL="https://gitlab.alpinelinux.org/alpine/aports/-/issues"\n'
            )
        if "debian" in distro:
            return (
                'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
                'NAME="Debian GNU/Linux"\n'
                'VERSION_ID="12"\n'
                'VERSION="12 (bookworm)"\n'
                "ID=debian\n"
                'HOME_URL="https://www.debian.org/"\n'
            )
        return (
            'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
            'NAME="Ubuntu"\n'
            'VERSION_ID="22.04"\n'
            'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
            "VERSION_CODENAME=jammy\n"
            "ID=ubuntu\n"
            "ID_LIKE=debian\n"
            'HOME_URL="https://www.ubuntu.com/"\n'
            'SUPPORT_URL="https://help.ubuntu.com/"\n'
            'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
            'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
            "UBUNTU_CODENAME=jammy\n"
        )

    def _proc_cmdline_from_dmesg(self, default_cmdline: str) -> str:
        for line in self.dmesg_lines:
            marker = "Command line:"
            if marker in line:
                return line.split(marker, 1)[1].strip()
        return default_cmdline

    def connect(self, auth_info: dict) -> HoneypotSession:
        logging.info(f"FakeFSDataHandler.connect: {auth_info}")
        return HoneypotSession(
            {
                "cwd": "/",
                "fs": self.fakefs,
                "username": auth_info.get("username", self.username),
                "hostname": self.hostname,
            }
        )

    def query(self, query: str, session: HoneypotSession, **kwargs) -> str:
        logging.info(f"FakeFSDataHandler.query: {query}")
        query = normalize_command_input(query)

        if not self._should_bypass_data_file(query) and self._data_file.exists():
            file_response = self.query_from_file(query)
            if file_response is not None:
                session["_last_parser_action"] = "hardcoded"
                return file_response

        system_response = self._handle_system_artifacts(query, session)
        if system_response is not None:
            session["_last_parser_action"] = "hardcoded"
            return self._strip_terminal_trailing_newlines(system_response)

        if "fs" in session:
            if query.startswith("ls"):
                parts = query.strip().split()
                flags = [p for p in parts if p.startswith("-")]
                session["_last_parser_action"] = "builtin"
                return handle_ls(session, flags=" ".join(flags))

            elif query.startswith("cd "):
                parts = query.split(maxsplit=1)
                if len(parts) == 2:
                    session["_last_parser_action"] = "builtin"
                    return handle_cd(session, parts[1])
                session["_last_parser_action"] = "blocked"
                return "Usage: cd <dir>"
            elif query.startswith("mkdir "):
                parts = query.split(maxsplit=1)
                if len(parts) == 2:
                    session["_last_parser_action"] = "builtin"
                    return handle_mkdir(session, parts[1])
                session["_last_parser_action"] = "blocked"
                return "Usage: mkdir <dir>"
            elif "wget" in query.lower() or "curl" in query.lower():
                parts = query.strip().split()
                if len(parts) >= 2:
                    url = parts[-1]
                    logging.info(f"[FakeFSDataHandler] Handling download: {url}")
                    session["_last_parser_action"] = "builtin"
                    return handle_download(session, url)
                logging.warning("[FakeFSDataHandler] Invalid wget/curl syntax")
                session["_last_parser_action"] = "blocked"
                return "Usage: wget <url> or curl <url>"
        session["_last_parser_action"] = "unknown"
        return None

    def _should_bypass_data_file(self, query: str) -> bool:
        return self._primary_command_name(query) == "uname"

    def _primary_command_name(self, query: str) -> str:
        try:
            command = shlex.split(query)[0]
        except (ValueError, IndexError):
            return ""

        return Path(command).name

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

    def _handle_system_artifacts(
        self, query: str, session: HoneypotSession
    ) -> Optional[str]:
        if query == "whoami":
            return f"{self.username}\n"
        if query == "id":
            return self._render_id()
        if query.startswith("id "):
            return self._handle_id(query)
        if query == "hostname":
            return f"{self.hostname}\n"
        if query in ("hostname -f", "hostname --fqdn"):
            return f"{self.hostname}.localdomain\n"
        if query == "pwd":
            return f"{self._cwd_for(session)}\n"
        if query == "uptime":
            return self._render_uptime()
        if query == "df -h":
            return self._render_df_h()
        if query == "free -m":
            return self._render_free_m()
        if query in ("ip a", "ip addr", "ip address"):
            return self._render_ip_addr()
        if query == "ifconfig":
            return self._render_ifconfig()
        if query == "which wget":
            return "/usr/bin/wget\n"
        if query == "which curl":
            return "/usr/bin/curl\n"
        if query == "which busybox":
            return "/bin/busybox\n"

        if self._primary_command_name(query) == "uname":
            return self._handle_uname(query)

        if query in ("cat /etc/os-release", "cat /etc/*release"):
            return self.os_release_content + "\n"
        if query == "cat /etc/issue":
            return f"{self.distro_name}\\n\\l\n"
        if query == "cat /etc/passwd":
            return self._render_passwd()

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

        if query == "ps aux":
            return self._render_ps_aux_output()
        if query in ("ps", "ps -ef"):
            return self._render_ps_output()
        if query.startswith("ss ") or query == "ss":
            return self._render_ss_output()
        if query.startswith("netstat"):
            return self._render_netstat_output()
        if query.startswith("lsof"):
            return self._render_lsof_output()

        return None

    def _cwd_for(self, session: Optional[HoneypotSession]) -> str:
        if session and session.get("cwd"):
            return session["cwd"]
        return "/"

    def _strip_terminal_trailing_newlines(self, response: str) -> str:
        return response.rstrip("\r\n")

    def _render_id(self) -> str:
        return (
            f"uid={self.uid}({self.username}) gid={self.gid}({self.group}) "
            f"groups={self.gid}({self.group})\n"
        )

    def _handle_id(self, query: str) -> str:
        try:
            parts = shlex.split(query)
        except ValueError:
            return self._render_id()

        if len(parts) == 2:
            if parts[1] in ("-u", "--user"):
                return f"{self.uid}\n"
            if parts[1] in ("-g", "--group"):
                return f"{self.gid}\n"
            if parts[1] in ("-un", "-nu", "--name"):
                return f"{self.username}\n"
            if parts[1] in ("-gn", "-ng"):
                return f"{self.group}\n"
        return self._render_id()

    def _render_passwd(self) -> str:
        lines = [
            "root:x:0:0:root:/root:/bin/sh",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
            "sync:x:4:65534:sync:/bin:/bin/sync",
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
            "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
            "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
            "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
            "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            "sshd:x:102:65534::/run/sshd:/usr/sbin/nologin",
        ]
        if self.username != "root":
            lines.append(
                f"{self.username}:x:{self.uid}:{self.gid}:"
                f"{self.username}:/home/{self.username}:/bin/sh"
            )
        return "\n".join(lines) + "\n"

    def _render_uptime(self) -> str:
        return " 13:37:42 up 5 days,  4:17,  1 user,  load average: 0.00, 0.01, 0.05\n"

    def _render_df_h(self) -> str:
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            f"{self.root_device}        20G  6.4G   13G  34% /\n"
            "tmpfs           997M     0  997M   0% /dev/shm\n"
            "tmpfs           399M  1.2M  398M   1% /run\n"
            "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
        )

    def _render_free_m(self) -> str:
        total = self.mem_total_kb // 1024
        used = max(total // 3, 1)
        free = max(total - used - 128, 0)
        shared = max(total // 128, 1)
        buff_cache = max(total - used - free, 0)
        available = free + buff_cache
        swap_total = 1024 if total >= 1024 else 0
        swap_used = 0
        swap_free = swap_total - swap_used
        return (
            "              total        used        free      shared  buff/cache   available\n"
            f"Mem:           {total:4d}        {used:4d}        {free:4d}"
            f"          {shared:2d}        {buff_cache:4d}        {available:4d}\n"
            f"Swap:          {swap_total:4d}        {swap_used:4d}        {swap_free:4d}\n"
        )

    def _render_ip_addr(self) -> str:
        return (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN "
            "group default qlen 1000\n"
            "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
            "    inet 127.0.0.1/8 scope host lo\n"
            "       valid_lft forever preferred_lft forever\n"
            f"2: {self.interface}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 "
            "qdisc fq_codel state UP group default qlen 1000\n"
            f"    link/ether {self.mac_address} brd ff:ff:ff:ff:ff:ff\n"
            f"    inet {self.ip_address}/{self.cidr_prefix} brd {self.broadcast} "
            f"scope global dynamic {self.interface}\n"
            "       valid_lft 86342sec preferred_lft 86342sec\n"
            "    inet6 fe80::5054:ff:fe12:3456/64 scope link\n"
            "       valid_lft forever preferred_lft forever\n"
        )

    def _render_ifconfig(self) -> str:
        return (
            f"{self.interface}: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            f"        inet {self.ip_address}  netmask {self.netmask}  "
            f"broadcast {self.broadcast}\n"
            "        inet6 fe80::5054:ff:fe12:3456  prefixlen 64  scopeid 0x20<link>\n"
            f"        ether {self.mac_address}  txqueuelen 1000  (Ethernet)\n"
            "        RX packets 1842  bytes 214287 (209.2 KiB)\n"
            "        RX errors 0  dropped 0  overruns 0  frame 0\n"
            "        TX packets 971  bytes 126042 (123.0 KiB)\n"
            "        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0\n"
            "\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
            "        loop  txqueuelen 1000  (Local Loopback)\n"
            "        RX packets 12  bytes 1024 (1.0 KiB)\n"
            "        TX packets 12  bytes 1024 (1.0 KiB)\n"
        )

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

    def _render_ps_aux_output(self) -> str:
        return (
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root           1  0.0  0.3 168420  6908 ?        Ss   09:17   0:01 /sbin/init\n"
            "root         112  0.0  0.2  15436  5120 ?        Ss   09:17   0:00 /usr/sbin/sshd -D\n"
            "root         118  0.0  0.1   6816  2864 ?        Ss   09:17   0:00 /usr/sbin/cron -f\n"
            "syslog       130  0.0  0.2 222400  4864 ?        Ssl  09:17   0:00 /usr/sbin/rsyslogd -n\n"
            "root         210  0.0  0.4  55284  9320 ?        Ss   09:18   0:00 nginx: master process /usr/sbin/nginx\n"
            "www-data     211  0.0  0.3  55824  7204 ?        S    09:18   0:00 nginx: worker process\n"
            f"{self.username:<8}    642  0.0  0.1   4632  3780 pts/0    Ss   13:37   0:00 -sh\n"
            f"{self.username:<8}    711  0.0  0.1   7484  3188 pts/0    R+   13:37   0:00 ps aux\n"
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

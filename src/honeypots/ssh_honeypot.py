import logging
import os
import select
import shlex
import socket
import stat
import threading
import time
from pathlib import Path

import paramiko
from paramiko import (
    SFTPAttributes,
    SFTPHandle,
    SFTP_NO_SUCH_FILE,
    SFTP_OK,
    SFTP_PERMISSION_DENIED,
    SFTPServer,
    SFTPServerInterface,
    Transport,
)
from paramiko.ssh_exception import SSHException

from honeypots.base_honeypot import BaseHoneypot, HoneypotSession
from infra.interfaces import HoneypotAction
from infra.prompt_utils import render_prompt
from analysis.ssh_fingerprint import FingerprintingTransport


CLEAR_SCREEN = "\x1b[2J\x1b[H"


def normalize_terminal_output(output: str) -> str:
    text = "" if output is None else str(output)
    text = text.rstrip("\r\n")
    return text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")


class EnhancedParamikoFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self.seen_errors = set()
        self.tracebacks_in_progress = False

    def filter(self, record):
        message = record.getMessage()
        if "EOFError" in message:
            return False

        if "Error reading SSH protocol banner" in message:
            # Only log the initial error message, not the traceback
            if not self.tracebacks_in_progress:
                self.seen_errors.add("SSH banner error")
            return False

        if "Socket exception: Connection reset by peer" in message:
            return False

        # Skip tracebacks
        if "Traceback (most recent call last)" in message:
            self.tracebacks_in_progress = True
            return False

        # If we're in a traceback, continue skipping
        if self.tracebacks_in_progress:
            # Check end of the traceback
            if message.strip() == "":
                self.tracebacks_in_progress = False
            return False
        return True


paramiko_logger = logging.getLogger("paramiko.transport")
paramiko_logger.addFilter(EnhancedParamikoFilter())


class SSHServerInterface(paramiko.ServerInterface):
    def __init__(self, action: HoneypotAction, honeypot: BaseHoneypot, config):
        self.client_addr: str | None = None
        self.transport: paramiko.Transport | None = None
        self._action = action
        self.username = None
        self.session = None
        self.honeypot = honeypot
        self.config = config or {}
        self._authenticated = False

    @property
    def action(self):
        return (
            self._action
            if self._action is not None
            else getattr(self.honeypot, "action", None)
        )

    @action.setter
    def action(self, value):
        self._action = value

    def get_allowed_auths(self, username):
        # Explicitly advertise password auth
        return "password"  # paramiko expects a comma-separated list

    def check_auth_password(self, username, password):
        logging.info("Authentication attempt: %s", username)
        self.username = username
        client_ip = self.client_addr
        if self.session is None:
            self.session = HoneypotSession()

        if client_ip is None and self.transport:
            try:
                client_ip = self.transport.getpeername()[0]
            except (OSError, SSHException):
                client_ip = "unknown"

        # Evaluate attempt through the password manager (logs every try)
        accepted = self.honeypot._password_manager.attempt(
            self.session, username, password, client_ip
        )

        attempt = self.session.get("_last_auth_attempt") or {}
        self.honeypot.log_auth_attempt(
            self.session,
            username=attempt.get("username", username),
            password=attempt.get("password", password),
            client_ip=attempt.get("client_ip", client_ip),
            attempt_number=attempt.get("attempt_number"),
            required_attempts=attempt.get("required_attempts"),
            success=bool(attempt.get("success", accepted)),
        )

        if not accepted:
            return paramiko.AUTH_FAILED

        # Accepted: wire up backend session
        self._authenticated = True
        if self.action is not None:
            try:
                creds = {"username": username, "password": password, "client_ip": client_ip}
                sess = self.action.connect(creds)
                if isinstance(sess, dict):
                    sid = self.session.session_id
                    self.session.update(sess)
                    self.session["session_id"] = sid
            except (SSHException, OSError) as e:
                logging.warning("Backend connect failed, continuing auth: %r", e)
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return (
            paramiko.OPEN_SUCCEEDED
            if kind == "session"
            else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        )

    # noinspection PyTypeChecker
    def handle_scp_upload(self, channel, command_str):
        try:
            channel.settimeout(10.0)
            logging.info(f"Handling SCP upload: {command_str}")

            # Step 1: Initial handshake
            channel.sendall(b"\x00")
            logging.info("Sent initial null byte to acknowledge SCP -t")

            # Step 2: Wait until header is ready to be read
            start_time = time.time()
            while True:
                rlist, _, _ = select.select([channel], [], [], 0.5)
                if rlist:
                    break
                if time.time() - start_time > 10:
                    raise TimeoutError("Timeout waiting for SCP header.")

            # Step 3: Read SCP header (e.g., C0644 1234 filename.txt\n)
            header = b""
            while not header.endswith(b"\n"):
                chunk = channel.recv(1)
                if not chunk:
                    logging.warning(
                        "SCP upload aborted: empty chunk while reading header"
                    )
                    return
                header += chunk
            logging.info(f"Received header: {header!r}")

            if not header.startswith(b"C"):
                logging.error("Invalid SCP header, expected 'C...'")
                return

            parts = header.strip().split(b" ")
            if len(parts) != 3:
                logging.error("Invalid SCP header format.")
                return

            mode = parts[0].decode()  # C0644
            size = int(parts[1])  # file size
            filename = parts[2].decode()

            logging.info(f"SCP Uploading file: {filename} ({size} bytes)")
            channel.sendall(b"\x00")  # Acknowledge file header

            # Step 4: Receive file content
            file_data = b""
            while len(file_data) < size:
                chunk = channel.recv(min(4096, size - len(file_data)))
                if not chunk:
                    logging.warning("Client closed before full file sent.")
                    return
                file_data += chunk

            # Step 5: Expect and check final null byte
            final_ack = channel.recv(1)
            if final_ack != b"\x00":
                logging.warning(f"Expected final ack null byte, got {final_ack!r}")

            # Step 6: Save the file
            upload_dir = self.config.get(
                "upload_dir",
                os.environ.get("HONEYPOT_UPLOAD_DIR", "/data/honeypot/uploads"),
            )
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, os.path.basename(filename))
            with open(file_path, "wb") as f:
                f.write(file_data)
            logging.info(f"File {filename} saved to {file_path}")

            # Step 7: Final ACK to sender
            channel.sendall(b"\x00")

        except TimeoutError as te:
            logging.error(f"SCP upload timed out: {te}")
        except (SSHException, OSError) as e:
            logging.error(f"Error handling SCP upload: {e}")
            try:
                channel.send(b"\x01")
            except OSError as e:
                logging.getLogger(f"Failed to start honeypot: {e}")


    def check_channel_exec_request(self, channel, command):
        command_str = command.decode().strip()
        logging.info(f"Command executed: {command_str}")
        channel.settimeout(60.0)

        try:
            parts = shlex.split(command_str)
        except ValueError:
            parts = []
        if parts and parts[0] == "scp" and "-t" in parts:
            logging.info("Detected SCP upload request.")
            self.handle_scp_upload(channel, command_str)
            return True

        try:
            # Check if action is available
            if self.action is None:
                logging.error("No action available for command processing")
                channel.sendall(b"Command not available")
                channel.send_exit_status(1)
                channel.shutdown_write()
                return False

            if command_str == "clear":
                output = CLEAR_SCREEN
                parser_action = "builtin"
            else:
                result = self.action.query(command_str, self.session)
                output = result["output"] if isinstance(result, dict) else str(result)
                parser_action = self.session.pop("_last_parser_action", "unknown")

            self.honeypot.log_command(
                self.session,
                raw=command_str,
                response=output,
                parser_action=parser_action,
                exit_code=0,
            )

            if command_str == "clear":
                channel.sendall(CLEAR_SCREEN.encode())
            else:
                payload = normalize_terminal_output(output)
                if payload:
                    payload += "\r\n"
                channel.sendall(payload.encode())
            channel.send_exit_status(0)
            def safe_shutdown():
                try:
                    channel.shutdown_write()
                except (EOFError, OSError):
                    pass

            threading.Timer(0.1, safe_shutdown).start()
            return True

        except (SSHException, OSError) as e:
            logging.error(f"Error executing command: {e}")
            try:
                channel.send_exit_status(1)
                def safe_shutdown():
                    try:
                        channel.shutdown_write()
                    except (EOFError, OSError):
                        pass

                threading.Timer(0.1, safe_shutdown).start()
            except (SSHException, OSError) as e:
                logging.error(f"Error sending exit status: {e}")
            return False

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.handle_shell, args=(channel,)).start()
        return True

    def handle_shell(self, channel):
        try:
            cwd = self.session.get("cwd", "/")
            prompt_template = (
                self.config.get("prompt_template")
                or self.config.get("shell-prompt")
                or f"{self.username}@SSHServer:{cwd}$ "
            )

            while not channel.closed:
                # Re-render prompt each loop to reflect updated session (cwd, username)
                prompt = render_prompt(prompt_template, self.session)
                buffer = ""
                channel.send(prompt)
                escape_seq = ""

                while True:
                    data = channel.recv(1)
                    if not data:
                        return

                    char = data.decode("utf-8", errors="ignore")

                    if char == "\x1b":
                        escape_seq = char
                        continue

                    if escape_seq:
                        escape_seq += char
                        if len(escape_seq) == 2 and char != "[":
                            channel.send(escape_seq)
                            escape_seq = ""
                        elif len(escape_seq) == 3:
                            # Ignore arrow keys: ↑↓←→
                            if escape_seq in ("\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D"):
                                pass  # Ignore silently
                            else:
                                channel.send(escape_seq)
                            escape_seq = ""
                        continue

                    if char in ("\r", "\n"):
                        break
                    elif char == "\x7f":  # Backspace
                        if buffer:
                            buffer = buffer[:-1]
                            channel.send("\b \b")
                    else:
                        buffer += char
                        channel.send(char)

                command = buffer.strip()
                if not command:
                    channel.send("\r\n")
                    continue

                logging.info(f"Shell command: {command}")

                if command.lower() in ["exit", "quit", "logout"]:
                    channel.send("\r\nConnection closed.\r\n")
                    break

                if command == "clear":
                    self.honeypot.log_command(
                        self.session,
                        raw=command,
                        response="",
                        parser_action="builtin",
                        exit_code=0,
                    )
                    channel.send(CLEAR_SCREEN)
                    continue

                if self.action is None:
                    channel.send(b"\r\nCommand not available\r\n")
                    continue

                response = self.action.query(command, self.session)
                output = (
                    response["output"] if isinstance(response, dict) else str(response)
                )
                parser_action = self.session.pop("_last_parser_action", "unknown")
                self.honeypot.log_command(
                    self.session,
                    raw=command,
                    response=output,
                    parser_action=parser_action,
                    exit_code=0,
                )
                payload = normalize_terminal_output(output)
                if payload:
                    channel.send(("\r\n" + payload + "\r\n").encode())
                else:
                    channel.send("\r\n")

        except (SSHException, OSError) as e:
            logging.error(f"Shell error: {e}")
        finally:
            try:
                channel.close()
            except (EOFError, OSError):
                pass


class HoneypotSFTPServerInterface(SFTPServerInterface):
    def __init__(self, server, honeypot=None, config=None):
        super().__init__(server)
        self.honeypot = honeypot
        self.config = config or {}
        upload_dir = self.config.get(
            "upload_dir", os.environ.get("HONEYPOT_UPLOAD_DIR", "/data/honeypot/uploads")
        )
        self.upload_dir = Path(upload_dir)
        self.upload_dir.mkdir(parents=True, exist_ok=True)

    def _remote_path(self, path: str) -> Path:
        if not path or path == "/":
            return self.upload_dir
        return self.upload_dir / Path(path).name

    @staticmethod
    def _attrs(path: Path) -> SFTPAttributes:
        return SFTPAttributes.from_stat(path.stat())

    def stat(self, path):
        local_path = self._remote_path(path)
        if local_path.exists():
            return self._attrs(local_path)
        return SFTP_NO_SUCH_FILE

    lstat = stat

    def list_folder(self, path):
        local_path = self._remote_path(path)
        if not local_path.exists() or not local_path.is_dir():
            return SFTP_NO_SUCH_FILE

        entries = []
        for child in local_path.iterdir():
            attr = self._attrs(child)
            attr.filename = child.name
            entries.append(attr)
        return entries

    def canonicalize(self, path):
        return "/" if not path else path

    def open(self, path, flags, attr):
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND) == 0:
            return SFTP_PERMISSION_DENIED

        local_path = self._remote_path(path)
        local_path.parent.mkdir(parents=True, exist_ok=True)

        if flags & os.O_APPEND:
            mode = "ab"
        elif flags & os.O_RDWR:
            mode = "w+b"
        else:
            mode = "wb"

        try:
            file_obj = local_path.open(mode)
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)

        handle = SFTPHandle(flags)
        handle.writefile = file_obj
        if flags & os.O_RDWR:
            handle.readfile = file_obj
        handle.filename = str(local_path)
        return handle

    def remove(self, path):
        local_path = self._remote_path(path)
        if not local_path.exists():
            return SFTP_NO_SUCH_FILE
        try:
            local_path.unlink()
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return SFTP_OK

    def rename(self, oldpath, newpath):
        old_local = self._remote_path(oldpath)
        new_local = self._remote_path(newpath)
        if not old_local.exists():
            return SFTP_NO_SUCH_FILE
        new_local.parent.mkdir(parents=True, exist_ok=True)
        try:
            old_local.replace(new_local)
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return SFTP_OK

    def mkdir(self, path, attr):
        local_path = self._remote_path(path)
        try:
            local_path.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return SFTP_OK

    def rmdir(self, path):
        local_path = self._remote_path(path)
        if not local_path.exists():
            return SFTP_NO_SUCH_FILE
        try:
            local_path.rmdir()
        except OSError as exc:
            return paramiko.SFTPServer.convert_errno(exc.errno)
        return SFTP_OK


class SSHHoneypot(BaseHoneypot):
    def __init__(self, port=0, action: HoneypotAction = None, config: dict = None):
        super().__init__(port, config)
        self.server_socket = None
        self.running = False
        self.session = {}
        self.host_key = self._load_host_key()
        self.action = action
        from core.password_manager import PasswordManager
        self._password_manager = PasswordManager(config)

    def _load_host_key(self):
        import os
        from paramiko import RSAKey

        key_path_env = os.environ.get("HONEYPOT_HOST_KEY")
        if key_path_env:
            key_path = Path(key_path_env)
        else:
            cfg_dir = (self.config or {}).get("config_dir")
            key_path = Path(cfg_dir) / "host.key" if cfg_dir else Path("host.key")

        if not key_path.exists():
            key_path.parent.mkdir(parents=True, exist_ok=True)
            RSAKey.generate(4096).write_private_key_file(str(key_path))

        return RSAKey(filename=str(key_path))

    def start(self):
        logging.getLogger("paramiko.transport").setLevel(logging.WARNING)
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(("0.0.0.0", self.port))
        if self.port == 0:
            self.port = self.server_socket.getsockname()[1]
        cfg_dir = (self.config or {}).get("config_dir")
        if cfg_dir:
            try:
                with open(os.path.join(cfg_dir, "bound_port"), "w") as f:
                    f.write(str(self.port))
            except OSError:
                pass
        self.server_socket.listen(100)
        self.running = True

        logging.info(f"SSH Honeypot running on port {self.port}")
        threading.Thread(target=self._listen, daemon=True).start()
        return self

    def _listen(self):
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                client_socket.settimeout(10)
                threading.Thread(
                    target=self._handle_client, args=(client_socket, addr), daemon=True
                ).start()
            except ConnectionAbortedError:
                break
            except OSError as e:
                # Handle "Invalid argument" error when shutting down
                if e.errno == 22 and not self.running:
                    break
                logging.error(f"Socket error in _listen: {e}")
                if self.running:
                    time.sleep(0.1)

    def _handle_client(self, client_socket, addr):
        transport = None
        peer = f"{addr[0]}:{addr[1]}"
        start_ts = time.time()
        session = HoneypotSession({"client_ip": addr[0]})
        close_reason = "closed"
        try:
            logging.info("SSH connection accepted from %s", peer)
            self.log_session_start(session, client_ip=addr[0])
            transport = FingerprintingTransport(client_socket)
            # Use configured SSH banner when available to match the fake system
            banner = (self.config or {}).get("ssh_banner") if hasattr(self, "config") else None
            transport.local_version = banner or "SSH-2.0-OpenSSH_8.9p1"
            transport.handshake_timeout = 30
            transport.banner_timeout = 30

            logging.info(
                "SSH handshake starting for %s (server_banner=%s, banner_timeout=%ss, handshake_timeout=%ss)",
                peer,
                transport.local_version,
                transport.banner_timeout,
                transport.handshake_timeout,
            )

            handler = SSHServerInterface(self.action, self, self.config)
            handler.client_addr = addr[0]
            handler.transport = transport
            handler.session = session

            transport.add_server_key(self.host_key)
            transport.set_subsystem_handler(
                "sftp",
                SFTPServer,
                HoneypotSFTPServerInterface,
                honeypot=self,
                config=self.config,
            )
            transport.start_server(server=handler)

            # Log SSH client fingerprint after handshake
            fp = transport.client_fingerprint()
            if any(fp.values()):
                session["ssh_fingerprint"] = fp
                self.log_data(session, {"ssh_fingerprint": fp})
                logging.info(
                    "SSH fingerprint from %s: banner=%s hassh=%s",
                    peer, fp.get("client_banner"), fp.get("hassh"),
                )

            logging.info("SSH server banner exchanged with %s, waiting for channel requests", peer)

            while transport.is_active() and (time.time() - start_ts < 60):
                channel = transport.accept(1)
                if channel:
                    logging.info("SSH channel opened from %s (active=%s)", peer, transport.is_active())
                    channel.event.wait()

        except EOFError:
            elapsed = time.time() - start_ts
            close_reason = "client_disconnected"
            logging.warning("SSH client disconnected early from %s after %.2fs", peer, elapsed)
        except (SSHException, OSError) as e:
            elapsed = time.time() - start_ts
            message = str(e)
            if "SSH protocol banner" in message:
                close_reason = "banner_error"
                logging.warning(
                    "SSH banner read failed from %s after %.2fs: %s",
                    peer,
                    elapsed,
                    message,
                )
            elif "Connection reset by peer" in message:
                close_reason = "connection_reset"
                logging.info(
                    "SSH peer reset connection during handshake from %s after %.2fs: %s",
                    peer,
                    elapsed,
                    message,
                )
            else:
                close_reason = "ssh_error"
                logging.error(
                    "SSH error from %s after %.2fs: %s",
                    peer,
                    elapsed,
                    message,
                    exc_info=True,
                )
        finally:
            if transport:
                try:
                    transport.close()
                except (EOFError, OSError):
                    pass
            self.log_session_end(
                session,
                client_ip=addr[0],
                username=session.get("username"),
                close_reason=close_reason,
            )
            logging.info("SSH connection closed for %s", peer)

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

            try:
                self.server_socket.close()
            except OSError:
                pass

        logging.info("SSH Honeypot stopped")

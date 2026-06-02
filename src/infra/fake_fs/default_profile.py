DEFAULT_MODIFIED_AT = "2026-01-15T09:24:00"


def make_dir(path: str, permissions: str = "drwxr-xr-x", owner: str = "root") -> dict:
    return {
        "path": path,
        "is_dir": True,
        "permissions": permissions,
        "owner": owner,
        "modified_at": DEFAULT_MODIFIED_AT,
    }


def make_file(
    path: str,
    content: str,
    permissions: str = "-rw-r--r--",
    owner: str = "root",
) -> dict:
    return {
        "path": path,
        "is_dir": False,
        "permissions": permissions,
        "owner": owner,
        "size": len(content),
        "modified_at": DEFAULT_MODIFIED_AT,
        "content": content,
    }


def build_honeymind_profile(profile: dict) -> list[dict]:
    hostname = profile["hostname"]
    private_ip = profile["ip_address"]
    gateway = profile["gateway"]
    os_release = profile["os_release"]
    passwd = profile["passwd"]
    cpuinfo = profile["cpuinfo"]
    meminfo = profile["meminfo"]
    proc_version = profile["proc_version"]
    route = profile["proc_route"]

    entries = [
        make_dir("/"),
        make_dir("/etc"),
        make_dir("/etc/netplan"),
        make_dir("/etc/nginx"),
        make_dir("/etc/nginx/sites-enabled"),
        make_dir("/etc/mysql"),
        make_dir("/etc/mysql/mysql.conf.d"),
        make_dir("/etc/cron.d"),
        make_dir("/etc/ssh"),
        make_dir("/proc"),
        make_dir("/root", "drwx------"),
        make_dir("/root/.ssh", "drwx------"),
        make_dir("/home"),
        make_dir("/home/ubuntu", "drwxr-x---", "ubuntu"),
        make_dir("/home/ubuntu/.ssh", "drwx------", "ubuntu"),
        make_dir("/srv"),
        make_dir("/srv/app", "drwxr-xr-x", "deploy"),
        make_dir("/srv/app/logs", "drwxr-xr-x", "deploy"),
        make_dir("/var"),
        make_dir("/var/www"),
        make_dir("/var/www/html", "drwxr-xr-x", "www-data"),
        make_dir("/var/log"),
        make_dir("/var/log/nginx", "drwxr-xr-x", "www-data"),
        make_dir("/var/log/mysql", "drwxr-xr-x", "mysql"),
        make_dir("/var/backups", "drwxr-xr-x"),
        make_dir("/usr"),
        make_dir("/usr/local"),
        make_dir("/usr/local/bin"),
        make_dir("/opt"),
        make_dir("/opt/backup"),
        make_dir("/etc/docker"),
        make_dir("/root/.config", "drwx------"),
        make_dir("/var/lib"),
        make_dir("/var/lib/docker"),
        make_dir("/var/lib/docker/containers"),
        make_dir("/var/lib/docker/containers/fake-container-id"),
    ]

    entries.extend(
        [
            make_file("/etc/os-release", os_release),
            make_file("/etc/passwd", passwd),
            make_file(
                "/etc/group",
                "\n".join(
                    [
                        "root:x:0:",
                        "daemon:x:1:",
                        "sudo:x:27:ubuntu",
                        "www-data:x:33:",
                        "backup:x:34:",
                        "mysql:x:117:",
                        "docker:x:998:ubuntu",
                        "ubuntu:x:1000:",
                    ]
                )
                + "\n",
            ),
            make_file("/etc/hostname", f"{hostname}\n"),
            make_file(
                "/etc/hosts",
                f"127.0.0.1 localhost\n127.0.1.1 {hostname}\n{private_ip} {hostname}\n",
            ),
            make_file("/etc/resolv.conf", "nameserver 127.0.0.53\noptions edns0 trust-ad\n"),
            make_file("/etc/issue", "Ubuntu 20.04.6 LTS \\n \\l\n"),
            make_file(
                "/etc/motd",
                "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-91-generic x86_64)\n",
            ),
            make_file(
                "/etc/fstab",
                "UUID=fake-root-uuid / ext4 defaults,discard 0 1\n/swapfile none swap sw 0 0\n",
            ),
            make_file(
                "/etc/crontab",
                "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
                "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
                "25 6    * * *   root    test -x /usr/local/bin/backup.sh && /usr/local/bin/backup.sh\n",
            ),
            make_file(
                "/etc/sudoers",
                "Defaults env_reset\nDefaults mail_badpass\nroot ALL=(ALL:ALL) ALL\n%sudo ALL=(ALL:ALL) ALL\n",
                "-r--r-----",
            ),
            make_file(
                "/etc/ssh/sshd_config",
                "Port 22\nPermitRootLogin prohibit-password\nPasswordAuthentication yes\n"
                "ChallengeResponseAuthentication no\nUsePAM yes\nX11Forwarding yes\n",
            ),
            make_file(
                "/etc/netplan/50-cloud-init.yaml",
                f"network:\n  version: 2\n  ethernets:\n    eth0:\n      dhcp4: false\n"
                f"      addresses: [{private_ip}/24]\n      gateway4: {gateway}\n"
                "      nameservers:\n        addresses: [1.1.1.1, 8.8.8.8]\n",
            ),
            make_file(
                "/etc/systemd/resolved.conf",
                "[Resolve]\nDNS=1.1.1.1 8.8.8.8\nFallbackDNS=9.9.9.9\n",
            ),
            make_file("/proc/cpuinfo", cpuinfo),
            make_file("/proc/meminfo", meminfo),
            make_file("/proc/version", proc_version),
            make_file("/proc/net/route", route),
            make_file(
                "/root/.bash_history",
                "cd /srv/app\nls -la\ncat .env\nmysql -u appuser -p\n./backup.sh\n",
                "-rw-------",
            ),
            make_file(
                "/root/.ssh/authorized_keys",
                "ssh-rsa AAAAFAKEHONEYMINDKEY000000000000000000 root@admin-laptop # synthetic placeholder\n",
                "-rw-------",
            ),
            make_file("/root/.profile", "# ~/.profile\n[ -f ~/.bashrc ] && . ~/.bashrc\n"),
            make_file("/root/.bashrc", "alias ll='ls -alF'\nexport HISTCONTROL=ignoredups\n"),
            make_file("/root/notes.txt", "TODO rotate app password after staging deploy\n"),
            make_file("/root/todo.txt", "- clean old backups\n- move .env out of web root\n"),
            make_file("/root/.mysql_history", "show databases;\nuse appdb;\nselect user,password from users;\n"),
            make_file("/root/.wget-hsts", "# HSTS 1.0 Known Hosts database for GNU Wget.\n"),
            make_file(
                "/root/backup.sql",
                "-- HoneyMind synthetic backup\nCREATE DATABASE appdb;\nINSERT INTO users VALUES (1,'admin','fake_hash_not_real');\n",
                "-rw-------",
            ),
            make_file(
                "/home/ubuntu/.bash_history",
                "sudo systemctl status nginx\ncd /var/www/html\ncat config.php\n",
                "-rw-------",
                "ubuntu",
            ),
            make_file(
                "/home/ubuntu/.ssh/authorized_keys",
                "ssh-ed25519 AAAAFAKEHONEYMINDDEPLOYKEY000000000 ubuntu@deploy-box # synthetic placeholder\n",
                "-rw-------",
                "ubuntu",
            ),
            make_file("/home/ubuntu/.profile", "# ~/.profile\n[ -f ~/.bashrc ] && . ~/.bashrc\n", owner="ubuntu"),
            make_file("/home/ubuntu/.bashrc", "alias ll='ls -alF'\n", owner="ubuntu"),
            make_file("/home/ubuntu/notes.txt", "staging and prod share the same nginx template\n", owner="ubuntu"),
            make_file(
                "/home/ubuntu/deploy_key.old",
                "FAKE-SSH-PRIVATE-KEY-PLACEHOLDER-HONEYMIND-DO-NOT-USE\n",
                "-rw-------",
                "ubuntu",
            ),
            make_file(
                "/home/ubuntu/.git-credentials",
                "https://deploy:fake-honeymind-token@example.invalid\n",
                "-rw-------",
                "ubuntu",
            ),
            make_file(
                "/home/ubuntu/db_backup.sql",
                "-- synthetic mysql dump\nCREATE TABLE sessions(id int, token varchar(255));\n",
                "-rw-------",
                "ubuntu",
            ),
            make_file(
                "/var/www/html/index.html",
                "<html><head><title>Welcome</title></head><body><h1>nginx default site</h1></body></html>\n",
                owner="www-data",
            ),
            make_file("/var/www/html/info.php", "<?php phpinfo();\n", owner="www-data"),
            make_file(
                "/var/www/html/.env",
                "APP_ENV=production\nDB_HOST=127.0.0.1\nDB_USER=webapp\nDB_PASSWORD=dev_password_123\n"
                "API_KEY=HONEYMIND_FAKE_API_KEY\n",
                "-rw-r-----",
                "www-data",
            ),
            make_file(
                "/var/www/html/config.php",
                "<?php\n$DB_HOST='127.0.0.1';\n$DB_USER='webapp';\n$DB_PASS='changeme123';\n"
                "$password_hint='fake-web-password-only';\n",
                "-rw-r-----",
                "www-data",
            ),
            make_file(
                "/etc/nginx/nginx.conf",
                "user www-data;\nworker_processes auto;\nevents { worker_connections 768; }\n"
                "http { include /etc/nginx/sites-enabled/*; }\n",
            ),
            make_file(
                "/etc/nginx/sites-enabled/default",
                "server {\n    listen 80 default_server;\n    root /var/www/html;\n"
                "    index index.html index.php;\n    server_name _;\n}\n",
            ),
            make_file(
                "/var/log/nginx/access.log",
                "198.51.100.23 - - [15/Jan/2026:08:14:11 +0000] \"GET / HTTP/1.1\" 200 612\n"
                "203.0.113.44 - - [15/Jan/2026:08:16:02 +0000] \"GET /info.php HTTP/1.1\" 200 1240\n",
                owner="www-data",
            ),
            make_file(
                "/var/log/nginx/error.log",
                "2026/01/15 08:16:02 [error] 211#211: *17 open() \"/var/www/html/favicon.ico\" failed (2: No such file or directory)\n",
                owner="www-data",
            ),
            make_file(
                "/srv/app/.env",
                "APP_NAME=HoneyMindDemo\nAPP_ENV=production\nDB_HOST=mysql\nDB_PORT=3306\n"
                "DB_DATABASE=appdb\nDB_USERNAME=appuser\nDB_PASSWORD=dev_password_123\n"
                "MYSQL_PASSWORD=changeme123\n"
                "API_KEY=HONEYMIND_FAKE_API_KEY\n"
                "AWS_ACCESS_KEY_ID=HONEYMIND_FAKE_AWS_ACCESS_KEY_ID\n"
                "AWS_SECRET_ACCESS_KEY=HONEYMIND_FAKE_AWS_SECRET_ACCESS_KEY\n",
                "-rw-r-----",
                "deploy",
            ),
            make_file(
                "/srv/app/.env.backup",
                "APP_ENV=staging\nDB_PASSWORD=old_fake_password_123\nAPI_KEY=HONEYMIND_FAKE_BACKUP_API_KEY\n",
                "-rw-------",
                "deploy",
            ),
            make_file(
                "/srv/app/config.yaml",
                "server:\n  host: 0.0.0.0\n  port: 8080\ndatabase:\n  host: mysql\n  user: appuser\n",
                owner="deploy",
            ),
            make_file(
                "/srv/app/config.old",
                "database_password: changeme123\nlegacy_token: fake-honeymind-legacy-token\n",
                "-rw-------",
                "deploy",
            ),
            make_file(
                "/srv/app/docker-compose.yml",
                "version: '3.8'\nservices:\n  web:\n    image: nginx:1.24\n    ports:\n      - '80:80'\n"
                "  mysql:\n    image: mysql:8\n    environment:\n      MYSQL_PASSWORD: changeme123\n",
                owner="deploy",
            ),
            make_file(
                "/srv/app/package.json",
                '{"name":"honeymind-demo-app","version":"1.4.2","scripts":{"start":"node index.js"}}\n',
                owner="deploy",
            ),
            make_file(
                "/srv/app/app.py",
                "import os\nprint('starting web app on 0.0.0.0:8080')\n",
                owner="deploy",
            ),
            make_file(
                "/srv/app/logs/app.log",
                "2026-01-15T08:12:14Z INFO started web worker\n2026-01-15T08:16:02Z WARN missing favicon\n",
                owner="deploy",
            ),
            make_file(
                "/etc/mysql/mysql.conf.d/mysqld.cnf",
                "[mysqld]\nbind-address = 127.0.0.1\nmax_connections = 151\n",
            ),
            make_file(
                "/var/log/mysql/error.log",
                "2026-01-15T08:10:44.123456Z 0 [System] [MY-010116] [Server] /usr/sbin/mysqld ready for connections.\n",
                owner="mysql",
            ),
            make_file(
                "/etc/cron.d/backup",
                "MAILTO=root\n15 2 * * * root /usr/local/bin/backup.sh >/var/log/backup.log 2>&1\n",
            ),
            make_file(
                "/usr/local/bin/backup.sh",
                "#!/bin/sh\nset -eu\ntar czf /var/backups/app_backup.tar.gz /srv/app\n",
                "-rwxr-xr-x",
            ),
            make_file(
                "/opt/backup/backup.sh",
                "#!/bin/sh\nmysqldump -u appuser -pchangeme123 appdb > /var/backups/mysql_backup_2024-11-03.sql\n",
                "-rwxr-xr-x",
            ),
            make_file("/opt/backup/README.txt", "Legacy backup scripts. Credentials are synthetic HoneyMind placeholders.\n"),
            make_file(
                "/root/docker-compose.yml",
                "version: '3.8'\nservices:\n  web:\n    build: /srv/app\n  mysql:\n    image: mysql:8\n",
                "-rw-------",
            ),
            make_file("/etc/docker/daemon.json", '{"log-driver":"json-file","log-opts":{"max-size":"10m"}}\n'),
            make_file(
                "/var/lib/docker/containers/fake-container-id/config.v2.json",
                '{"Name":"/web-prod-01-web","Config":{"Image":"nginx:1.24"}}\n',
            ),
            make_file("/var/backups/app_backup.tar.gz", "FAKE-TAR-GZ-CONTENT-HONEYMIND\n", "-rw-------"),
            make_file(
                "/var/backups/mysql_backup_2024-11-03.sql",
                "-- synthetic backup\nCREATE DATABASE appdb;\n",
                "-rw-------",
            ),
        ]
    )

    return entries

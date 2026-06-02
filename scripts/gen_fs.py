#!/usr/bin/env python3
"""
Generate a base fake filesystem JSONL file for HoneyMind.

Edit the output file to add lure content, then pack it with:
    python scripts/pack_fs.py my_fs.jsonl
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from analysis.ai_traps import trap_files_for_fs

_D = True   # is_dir
_F = False  # is_file

DEBIAN_FS = [
    # --- Directories ---
    {"path": "/",                               "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/bin",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/boot",                           "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/dev",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/etc",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/etc/ssh",                        "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/etc/nginx",                      "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/etc/nginx/sites-available",      "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/etc/nginx/sites-enabled",        "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/etc/ssl",                        "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/etc/ssl/private",                "is_dir": _D, "permissions": "drwx------", "owner": "root"},
    {"path": "/etc/ssl/certs",                  "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/home",                           "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/home/debian",                    "is_dir": _D, "permissions": "drwxr-x--",  "owner": "debian"},
    {"path": "/home/debian/.ssh",               "is_dir": _D, "permissions": "drwx------", "owner": "debian"},
    {"path": "/home/debian/.aws",               "is_dir": _D, "permissions": "drwx------", "owner": "debian"},
    {"path": "/lib",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/media",                          "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/mnt",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/opt",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/opt/app",                        "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "debian"},
    {"path": "/proc",                           "is_dir": _D, "permissions": "dr-xr-xr-x", "owner": "root"},
    {"path": "/root",                           "is_dir": _D, "permissions": "drwx------", "owner": "root"},
    {"path": "/root/.ssh",                      "is_dir": _D, "permissions": "drwx------", "owner": "root"},
    {"path": "/root/.aws",                      "is_dir": _D, "permissions": "drwx------", "owner": "root"},
    {"path": "/run",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/sbin",                           "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/srv",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/sys",                            "is_dir": _D, "permissions": "dr-xr-xr-x", "owner": "root"},
    {"path": "/tmp",                            "is_dir": _D, "permissions": "drwxrwxrwt", "owner": "root"},
    {"path": "/usr",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/usr/bin",                        "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/usr/lib",                        "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/usr/local",                      "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/usr/local/bin",                  "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/usr/sbin",                       "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/usr/share",                      "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/var",                            "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/var/log",                        "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/var/log/nginx",                  "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "www-data"},
    {"path": "/var/www",                        "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/var/www/html",                   "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "www-data"},
    {"path": "/var/cache",                      "is_dir": _D, "permissions": "drwxr-xr-x", "owner": "root"},
    {"path": "/var/backups",                    "is_dir": _D, "permissions": "drwxr-x---", "owner": "root"},

    # --- /etc ---
    {
        "path": "/etc/passwd",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n"
            "debian:x:1000:1000:Debian,,,:/home/debian:/bin/bash\n"
        ),
    },
    {
        "path": "/etc/shadow",
        "is_dir": _F, "permissions": "-rw-r-----", "owner": "root",
        "content": (
            "root:$6$rounds=4096$TaJz3mVq$Kx8L2pQr9YnWbHcDfUe1sNvOiGjAk7ZmXtSw5BhMEpRyCdIoFlTu4VnJq6YgXaKw3PbNsRhUzLiWoEcMv0:19600:0:99999:7:::\n"
            "daemon:*:18858:0:99999:7:::\n"
            "nobody:*:18858:0:99999:7:::\n"
            "sshd:*:18858:0:99999:7:::\n"
            "debian:$6$rounds=4096$xy7Qm2Lp$Ab3Cd4Ef5Gh6Ij7Kl8Mn9Op0Qr1St2Uv3Wx4Yz5Aa6Bb7Cc8Dd9Ee0Ff1Gg2Hh3Ii4Jj5Kk6Ll7Mm8Nn9:19600:0:99999:7:::\n"
        ),
    },
    {
        "path": "/etc/group",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            "root:x:0:\n"
            "daemon:x:1:\n"
            "sudo:x:27:debian\n"
            "www-data:x:33:\n"
            "debian:x:1000:\n"
        ),
    },
    {
        "path": "/etc/hosts",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            "127.0.0.1\tlocalhost\n"
            "127.0.1.1\thoneymind-server\n"
            "::1\t\tlocalhost ip6-localhost ip6-loopback\n"
            "10.0.0.10\tdb01.internal\n"
            "10.0.0.11\tdb02.internal\n"
            "10.0.0.20\tredis.internal\n"
            "10.0.0.30\tmonitoring.internal\n"
        ),
    },
    {
        "path": "/etc/hostname",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": "honeymind-server\n",
    },
    {
        "path": "/etc/resolv.conf",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": "nameserver 8.8.8.8\nnameserver 8.8.4.4\nsearch internal\n",
    },
    {
        "path": "/etc/os-release",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
            'NAME="Debian GNU/Linux"\n'
            'VERSION_ID="12"\n'
            'VERSION="12 (bookworm)"\n'
            'VERSION_CODENAME=bookworm\n'
            'ID=debian\n'
        ),
    },
    {
        "path": "/etc/issue",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": "Debian GNU/Linux 12 \\n \\l\n",
    },
    {
        "path": "/etc/crontab",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
            "# m h dom mon dow user\tcommand\n"
            "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
            "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
            "*/5 * * * *\troot\t/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1\n"
        ),
    },
    {
        "path": "/etc/ssh/sshd_config",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            "Port 22\n"
            "PermitRootLogin yes\n"
            "PubkeyAuthentication yes\n"
            "AuthorizedKeysFile\t.ssh/authorized_keys\n"
            "PasswordAuthentication yes\n"
            "PermitEmptyPasswords no\n"
            "UsePAM yes\n"
            "X11Forwarding yes\n"
            "Subsystem\tsftp\t/usr/lib/openssh/sftp-server\n"
        ),
    },
    {
        "path": "/etc/nginx/nginx.conf",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            "user www-data;\n"
            "worker_processes auto;\n"
            "pid /run/nginx.pid;\n\n"
            "events { worker_connections 768; }\n\n"
            "http {\n"
            "    access_log /var/log/nginx/access.log;\n"
            "    error_log /var/log/nginx/error.log;\n"
            "    include /etc/nginx/sites-enabled/*;\n"
            "}\n"
        ),
    },
    {
        "path": "/etc/nginx/sites-available/default",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            "server {\n"
            "    listen 80 default_server;\n"
            "    root /var/www/html;\n"
            "    index index.html;\n\n"
            "    location / { try_files $uri $uri/ =404; }\n\n"
            "    location /admin {\n"
            "        proxy_pass http://127.0.0.1:8080;\n"
            "        auth_basic \"Admin Area\";\n"
            "        auth_basic_user_file /etc/nginx/.htpasswd;\n"
            "    }\n"
            "}\n"
        ),
    },

    # --- SSL private key (lure) ---
    {
        "path": "/etc/ssl/private/honeymind-server.key",
        "is_dir": _F, "permissions": "-rw-------", "owner": "root",
        "content": (
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC9mK7pLqRvNwTj\n"
            "Y4sHbCfUeGiDkPaVxZlQnRmWtBcCsFtEv9iKeMzOpLoMwXyUrSvJcHdIfVfOtDa\n"
            "PlWkamXnRqDsFuCyFzEjNoQtMvLpKiJiHg8cUrSvJbHdIfVeOtDaPlWkamXnRqDs\n"
            "FuCyFzEjNoQtMvLpKiJiHg8cUrSvJbHdIfVeOtDaPlWkamXnRqDsFuCyFzEjNoQt\n"
            "MvLpKiJiHg8cUrSvJbHdIfVeOtDaPlWkamXnRqDsFuCyFzEjNoQtMvLpKiJiHg8c\n"
            "UrSvJbHdIfVeOtDaPlWkamXnRqDsFuCyFzEjNoQtMvLpKiJiHg8cUrSvJbHdIfVe\n"
            "OtDaPlWkagMBAAECggEAIzK9pLqRvNwTjY4sHbCfUeGiDkPaVxZlQnRmWtBcCsF\n"
            "tEv9iKeMzOpLoMwXyUrSvJcHdIfVfOtDaPlWkamXnRqDsFuCyFzEjNoQtMvLpKi\n"
            "JiHg8cUrSvJbHdIfVeOtDaPlWkamXnRqDsFuCyFzEjNoQtMvLpKiJiHg8cUrSvJ\n"
            "bHdIfVeOtDaPlWkamXnRqDsFuCyFzEjNoQtMvLpKiJiHg8cUrSvJbHdIfVeOtDa\n"
            "PlWkamXnRqDsFuCyFzEjNoQtMvLpKiJiHg8cUrSvJbHdIfVeOtDaPlWkamXnRqD\n"
            "sFuCyFzEjNoQtMvLpKiJiHg8cUrSvJbHdIfVeOQKBgQDhmK7pLqRvNwTjY4sHbC\n"
            "fUeGiDkPaVxZlQnRmWtBcCsFtEv9iKeMzOpLoMwXyUrSvJcHdIfVfOtDaPlWkam\n"
            "XnRqDsFuCyFzEjNoQtMvLpKiJiHg8cUrSvJbHdIfVeOtDaPlWkamXnRqDsFuCyA\n"
            "oGBANXmK7pLqRvNwTjY4sHbCfUeGiDkPaVxZlQnRmWtBcCsFtEv9iKeMzOpLoMw\n"
            "XyUrSvJcHdIfVfOtDaPlWkamXnRqDsFuCyFzEjNoQtMvLpKiJiHg8cUrSvJbHdI\n"
            "fVeOtDaPlWkamXnRqDsFuCyFzEjNoQtMvLpKiJiHg8cUrSvJbHdIfVeOtEWAgYA\n"
            "-----END PRIVATE KEY-----\n"
        ),
    },
    {
        "path": "/etc/nginx/.htpasswd",
        "is_dir": _F, "permissions": "-rw-r-----", "owner": "root",
        "content": (
            "admin:$apr1$Kx3mP9vQ$nRjLwZuYtAbCdEfGhIjKlM0\n"
            "jdupont:$apr1$Ry7bN2wL$tAbCdEfGhIjKlMnOpQrStU1\n"
        ),
    },

    # --- Logs ---
    {
        "path": "/var/log/auth.log",
        "is_dir": _F, "permissions": "-rw-r-----", "owner": "root",
        "content": (
            "Jun  1 08:12:03 honeymind-server sshd[1234]: Accepted password for debian from 10.0.0.5 port 52341 ssh2\n"
            "Jun  1 09:45:11 honeymind-server sshd[2341]: Failed password for root from 185.220.101.42 port 39871 ssh2\n"
            "Jun  1 09:45:13 honeymind-server sshd[2341]: Failed password for root from 185.220.101.42 port 39871 ssh2\n"
            "Jun  1 09:45:15 honeymind-server sshd[2341]: Failed password for root from 185.220.101.42 port 39871 ssh2\n"
            "Jun  1 09:45:16 honeymind-server sshd[2341]: error: maximum authentication attempts exceeded for root from 185.220.101.42\n"
            "Jun  1 14:23:44 honeymind-server sudo: debian : TTY=pts/0 ; PWD=/home/debian ; USER=root ; COMMAND=/usr/bin/apt update\n"
        ),
    },
    {
        "path": "/var/log/syslog",
        "is_dir": _F, "permissions": "-rw-r-----", "owner": "root",
        "content": (
            "Jun  1 00:17:01 honeymind-server CRON[3456]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)\n"
            "Jun  1 08:12:03 honeymind-server systemd[1]: Started Session 4 of user debian.\n"
            "Jun  1 10:00:00 honeymind-server CRON[5678]: (root) CMD (/usr/local/bin/backup.sh >> /var/log/backup.log 2>&1)\n"
            "Jun  1 10:00:02 honeymind-server backup: Starting backup of /var/www/html to s3://internal-backups/web/\n"
            "Jun  1 10:00:15 honeymind-server backup: Backup completed: 142 files, 28.4 MB\n"
        ),
    },
    {
        "path": "/var/log/nginx/access.log",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "www-data",
        "content": (
            '10.0.0.1 - - [01/Jun/2026:08:00:01 +0000] "GET / HTTP/1.1" 200 612 "-" "Mozilla/5.0"\n'
            '185.220.101.42 - - [01/Jun/2026:09:44:32 +0000] "GET /admin HTTP/1.1" 401 188 "-" "curl/7.88.1"\n'
            '10.0.0.5 - - [01/Jun/2026:10:15:22 +0000] "GET /admin HTTP/1.1" 200 4821 "-" "Mozilla/5.0"\n'
        ),
    },
    {
        "path": "/var/log/nginx/error.log",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "www-data",
        "content": '2026/06/01 09:44:32 [error] 1234#1234: *42 no user/password was provided for basic authentication, client: 185.220.101.42\n',
    },

    # --- Web ---
    {
        "path": "/var/www/html/index.html",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "www-data",
        "content": (
            "<!DOCTYPE html><html>\n"
            "<head><title>Internal Portal</title></head>\n"
            "<body>\n"
            "<h1>Welcome to the Internal Portal</h1>\n"
            "<p>Authorized personnel only.</p>\n"
            "<p><a href='/admin'>Admin Panel</a></p>\n"
            "</body></html>\n"
        ),
    },

    # --- App (lure) ---
    {
        "path": "/opt/app/docker-compose.yml",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "debian",
        "content": (
            "version: '3.8'\n\n"
            "services:\n"
            "  app:\n"
            "    build: .\n"
            "    ports:\n"
            "      - '8080:8080'\n"
            "    env_file: .env\n"
            "    depends_on:\n"
            "      - db\n"
            "      - redis\n\n"
            "  db:\n"
            "    image: mysql:8.0\n"
            "    environment:\n"
            "      MYSQL_ROOT_PASSWORD: r00t_Mysql!2024\n"
            "      MYSQL_DATABASE: app_production\n"
            "      MYSQL_USER: app_user\n"
            "      MYSQL_PASSWORD: Sup3rS3cr3t!2024\n"
            "    volumes:\n"
            "      - db_data:/var/lib/mysql\n\n"
            "  redis:\n"
            "    image: redis:7-alpine\n"
            "    command: redis-server --requirepass redis_s3cr3t\n\n"
            "volumes:\n"
            "  db_data:\n"
        ),
    },
    {
        "path": "/opt/app/deploy.sh",
        "is_dir": _F, "permissions": "-rwxr-x---", "owner": "debian",
        "content": (
            "#!/bin/bash\n"
            "set -e\n\n"
            "DEPLOY_HOST=10.0.0.50\n"
            "DEPLOY_USER=deployer\n"
            "DEPLOY_KEY=/root/.ssh/id_rsa\n"
            "REPO=git@github.com:company-internal/app.git\n\n"
            "echo '[deploy] pulling latest...'\n"
            "git pull origin main\n\n"
            "echo '[deploy] syncing to prod...'\n"
            "rsync -avz --exclude='.git' -e \"ssh -i $DEPLOY_KEY\" \\\n"
            "    ./ $DEPLOY_USER@$DEPLOY_HOST:/opt/app/\n\n"
            "echo '[deploy] restarting services...'\n"
            "ssh -i $DEPLOY_KEY $DEPLOY_USER@$DEPLOY_HOST \\\n"
            "    'cd /opt/app && docker-compose up -d --build'\n\n"
            "echo '[deploy] done.'\n"
        ),
    },


    {
        "path": "/opt/app/.env",
        "is_dir": _F, "permissions": "-rw-r-----", "owner": "debian",
        "content": (
            "APP_ENV=production\n"
            "APP_KEY=base64:Xk3mP9vQnRjLwZuYtAbCdEfGhIjKlMnOpQrStUvWxYz=\n"
            "APP_DEBUG=false\n\n"
            "DB_HOST=db01.internal\n"
            "DB_PORT=3306\n"
            "DB_DATABASE=app_production\n"
            "DB_USERNAME=app_user\n"
            "DB_PASSWORD=Sup3rS3cr3t!2024\n\n"
            "REDIS_HOST=redis.internal\n"
            "REDIS_PASSWORD=redis_s3cr3t\n"
            "REDIS_PORT=6379\n\n"
            "AWS_ACCESS_KEY_ID=AKIAQXL7NBPZR3KWT4MC\n"
            "AWS_SECRET_ACCESS_KEY=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\n"
            "AWS_DEFAULT_REGION=eu-west-1\n"
            "S3_BUCKET=internal-backups\n"
        ),
    },
    {
        "path": "/opt/app/config.php",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "debian",
        "content": (
            "<?php\n"
            "return [\n"
            "    'db' => [\n"
            "        'host'     => 'db01.internal',\n"
            "        'user'     => 'app_user',\n"
            "        'password' => 'Sup3rS3cr3t!2024',\n"
            "        'dbname'   => 'app_production',\n"
            "    ],\n"
            "    'admin_email' => 'admin@internal.company.com',\n"
            "];\n"
        ),
    },

    # --- SSH keys (lure) ---
    {
        "path": "/root/.ssh/id_rsa",
        "is_dir": _F, "permissions": "-rw-------", "owner": "root",
        "content": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA7X2mK9pLqRvNwTjY3sHbCfUeGiDkOaVxZlPnQmWtAcBrFs\n"
            "Eu8hJdMzNpKoLwXyTqRvIbGcHfUeNsDaOkVjZlWmQpCrFtBxEyDiMnPsLuKoJh\n"
            "Gf7bTqRvIcDkNaVxZlWmQpEuFsBrCtAyHiDjMoLwXyTqRvNbGcHfUeNsDaOkVj\n"
            "ZlWmQpCrFtBxEyDiMnPsLuKoJhGf7bTqRvIcDkNaVxZlWmQpEuFsBrCtAyHiDj\n"
            "MoLwXyTqRvNbGcHfUeNsDaOkVjZlWmQpCrFtBxEyDiMnPsLuKoJhGf7bTqRvIc\n"
            "DkNaVxZlWmQpEuFsBrCtAyHiDjMoLwXyTqRvNwIDAQABAoIBAC5mK9pLqRvNwTj\n"
            "Y3sHbCfUeGiDkOaVxZlPnQmWtAcBrFsEu8hJdMzNpKoLwXyTqRvIbGcHfUeNsD\n"
            "aOkVjZlWmQpCrFtBxEyDiMnPsLuKoJhGf7bTqRvIcDkNaVxZlWmQpEuFsBrCtA\n"
            "yHiDjMoLwXyTqRvNbGcHfUeNsDaOkVjZlWmQpCrFtBxEyDiMnPsLuKoJhGf7bT\n"
            "qRvIcDkNaVxZlWmQpEuFsBrCtAyHiDjMoLwXyTqRvNbGcHfUeNsDaOkVjZlWmQp\n"
            "CrFtBxEyDiMnPsLuKoJhGf7bTqRvIcDkNaVxZlWmQpEuFsBrCtAyHiDjMoLwXy\n"
            "TqRvNbAoGBAP3mK9pLqRvNwTjY3sHbCfUeGiDkOaVxZlPnQmWtAcBrFsEu8hJd\n"
            "MzNpKoLwXyTqRvIbGcHfUeNsDaOkVjZlWmQpCrFtBxEyDiMnPsLuKoJhGf7bTq\n"
            "RvIcDkNaVxZlWmQpEuFsBrCtAyHiDjMoLwXyTqRvNbGcHfUeNsDaOkVjAoGBAO9\n"
            "mK9pLqRvNwTjY3sHbCfUeGiDkOaVxZlPnQmWtAcBrFsEu8hJdMzNpKoLwXyTqR\n"
            "vIbGcHfUeNsDaOkVjZlWmQpCrFtBxEyDiMnPsLuKoJhGf7bTqRvIcDkNaVxZlWm\n"
            "QpEuFsBrCtAyHiDjMoLwXyTqRvNbGcHfUeNsDaOkVjZlWmQpCrFtBxAoGBANHm\n"
            "K9pLqRvNwTjY3sHbCfUeGiDkOaVxZlPnQmWtAcBrFsEu8hJdMzNpKoLwXyTqRv\n"
            "IbGcHfUeNsDaOkVjZlWmQpCrFtBxEyDiMnPsLuKoJhGf7bTqRvIcDkNaVxZlWmQ\n"
            "pEuFsBrCtAyHiDjMoLwXyTqRvNbGcHfUeNsDaOkVjZlWmQpCrFtBxEyAoGADkm\n"
            "K9pLqRvNwTjY3sHbCfUeGiDkOaVxZlPnQmWtAcBrFsEu8hJdMzNpKoLwXyTqRv\n"
            "IbGcHfUeNsDaOkVjZlWmQpCrFtBxEyDiMnPsLuKoJhGf7bTqRvIcDkNaVxZlWmQ\n"
            "pEuFsBrCtAyHiDjMoLwXyTqRvNbGcHfUeNsDaOkVjZlWmQpCrFtBxEyCo=\n"
            "-----END RSA PRIVATE KEY-----\n"
        ),
    },
    {
        "path": "/root/.ssh/id_rsa.pub",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDtfaYr2kupG83BONjewdsJ8R4aIOQ5pXFmU+dCZa0BwGsWwQ7yEl0zM2kqgvBfJOpG9BsZwR8V5R4yw9oaRWOWVaZCkKvG0HEzIOIyc+wuIqIhh1Z+ttOpG8hwIQi6TkuJhGf7bTqRvIcDkNaVxZlWmQpEuFsBrCtAyHiDjMoLwXy root@honeymind-server\n",
    },
    {
        "path": "/root/.ssh/authorized_keys",
        "is_dir": _F, "permissions": "-rw-------", "owner": "root",
        "content": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDtfaYr2kupG83BONjewdsJ8R4aIOQ5pXFmU+dCZa0BwGsWwQ7yEl0zM2kqgvBfJOpG9BsZwR8V5R4yw9oaRWOWVaZCkKvG0HEzIOIyc+wuIqIhh1Z+ttOpG8hwIQi6TkuJhGf7bTqRvIcDk root@honeymind-server\n",
    },

    # --- Backup SQL dump (lure) ---
    {
        "path": "/var/backups/app_20260601.sql",
        "is_dir": _F, "permissions": "-rw-r-----", "owner": "root",
        "content": (
            "-- MySQL dump 10.19  Distrib 8.0.36\n"
            "-- Host: db01.internal  Database: app_production\n"
            "-- Date: 2026-06-01 02:00:01\n\n"
            "CREATE TABLE `users` (\n"
            "  `id` int NOT NULL AUTO_INCREMENT,\n"
            "  `username` varchar(64) NOT NULL,\n"
            "  `email` varchar(128) NOT NULL,\n"
            "  `password_hash` varchar(255) NOT NULL,\n"
            "  `role` enum('admin','user') DEFAULT 'user',\n"
            "  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB;\n\n"
            "INSERT INTO `users` VALUES\n"
            "(1,'admin','admin@internal.company.com','$2y$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.j7Ey','admin','2025-01-15 10:23:44'),\n"
            "(2,'jdupont','j.dupont@internal.company.com','$2y$12$KPv3c1yqBWVHxkd0LHAkCO7z6TtxMQJqhN8/LewdBPj4J/HS.j7Ez','user','2025-03-02 14:12:01'),\n"
            "(3,'mmartin','m.martin@internal.company.com','$2y$12$MPv3c1yqBWVHxkd0LHAkCO9z6TtxMQJqhN8/LewdBPj4J/HS.j7Ea','user','2025-04-18 09:44:22');\n\n"
            "CREATE TABLE `api_keys` (\n"
            "  `id` int NOT NULL AUTO_INCREMENT,\n"
            "  `user_id` int NOT NULL,\n"
            "  `key` varchar(64) NOT NULL,\n"
            "  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB;\n\n"
            "INSERT INTO `api_keys` VALUES\n"
            "(1,1,'sk-prod-4Xk9mP2vQnRjLwZuYtAbCdEfGhIjKlMnOpQrStUv','2025-06-01 00:00:00');\n"
        ),
    },

    # --- AWS credentials (lure) ---
    {
        "path": "/root/.aws/credentials",
        "is_dir": _F, "permissions": "-rw-------", "owner": "root",
        "content": (
            "[default]\n"
            "aws_access_key_id = AKIAQXL7NBPZR3KWT4MC\n"
            "aws_secret_access_key = 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\n"
            "region = eu-west-1\n\n"
            "[prod]\n"
            "aws_access_key_id = AKIAQXL7NBPZR3KWT4MC\n"
            "aws_secret_access_key = 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\n"
            "region = eu-west-1\n"
        ),
    },
    {
        "path": "/root/.aws/config",
        "is_dir": _F, "permissions": "-rw-------", "owner": "root",
        "content": "[default]\nregion = eu-west-1\noutput = json\n",
    },
    {
        "path": "/home/debian/.aws/credentials",
        "is_dir": _F, "permissions": "-rw-------", "owner": "debian",
        "content": (
            "[default]\n"
            "aws_access_key_id = AKIAQXL7NBPZR3KWT4MC\n"
            "aws_secret_access_key = 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\n"
            "region = eu-west-1\n"
        ),
    },

    # --- MySQL history (lure) ---
    {
        "path": "/root/.mysql_history",
        "is_dir": _F, "permissions": "-rw-------", "owner": "root",
        "content": (
            "show databases;\n"
            "use app_production;\n"
            "show tables;\n"
            "select id, username, email, password_hash from users;\n"
            "select * from api_keys;\n"
            "update users set role='admin' where username='jdupont';\n"
            "select * from users where role='admin';\n"
            "grant all privileges on app_production.* to 'app_user'@'%' identified by 'Sup3rS3cr3t!2024';\n"
            "flush privileges;\n"
        ),
    },

    # --- /tmp suspicious file ---
    {
        "path": "/tmp/linpeas.sh",
        "is_dir": _F, "permissions": "-rwxr-xr-x", "owner": "root",
        "content": (
            "#!/bin/bash\n"
            "# linpeas - Linux Privilege Escalation Awesome Script\n"
            "# Downloaded from: https://github.com/carlospolop/PEASS-ng\n"
            "# Run: ./linpeas.sh | tee /tmp/linpeas_output.txt\n"
            "echo '[*] Linux Privilege Escalation Checker'\n"
            "echo '[*] https://github.com/carlospolop/PEASS-ng'\n"
            "# [... truncated for brevity ...]\n"
        ),
    },
    {
        "path": "/tmp/linpeas_output.txt",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            "[*] Linux Privilege Escalation Checker\n"
            "[+] Operative system: Debian GNU/Linux 12 (bookworm)\n"
            "[+] Kernel: Linux 6.1.0-21-amd64\n"
            "[+] Are there any SUID binaries?\n"
            "-rwsr-xr-x 1 root root 71912 Jan 14 2025 /usr/bin/passwd\n"
            "-rwsr-xr-x 1 root root 40664 Jan 14 2025 /usr/bin/newgrp\n"
            "-rwsr-xr-x 1 root root 35128 Jan 14 2025 /usr/bin/umount\n"
            "[+] Interesting files in home dirs:\n"
            "/home/debian/.bash_history\n"
            "/root/.bash_history\n"
            "/root/.aws/credentials\n"
            "[+] Cron jobs:\n"
            "*/5 * * * * root /usr/local/bin/backup.sh\n"
        ),
    },

    # --- Home directories ---
    {
        "path": "/home/debian/.bash_history",
        "is_dir": _F, "permissions": "-rw-------", "owner": "debian",
        "content": (
            "ls -la\n"
            "cd /var/www/html\n"
            "sudo apt update && sudo apt upgrade -y\n"
            "mysql -u app_user -pSup3rS3cr3t!2024 -h db01.internal app_production\n"
            "ssh root@10.0.0.10\n"
            "cat /opt/app/.env\n"
            "cd /opt/app && git pull origin main\n"
            "sudo systemctl restart nginx\n"
            "cat /var/log/nginx/access.log | tail -50\n"
        ),
    },
    {
        "path": "/home/debian/.bashrc",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "debian",
        "content": (
            "# ~/.bashrc\n"
            "HISTCONTROL=ignoreboth\n"
            "HISTSIZE=1000\n"
            "alias ll='ls -alF'\n"
            "alias la='ls -A'\n"
        ),
    },
    {
        "path": "/home/debian/.ssh/authorized_keys",
        "is_dir": _F, "permissions": "-rw-------", "owner": "debian",
        "content": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3xK9mPvQnRjLwZuY debian@workstation\n",
    },
    {
        "path": "/root/.bash_history",
        "is_dir": _F, "permissions": "-rw-------", "owner": "root",
        "content": (
            "id\n"
            "whoami\n"
            "cat /etc/shadow\n"
            "find / -name '*.env' 2>/dev/null\n"
            "cat /opt/app/.env\n"
            "mysql -u root -p\n"
            "crontab -l\n"
            "netstat -tlnp\n"
            "ps aux\n"
        ),
    },
    {
        "path": "/root/.bashrc",
        "is_dir": _F, "permissions": "-rw-r--r--", "owner": "root",
        "content": (
            "# ~/.bashrc\n"
            "export PS1='\\[\\e[1;31m\\]\\u@\\h:\\w\\$ \\[\\e[0m\\]'\n"
            "alias ll='ls -alF'\n"
        ),
    },
]


def _enrich(entry: dict) -> dict:
    path = entry["path"]
    result = dict(entry)
    result.setdefault("parent_path", str(Path(path).parent) if path != "/" else None)
    result.setdefault("name", Path(path).name if path != "/" else "")
    content = result.get("content", "")
    result.setdefault("size", len(content.encode()) if content else 0)
    result.setdefault("modified_at", 1748736000)  # 2026-06-01 00:00 UTC
    return result


def main():
    parser = argparse.ArgumentParser(description="Generate a base HoneyMind fake filesystem")
    parser.add_argument("output", help="Output JSONL file (e.g. my_fs.jsonl)")
    args = parser.parse_args()

    output = args.output
    if not output.endswith(".jsonl"):
        output += ".jsonl"

    os.makedirs(os.path.dirname(os.path.abspath(output)) or ".", exist_ok=True)

    all_entries = DEBIAN_FS + trap_files_for_fs()

    with open(output, "w", encoding="utf-8") as f:
        for entry in all_entries:
            f.write(json.dumps(_enrich(entry), ensure_ascii=False) + "\n")

    print(f"written {len(all_entries)} entries to {output} ({len(trap_files_for_fs())} AI traps)")
    print(f"edit the file, then run: python scripts/pack_fs.py {output}")


if __name__ == "__main__":
    main()

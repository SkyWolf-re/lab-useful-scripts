#!/usr/bin/env bash
#
#Author: Skywolf
#Date: 2025-09-17 | Last modified: 2025-10-03
#
#Basic setup script to create lab-doctor user who owns all reports for accessibility
#

set -euo pipefail

#added to test easily new changed without disabling manually
sudo systemctl stop lab-doctor.service 2>/dev/null || true
sudo systemctl stop lab-doctor.timer   2>/dev/null || true

DIR=${1:-/var/log/lab-doctor}

install -m 0755 lab-doctor.sh /usr/local/bin/lab-doctor

id -u lab-doctor >/dev/null 2>&1 || sudo useradd --system --no-create-home --shell /usr/sbin/nologin lab-doctor 2>/dev/null
install -d -o lab-doctor -g lab-doctor -m 0750 "$DIR"

printf 'export LABDOCTOR_REPORT_DIR=%q\n' "$DIR" | tee /etc/profile.d/labdoctor.sh >/dev/null
chmod 644 /etc/profile.d/labdoctor.sh

echo "Dir created at $DIR"
echo "Warning: reports are readable by all local users"

cat >/etc/systemd/system/lab-doctor.service <<EOF
[Unit]
Description=Lab Doctor pre-flight
After=network-online.target
Wants=network-online.target
ConditionPathIsExecutable=/usr/local/bin/lab-doctor

[Service]
Type=oneshot
User=lab-doctor
Group=lab-doctor
Environment=LABDOCTOR_REPORT_DIR=${DIR}
ReadWritePaths=${DIR}
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ExecStart=/usr/local/bin/lab-doctor
EOF

cat >/etc/systemd/system/lab-doctor.timer <<'EOF'
[Unit]
Description=Periodic Lab Doctor run

[Timer]
OnCalendar=*-*-* 03:00:00
Persistent=true
Unit=lab-doctor.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now lab-doctor.timer
systemctl start lab-doctor.service

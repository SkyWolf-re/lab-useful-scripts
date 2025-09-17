#!/usr/bin/env bash
#
#Author: Skywolf
#Date: 17-09-2025
#
#Basic setup script to create lab-doctor user who owns all reports for accessibility
#

set -euo pipefail

DIR=${1:-/var/log/lab-doctor}

install -m 0755 lab-doctor.sh /usr/local/bin/lab-doctor

id -u lab-doctor >/dev/null 2>&1 || sudo useradd -r -s /usr/sbin/nologin lab-doctor
install -d -o lab-doctor -g lab-doctor -m 1777 "$DIR"

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
Environment=LABDOCTOR_REPORT_DIR=${DIR}
ExecStart=/usr/local/bin/lab-doctor
EOF

cat >/etc/systemd/system/lab-doctor@.timer <<'EOF'
[Unit]
Description=Periodic Lab Doctor run for %i

[Timer]
OnBootSec=2m
OnUnitActiveSec=24h
Unit=lab-doctor@%i.service

[Install]
WantedBy=timers.target
EOF

systemctl --global enable lab-doctor.service
systemctl start lab-doctor.service

if [[ -n "${2:-}" ]]; then
	systemctl enable --now lab-doctor@${2}.timer
fi

systemctl daemon-reload

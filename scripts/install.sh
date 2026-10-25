#!/bin/sh
set -eu
umask 077
: "${RF_SERVER:?Set RF_SERVER=https://fleet.example.com}"
: "${RF_CODE_FILE:?Set protected enrollment code file}"
case "$RF_SERVER" in https://*) ;; *) echo 'HTTPS required' >&2; exit 1;; esac
[ "$(id -u)" = 0 ] || { echo 'Run installer as root' >&2; exit 1; }
arch=$(uname -m)
case "$arch" in x86_64) arch=amd64;; aarch64) arch=arm64;; *) echo 'Unsupported Linux architecture' >&2; exit 1;; esac
command -v systemctl >/dev/null
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsS --proto '=https' "$RF_SERVER/downloads/runner-fleet-agent-linux-$arch" -o "$work/agent"
curl -fsS --proto '=https' "$RF_SERVER/downloads/SHA256SUMS" -o "$work/SHA256SUMS"
curl -fsS --proto '=https' "$RF_SERVER/downloads/SHA256SUMS.sig" -o "$work/SHA256SUMS.sig"
curl -fsS --proto '=https' "$RF_SERVER/downloads/release-public.pem" -o "$work/release-public.pem"
if [ -n "${RF_RELEASE_PUBLIC_KEY_FILE:-}" ]; then cp "$RF_RELEASE_PUBLIC_KEY_FILE" "$work/release-public.pem"; fi
openssl pkeyutl -verify -pubin -inkey "$work/release-public.pem" -rawin -in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null
expected=$(awk -v name="runner-fleet-agent-linux-$arch" '$2==name {print $1}' "$work/SHA256SUMS")
[ ${#expected} = 64 ]
printf '%s  %s\n' "$expected" "$work/agent" | sha256sum -c - >/dev/null
getent passwd fleet-agent >/dev/null || useradd -m -s /bin/bash fleet-agent
uid=$(id -u fleet-agent)
install -d -m 700 -o fleet-agent -g fleet-agent /var/lib/runner-fleet-agent /opt/runner-fleet-agent
install -m 755 -o fleet-agent -g fleet-agent "$work/agent" /opt/runner-fleet-agent/agent
install -m 644 -o fleet-agent -g fleet-agent "$work/release-public.pem" /var/lib/runner-fleet-agent/release-public.pem
install -m 600 -o fleet-agent -g fleet-agent "$RF_CODE_FILE" /var/lib/runner-fleet-agent/.enrollment-code
# Existing rootless Docker must be configured for this user. Installer never exposes a daemon.
loginctl enable-linger fleet-agent
systemctl start "user@$uid.service"
if [ ! -f /var/lib/runner-fleet-agent/config.json ]; then
 if [ -n "${RF_CLOUD_INSTANCE_ID:-}" ]; then
  runuser -u fleet-agent -- /opt/runner-fleet-agent/agent enroll --state /var/lib/runner-fleet-agent --server "$RF_SERVER" --name "${RF_NAME:-$(hostname)}" --code-file /var/lib/runner-fleet-agent/.enrollment-code --cloud-instance-id "$RF_CLOUD_INSTANCE_ID"
 else
  runuser -u fleet-agent -- /opt/runner-fleet-agent/agent enroll --state /var/lib/runner-fleet-agent --server "$RF_SERVER" --name "${RF_NAME:-$(hostname)}" --code-file /var/lib/runner-fleet-agent/.enrollment-code
 fi
fi
rm -f /var/lib/runner-fleet-agent/.enrollment-code
cat > /etc/systemd/system/runner-fleet-agent.service <<UNIT
[Unit]
Description=Runner Fleet outbound agent
After=network-online.target user@$uid.service
Wants=network-online.target
[Service]
User=fleet-agent
Group=fleet-agent
Environment=XDG_RUNTIME_DIR=/run/user/$uid
Environment=DOCKER_HOST=unix:///run/user/$uid/docker.sock
ExecStart=/opt/runner-fleet-agent/agent run --state /var/lib/runner-fleet-agent
Restart=always
RestartSec=5
Delegate=yes
NoNewPrivileges=true
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now runner-fleet-agent
printf 'Agent installed. Configure rootless Docker for fleet-agent; check doctor before enabling pools.\n'

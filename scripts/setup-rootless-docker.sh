#!/bin/sh
# Run as root on Ubuntu/Debian after agent user exists; no inbound Docker port.
set -eu
[ "$(id -u)" = 0 ]
apt-get update
apt-get install -y uidmap dbus-user-session slirp4netns fuse-overlayfs curl ca-certificates
id fleet-agent >/dev/null
uid=$(id -u fleet-agent)
loginctl enable-linger fleet-agent
systemctl start "user@$uid.service"
# Official rootless Docker installer over HTTPS. Review it before executing.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl -fsSL --proto '=https' https://get.docker.com/rootless -o "$work/setup.sh"
install -m 700 -o fleet-agent -g fleet-agent "$work/setup.sh" /home/fleet-agent/setup-rootless-docker.sh
runuser -u fleet-agent -- env XDG_RUNTIME_DIR="/run/user/$uid" sh /home/fleet-agent/setup-rootless-docker.sh
rm -f /home/fleet-agent/setup-rootless-docker.sh
# Ensure the user-installed docker executable is available to the agent service.
mkdir -p /etc/systemd/system/runner-fleet-agent.service.d
cat > /etc/systemd/system/runner-fleet-agent.service.d/path.conf <<UNIT
[Service]
Environment=PATH=/home/fleet-agent/bin:/usr/local/bin:/usr/bin:/bin
UNIT
systemctl daemon-reload
systemctl restart runner-fleet-agent

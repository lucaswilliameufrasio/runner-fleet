#!/bin/sh
set -eu
[ "${RF_DRAIN_CONFIRMED:-}" = yes ] || { echo 'Drain runners, confirm zero active slots, revoke machine, then set RF_DRAIN_CONFIRMED=yes.' >&2; exit 1; }
systemctl disable --now runner-fleet-agent
rm -f /etc/systemd/system/runner-fleet-agent.service
systemctl daemon-reload
printf 'Service removed. Identity and logs remain in /var/lib/runner-fleet-agent for review.\n'

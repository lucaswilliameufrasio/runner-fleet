#!/bin/sh
set -eu
[ "${RF_DRAIN_CONFIRMED:-}" = yes ] || { echo 'Drain runners, confirm zero active slots, revoke machine, then set RF_DRAIN_CONFIRMED=yes.' >&2; exit 1; }
systemctl disable --now runner-fleet-agent || true
rm -f /etc/systemd/system/runner-fleet-agent.service
systemctl disable --now runner-fleet-service.service || true
rm -f /etc/systemd/system/runner-fleet-service.service
rm -f /usr/local/lib/runner-fleet/service-runner
for dropin in /etc/systemd/system/actions.runner.*.service.d/10-fleet.conf; do
  if [ ! -f "$dropin" ]; then
    continue
  fi
  unit_dir=$(dirname "$dropin")
  unit=$(basename "$unit_dir" .d)
  case "$unit" in
    actions.runner.*.service) ;;
    *)
      continue
      ;;
  esac
  systemctl disable --now "$unit" || true
  rm -rf "$unit_dir"
done
systemctl daemon-reload || true
printf '%s\n' 'Fleet services removed. Identity, logs, and /var/lib/fleet-runner remain for review.'

#!/bin/sh
set -eu
umask 077
[ "$(id -u)" = 0 ] || { echo 'Run installer as root' >&2; exit 1; }
if [ ! -d /run/systemd/system ] || ! command -v systemctl >/dev/null 2>&1; then
  echo 'systemd is required' >&2
  exit 1
fi

detect_package_family() {
  if [ -f /etc/debian_version ]; then
    printf '%s\n' apt
    return 0
  fi
  if [ -f /etc/redhat-release ]; then
    printf '%s\n' rpm
    return 0
  fi
  if [ -r /etc/os-release ]; then
    family_token=$(
      set +u
      # shellcheck disable=SC1091
      . /etc/os-release
      printf '%s %s' "${ID:-}" "${ID_LIKE:-}"
    )
    family_token=$(printf '%s' "$family_token" | tr '[:upper:]' '[:lower:]')
    case " ${family_token} " in
      *" suse "*)
        printf '%s\n' zypper
        return 0
        ;;
      *" amzn "*|*" amazon "*|*" fedora "*|*" rhel "*|*" centos "*|*" rocky "*|*" almalinux "*|*" ol "*|*" oracle "*)
        printf '%s\n' rpm
        return 0
        ;;
    esac
  fi
  printf '%s\n' unsupported
}

apt_get_install() {
  apt-get install -y --no-install-recommends \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    "$@"
}

install_first_available() {
  for package_name in "$@"; do
    if apt-cache show "$package_name" >/dev/null 2>&1; then
      apt_get_install "$package_name"
      return 0
    fi
  done
  echo "none of the candidate packages are available: $*" >&2
  return 1
}

rpm_install() {
  if command -v dnf >/dev/null 2>&1; then
    dnf install -y --setopt=install_weak_deps=False "$@"
    return 0
  fi
  if command -v yum >/dev/null 2>&1; then
    yum install -y "$@"
    return 0
  fi
  echo 'neither dnf nor yum is available' >&2
  return 1
}

rpm_ensure_curl() {
  if rpm -q curl >/dev/null 2>&1 || rpm -q curl-minimal >/dev/null 2>&1; then
    return 0
  fi
  rpm_install curl
}

enable_rpm_runtime_repos() {
  if ! command -v dnf >/dev/null 2>&1; then
    return 0
  fi
  if ! rpm -q dnf-plugins-core >/dev/null 2>&1; then
    dnf install -y --setopt=install_weak_deps=False dnf-plugins-core || return 0
  fi
  if ! dnf config-manager --help >/dev/null 2>&1; then
    return 0
  fi
  dnf repolist --all -q | while IFS= read -r repo_line; do
    repo_id=${repo_line%% *}
    repo_id_lower=$(printf '%s' "$repo_id" | tr '[:upper:]' '[:lower:]')
    case "$repo_id_lower" in
      ''|repo|*debug*|*source*|*src*)
        continue
        ;;
      crb|powertools|*codeready*)
        dnf config-manager --set-enabled "$repo_id" || true
        ;;
    esac
  done
}

zypper_install() {
  zypper --non-interactive --gpg-auto-import-keys install --no-recommends "$@"
}

zypper_install_first() {
  for package_name in "$@"; do
    if zypper --non-interactive info --type package "$package_name" >/dev/null 2>&1; then
      zypper_install "$package_name"
      return 0
    fi
  done
  echo "none of the candidate packages are available: $*" >&2
  return 1
}

zypper_install_existing() {
  installed_any=no
  for package_name in "$@"; do
    if zypper --non-interactive info --type package "$package_name" >/dev/null 2>&1; then
      zypper_install "$package_name"
      installed_any=yes
    fi
  done
  if [ "$installed_any" = no ]; then
    echo "none of the candidate packages are available: $*" >&2
    return 1
  fi
}

zypper_install_libicu() {
  libicu_package=$(
    zypper --non-interactive search --type package libicu \
      | awk -F'|' '{
          name = $2
          gsub(/[[:space:]]/, "", name)
          if (name ~ /^libicu[0-9]+(_[0-9]+)?$/) print name
        }' \
      | sort -V \
      | tail -n 1
  ) || true
  if [ -z "$libicu_package" ]; then
    echo 'libicu runtime package not found' >&2
    return 1
  fi
  zypper_install "$libicu_package"
}

prepare_host_packages() {
  package_family=$(detect_package_family)
  case "$package_family" in
    apt|rpm|zypper) ;;
    *)
      echo 'only Debian, Ubuntu, RHEL and derivatives, Fedora, Amazon Linux, and SUSE are supported' >&2
      exit 1
      ;;
  esac
  case "$package_family" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      export NEEDRESTART_MODE=l
      apt-get update
      apt_get_install ca-certificates curl tar gzip git openssl coreutils libkrb5-3 zlib1g
      install_first_available libssl3t64 libssl3 libssl1.1 libssl1.0.2 libssl1.0.0
      install_first_available liblttng-ust1t64 liblttng-ust1 liblttng-ust0
      libicu_package=$(apt-cache search --names-only '^libicu[0-9]+$' | awk '{print $1}' | sort -V | tail -n 1)
      if [ -z "$libicu_package" ]; then
        echo 'libicu runtime package not found' >&2
        exit 1
      fi
      apt_get_install "$libicu_package"
      ;;
    rpm)
      enable_rpm_runtime_repos
      rpm_ensure_curl
      rpm_install ca-certificates tar gzip git openssl coreutils krb5-libs zlib openssl-libs lttng-ust libicu
      ;;
    zypper)
      zypper --non-interactive --gpg-auto-import-keys refresh
      zypper_install ca-certificates curl tar gzip git openssl coreutils krb5
      zypper_install_first libz1 zlib
      zypper_install_existing libopenssl3 libopenssl1_1 libopenssl1_0_0
      zypper_install_first lttng-ust liblttng-ust1 liblttng-ust0
      zypper_install_libicu
      ;;
  esac
}

prepare_host_packages

: "${RF_SERVER:?Set RF_SERVER=https://fleet.example.com}"
: "${RF_CODE_FILE:?Set protected enrollment code file}"
case "$RF_SERVER" in
  https://*) ;;
  *) echo 'HTTPS required' >&2; exit 1 ;;
esac
arch=$(uname -m)
case "$arch" in
  x86_64) arch=amd64 ;;
  aarch64) arch=arm64 ;;
  *) echo 'Unsupported Linux architecture' >&2; exit 1 ;;
esac
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
install -d -m 0755 /usr/local/lib/runner-fleet
script_dir=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
# BEGIN service-runner.sh
if [ -f "$script_dir/service-runner.sh" ]; then
  install -m 0755 "$script_dir/service-runner.sh" /usr/local/lib/runner-fleet/service-runner
else
  cat > /usr/local/lib/runner-fleet/service-runner <<'RUNNER_FLEET_HELPER'
#!/bin/sh
# Root helper for one persistent official runner per request.
# fleet-agent cannot sudo: its unit sets NoNewPrivileges. This process is
# already root and only accepts the key=value request schema below.
# The download URL is built from the validated version and the machine
# architecture. It is never taken from the request.
set -eu
umask 077
cd /

REQUEST_DIR=/var/lib/runner-fleet-agent/service-requests
STATUS_DIR=/var/lib/runner-fleet-agent/service-status
RUNNER_USER=fleet-runner
RUNNER_HOME=/var/lib/fleet-runner

die() {
  printf '%s\n' "$1" >&2
  exit 1
}

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "service helper must run as root"
  fi
}

valid_id() {
  case "$1" in
    ''|*[!A-Za-z0-9_-]*)
      return 1
      ;;
  esac
  if [ "${#1}" -gt 64 ]; then
    return 1
  fi
  return 0
}

write_status() {
  status_id=$1
  status_state=$2
  status_unit=$3
  status_busy=$4
  status_error=$5
  if ! valid_id "$status_id"; then
    return 1
  fi
  tmp="$STATUS_DIR/$status_id.status.tmp"
  final="$STATUS_DIR/$status_id.status"
  if ! printf 'state=%s\nunit=%s\nbusy=%s\nerror=%s\n' "$status_state" "$status_unit" "$status_busy" "$status_error" > "$tmp"; then
    return 1
  fi
  if ! chgrp fleet-agent "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! chmod 0640 "$tmp"; then
    rm -f "$tmp"
    return 1
  fi
  if ! mv "$tmp" "$final"; then
    rm -f "$tmp"
    return 1
  fi
  return 0
}

load_request() {
  action=
  req_id=
  req_url=
  req_token=
  req_name=
  req_labels=
  req_group=
  req_version=
  req_sha=
  req_cpu=
  req_memory=
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      ''|'#'*)
        continue
        ;;
    esac
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
      action) action=$value ;;
      id) req_id=$value ;;
      url) req_url=$value ;;
      token) req_token=$value ;;
      name) req_name=$value ;;
      labels) req_labels=$value ;;
      group) req_group=$value ;;
      version) req_version=$value ;;
      sha256) req_sha=$value ;;
      cpu) req_cpu=$value ;;
      memory_mb) req_memory=$value ;;
      *)
        return 1
        ;;
    esac
  done < "$1"
}

clear_secret() {
  req_token=
}

github_url_ok() {
  case "$1" in
    https://github.com/*) ;;
    *) return 1 ;;
  esac
  rest=${1#https://github.com/}
  case "$rest" in
    ''|*[!A-Za-z0-9._/-]*)
      return 1
      ;;
  esac
  if [ "${#1}" -gt 512 ]; then
    return 1
  fi
  return 0
}

token_ok() {
  case "$1" in
    ''|*[!A-Za-z0-9._~+/=-]*)
      return 1
      ;;
  esac
  if [ "${#1}" -gt 512 ]; then
    return 1
  fi
  return 0
}

name_ok() {
  case "$1" in
    ''|*[!A-Za-z0-9._-]*)
      return 1
      ;;
  esac
  if [ "${#1}" -gt 64 ]; then
    return 1
  fi
  return 0
}

labels_ok() {
  (
    set -f
    IFS=,
    # Intentional split on commas. Globbing is disabled.
    # shellcheck disable=SC2086
    set -- $1
    if [ "$#" -eq 0 ]; then
      exit 1
    fi
    for label in "$@"; do
      case "$label" in
        ''|-*|*[!A-Za-z0-9._-]*)
          exit 1
          ;;
      esac
      if [ "${#label}" -gt 64 ]; then
        exit 1
      fi
    done
    exit 0
  )
}

group_ok() {
  case "$1" in
    *[!A-Za-z0-9._\ -]*)
      return 1
      ;;
  esac
  if [ "${#1}" -gt 128 ]; then
    return 1
  fi
  return 0
}

version_ok() {
  printf '%s\n' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'
}

hex64() {
  case "$1" in
    *[!0-9a-fA-F]*)
      return 1
      ;;
  esac
  if [ "${#1}" -ne 64 ]; then
    return 1
  fi
  return 0
}

memory_ok() {
  case "$1" in
    ''|*[!0-9]*)
      return 1
      ;;
  esac
  if [ "$1" -lt 256 ] || [ "$1" -gt 1048576 ]; then
    return 1
  fi
  return 0
}

cpu_quota() {
  printf '%s\n' "$1" | awk '
    $0 ~ /^[0-9]+(\.[0-9]+)?$/ {
      quota = $0 * 100
      if (quota < 1 || quota > 6400) exit 1
      printf "%d\n", quota
      exit 0
    }
    { exit 1 }
  '
}

runner_arch() {
  machine=$(uname -m)
  case "$machine" in
    x86_64)
      printf '%s\n' x64
      ;;
    aarch64)
      printf '%s\n' arm64
      ;;
    *)
      return 1
      ;;
  esac
}

nologin_shell() {
  for candidate in /usr/sbin/nologin /usr/bin/nologin /sbin/nologin /bin/false; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

# 0 means the user is in a privileged group, 1 means it is not, 2 means unknown.
privileged_group_state() {
  groups=$(id -nG "$RUNNER_USER") || return 2
  (
    set -f
    for group_name in sudo admin wheel docker; do
      for current in $groups; do
        if [ "$current" = "$group_name" ]; then
          exit 0
        fi
      done
    done
    exit 1
  )
}

ensure_runner_user() {
  shell=$(nologin_shell) || return 1
  if getent passwd "$RUNNER_USER" >/dev/null 2>&1; then
    home=$(getent passwd "$RUNNER_USER" | cut -d: -f6)
    current_shell=$(getent passwd "$RUNNER_USER" | cut -d: -f7)
    if [ "$home" != "$RUNNER_HOME" ]; then
      return 1
    fi
    case "$current_shell" in
      /usr/sbin/nologin|/bin/false|/usr/bin/nologin|/sbin/nologin) ;;
      *)
        return 1
        ;;
    esac
    if [ "$(id -u "$RUNNER_USER")" -eq 0 ]; then
      return 1
    fi
    group_state=0
    privileged_group_state || group_state=$?
    if [ "$group_state" -ne 1 ]; then
      return 1
    fi
  else
    if [ -e "$RUNNER_HOME" ]; then
      return 1
    fi
    if ! useradd --system --create-home --home-dir "$RUNNER_HOME" --shell "$shell" --user-group "$RUNNER_USER"; then
      return 1
    fi
  fi
  if ! install -d -m 0700 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME"; then
    return 1
  fi
  if ! install -d -m 0750 -o "$RUNNER_USER" -g "$RUNNER_USER" "$RUNNER_HOME/runners"; then
    return 1
  fi
  group_state=0
  privileged_group_state || group_state=$?
  if [ "$group_state" -ne 1 ]; then
    return 1
  fi
  if command -v sudo >/dev/null 2>&1; then
    if sudo -n -l -U "$RUNNER_USER" >/dev/null 2>&1; then
      return 1
    fi
  fi
  return 0
}

runner_busy() {
  needle="/var/lib/fleet-runner/runners/$1/bin/Runner.Worker"
  found=no
  for cmdline in /proc/[0-9]*/cmdline; do
    if [ ! -r "$cmdline" ]; then
      continue
    fi
    if tr '\000' ' ' < "$cmdline" | grep -F "$needle" >/dev/null 2>&1; then
      found=yes
      break
    fi
  done
  if [ "$found" = yes ]; then
    printf '%s\n' yes
  else
    printf '%s\n' no
  fi
}

read_unit() {
  if [ ! -f "$1/.service" ]; then
    return 1
  fi
  unit=$(head -n 1 "$1/.service" | tr -d '\r')
  case "$unit" in
    actions.runner.*.service) ;;
    *)
      return 1
      ;;
  esac
  case "$unit" in
    *[!A-Za-z0-9@._-]*)
      return 1
      ;;
  esac
  printf '%s\n' "$unit"
}

archive_members_ok() {
  listing=$(tar -tzf "$1") || return 1
  if printf '%s\n' "$listing" | grep -E '(^/|(^|/)\.\.(/|$))' >/dev/null 2>&1; then
    return 1
  fi
  return 0
}

install_runner() {
  if ! valid_id "$req_id" || ! github_url_ok "$req_url" || ! token_ok "$req_token" || ! name_ok "$req_name" || ! labels_ok "$req_labels" || ! group_ok "$req_group" || ! version_ok "$req_version" || ! hex64 "$req_sha" || ! memory_ok "$req_memory"; then
    clear_secret
    write_status "$req_id" error "" no "invalid request" || true
    return 1
  fi
  quota=$(cpu_quota "$req_cpu") || {
    clear_secret
    write_status "$req_id" error "" no "invalid request" || true
    return 1
  }
  archive_arch=$(runner_arch) || {
    clear_secret
    write_status "$req_id" error "" no "unsupported architecture" || true
    return 1
  }
  if ! ensure_runner_user; then
    clear_secret
    write_status "$req_id" error "" no "runner user rejected" || true
    return 1
  fi
  if ! write_status "$req_id" installing "" no ""; then
    clear_secret
    return 1
  fi
  runner_dir="$RUNNER_HOME/runners/$req_id"
  if ! install -d -m 0750 -o "$RUNNER_USER" -g "$RUNNER_USER" "$runner_dir"; then
    clear_secret
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  fi
  work=$(mktemp -d) || {
    clear_secret
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  }
  download_url="https://github.com/actions/runner/releases/download/v${req_version}/actions-runner-linux-${archive_arch}-${req_version}.tar.gz"
  if ! curl -fsS --proto '=https' --tlsv1.2 --max-time 180 --max-filesize 300000000 -o "$work/runner.tar.gz" "$download_url"; then
    rm -rf "$work"
    clear_secret
    write_status "$req_id" error "" no "runner download failed" || true
    return 1
  fi
  if ! printf '%s  %s\n' "$req_sha" "$work/runner.tar.gz" | sha256sum -c - >/dev/null 2>&1; then
    rm -rf "$work"
    clear_secret
    write_status "$req_id" error "" no "runner checksum mismatch" || true
    return 1
  fi
  if ! archive_members_ok "$work/runner.tar.gz"; then
    rm -rf "$work"
    clear_secret
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  fi
  if ! tar -xzf "$work/runner.tar.gz" -C "$runner_dir" --no-same-owner --no-absolute-names; then
    rm -rf "$work"
    clear_secret
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  fi
  rm -rf "$work"
  if ! chown -R "$RUNNER_USER:$RUNNER_USER" "$runner_dir"; then
    clear_secret
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  fi
  if ! chmod -R u+rwX,g-rwx,o-rwx "$runner_dir"; then
    clear_secret
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  fi
  if ! chmod 0750 "$runner_dir"; then
    clear_secret
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  fi
  if [ -n "$req_group" ]; then
    if ! (
      cd "$runner_dir" && runuser -u "$RUNNER_USER" -- env -i \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        HOME="$RUNNER_HOME" \
        ./config.sh --unattended --disableupdate --replace \
        --url "$req_url" --token "$req_token" --name "$req_name" \
        --labels "$req_labels" --work _work --runnergroup "$req_group"
    ) >/dev/null 2>&1; then
      clear_secret
      write_status "$req_id" error "" no "runner configuration failed" || true
      return 1
    fi
  else
    if ! (
      cd "$runner_dir" && runuser -u "$RUNNER_USER" -- env -i \
        PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        HOME="$RUNNER_HOME" \
        ./config.sh --unattended --disableupdate --replace \
        --url "$req_url" --token "$req_token" --name "$req_name" \
        --labels "$req_labels" --work _work
    ) >/dev/null 2>&1; then
      clear_secret
      write_status "$req_id" error "" no "runner configuration failed" || true
      return 1
    fi
  fi
  clear_secret
  if ! ( cd "$runner_dir" && ./svc.sh install "$RUNNER_USER" ) >/dev/null 2>&1; then
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  fi
  if ! ( cd "$runner_dir" && ./svc.sh start ) >/dev/null 2>&1; then
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  fi
  unit=$(read_unit "$runner_dir") || {
    write_status "$req_id" error "" no "runner configuration failed" || true
    return 1
  }
  if ! install -d -m 0755 "/etc/systemd/system/${unit}.d"; then
    write_status "$req_id" error "$unit" no "runner configuration failed" || true
    return 1
  fi
  if ! printf '[Service]\nCPUQuota=%s%%\nMemoryMax=%sM\n' "$quota" "$req_memory" > "/etc/systemd/system/${unit}.d/10-fleet.conf"; then
    write_status "$req_id" error "$unit" no "runner configuration failed" || true
    return 1
  fi
  if ! systemctl daemon-reload; then
    write_status "$req_id" error "$unit" no "runner configuration failed" || true
    return 1
  fi
  if ! systemctl restart "$unit"; then
    write_status "$req_id" error "$unit" no "runner configuration failed" || true
    return 1
  fi
  busy=$(runner_busy "$req_id")
  write_status "$req_id" ready "$unit" "$busy" ""
}

remove_runner() {
  if ! valid_id "$req_id"; then
    return 1
  fi
  runner_dir="$RUNNER_HOME/runners/$req_id"
  if [ -d "$runner_dir" ]; then
    unit=$(read_unit "$runner_dir" || true)
    if [ -n "$unit" ]; then
      systemctl stop "$unit" || true
      systemctl disable "$unit" || true
      rm -rf "/etc/systemd/system/${unit}.d"
    fi
    if [ -x "$runner_dir/svc.sh" ]; then
      ( cd "$runner_dir" && ./svc.sh stop ) >/dev/null 2>&1 || true
      ( cd "$runner_dir" && ./svc.sh uninstall ) >/dev/null 2>&1 || true
    fi
    rm -rf "$runner_dir"
  fi
  systemctl daemon-reload || true
  write_status "$req_id" removed "" no ""
}

refresh_status() {
  if ! valid_id "$req_id"; then
    return 1
  fi
  final="$STATUS_DIR/$req_id.status"
  if [ ! -f "$final" ]; then
    return 0
  fi
  state=
  unit=
  while IFS= read -r line; do
    key=${line%%=*}
    value=${line#*=}
    case "$key" in
      state) state=$value ;;
      unit) unit=$value ;;
    esac
  done < "$final"
  if [ "$state" != ready ]; then
    return 0
  fi
  busy=$(runner_busy "$req_id")
  write_status "$req_id" ready "$unit" "$busy" ""
}

handle_request() {
  processing="$1.processing"
  if ! mv "$1" "$processing"; then
    return 1
  fi
  if ! load_request "$processing"; then
    rm -f "$processing"
    clear_secret
    return 1
  fi
  rm -f "$processing"
  if ! valid_id "$req_id"; then
    clear_secret
    return 1
  fi
  case "$action" in
    install)
      install_runner
      ;;
    remove)
      clear_secret
      remove_runner
      ;;
    refresh_status)
      clear_secret
      refresh_status
      ;;
    *)
      clear_secret
      return 1
      ;;
  esac
}

refresh_ready() {
  for status_file in "$STATUS_DIR"/*.status; do
    if [ ! -f "$status_file" ]; then
      continue
    fi
    req_id=$(basename "$status_file" .status)
    refresh_status || true
  done
}

watch() {
  while true; do
    for request_file in "$REQUEST_DIR"/*.request; do
      if [ ! -f "$request_file" ]; then
        continue
      fi
      case "$request_file" in
        *.processing)
          continue
          ;;
      esac
      handle_request "$request_file" || true
    done
    refresh_ready || true
    sleep 1
  done
}

require_root
if [ "${1:-}" != watch ]; then
  die "usage: service-runner watch"
fi
install -d -m 2770 -o root -g fleet-agent "$REQUEST_DIR"
install -d -m 2750 -o root -g fleet-agent "$STATUS_DIR"
watch
RUNNER_FLEET_HELPER
  chmod 0755 /usr/local/lib/runner-fleet/service-runner
fi
# END service-runner.sh
install -d -m 2770 -o root -g fleet-agent /var/lib/runner-fleet-agent/service-requests
install -d -m 2750 -o root -g fleet-agent /var/lib/runner-fleet-agent/service-status
cat > /etc/systemd/system/runner-fleet-service.service <<'UNIT'
[Unit]
Description=Runner Fleet service runner helper
After=network-online.target
[Service]
Type=simple
ExecStart=/usr/local/lib/runner-fleet/service-runner watch
Restart=always
RestartSec=1
User=root
NoNewPrivileges=true
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now runner-fleet-service.service
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
printf '%s\n' 'Agent installed. Container pools need rootless Docker for fleet-agent. Persistent service pools use fleet-runner and do not need Docker. Check doctor before enabling a pool.'

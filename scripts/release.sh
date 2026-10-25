#!/bin/sh
set -eu
# GO must point to a Go 1.25+ binary. Inject the signing key via a secret manager.
GO=${GO:-go}
: "${RF_SIGNING_KEY:?Set Ed25519 private release signing key in RF_SIGNING_KEY}"
old_umask=$(umask)
umask 077
key_dir=$(mktemp -d)
key_file="$key_dir/release.key"
trap 'rm -f "$key_file"; rmdir "$key_dir"' 0
trap 'exit 1' HUP INT TERM
printf '%s\n' "$RF_SIGNING_KEY" > "$key_file"
unset RF_SIGNING_KEY
umask "$old_umask"
root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
(cd web && corepack pnpm install --frozen-lockfile && corepack pnpm run check && corepack pnpm run build)
mkdir -p dist web/build/downloads
for arch in amd64 arm64; do
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO" build -buildvcs=false -trimpath -ldflags='-s -w' -o "dist/runner-fleet-server-linux-$arch" ./cmd/server
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO" build -buildvcs=false -trimpath -ldflags='-s -w' -o "dist/runner-fleet-agent-linux-$arch" ./cmd/agent
done
(cd dist && sha256sum runner-fleet-*-linux-* > SHA256SUMS)
openssl pkey -in "$key_file" -pubout -out dist/release-public.pem
openssl pkeyutl -sign -inkey "$key_file" -rawin -in dist/SHA256SUMS -out dist/SHA256SUMS.sig
cp dist/runner-fleet-agent-linux-* dist/SHA256SUMS dist/SHA256SUMS.sig dist/release-public.pem scripts/install.sh scripts/setup-rootless-docker.sh web/build/downloads/
printf 'Release prepared. Publish web/build and dist together; do not distribute the signing private key.\n'

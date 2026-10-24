#!/bin/sh
set -eu
# GO must point to a Go 1.25+ binary. Keep signing key outside the repository.
GO=${GO:-go}
: "${RF_SIGNING_KEY_FILE:?Set path to Ed25519 private release signing key}"
root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
cd "$root"
(cd web && npm ci && npm run check && npm run build)
mkdir -p dist web/build/downloads
for arch in amd64 arm64; do
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO" build -buildvcs=false -trimpath -ldflags='-s -w' -o "dist/runner-fleet-server-linux-$arch" ./cmd/server
 CGO_ENABLED=0 GOOS=linux GOARCH="$arch" "$GO" build -buildvcs=false -trimpath -ldflags='-s -w' -o "dist/runner-fleet-agent-linux-$arch" ./cmd/agent
done
(cd dist && sha256sum runner-fleet-*-linux-* > SHA256SUMS)
openssl pkey -in "$RF_SIGNING_KEY_FILE" -pubout -out dist/release-public.pem
openssl pkeyutl -sign -inkey "$RF_SIGNING_KEY_FILE" -rawin -in dist/SHA256SUMS -out dist/SHA256SUMS.sig
cp dist/runner-fleet-agent-linux-* dist/SHA256SUMS dist/SHA256SUMS.sig dist/release-public.pem scripts/install.sh web/build/downloads/
printf 'Release prepared. Publish web/build and dist together; do not distribute the signing private key.\n'

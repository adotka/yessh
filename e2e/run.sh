#!/usr/bin/env bash
# End-to-end test: local ntfy + sshd (docker compose), real yessh binary, the Android app's
# Kotlin engine (android/core) as the phone.
#   e2e/run.sh                  # docker sshd
#   E2E_SSHD=local e2e/run.sh   # use /usr/sbin/sshd on this machine (as root) instead of the container
#   E2E_EXPIRY=0 e2e/run.sh     # skip the ~70 s certificate-expiry check
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"
services="ntfy"
[ "${E2E_SSHD:-docker}" = docker ] && services="ntfy sshd"
mkdir -p work/ca
docker compose up -d --build $services
trap 'docker compose -f "$here/docker-compose.yml" down' EXIT
for _ in $(seq 30); do curl -fsS http://localhost:18080/v1/health >/dev/null 2>&1 && break; sleep 1; done

bin="$here/work/yessh"
(cd ../host && go build -o "$bin" ./cmd/yessh)

cd ../android
E2E_NTFY=http://localhost:18080 YESSH_BIN="$bin" E2E_CA_DIR="$here/work/ca" \
  ./gradlew -Pyessh.coreOnly=true :core:test --tests '*EndToEndTest' --rerun-tasks

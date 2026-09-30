#!/usr/bin/env bash
# End-to-end test: local ntfy + sshd (docker compose), real yessh binary, PWA logic as the phone.
#   e2e/run.sh              # docker sshd
#   E2E_SSHD=local e2e/run.sh   # use /usr/sbin/sshd on the host instead of the container
#   E2E_BROWSER=1 e2e/run.sh    # also drive the real PWA UI in Chromium (needs Playwright)
set -euo pipefail
cd "$(dirname "$0")"
services="ntfy"
[ "${E2E_SSHD:-docker}" = docker ] && services="ntfy sshd"
mkdir -p work/ca
docker compose up -d --build $services
trap 'docker compose down' EXIT
for _ in $(seq 30); do curl -fsS http://localhost:18080/v1/health >/dev/null 2>&1 && break; sleep 1; done
node --test ./*.test.mjs
if [ "${E2E_BROWSER:-0}" = 1 ]; then node browser.mjs; fi

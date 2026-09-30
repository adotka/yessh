# End-to-end tests

`run.sh` starts a local ntfy and an sshd that trusts only the yessh CA
(`TrustedUserCAKeys /yessh/ca.pub`, written by the harness into `work/ca/`), then runs:

- `e2e.test.mjs`: the real `yessh` binary against the PWA's `App` logic acting as the phone
  (in-memory store, real ntfy). Covers pair, approve → `ssh` succeeds, `ensure` reuse, deny
  (exit 3), timeout (exit 2), tampered response from another CA (rejected, nothing written),
  wrong-PSK and replayed requests, and `ssh` failing after the cert expires (~70 s; skip with
  `E2E_EXPIRY=0`).
- `browser.mjs` (with `E2E_BROWSER=1`): drives the actual PWA UI in Chromium via Playwright.
  It creates the CA, reads the pairing string, runs `yessh pair` and `yessh request`, then
  approves in the UI. `E2E_SCREENSHOTS=dir` saves screenshots.

Requirements: Docker, Go, Node ≥ 20, `ssh`/`ssh-keygen`. If Docker Hub is rate-limited, set
`SSHD_BASE` to another Alpine-based image. `E2E_SSHD=local` uses the host's `/usr/sbin/sshd`
(run as root) instead of the container.

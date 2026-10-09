# End-to-end tests

`run.sh` starts a local ntfy and an sshd that trusts only the yessh CA
(`TrustedUserCAKeys /yessh/ca.pub`, written by the test into `work/ca/`). Then it runs
`android/core`'s `EndToEndTest`: the real `yessh` binary against the Android app's engine acting
as the phone, with a software CA key standing in for Keystore.

Covered: pair, approve → `ssh` succeeds, `ensure` reuses the cert silently, deny (exit 3, the
previous cert is untouched), timeout (exit 2), a tampered response signed by another CA
(rejected, nothing written), a wrong-PSK request (invisible to the phone), replayed requests,
and `ssh` failing after the cert expires (~70 s; skip with `E2E_EXPIRY=0`).

Requirements: Docker, Go, JDK 17, `ssh`/`ssh-keygen`. If Docker Hub is rate-limited, set
`SSHD_BASE` to another Alpine-based image. `E2E_SSHD=local` uses the host's `/usr/sbin/sshd`
(run as root) instead of the container.

The Keystore side (real hardware-backed signatures) is covered separately by the app's
instrumented tests on an emulator; see `android/README.md`.

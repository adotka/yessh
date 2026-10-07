# yessh

Phone-held SSH certificate authority with an approval tap for every certificate.

A PWA on your phone holds the CA key and signs short-lived SSH user certificates on request. The
`yessh` CLI on your management host asks for a certificate through an untrusted
[ntfy](https://ntfy.sh) relay. You tap **`yessh`** on the phone, and the host gets a certificate
valid for hours. Fleet hosts trust only the CA public key.

```
yessh request -p root   →  notification on phone  →  tap  →  yessh  →  ~/.../id_yessh-cert.pub
ssh root@fleet-host     ✓ (until the TTL runs out)
```

- `android/`: native Android app. CA key in Android Keystore (StrongBox/TEE), `yessh`/`nope`
  buttons right on the notification, fingerprint/PIN per approval. See [android/README.md](android/README.md).
- `pwa/`: static site, vanilla ES modules, no build step. Tests: `cd pwa && npm test`
  (needs `ssh-keygen` for the certificate checks).
- `host/`: Go CLI. `cd host && go build ./cmd/yessh`, tests `go test ./...`.
- `e2e/`: docker compose (ntfy + sshd) and a harness driving the real binary; `e2e/run.sh`.
- `docs/`: [setup and ssh_config](docs/setup.md), [threat model](docs/threat-model.md).
- [SPEC.md](SPEC.md): the design.

Two phone apps, one protocol: the PWA (https://adotka.github.io/yessh/, CA key protected by the
browser sandbox) and the Android app (CA key in secure hardware, recommended). Keep a
break-glass path to your fleet.

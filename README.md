# yessh

Phone-held SSH certificate authority with an approval tap for every certificate.

An Android app holds the CA key in the phone's secure hardware and signs short-lived SSH user
certificates on request. The
`yessh` CLI on your management host asks for a certificate through an untrusted
[ntfy](https://ntfy.sh) relay. You tap **`yessh`** on the notification, and the host gets a certificate
valid for hours. Fleet hosts trust only the CA public key.

```
yessh request -p root   →  notification on phone  →  tap  →  yessh  →  ~/.../id_yessh-cert.pub
ssh root@fleet-host     ✓ (until the TTL runs out)
```

- `android/`: native Android app. CA key in Android Keystore (StrongBox/TEE), `yessh`/`nope`
  buttons right on the notification, fingerprint/PIN per approval. See [android/README.md](android/README.md).
- `host/`: Go CLI. `cd host && go build ./cmd/yessh`, tests `go test ./...`.
- `e2e/`: docker compose (ntfy + sshd); `e2e/run.sh` drives the real binary against the app's engine and logs in over ssh.
- `docs/`: [setup and ssh_config](docs/setup.md), [threat model](docs/threat-model.md).
- [SPEC.md](SPEC.md): the original design. The phone side started as a PWA and has since been
  replaced by the Android app; the wire protocol is unchanged.

Keep a break-glass path to your fleet.

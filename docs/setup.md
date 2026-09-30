# Setting up yessh

## 1. Phone: create the CA

1. Open the yessh PWA on your phone (install it with *Add to Home screen*).
2. Tap **Create CA**. This generates a non-extractable ECDSA P-256 key and a random PSK.
3. Under **Policy**, add the principals you want to be able to grant (e.g. `root`), and set
   `maxTtl` / `defaultTtl`.
4. Install the [ntfy Android app](https://ntfy.sh/) and subscribe to the request topic the PWA
   shows (the **Subscribe in ntfy** link does this). If you self-host ntfy, point the app at your
   server.

## 2. Management host: install and pair

```sh
cd host && go build -o ~/.local/bin/yessh ./cmd/yessh
```

Copy the pairing string from the PWA and **type or paste it into a shell yourself**. Do not
route it through a coding agent: it contains the PSK.

```sh
yessh pair 'yessh1:eyJ2IjoxLC...'
```

This writes `~/.config/yessh/config.json` (mode 0600) and prints the CA line. Check it
against the phone.

## 3. Fleet hosts: trust the CA

On each fleet host, as root:

```sh
yessh ca | ssh root@fleet-host 'cat > /etc/ssh/yessh_ca.pub'   # or copy the line from the PWA
```

`/etc/ssh/sshd_config`:

```
TrustedUserCAKeys /etc/ssh/yessh_ca.pub
# Optional: restrict which principals map to which account.
# AuthorizedPrincipalsFile /etc/ssh/principals/%u
```

With `AuthorizedPrincipalsFile`, `/etc/ssh/principals/root` lists the principals allowed to log
in as root (one per line). Without it, a cert principal must equal the target user name.

Reload sshd (`systemctl reload ssh` or `sshd`). **Keep a break-glass path** (an existing
authorized key kept offline, or your provider's console) until you have proven the flow.

## 4. ssh_config on the management host

```
Match host *.internal exec "yessh ensure -p root"
    IdentityFile ${XDG_RUNTIME_DIR}/yessh/id_yessh
    CertificateFile ${XDG_RUNTIME_DIR}/yessh/id_yessh-cert.pub
    IdentitiesOnly yes
```

`yessh ensure` exits 0 immediately if a valid cert with at least `--min-remaining` (default
10m) left covers the requested principals. Otherwise it sends a request and waits (default
120 s) for you to approve on the phone. Concurrent `ensure` runs (parallel ssh, Ansible) share a
lock, so you get one prompt, not many.

If `XDG_RUNTIME_DIR` is unset (e.g. in cron), yessh falls back to `~/.cache/yessh` and warns.
Set `YESSH_DIR` to pin a location, and use the same path in `ssh_config`.

## Commands

| Command | |
|---|---|
| `yessh pair '<string>'` | Store config (0600) and print the CA line. |
| `yessh ca` | Print the CA public key line. |
| `yessh request [-p principal]... [-t 1h] [--label L] [--timeout 120s]` | Always request a new cert. |
| `yessh ensure [-p principal]... [-t 1h] [--min-remaining 10m]` | Reuse a valid cert or request one. |
| `yessh status` | Show principals, expiry, fingerprints. Exit 1 if missing or expired. |
| `yessh forget` | Delete the ephemeral key and cert. |

Exit codes: `0` ok, `1` error (including a rejected/tampered response), `2` timeout, `3` denied.

Environment: `YESSH_CONFIG` (config path), `YESSH_DIR` (key dir), `YESSH_PRINCIPALS`
(default principals, comma-separated; otherwise `root`).

## Coding agents on the management host

An agent running as your user can trigger `yessh request` and use a cert that is currently
valid. It cannot approve. That's the intended blast radius, bounded by TTL and principals.
Keep `defaultTtl` short and principals narrow for agent-driven work.

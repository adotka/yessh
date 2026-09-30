# yessh: implementation specification (v0.1, MVP)

Phone-held SSH certificate authority with approval-per-issuance.
A PWA on the phone holds the CA key and signs short-lived SSH user certificates on request.
A host-side CLI requests certs via an ntfy rendezvous. Fleet hosts trust only the CA public key.

## 1. Goals and non-goals

**Goals**
- No long-lived SSH credential on the management host. Only an ephemeral key plus a cert with a TTL of hours.
- Every issuance needs an explicit tap on the phone and is logged there.
- Works while the workstation is off. Survives fleet reboots and maintenance: no fleet host is in the trust or signalling path.
- Relay (ntfy) is untrusted. Compromise of it yields at most DoS or prompt spam.

**Non-goals for MVP**
- Hardware-bound CA key (Android Keystore). Planned as a native app in v2 with the same wire protocol.
- GPG.
- Multi-user, revocation lists (short TTL is the revocation), Vault/step-ca integration.
- Direct VAPID Web Push (v1.1; see section 5).

## 2. Architecture

```
 management host                 ntfy (untrusted relay)               phone
 ┌──────────────┐  publish req   ┌─────────────────┐   push via     ┌──────────────┐
 │ yessh CLI    │───────────────▶│ topic  req-<t>  │──ntfy Android─▶│ notification │
 │ ephemeral    │                │                 │   app, tap     │  ↓ opens     │
 │ ed25519 key  │◀───────────────│ topic  resp-<t> │◀───────────────│ yessh PWA    │
 └──────┬───────┘  subscribe SSE └─────────────────┘  publish resp  │ CA key,      │
        │ ssh + cert                                                │ approve UI,  │
        ▼                                                           │ audit log    │
   fleet hosts: TrustedUserCAKeys = CA pubkey                       └──────────────┘
```

Repository layout (monorepo):

```
yessh/
  SPEC.md
  pwa/            # static site, vanilla ES modules, no framework
    index.html manifest.webmanifest sw.js
    src/{app,crypto,sshcert,protocol,ntfy,store,ui}.js
    test/         # node:test, uses Node's WebCrypto
  host/           # Go module, single static binary `yessh`
    cmd/yessh/ internal/{config,protocol,ntfy,sshcert,keys}
  e2e/            # docker compose: ntfy + sshd + test runner
  docs/           # threat model, ssh_config examples
```

Language choices: PWA is plain JS with ES modules (no build step; optional esbuild later). Host is Go 1.22+, using `golang.org/x/crypto/ssh` for cert parsing and verification.

## 3. Pairing and configuration

Done once, on the phone and on the host.

1. In the PWA, first launch: generate the CA key pair with WebCrypto, ECDSA P-256, `extractable: false`, stored in IndexedDB. The public key is always exportable.
2. PWA generates `psk`: 32 random bytes.
3. PWA shows:
   - CA public key as an OpenSSH line (`ecdsa-sha2-nistp256 AAAA... yessh-ca`) with a Copy button. This goes into `TrustedUserCAKeys` on fleet hosts.
   - A **pairing string** `yessh1:<base64url(JSON)>` (also as QR), where the JSON is `{v:1, ntfy:"https://ntfy.sh", pwa:"https://<origin>/", psk:"<b64>", ca:"<openssh pubkey line>"}`.
4. On the host: `yessh pair '<string>'` writes `~/.config/yessh/config.json` (mode 0600). **The user types or pastes it into a shell themselves. It must never go through a coding-agent session**, because it contains the PSK.

Derived values (both sides, HKDF-SHA256 over `psk`, empty salt):
- `enc_key` = HKDF(info=`"yessh1 enc"`, 32 bytes)
- `req_topic` = `"yessh-r-" + base32(HKDF(info="yessh1 req topic", 20 bytes))` lowercase, no padding
- `resp_topic` = same with info `"yessh1 resp topic"`

Topic names are effectively capabilities. Optional ntfy access token is stored in the config if the user self-hosts with auth.

PWA policy settings (stored in IndexedDB, editable in the UI):
- `allowedPrincipals` (default: empty, so the first request forces the user to add them)
- `maxTtl` (default 8h), `defaultTtl` (default 1h)
- `extensions` (default `permit-pty` only)
- `sourceAddress` critical option: optional, off by default

## 4. Wire protocol

Envelope (ntfy message body, JSON, well under ntfy's 4 KB limit):

```json
{ "v": 1, "n": "<b64url 12-byte nonce>", "c": "<b64url ciphertext+tag>" }
```

AES-256-GCM with `enc_key`. AAD = `"yessh1|req"` or `"yessh1|resp"`. Random nonce per message. Anything that fails to decrypt is dropped silently.

**Request** (host → `req_topic`), plaintext JSON:

```json
{ "id": "<16 random bytes b64url>", "ts": 1790000000,
  "label": "mgmt-1", "who": "claude@mgmt-1",
  "pubkey": "ssh-ed25519 AAAA...",
  "principals": ["root"], "ttl": 14400 }
```

**Response** (phone → `resp_topic`), plaintext JSON:

```json
{ "id": "<same id>", "ts": 1790000042, "status": "approved",
  "cert": "ssh-ed25519-cert-v01@openssh.com AAAA... yessh:mgmt-1:<id>" }
```

or `{ "id": ..., "status": "denied" }`.

Rules:
- Phone rejects requests where `|now - ts| > 120s`, or where `id` was already seen (persist seen ids for 24h).
- Phone clamps `principals` to `allowedPrincipals` (rejects if none remain) and `ttl` to `maxTtl`. The user can lower the TTL in the approval dialog. The phone never grants more than requested.
- Host accepts a response only if: it decrypts, `id` matches an outstanding request, and the cert passes verification (section 6). Host never trusts `status` alone.
- Host request timeout: 120 s by default, configurable. Exit code 2 on timeout, 3 on denial.

## 5. Wake-up (MVP)

MVP wake-up uses the **ntfy Android app** as the push transport, so the PWA needs no push infrastructure:
- The user installs the ntfy app and subscribes to `req_topic` once (the PWA shows a Subscribe deep link and the topic name).
- Host publishes the request with headers `Priority: high`, `Title: yessh request from <label>`, and `Click: <pwa>#/r/<id>`. The visible notification carries only the label, never crypto material.
- Tapping opens the PWA at `#/r/<id>`. The PWA polls `GET <ntfy>/<req_topic>/json?poll=1&since=10m`, decrypts, finds the request, and shows the approval screen.
- The PWA also polls on open and on visibility change, so it works even if the notification was dismissed.

v1.1: replace the ntfy app with direct Web Push (VAPID key held by the host, subscription registered with the phone's push service). The protocol and PWA approval flow stay unchanged.

## 6. SSH certificate construction (PWA, `sshcert.js`)

Subject keys supported: Ed25519 (default from the host) and ECDSA P-256. The cert type follows the subject key.

Layout (RFC 4251 encodings, per OpenSSH `PROTOCOL.certkeys`) for `ssh-ed25519-cert-v01@openssh.com`:

```
string   "ssh-ed25519-cert-v01@openssh.com"
string   nonce            (32 random bytes)
string   pk               (32 bytes)
uint64   serial           (unix ms at issuance)
uint32   type             (1 = user)
string   key id           ("yessh:<label>:<id>")
string   valid principals (concatenation of string(principal))
uint64   valid after      (now - 60s, clock-skew tolerance)
uint64   valid before     (now + ttl)
string   critical options (empty, or source-address)
string   extensions       (sorted: permit-pty ...; each as string name + string data)
string   reserved         (empty)
string   signature key    (CA pubkey wire blob: string "ecdsa-sha2-nistp256", string "nistp256", string Q)
string   signature        (see below)
```

For an `ecdsa-sha2-nistp256-cert-v01@openssh.com` subject, the `pk` field becomes `string "nistp256", string Q`.

Signature: ECDSA P-256 with SHA-256 over all bytes preceding the final `signature` field. WebCrypto returns 64-byte `r||s`. Convert to the SSH signature blob:

```
signature = string( string "ecdsa-sha2-nistp256" ,
                    string( mpint(r) || mpint(s) ) )
```

`mpint`: strip leading zeros, prepend `0x00` if the top bit is set. This is the classic bug source, so unit-test it with r/s values that have high bits set and leading zeros.

Output line: `<cert type> <base64 of the whole blob> <key id>`.

**Host-side verification (Go)**: parse with `ssh.ParseAuthorizedKey`; assert it is a `*ssh.Certificate`; `SignatureKey` equals the pinned CA key from config; `Key` equals the ephemeral public key; `CertType == UserCert`; principals ⊆ requested; `ValidBefore - now <= requested ttl + 60s`; then `ssh.CertChecker`-style signature verification. Refuse to write a cert that fails any check.

## 7. Host CLI (`yessh`)

| Command | Behaviour |
|---|---|
| `yessh pair <string>` | Write config (0600). Prints the CA line so the user can double-check it. |
| `yessh ca` | Print the CA public key line (for `TrustedUserCAKeys`). |
| `yessh request [-p principal]... [-t ttl] [--label L]` | Generate an ephemeral Ed25519 key in `$XDG_RUNTIME_DIR/yessh/` (tmpfs, dir 0700, files 0600; fall back to `~/.cache/yessh` with a warning), publish the request, wait for the response, verify, write `id_yessh` and `id_yessh-cert.pub`. |
| `yessh ensure [-t ttl] [--min-remaining 10m]` | Exit 0 silently if a valid cert exists with enough time left; otherwise behave like `request`. Meant for ssh config. |
| `yessh status` | Show current cert: principals, expiry, fingerprint. |
| `yessh forget` | Delete the ephemeral key and cert. |

ssh_config integration example (document in `docs/`):

```
Match host *.internal exec "yessh ensure -p root"
    IdentityFile ${XDG_RUNTIME_DIR}/yessh/id_yessh
    CertificateFile ${XDG_RUNTIME_DIR}/yessh/id_yessh-cert.pub
    IdentitiesOnly yes
```

Constraint to note in docs: the coding agent on the host can trigger a request but cannot approve it. While a cert is valid, the agent can use it. That is the intended blast radius, bounded by TTL and principals.

Fleet-side setup (document in `docs/`): copy the CA line to `/etc/ssh/yessh_ca.pub`, set `TrustedUserCAKeys /etc/ssh/yessh_ca.pub`, optionally use `AuthorizedPrincipalsFile`. **Keep a break-glass path** (a separate offline key or provider console) until the flow is proven.

## 8. PWA UI

Screens, mobile-first, dark/light aware:
1. **Setup**: create CA, show CA line and pairing string/QR, policy form, ntfy Subscribe deep link.
2. **Approval** (`#/r/<id>`): shows label, `who`, ephemeral key fingerprint (`SHA256:...`), principals, requested TTL with a selector (lower only), request age.
   - Confirmation button text is exactly **`yessh`**.
   - Secondary button **`nope`**.
   - Both publish a response and write an audit entry.
3. **Pending list**: unexpired, unanswered requests from the last 10 minutes.
4. **Log**: append-only view of issuances and denials (time, label, principals, TTL, fingerprint, serial), export as JSON.

Service worker caches the app shell for offline open. Installable manifest, name `yessh`.

## 9. Security notes (put in `docs/threat-model.md`)

- CA key protection in the MVP is the browser sandbox only (non-extractable CryptoKey). Rooted phone, malware, or profile backup extraction is out of scope. This is the known gap that motivates the native Keystore app.
- PSK compromise lets an attacker forge prompts and read requests, but not produce certs. Only the CA key signs, and only after a tap.
- Approval fatigue is the main human risk. Show the fingerprint prominently, and default the TTL low.
- Do not log the PSK or decrypted payloads on the host. Never put secrets in ntfy headers or the notification text.
- Clocks: host and phone need roughly correct time. The 60 s backdate and 120 s request window assume NTP.

## 10. Testing and acceptance

Unit (PWA, `node --test`):
- mpint conversion vectors, including high-bit and leading-zero cases.
- Cert builder output parsed by `ssh-keygen -L -f cert` (run in the test via `child_process`) matches the expected principals, validity, key id, and CA fingerprint.
- Envelope encrypt/decrypt round trip, and cross-implementation vectors generated by Go and checked in JS.

Unit (host): envelope, HKDF derivation vectors, cert verifier accepts good and rejects tampered certs (wrong CA, wrong key, extra principal, excess TTL).

E2E (`e2e/`, docker compose): local ntfy, an sshd container with `TrustedUserCAKeys`, a headless-browser or Node harness that drives the PWA logic (`approve()`), and the real `yessh request` followed by `ssh` into the container using the issued cert.

Acceptance for MVP:
1. `yessh request -p root` on a VPS → notification on the phone → tap → `yessh` → cert written in under 10 s on a good connection.
2. `ssh root@fleet-host` succeeds with that cert and fails after expiry.
3. Denial, timeout, replayed request, wrong-PSK message, and tampered response all fail closed.
4. Everything works with the fleet host list changing or hosts rebooting, since only ntfy and the phone are involved.

## 11. Milestones

1. `sshcert.js` plus tests against `ssh-keygen -L` (the riskiest part first).
2. Protocol + envelope in both languages, with cross vectors.
3. Host CLI: `pair`, `request`, `ensure`, verification. Test against a local ntfy.
4. PWA: setup, approval, log. Deploy to a static host.
5. E2E with docker sshd. Docs and ssh_config examples.
6. Dogfood on one non-critical VPS with a break-glass key retained.

## 12. Open questions

- Public ntfy.sh vs. self-hosted ntfy (self-host on an off-fleet box, or use ntfy.sh with random topics for the MVP)?
- PWA origin: GitHub Pages, Cloudflare Pages, or a custom domain?
- Multiple management hosts: one PSK per host (recommended, so each gets its own topics and can be revoked) or one shared. Pairing string per host is the simple answer.

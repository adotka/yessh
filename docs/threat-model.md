# yessh threat model (MVP)

yessh moves the SSH credential for a fleet off the management host and onto a phone.
The management host only ever holds an ephemeral Ed25519 key plus a certificate that
expires within hours, and every certificate needs a tap on the phone.

## Assets

| Asset | Where | Protection |
|---|---|---|
| CA private key (ECDSA P-256) | Phone, IndexedDB of the PWA origin | Non-extractable WebCrypto `CryptoKey` (browser sandbox only) |
| PSK (32 bytes) | Phone (IndexedDB) and host (`~/.config/yessh/config.json`, 0600) | File permissions; never sent over ntfy |
| Ephemeral key + certificate | Host, `$XDG_RUNTIME_DIR/yessh/` (tmpfs, 0700/0600) | Short TTL, principal list |
| Audit log | Phone, IndexedDB | Browser storage; export as JSON |

## Trust boundaries

- **ntfy (relay) is untrusted.** Everything it carries is AES-256-GCM encrypted under a
  key derived from the PSK, with a direction-specific AAD (`yessh1|req` / `yessh1|resp`).
  Topics are derived from the PSK too, so they act as capabilities. A malicious relay can
  drop, delay or replay messages (DoS), or spam notifications. It cannot read requests or
  forge approvals.
- **The host never trusts `status: approved`.** It verifies the certificate itself: pinned
  CA key, the ephemeral key it generated, user cert type, principals ⊆ requested, lifetime
  ≤ requested TTL + 60 s, and a valid signature. Anything else fails closed and nothing is
  written.
- **Fleet hosts trust only the CA public key** (`TrustedUserCAKeys`). They are not in the
  signalling path, so reboots or changes to the fleet don't affect issuance.

## What an attacker gets

| Compromise | Impact |
|---|---|
| ntfy operator / network | DoS, prompt spam. No certs, no plaintext. |
| PSK (e.g. host config file leaked) | Read requests (labels, principals, public keys); forge prompts on the phone; forge denials (DoS). **Cannot produce certificates.** Only the CA key signs, and only after a tap. Re-pair to rotate. |
| Management host (root or the agent's user) | Can trigger requests and use any certificate that is currently valid. Cannot approve. Blast radius = TTL × principals. |
| Phone browser profile (malware, root, backup extraction) | CA key usable or extractable → full fleet access. **Out of scope for the MVP**; this is the gap the planned native Android Keystore app closes. |
| Phone unlocked in someone else's hands | They can approve pending requests. Use a screen lock. |

## Replay and freshness

- The phone rejects requests with `|now - ts| > 120 s` and remembers request ids for 24 h.
- The host accepts only a response whose `id` matches its outstanding request, and only
  if the certificate certifies the key it just generated. A replayed old response carries
  an old key, so it fails verification.
- Certificates are backdated 60 s (`valid after`) for clock skew. Both sides need roughly
  correct time (NTP).

## Human factors

- **Approval fatigue** is the main risk. The approval screen shows the ephemeral key
  fingerprint, principals, label, `who`, and request age. The TTL preselects the lower of
  the requested value and `defaultTtl` (1 h), and can only be lowered.
- The approve button reads **`yessh`** and the deny button **`nope`**, so a stray tap on
  a notification doesn't approve anything. Approval always takes a second, deliberate tap
  in the PWA.
- An unexpected prompt means someone holds the PSK or the host is compromised. Deny it,
  then re-pair.

## Operational rules

- Pair by typing or pasting the pairing string into a shell yourself. **Never pass it through
  a coding-agent session.** It contains the PSK.
- The host never logs the PSK or decrypted payloads. ntfy headers and notification text carry
  only the label, never crypto material. (The ntfy message body is the encrypted envelope; the
  ntfy app may show it as opaque text.)
- Keep a break-glass path to the fleet (an offline key, or provider console) until the flow is
  proven in your environment.
- Revocation is by expiry. Keep `maxTtl` short. To cut off a host before its cert expires,
  remove the CA from `TrustedUserCAKeys` or use a `RevokedKeys` file on the fleet.

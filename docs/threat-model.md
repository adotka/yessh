# yessh threat model

yessh moves the SSH credential for a fleet off the management host and onto a phone. The
management host only ever holds an ephemeral Ed25519 key plus a certificate that expires within
hours, and every certificate needs a tap on the phone. This document says what that protects
against, what it assumes, and where it stops. The cryptography itself is described in
[crypto.md](crypto.md); the review that produced the current state is in
[security-review.md](security-review.md).

## Parties

| Party | Role | Trust |
|---|---|---|
| Phone (yessh app) | Holds the CA key, decides on requests, signs certificates | Trusted. Its OS, screen lock and Keystore are the security root. |
| Management host (`yessh` CLI) | Generates ephemeral keys, requests certificates, uses them to ssh | Semi-trusted: it may run coding agents or other automation that can *ask* but not *approve*. |
| ntfy relay | Carries encrypted messages between host and phone | **Untrusted.** Treated as a public, adversarial network. |
| Fleet hosts (sshd) | Accept certificates signed by the CA | Trusted to enforce `TrustedUserCAKeys` and the certificate's principals, validity and options. |
| You | Tap `yessh` or `nope` | The approval decision rests on what the prompt shows you. |

## Assets

| Asset | Where | Protection |
|---|---|---|
| CA private key (ECDSA P-256) | Phone, Android Keystore | StrongBox when available, otherwise TEE. Non-exportable. Usable only while the device is unlocked. In per-approval mode, usable only once per biometric/PIN confirmation. |
| PSK (32 bytes) | Phone: `psk.bin` wrapped by a Keystore AES key. Host: `~/.config/yessh/config.json`, mode 0600. | Keystore wrapping and file permissions. Never sent over the relay. Shown once, in the pairing string. |
| Ephemeral key + certificate | Host, `$XDG_RUNTIME_DIR/yessh/` (tmpfs, 0700/0600) | Short TTL, principal list, optional `source-address`. |
| Policy (allowed principals, TTLs, extensions, source-address) | Phone, app-private file | App sandbox. Enforced at both notification time and tap time. |
| Audit log | Phone, app-private file; exportable as JSON | App sandbox, no backups. Not tamper-evident. |
| ntfy access token (optional) | Phone settings file, host config, pairing string | Same protection as the PSK; its loss only affects relay access. |

## Trust boundaries

- **The relay is untrusted.** Every message is an AES-256-GCM envelope under a key derived
  from the PSK, with a direction-specific AAD (`yessh1|req` / `yessh1|resp`). Topic names are
  derived from the PSK too, so a passive observer cannot find them by guessing, but the relay
  operator sees them, sees when messages flow, sees the request label in the ntfy title header,
  and sees the access token. A malicious relay can drop, delay, duplicate or reorder messages,
  and can spam the phone's topic with garbage (which fails authentication and is dropped
  silently). It cannot read requests, forge requests, or forge approvals.
- **The host never trusts `status: approved`.** It verifies the returned certificate itself
  before writing it: pinned CA key, the exact ephemeral key it generated for this request, user
  certificate type, principals a subset of what it asked for, lifetime at most the requested TTL
  plus 60 s skew, only `source-address` as a critical option, and a valid ECDSA signature. Any
  failure exits 1 and writes nothing.
- **The phone never trusts a request's claims.** Decryption proves the sender holds the PSK,
  nothing more. `label` and `who` are shown as the requester's claims. The request id, timestamp,
  public key and principals are validated syntactically; freshness and replay are checked at
  arrival and again when you tap; principals are intersected with your allowlist; TTL is clamped
  to your policy; extensions and `source-address` come from your policy, never from the request.
- **Fleet hosts trust only the CA public key.** They are not in the signalling path. Everything
  the certificate says (principals, validity, options) is enforced by sshd.

## What an attacker gets

| Compromise | Impact | Recovery |
|---|---|---|
| Relay operator or network path | Denial of service (drop/delay), metadata (topics, timing, labels, token), notification spam that the phone drops silently. No plaintext, no certificates. | Switch relay; re-pair if you want new topic names. |
| PSK only (e.g. host config leaked via dotfile sync or backup) | Read requests (labels, principals, public keys). Publish forged requests: prompts on your phone that look like the host's, including a look-alike request timed to coincide with one you expect. Forge denials (DoS). **Cannot produce certificates.** | Deny unexpected prompts. Compare the key fingerprint the CLI prints with the one in the prompt. Re-pair to rotate the PSK. |
| Management host (root or your user, including a coding agent) | Trigger requests; use any certificate currently installed. Cannot approve. Blast radius is TTL x principals, further bounded by `source-address` if set. | `yessh forget`; wait out or revoke by serial on the fleet; keep TTLs short. |
| Unlocked phone in someone else's hands | Per-approval mode: they also need your fingerprint or PIN for each signature. One-tap mode: they can approve anything pending while it is unlocked. | Lock the phone; delete the CA from Settings if it is lost. |
| Malicious app on the phone (no root) | Cannot read `psk.bin` plaintext, cannot touch the CA key, cannot fire the approve receiver (not exported, immutable PendingIntents). **In one-tap mode, an app that holds notification-listener access can press the `yessh` notification button while the phone is unlocked**, as can a paired watch. Per-approval mode is immune: the button only opens the biometric sheet. | Use per-approval mode. Audit which apps have notification access. |
| Root / compromised OS on the phone | Can decrypt the PSK (the wrapping key needs no user auth), read policy and log, and in one-tap mode use the CA key freely while unlocked. In per-approval mode the key still needs a real biometric/credential event per signature, but a compromised OS can spoof what the prompt says. Key extraction is still prevented by the hardware. | Out of scope. Rotate the CA (new key on a clean device, new CA line on the fleet). |
| Phone backup or device transfer | Nothing: backups and transfer are disabled for all app data, and the key cannot leave Keystore. | A new phone means a new CA. |
| Lost or wiped phone | The CA is gone; nothing can be recovered. Existing certificates keep working until they expire. | Create a new CA, install the new CA line on the fleet, re-pair the host. Keep a break-glass path. |
| Fleet host | Can use the session it was given; cannot mint certificates. | Normal incident response. |

## Replay and freshness

- A request carries a 128-bit random id and a timestamp. The phone rejects `|now - ts| > 120 s`
  and remembers every answered id for 24 h, so a replayed request within the window is refused
  as already answered and a replayed request after it is stale. Unanswered duplicates are
  deduplicated in memory while the app runs.
- The host subscribes to the response topic before publishing and accepts only a response whose
  id matches the outstanding request *and* whose certificate certifies the key it just generated.
  A replayed old response names an old key and fails verification.
- Certificates are backdated 60 s (`valid after`) for clock skew. Both devices need roughly
  correct time; a phone or host more than two minutes off will see every request as stale.
- The phone signs at tap time, not arrival time: `prepare` re-evaluates staleness, replay and
  policy when you tap, and the certificate window starts then. `complete` refuses to publish if
  the same request was answered in the meantime (two review paths open at once).

## Human factors

- **Approval fatigue** is the main risk. Keep `yessh ensure` cheap: a valid certificate is
  reused silently, so you are only asked when one is really needed.
- The prompt shows label, `who`, principals, TTL, request age and the ephemeral key fingerprint.
  The label is restricted to a boring ASCII set and `who` to printable text without control,
  format or bidi characters, so the prompt cannot be visually spoofed within the fields.
- **The fingerprint is the only authenticated link between a prompt and the command you ran.**
  The CLI prints it when it sends the request. If a prompt arrives that you did not expect, or
  the fingerprint differs, tap `nope`: someone holds your PSK or your host is compromised.
- The approve button reads `yessh`, the deny button `nope`, so a stray tap on the notification
  body opens the review screen rather than approving. In per-approval mode the biometric sheet
  asks for explicit confirmation even with passive biometrics such as face unlock.
- The TTL preselects the lower of the request and `defaultTtl` (1 h) and can only be lowered.
  Principals can only be unticked, never added, at approval time; adding one to the allowlist is
  a separate explicit action.

## Security assumptions

1. The phone's screen lock, biometrics and Keystore work as Android documents them, and the
   device is not rooted or running a tampered OS.
2. The pairing string was carried from phone to host intact and privately: it holds the PSK and
   the CA public key, so whoever intercepts or alters it can either forge prompts (PSK) or make
   the host trust a different CA (CA line). Compare the CA line the CLI prints with the phone.
3. The host's user account and `~/.config/yessh/config.json` are private to you. Dotfile
   synchronisation, home-directory backups and shared accounts expose the PSK.
4. TLS to the relay is used for everything but a local test relay. End-to-end encryption does
   not depend on it, but the access token and topic names do.
5. Fleet sshd is configured so that a certificate principal maps to the account you intend
   (`AuthorizedPrincipalsFile` or principal == username), and `TrustedUserCAKeys` contains only
   CAs you mean to trust.
6. Clocks are within about a minute of real time on both devices.

## Known limits

- **No remote attestation.** The host cannot prove the CA key is hardware-backed or that the
  phone app is genuine; the app displays the Keystore security level (StrongBox, TEE, software)
  and you read it. On devices without secure hardware the key is software-backed.
- **No trusted display.** What you confirm with your fingerprint is what Android drew on the
  screen; Android Protected Confirmation is not used. A compromised OS can show one thing and
  sign another.
- **PIN is as good as a fingerprint.** Device credential is an allowed fallback for per-approval
  mode (otherwise a failed sensor would lock the CA out), and new biometric enrolment does not
  invalidate the key (enrolment already requires the credential). Someone who knows your PIN can
  approve.
- **The PSK is decryptable while the phone is locked**, because the listener must decrypt
  incoming requests to show you what they are. This is why the PSK is a request credential, not
  a signing credential.
- **One-tap mode trades a prompt for convenience.** Anything that can press notification buttons
  while the phone is unlocked can approve. Choose it knowingly.
- **Revocation is by expiry.** There is no OCSP or online check. Keep `maxTtl` short. To cut a
  certificate off early, put its serial (shown in the log) or the CA in a `RevokedKeys` file on
  the fleet, or remove the CA line.
- **The audit log is a plain file** in app-private storage. It is complete for decisions made by
  this app, but a rooted phone can edit it. Correlate with sshd logs: the certificate key id is
  `yessh:<label>:<request id>` and sshd logs it at `LogLevel VERBOSE`.
- **Stolen host material works until expiry.** The ephemeral private key is unencrypted on tmpfs
  (ssh must use it unattended). A `source-address` policy limits where a stolen key and
  certificate can be used from.
- **A PSK holder can race you.** They can submit a look-alike request the moment they expect you
  to approve one. Check the fingerprint; if the relay also cooperates they can suppress your real
  request so that only theirs arrives.
- **Debug builds are not for real CAs.** A debuggable app can be driven through `run-as` and a
  debugger, bypassing the UI (though not the key's authentication requirement).
- **No post-quantum protection** anywhere in the chain; this matches today's OpenSSH certificate
  authorities.

## Operational rules

- Pair by typing or pasting the pairing string into a shell yourself. **Never pass it through a
  coding-agent session or a chat.** It contains the PSK.
- Keep `~/.config/yessh/` out of dotfile repositories and cloud-synced folders.
- Prefer per-approval mode. Prefer StrongBox devices for the CA.
- Set `source-address` in the phone policy to the management host's address when it is static.
- Keep `maxTtl` and `defaultTtl` short; request only the principals you need.
- The host never logs the PSK or decrypted payloads. ntfy headers carry only the label.
- Keep a break-glass path to the fleet (an offline key or the provider console) until the flow is
  proven, and for the day the phone is lost.
- Delete the CA from the app before you give the phone away; a factory reset also destroys it.

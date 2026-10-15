# Security review, October 2026

A code and architecture review of the Android app, the Kotlin protocol engine and the Go host
CLI as of commit `9b06a6e`, with the fixes that followed. Scope: everything in `android/`,
`host/` and the wire protocol. Out of scope: the GitHub Actions supply chain and the ntfy
server itself.

The design held up. No way was found for the relay, a PSK holder or the management host to
obtain a certificate without a tap on the phone, and no way to extract the CA key. The findings
below are about what the person tapping can be made to believe, about double-answers, and about
hardening around the edges. Each one is either fixed in code or stated as a limit in
[threat-model.md](threat-model.md).

## Findings

| # | Severity | Finding | Resolution |
|---|---|---|---|
| 1 | Medium | **Look-alike prompts are indistinguishable without the fingerprint.** A PSK holder can publish a request with the same label and `who` as the real host at the moment the user expects a prompt. The prompt shows the ephemeral key fingerprint, but the CLI never printed it, so nobody could compare. | Fixed: `yessh request`/`ensure` print `the prompt must show key SHA256:…`. Setup docs and the threat model tell you to compare it. |
| 2 | Medium | **One-tap mode is a notification action.** Any app with notification-listener access, or a paired wearable, can fire the `yessh` button's PendingIntent while the phone is unlocked, with no interaction. Per-approval mode is not affected (the button only opens the biometric sheet). | Documented as a limit of one-tap mode; the mode picker, the Android README and the threat model now say so. The architecture cannot prevent it without removing the one-tap property. |
| 3 | Low | **Double answers.** The notification and the review screen could both `prepare` the same request; `complete` did not check whether it had been answered in between, so the phone could publish two certificates and log two approvals (the host accepts only the first). | Fixed: `complete` and `deny` refuse already-answered or in-flight ids and publish nothing. Tested. |
| 4 | Low | **Prompt spoofing with Unicode.** `who` rejected ASCII control characters only. Bidi overrides (U+202E), isolates and zero-width characters would render misleadingly in the notification and biometric sheet. | Fixed: the phone rejects all Cc, Cf, Zl and Zp characters; the host strips them and truncates on rune boundaries. Tested on both sides. |
| 5 | Low | **Passive biometrics confirmed instantly.** `BiometricPrompt` was built with `setConfirmationRequired(false)`, so face unlock would sign as soon as the face was recognised after the notification tap. | Fixed: explicit confirmation required (no effect on fingerprint or PIN). |
| 6 | Low | **Tapjacking of the in-app approve button.** In one-tap mode no system prompt follows the in-app `yessh` button, so an overlay could guide a blind tap. | Fixed: the main window drops touches that arrive through an overlay. |
| 7 | Low | **PSK wrapping key not in StrongBox.** The CA key tries StrongBox first; the AES key wrapping the PSK did not. | Fixed: StrongBox first, TEE fallback. Existing installs keep their current key until re-pairing. |
| 8 | Low | **`source-address` policy unvalidated.** A typo produced certificates sshd rejects; a malformed value gave the impression of a restriction without one. | Fixed: validated as a list of IPv4/IPv6 addresses or CIDRs in the editor and again at signing time. Tested. |
| 9 | Low | **Plain-http relay accepted silently** by the host. End-to-end encryption does not depend on TLS, but the ntfy access token and topic names would travel in the clear. | Fixed: `yessh pair` warns. Still allowed for a local test relay. The phone blocks cleartext entirely. |
| 10 | Info | **PSK on the host lives in `~/.config`**, a directory people commonly put in dotfile repositories and cloud sync. | Documented in setup and the threat model. |
| 11 | Info | No remote attestation, no trusted display (Protected Confirmation), device-credential fallback, non-invalidation on biometric enrolment, audit log not tamper-evident, revocation only by expiry or serial, debug builds, relay metadata. | Each is stated in the threat model's "Known limits" with the reasoning. |

## What was checked and found sound

- **Envelope.** AES-256-GCM with a 96-bit random nonce and 128-bit tag, direction-separated by
  AAD, under a key derived by HKDF-SHA256 from a 256-bit random PSK. Both implementations fail
  closed and silently on any parse or tag failure. The Kotlin HKDF and envelope match the Go
  implementation byte for byte on the shared vectors.
- **Freshness and replay.** 128-bit request ids, a ±120 s window checked at arrival and at tap,
  answered ids persisted for 24 h, in-memory deduplication of unanswered duplicates. The host binds
  a response to its outstanding id *and* to the ephemeral key it generated, so old responses cannot
  be replayed.
- **Host verification.** Pinned CA, exact subject key, user cert type, principals ⊆ requested,
  lifetime ≤ requested + 60 s, `source-address` as the only critical option, signature and window
  checked by `ssh.CertChecker`. Nothing is written to disk on failure; the old certificate is
  removed before the new key is written so a key/cert mismatch is never observable as valid.
- **Certificate construction.** Field layout matches PROTOCOL.certkeys and is verified against
  `ssh-keygen -L`; DER to SSH signature conversion uses minimal mpints; principals and key ids are
  restricted to safe characters; incoming ECDSA subject points are checked to be on the curve.
- **Keystore use.** P-256 key with `setUnlockedDeviceRequired`, StrongBox-first; per-approval mode
  is auth-per-use with class 3 biometrics or credential, and the `Signature` is bound to the
  `BiometricPrompt` as its `CryptoObject` so the authorisation covers exactly one signature over
  exactly these bytes.
- **App surface.** The approve receiver and the approve activity are not exported; PendingIntents
  are immutable; notifications are private on the lock screen with a redacted public version;
  actions require an unlock from the lock screen; `FLAG_SECURE` on the main window; the pairing
  string is marked sensitive on the clipboard; backups and device transfer are disabled; cleartext
  traffic is blocked by the network security config.
- **Host file handling.** Config written atomically with mode 0600 and refused if group/world
  readable; key material in `$XDG_RUNTIME_DIR` (tmpfs) with 0700/0600, atomic renames, a lock so
  parallel `ensure` runs make one request, and a warning when falling back to `~/.cache`.
- **Policy enforcement.** Principals are intersected with the allowlist, TTL clamped to the
  policy maximum, extensions and `source-address` come from the policy only; the review screen
  can only remove principals or shorten the TTL relative to what the engine allows.

## Method

Manual reading of every source file in `android/core`, `android/app` and `host`, the manifest
and resource XML, the workflows and the e2e harness, followed by targeted fixes with tests. The
Go test suite (`go vet`, `go test -race`), the Kotlin core tests (which check the Go vectors
and `ssh-keygen -L`) and the docker end-to-end run were executed after the changes. The Android
`app` module is compiled by CI only.

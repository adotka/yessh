# Cryptography in yessh

Every primitive, where it is used, with what parameters, and why. Both implementations (Go host,
Kotlin phone) are checked against shared test vectors in `host/internal/protocol/testdata/` and
`host/internal/sshcert/testdata/`, and the Kotlin tests verify built certificates with
`ssh-keygen -L`.

## Summary

| Purpose | Primitive | Parameters | Implementation |
|---|---|---|---|
| CA signing key | ECDSA on NIST P-256 (secp256r1) with SHA-256 | Generated and kept in Android Keystore; StrongBox if present, otherwise TEE | Keystore `SHA256withECDSA`; signature DER converted to the SSH `ecdsa-sha2-nistp256` blob |
| Certificate format | OpenSSH user certificate `*-cert-v01@openssh.com` | Subject key Ed25519 or ECDSA P-256; 32-byte random nonce; serial = ms timestamp | `SshCert.kt` (phone), `golang.org/x/crypto/ssh` (host verifies) |
| Host ephemeral key | Ed25519 | New key per request; OpenSSH private key format, unencrypted, on tmpfs | Go `crypto/ed25519` |
| Pairing secret (PSK) | 32 random bytes | Generated on the phone at CA creation | Java `SecureRandom` |
| Key and topic derivation | HKDF-SHA256 (RFC 5869) | Salt empty (32 zero bytes); info `yessh1 enc`, `yessh1 req topic`, `yessh1 resp topic` | Go `x/crypto/hkdf`; phone has a 20-line HMAC implementation, vector-tested |
| Message encryption | AES-256-GCM | 96-bit random nonce, 128-bit tag; AAD `yessh1|req` or `yessh1|resp` | Go `crypto/aes` + `cipher.NewGCM`; phone `AES/GCM/NoPadding` |
| Request id | 128 random bits | base64url, 22 characters | `crypto/rand` |
| Topic names | `yessh-r-` + base32(160 bits of HKDF output) | Lowercase, unpadded | Both sides |
| PSK at rest on the phone | AES-256-GCM under a Keystore key | Keystore-generated 12-byte IV, 128-bit tag; StrongBox when available | `PskVault.kt` |
| Fingerprints | SHA-256 of the SSH wire blob, `SHA256:` + unpadded base64 | As `ssh-keygen -l` prints | Both sides |
| Transport | TLS to the ntfy relay | Platform trust store; cleartext blocked on the phone | `HttpURLConnection`, Go `net/http` |

Nothing here is custom cryptography. The two hand-written pieces are RFC 5869 HKDF on the phone
(because `javax.crypto` has no HKDF below API 34) and the P-256 on-curve check for incoming
subject keys; both are covered by tests against the Go implementation and known vectors.

## Key derivation

```
PRK      = HMAC-SHA256(key = 0x00*32, msg = PSK)
enc_key  = HKDF-Expand(PRK, "yessh1 enc",        32)
req_topic  = "yessh-r-" + base32(HKDF-Expand(PRK, "yessh1 req topic",  20))
resp_topic = "yessh-r-" + base32(HKDF-Expand(PRK, "yessh1 resp topic", 20))
```

One PSK yields one encryption key used in both directions. Direction separation comes from the
AAD, so a request can never be replayed as a response or vice versa. The topic names are 160-bit
values: a passive party cannot enumerate them, but the relay sees them in URLs and they must be
treated as public once the relay does.

Rotating the PSK (re-pairing) changes the key and both topics; the CA key is unaffected.

## Message envelope

```json
{"v":1,"n":"<base64url 12-byte nonce>","c":"<base64url ciphertext||tag>"}
```

- Plaintexts are JSON: request `{id, ts, label, who, pubkey, principals, ttl}` and response
  `{id, ts, status, cert?}`.
- Nonces are random per message. The NIST bound for 96-bit random nonces is 2^32 messages per
  key; yessh sends a handful per day, so collision probability is negligible over the life of a
  pairing. Re-pair if you ever approach that.
- Anything that fails to parse, has the wrong version, the wrong nonce length or fails the GCM
  tag is dropped silently, on both sides. No error reaches the relay, so there is no oracle.
- Message bodies are bounded by ntfy's size limit (a few KB); the request contains one public key
  line and a few short strings.

## Certificates

The phone builds the `to-be-signed` bytes exactly as PROTOCOL.certkeys specifies:

```
string  "<subject type>-cert-v01@openssh.com"
string  nonce                (32 random bytes)
<subject public key fields>  (verbatim from the request's key blob)
uint64  serial               (System.currentTimeMillis())
uint32  type                 (1 = user)
string  key id               ("yessh:<label>:<request id>")
string  valid principals     (user's selection ⊆ requested ∩ allowlist)
uint64  valid after          (now - 60 s)
uint64  valid before         (now + ttl, ttl ≤ requested, ≤ policy max)
string  critical options     (only "source-address", from policy)
string  extensions           (from policy, default "permit-pty")
string  reserved             (empty)
string  signature key        (CA public key blob)
```

Keystore signs these bytes with SHA-256/ECDSA and returns a DER `SEQUENCE { INTEGER r, INTEGER s }`.
The phone converts it to the SSH blob `string("ecdsa-sha2-nistp256") string(mpint(r) || mpint(s))`
with minimal mpint encoding. The host side parses with `x/crypto/ssh`, which is strict about the
same encodings, and `ssh.CertChecker` verifies the signature with the pinned CA.

Subject keys accepted in requests: `ssh-ed25519` (32-byte point) and `ecdsa-sha2-nistp256`
(uncompressed point, checked to lie on the curve). The host always sends Ed25519.

Serial numbers are millisecond timestamps, unique in practice, and shown in the phone log so a
certificate can be revoked by serial in a `RevokedKeys` file.

## The CA key in Keystore

```
KeyGenParameterSpec(alias "yessh-ca", PURPOSE_SIGN)
  EC secp256r1, digest SHA-256
  setUnlockedDeviceRequired(true)
  setIsStrongBoxBacked(true)            # falls back to TEE if unavailable
  per-approval mode only:
    setUserAuthenticationRequired(true)
    setUserAuthenticationParameters(0, BIOMETRIC_STRONG | DEVICE_CREDENTIAL)   # auth per use
    setInvalidatedByBiometricEnrollment(false)
```

- The private key is generated inside the secure element or TEE and is never present in app
  memory. There is no export path; backups and device transfer are disabled.
- Auth-per-use (timeout 0) means Keystore releases exactly one signature per successful
  `BiometricPrompt` with the `Signature` object as its `CryptoObject`. The `Signature` is
  initialised before the prompt and the to-be-signed bytes are fed in only after it succeeds,
  so the prompt is bound to this key operation.
- `BIOMETRIC_STRONG` admits class 3 biometrics only. Device credential is allowed as fallback so
  a broken sensor cannot lock you out of your CA.
- The security level reported by `KeyInfo` (StrongBox, TEE, software) is shown in Settings.
  There is no attestation to a remote party.

## The PSK at rest

The PSK file is `len(IV) || IV || AES-GCM(PSK)` under a non-exportable Keystore AES-256 key
(`yessh-psk-wrap`, StrongBox when available). That key deliberately needs neither user
authentication nor an unlocked device: the listener service must decrypt a request while the
phone is locked to show you what it is. So the PSK is protected against extraction from the
file system and from backups, but not against code running as the app or as root on the device.
This is acceptable because the PSK can only *ask*; signing needs the CA key.

## Randomness

- Phone: `java.security.SecureRandom` (PSK, envelope nonces, certificate nonces). Keystore
  generates its own key material and GCM IVs inside the hardware.
- Host: `crypto/rand` (ephemeral keys, request ids, envelope nonces).

## Validation rules that matter for security

| Field | Rule | Where |
|---|---|---|
| Request id | exactly 22 base64url chars | phone |
| Timestamp | within ±120 s of the phone's clock | phone, at arrival and at tap |
| Label | `[A-Za-z0-9._-]{1,64}` (ends up in the key id) | host and phone |
| `who` | 1..128 chars, no control, format, bidi or line-separator characters | host (sanitises), phone (rejects) |
| Principals | 1..32 items, each `[A-Za-z0-9._@+-]{1,64}`, intersected with the allowlist | phone; host checks ⊆ requested |
| TTL | > 0, clamped to policy `maxTtl`; host checks ≤ requested + 60 s | both |
| Subject key | supported type, well-formed, on-curve for ECDSA | phone; host checks identity with its own key |
| `source-address` | list of IPv4/IPv6 addresses or CIDRs | phone policy editor and at signing time |
| Critical options | only `source-address` | host |
| CA key | pinned from pairing, type `ecdsa-sha2-nistp256` | host |

## What is not used, and why

- **No password-based crypto.** The PSK is random, never typed, and transported once as a
  pairing string.
- **No asymmetric handshake between host and phone.** A pairwise symmetric key keeps the protocol
  two messages long and makes the relay a dumb pipe. The cost is that a PSK leak lets an attacker
  prompt you; it still cannot sign.
- **No message signing by the host.** Authentication of requests is the GCM tag under the PSK;
  there is no separate host identity, and `who`/`label` are informational.
- **No certificate revocation protocol.** Lifetimes are short by design.
- **No post-quantum algorithms.** OpenSSH certificates and Android Keystore do not yet offer
  them for this use.

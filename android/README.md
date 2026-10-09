# yessh for Android

Native version of the yessh phone CA. It speaks the same wire protocol as the PWA, so the `yessh`
host CLI works unchanged. What's different:

| | PWA | Android app |
|---|---|---|
| CA key | Non-extractable WebCrypto key (browser sandbox) | Android Keystore, StrongBox when available, otherwise the TEE. Can't be exported, backed up or copied. |
| Approve | Notification (ntfy app) → open PWA → tap `yessh` | **`yessh` / `nope` buttons on the notification itself** |
| Per-approval check | None (anyone with the unlocked phone) | Fingerprint/face/PIN for every signature, enforced by the key itself (or one-tap mode, see below) |
| Wake-up | ntfy Android app | Built-in listener (foreground service); the ntfy app isn't needed |

## Approval modes

You pick one when you create the CA. It's a property of the Keystore key, so changing it means
creating a new CA.

- **Fingerprint / PIN for every approval (default).** The key is auth-per-use: Keystore refuses
  to sign unless a biometric or device-credential check happened for *that* signature. Tap `yessh`
  on the notification, the system fingerprint sheet slides up over whatever you're doing, touch,
  done. The app is never brought to the front.
- **One tap while unlocked.** The key works only while the phone is unlocked. Tap `yessh` and the
  certificate is sent. On the lock screen, Android asks you to unlock first.

In both modes the notification buttons require an unlock when tapped from the lock screen, and
tapping the notification body opens the full review screen, where you can untick principals or
lower the TTL.

## Install

1. Get the APK: either a signed release (`android-v*` tags on GitHub), or build it yourself (below).
2. Install it and open **yessh**. Set a screen lock first if you don't have one; Keystore keys
   that need unlocking can't exist without it.
3. **Create CA**, then under **Setup**:
   - add allowed principals (e.g. `root`) under Policy,
   - allow notifications and "running in background" (battery), so requests arrive within seconds,
   - copy the CA line to fleet hosts (`TrustedUserCAKeys`),
   - **Show pairing string** and type/paste it into a shell on the management host:
     `yessh pair '<string>'`. Never route it through a coding agent.
4. If the ntfy app is subscribed to the request topic (from the PWA setup), unsubscribe it there,
   or you'll get two notifications.

### Moving from the PWA

The PWA's CA key can't be exported (by design), so the app creates a new CA:

1. Add the app's CA line to `/etc/ssh/yessh_ca.pub` on each fleet host **next to** the PWA's line.
   `TrustedUserCAKeys` accepts several keys, one per line.
2. Re-pair the management host with the app's pairing string (`yessh pair '…'`).
3. Once everything works, remove the PWA's CA line from the fleet and delete the CA in the PWA.

## Signing key (read this before the first install)

The CA key belongs to the app's Keystore identity. Android only installs an update if it's
signed with the **same key** as the installed app. Otherwise you must uninstall first, and
uninstalling destroys the CA. So:

- Use the release APKs from this repo's GitHub releases (always the same key), **or**
- build with your own key and keep that key for every future build.

Debug builds (`io.github.adotka.yessh.debug`) install next to release builds and have their own
CA. Use them for testing only.

### Setting up release signing for CI

Create a key once, on your own machine (not in a coding-agent session):

```sh
keytool -genkeypair -v -keystore yessh-release.jks -alias yessh -keyalg EC -groupname secp256r1 -validity 36500
base64 -w0 yessh-release.jks   # value for YESSH_SIGNING_KEYSTORE_B64
```

`keytool` asks for one password: its default PKCS12 format uses the same password for the store
and the key.

Add repository secrets: `YESSH_SIGNING_KEYSTORE_B64`, `YESSH_SIGNING_STORE_PASSWORD` (that
password), and `YESSH_SIGNING_KEY_ALIAS` (`yessh`). `YESSH_SIGNING_KEY_PASSWORD` is only needed
for an old JKS-format keystore with a separate key password; otherwise the store password is
used. Back up the `.jks` file and
passwords offline. Then push a tag:

```sh
git tag android-v0.1.0 && git push origin android-v0.1.0
```

The `android-release` workflow builds, signs, and attaches `yessh-0.1.0.apk` to a GitHub release
with its SHA-256 and the signing certificate fingerprint.

### Building locally

Needs JDK 17 and the Android SDK (Android Studio, or `ANDROID_HOME` set).

```sh
cd android
./gradlew :app:assembleDebug           # app/build/outputs/apk/debug/app-debug.apk
YESSH_SIGNING_STORE_FILE=… YESSH_SIGNING_STORE_PASSWORD=… YESSH_SIGNING_KEY_ALIAS=yessh \
  ./gradlew :app:assembleRelease
```

## Layout and tests

- `core/`: plain Kotlin/JVM (protocol, certificate builder, approval engine, ntfy client).
  Builds without the Android SDK. `./gradlew :core:test` checks the Go test vectors
  (byte-identical envelopes), `ssh-keygen -L` on built certificates, tampering, DER/mpint edge
  cases and the engine. With `YESSH_E2E_NTFY` and `YESSH_BIN` set it also runs against the real
  `yessh` host binary over ntfy.
- `app/`: the Android app. `./gradlew :app:connectedDebugAndroidTest` runs the Keystore tests on a
  device or emulator: real Keystore signatures verified, the PSK vault, and storage.

CI (`.github/workflows/android.yml`) runs all of the above, including the emulator tests.

## Security notes

- The CA private key is generated inside Keystore and never exists in app memory.
  `setUnlockedDeviceRequired` makes it unusable while the phone is locked. In per-approval mode,
  auth-per-use makes every signature need its own biometric/PIN confirmation, so a compromised
  app process can't sign silently.
- The PSK is encrypted with a Keystore AES key (no user auth, because the listener must decrypt
  requests in the background). Backups and device transfer are disabled for all app data.
- Screens use `FLAG_SECURE` (no screenshots, hidden in recents). The pairing string is copied to
  the clipboard marked as sensitive.
- What a stolen, unlocked phone can do: per-approval mode needs the PIN or fingerprint as well.
  One-tap mode approves anything while unlocked. That's the trade-off you pick at setup.
- Rooted devices or a malicious OS update are out of scope: Keystore protects the key material,
  but whoever controls the OS can ask Keystore to sign once the user authenticates.

package io.github.adotka.yessh.security

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import io.github.adotka.yessh.core.SshCert
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The CA signing key: ECDSA P-256 in Android Keystore. The private key never leaves secure
 * hardware (StrongBox when the device has it, otherwise the TEE).
 *
 * Two modes, fixed when the key is created:
 *  - [Mode.PER_APPROVAL]: every signature needs a fresh biometric or device-credential
 *    confirmation (auth-per-use key + BiometricPrompt CryptoObject).
 *  - [Mode.UNLOCKED]: the key works only while the device is unlocked; approving from the
 *    notification is a single tap (Android asks to unlock first when on the lock screen).
 */
object CaKey {
    const val ALIAS = "yessh-ca"

    enum class Mode { PER_APPROVAL, UNLOCKED }

    private fun keyStore() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun exists(): Boolean = keyStore().containsAlias(ALIAS)

    fun deviceSecure(context: Context): Boolean =
        context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    /** Creates the key. Returns true if it is StrongBox-backed. */
    fun generate(mode: Mode): Boolean {
        check(!exists()) { "CA key already exists" }
        return try {
            generate(mode, strongBox = true)
            true
        } catch (e: StrongBoxUnavailableException) {
            generate(mode, strongBox = false)
            false
        }
    }

    private fun generate(mode: Mode, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUnlockedDeviceRequired(true)
            .setIsStrongBoxBacked(strongBox)
            .apply {
                if (mode == Mode.PER_APPROVAL) {
                    setUserAuthenticationRequired(true)
                    setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL)
                    // Enrolling a new fingerprint already requires the device credential, which can
                    // approve anyway; invalidating would silently destroy the CA.
                    setInvalidatedByBiometricEnrollment(false)
                }
            }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(spec)
            generateKeyPair()
        }
    }

    fun delete() {
        if (exists()) keyStore().deleteEntry(ALIAS)
    }

    /** Uncompressed public point (0x04 || X || Y). */
    fun point(): ByteArray =
        SshCert.point(keyStore().getCertificate(ALIAS).publicKey as ECPublicKey)

    private fun privateKey(): PrivateKey = keyStore().getKey(ALIAS, null) as PrivateKey

    /** A Signature ready for update/sign. For [Mode.PER_APPROVAL] it must go through BiometricPrompt first. */
    fun signature(): Signature = Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey()) }

    private fun info(): KeyInfo =
        KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").getKeySpec(privateKey(), KeyInfo::class.java)

    fun mode(): Mode = if (info().isUserAuthenticationRequired) Mode.PER_APPROVAL else Mode.UNLOCKED

    /** Human-readable protection level of the key. */
    fun securityLevel(): String {
        val info = info()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> "StrongBox (dedicated secure chip)"
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TEE (hardware-isolated)"
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> "Software only"
                else -> "Unknown (${info.securityLevel})"
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) "Secure hardware" else "Software only"
        }
    }
}

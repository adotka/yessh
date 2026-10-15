package io.github.adotka.yessh.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stores the 32-byte pairing PSK encrypted under a non-exportable Keystore AES key, so the file
 * on disk is useless without this device's secure hardware (StrongBox when available). No user
 * auth: the listener service must decrypt requests in the background.
 */
class PskVault(private val file: File) {
    private val alias = "yessh-psk-wrap"

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? SecretKey)?.let { return it }
        return try {
            generateKey(strongBox = true)
        } catch (e: StrongBoxUnavailableException) {
            generateKey(strongBox = false)
        }
    }

    private fun generateKey(strongBox: Boolean): SecretKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setIsStrongBoxBacked(strongBox)
            .build()
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
            init(spec)
            generateKey()
        }
    }

    fun exists() = file.exists()

    fun store(psk: ByteArray) {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        val ct = c.doFinal(psk)
        val tmp = File(file.path + ".tmp")
        tmp.writeBytes(byteArrayOf(c.iv.size.toByte()) + c.iv + ct)
        check(tmp.renameTo(file)) { "could not write ${file.name}" }
    }

    fun load(): ByteArray {
        val raw = file.readBytes()
        check(raw.isNotEmpty()) { "psk file corrupt" }
        val ivLen = raw[0].toInt()
        // The Keystore always generates 12-byte GCM IVs; the tag is 16 bytes.
        check(ivLen == 12 && raw.size >= 1 + ivLen + 16) { "psk file corrupt" }
        val iv = raw.copyOfRange(1, 1 + ivLen)
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, iv)) }
        return c.doFinal(raw, 1 + ivLen, raw.size - 1 - ivLen)
    }

    fun delete() {
        file.delete()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.run { if (containsAlias(alias)) deleteEntry(alias) }
    }
}

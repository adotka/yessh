package io.github.adotka.yessh

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.adotka.yessh.core.B64
import io.github.adotka.yessh.core.MemoryStore
import io.github.adotka.yessh.core.Ntfy
import io.github.adotka.yessh.core.Phone
import io.github.adotka.yessh.core.Protocol
import io.github.adotka.yessh.core.SshCert
import io.github.adotka.yessh.core.randomBytes
import io.github.adotka.yessh.data.FileStore
import io.github.adotka.yessh.security.PskVault
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@RunWith(AndroidJUnit4::class)
class KeystoreTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"

    /** Keystore EC key (no user auth, so the test can sign) with the same algorithm as the CA. */
    private fun testKey(alias: String): Pair<ByteArray, () -> Signature> {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        val kp = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore").run {
            initialize(
                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build(),
            )
            generateKeyPair()
        }
        return SshCert.point(kp.public as ECPublicKey) to { Signature.getInstance("SHA256withECDSA").apply { initSign(kp.private) } }
    }

    @Test
    fun keystoreSignedCertificatesVerify() {
        val (point, sig) = testKey("yessh-test-ca")
        // Many signatures: covers r/s with the high bit set and with leading zeros.
        repeat(40) { i ->
            val u = SshCert.toBeSigned(SshCert.Template(ed, "yessh:test:$i", listOf("root"), 1000, 2000L + i, i.toLong()), point)
            val line = SshCert.assemble(u, sig().run { update(u.tbs); sign() })
            val cert = SshCert.parseCert(line) // throws if the signature does not verify
            assertEquals("yessh:test:$i", cert.keyId)
        }
    }

    @Test
    fun engineApprovesWithKeystoreKey() {
        val (point, sig) = testKey("yessh-test-ca2")
        val keys = Protocol.derive(randomBytes(32))
        val store = MemoryStore().apply { setPolicy(Protocol.Policy(allowedPrincipals = listOf("root"))) }
        val phone = Phone(store, Ntfy("http://127.0.0.1:9"), keys, point)
        val now = System.currentTimeMillis() / 1000
        val id = B64.urlEncode(randomBytes(16))
        val req = """{"id":"$id","ts":$now,"label":"emu","who":"t@emu","pubkey":"$ed","principals":["root"],"ttl":600}"""
        val item = phone.ingest(Protocol.seal(keys.encKey, Protocol.AAD_REQ, req))!!
        assertTrue(item.ok)
        val prepared = phone.prepare(id)
        val line = SshCert.assemble(prepared.unsigned, sig().run { update(prepared.toBeSigned); sign() })
        val cert = SshCert.parseCert(line)
        assertEquals(listOf("root"), cert.principals)
        assertEquals("yessh:emu:$id", cert.keyId)
    }

    @Test
    fun pskVaultRoundTrip() {
        val f = File(context.noBackupFilesDir, "psk-test.bin")
        val v = PskVault(f)
        val psk = randomBytes(32)
        v.store(psk)
        assertContentEquals(psk, PskVault(f).load())
        // The file is ciphertext, not the PSK.
        assertTrue(!f.readBytes().toList().windowed(32).any { it == psk.toList() })
        v.delete()
    }

    @Test
    fun fileStorePersists() {
        val dir = File(context.cacheDir, "store-test").apply { deleteRecursively(); mkdirs() }
        val s = FileStore(dir)
        s.setPolicy(Protocol.Policy(allowedPrincipals = listOf("root"), maxTtl = 7200))
        s.markSeen("a", 1000)
        s.markSeen("b", 1000 + Protocol.SEEN_TTL)
        s.appendLog(Protocol.AuditEntry(1, "approved", "a", "l", "w", listOf("root"), 60, "SHA256:x", "1", "k"))
        val t = FileStore(dir)
        assertEquals(listOf("root"), t.policy().allowedPrincipals)
        assertEquals(setOf("b"), t.seen(1001 + Protocol.SEEN_TTL))
        assertEquals("approved", t.log().single().decision)
        dir.deleteRecursively()
    }
}

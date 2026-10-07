package io.github.adotka.yessh.core

import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.math.BigInteger
import java.nio.file.Files
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SshCertTest {
    @Test
    fun mpintVectors() {
        val cases = listOf(
            "" to "", "00" to "", "0000" to "", "01" to "01", "7f" to "7f", "80" to "0080", "ff" to "00ff",
            "0080" to "0080", "000080" to "0080", "00007f" to "7f", "0001ff" to "01ff",
            "00".repeat(31) + "ab" to "00ab",
            "80" + "00".repeat(30) + "01" to "0080" + "00".repeat(30) + "01",
        )
        for ((input, want) in cases) assertEquals(want, mpint(hexBytes(input)).hex(), "mpint($input)")
    }

    @Test
    fun derToSshAndBack() {
        // r with the top bit set (33-byte mpint), s with leading zero bytes.
        val r = BigInteger(1, hexBytes("ff" + "11".repeat(31)))
        val s = BigInteger(1, hexBytes("0000" + "7f" + "22".repeat(29)))
        val blob = SshCert.sshSignature(r, s)
        val expect = "00000013" + "ecdsa-sha2-nistp256".toByteArray().hex() + "00000047" +
            "00000021" + "00" + "ff" + "11".repeat(31) + "0000001e" + "7f" + "22".repeat(29)
        assertEquals(expect, blob.hex())
        val der = SshCert.sshSignatureToDer(blob)
        assertEquals(r to s, SshCert.derToRs(der))
        assertEquals(blob.hex(), SshCert.sshSignatureFromDer(der).hex())
    }

    @Test
    fun rejectsNonMinimalMpint() {
        val inner = hexBytes("00000021" + "00" + "01".repeat(32) + "00000020" + "01".repeat(32))
        val blob = SshWriter().string("ecdsa-sha2-nistp256").string(inner).bytes()
        assertFailsWith<IllegalArgumentException> { SshCert.sshSignatureToDer(blob) }
    }

    @Test
    fun parsePublicKeyRejectsJunk() {
        assertFailsWith<IllegalArgumentException> { SshCert.parsePublicKey("ssh-rsa AAAAB3NzaC1yc2E= x") }
        assertFailsWith<IllegalArgumentException> { SshCert.parsePublicKey("ssh-ed25519") }
        assertFailsWith<IllegalArgumentException> { SshCert.parsePublicKey("ssh-ed25519 !!!") }
        val short = SshWriter().string("ssh-ed25519").string(byteArrayOf(1, 2)).bytes()
        assertFailsWith<IllegalArgumentException> { SshCert.parsePublicKey("ssh-ed25519 " + B64.encode(short)) }
        val offCurve = byteArrayOf(4) + ByteArray(64) { 1 }
        val ec = SshWriter().string("ecdsa-sha2-nistp256").string("nistp256").string(offCurve).bytes()
        assertFailsWith<IllegalArgumentException> { SshCert.parsePublicKey("ecdsa-sha2-nistp256 " + B64.encode(ec)) }
        // A real point is on the curve.
        assertTrue(P256.isOnCurve(newCa().point()))
    }

    private val edSubject = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"

    @Test
    fun templateValidation() {
        val ca = newCa()
        val t = SshCert.Template(edSubject, "k", listOf("root"), 1000, 2000, 1)
        SshCert.sign(t, ca.point(), ca::signDer)
        for (bad in listOf(
            t.copy(principals = emptyList()), t.copy(principals = listOf("a,b")), t.copy(principals = listOf("ro ot")),
            t.copy(keyId = "a\nb"), t.copy(validBefore = 1000),
        )) {
            assertFailsWith<IllegalArgumentException> { SshCert.sign(bad, ca.point(), ca::signDer) }
        }
    }

    // ---- against ssh-keygen ----

    private fun tmp(): File = Files.createTempDirectory("yessh-kt").toFile()

    private fun keygen(dir: File, type: String): String {
        val f = File(dir, "id_$type")
        val args = if (type == "ecdsa") arrayOf("-t", "ecdsa", "-b", "256") else arrayOf("-t", type)
        val (code, out) = run("ssh-keygen", *args, "-N", "", "-q", "-C", "subject", "-f", f.path)
        assertEquals(0, code, out)
        return File(f.path + ".pub").readText().trim()
    }

    private fun list(dir: File, line: String): Pair<Int, String> {
        val f = File(dir, "c-${System.nanoTime()}-cert.pub")
        f.writeText(line + "\n")
        return run("ssh-keygen", "-L", "-f", f.path, env = mapOf("TZ" to "UTC"))
    }

    private fun field(out: String, name: String) = Regex("^\\s+$name: ?(.*)$", RegexOption.MULTILINE).find(out)?.groupValues?.get(1)

    private fun listField(out: String, name: String): List<String> {
        val m = Regex("^\\s+$name: ?(.*)\\n((?:\\s{16}.*\\n)*)", RegexOption.MULTILINE).find(out) ?: return emptyList()
        if (m.groupValues[1].trim() == "(none)") return emptyList()
        return m.groupValues[2].lines().map { it.trim() }.filter { it.isNotEmpty() }
    }

    private fun iso(s: Long) = Instant.ofEpochSecond(s).toString().removeSuffix("Z")

    @Test
    fun caLineMatchesSshKeygen() {
        assumeTrue("ssh-keygen not installed", hasCommand("ssh-keygen"))
        val dir = tmp()
        val ca = newCa()
        val line = SshCert.caPublicKeyLine(ca.point())
        File(dir, "ca.pub").writeText(line + "\n")
        val (code, out) = run("ssh-keygen", "-l", "-f", File(dir, "ca.pub").path)
        assertEquals(0, code, out)
        assertEquals("256 ${SshCert.fingerprint(SshCert.caPublicKeyBlob(ca.point()))} yessh-ca (ECDSA)", out.trim())
        dir.deleteRecursively()
    }

    @Test
    fun sshKeygenAgreesWithBuilder() {
        assumeTrue("ssh-keygen not installed", hasCommand("ssh-keygen"))
        for (keyType in listOf("ed25519", "ecdsa")) {
            val dir = tmp()
            val ca = newCa()
            val subject = keygen(dir, keyType)
            val now = 1790000000L
            val line = SshCert.sign(
                SshCert.Template(subject, "yessh:mgmt-1:AAECAwQFBgcICQoLDA0ODw", listOf("root", "deploy"), now - 60, now + 3600, 1790000000123),
                ca.point(), ca::signDer,
            )
            val certType = if (keyType == "ed25519") "ssh-ed25519-cert-v01@openssh.com" else "ecdsa-sha2-nistp256-cert-v01@openssh.com"
            assertTrue(line.startsWith("$certType "))
            val (code, out) = list(dir, line)
            assertEquals(0, code, out)
            assertEquals("$certType user certificate", field(out, "Type"))
            val subjectFp = SshCert.fingerprint(SshCert.parsePublicKey(subject).blob)
            assertEquals("${if (keyType == "ed25519") "ED25519" else "ECDSA"}-CERT $subjectFp", field(out, "Public key"))
            assertEquals("ECDSA ${SshCert.fingerprint(SshCert.caPublicKeyBlob(ca.point()))} (using ecdsa-sha2-nistp256)", field(out, "Signing CA"))
            assertEquals("\"yessh:mgmt-1:AAECAwQFBgcICQoLDA0ODw\"", field(out, "Key ID"))
            assertEquals("1790000000123", field(out, "Serial"))
            assertEquals("from ${iso(now - 60)} to ${iso(now + 3600)}", field(out, "Valid"))
            assertEquals(listOf("root", "deploy"), listField(out, "Principals"))
            assertEquals(emptyList(), listField(out, "Critical Options"))
            assertEquals(listOf("permit-pty"), listField(out, "Extensions"))

            val parsed = SshCert.parseCert(line)
            assertEquals(listOf("root", "deploy"), parsed.principals)
            assertEquals(subjectFp, SshCert.fingerprint(parsed.subjectBlob))
            dir.deleteRecursively()
        }
    }

    @Test
    fun criticalOptionsAndSortedExtensions() {
        assumeTrue("ssh-keygen not installed", hasCommand("ssh-keygen"))
        val dir = tmp()
        val ca = newCa()
        val line = SshCert.sign(
            SshCert.Template(
                keygen(dir, "ed25519"), "yessh:x:y", listOf("root"), 1000, 2000, 1,
                criticalOptions = mapOf("source-address" to "10.0.0.0/8,192.168.1.1"),
                extensions = listOf("permit-pty", "permit-agent-forwarding", "permit-port-forwarding"),
            ),
            ca.point(), ca::signDer,
        )
        val (code, out) = list(dir, line)
        assertEquals(0, code, out)
        assertEquals(listOf("source-address 10.0.0.0/8,192.168.1.1"), listField(out, "Critical Options"))
        assertEquals(listOf("permit-agent-forwarding", "permit-port-forwarding", "permit-pty"), listField(out, "Extensions"))
        dir.deleteRecursively()
    }

    @Test
    fun manySignaturesParseAndCoverMpintLengths() {
        assumeTrue("ssh-keygen not installed", hasCommand("ssh-keygen"))
        val dir = tmp()
        val ca = newCa()
        val subject = keygen(dir, "ed25519")
        val lens = mutableSetOf<Int>()
        repeat(64) { i ->
            val line = SshCert.sign(SshCert.Template(subject, "k$i", listOf("root"), 1000, 2000L + i, 1), ca.point(), ca::signDer)
            val cert = SshCert.parseCert(line)
            val sig = SshReader(cert.signature).apply { str() }
            val inner = SshReader(sig.bytes())
            lens += inner.bytes().size
            lens += inner.bytes().size
            val (code, out) = list(dir, line)
            assertEquals(0, code, out)
        }
        assertTrue(33 in lens && 32 in lens, "mpint lengths seen: $lens")
        dir.deleteRecursively()
    }

    @Test
    fun sshKeygenRejectsTampering() {
        assumeTrue("ssh-keygen not installed", hasCommand("ssh-keygen"))
        val dir = tmp()
        val ca = newCa()
        val line = SshCert.sign(SshCert.Template(keygen(dir, "ed25519"), "yessh:a:b", listOf("root"), 1000, 2000, 1), ca.point(), ca::signDer)
        val parts = line.split(" ")
        val blob = B64.decode(parts[1])
        val idx = String(blob, Charsets.ISO_8859_1).indexOf("root")
        for (pos in listOf(idx + 3, blob.size - 5)) {
            val t = blob.clone()
            t[pos] = (t[pos].toInt() xor 1).toByte()
            val tampered = "${parts[0]} ${B64.encode(t)} x"
            assertNotEquals(0, list(dir, tampered).first, "tampered byte $pos accepted")
            assertFailsWith<IllegalArgumentException> { SshCert.parseCert(tampered) }
        }
        dir.deleteRecursively()
    }

    /** Writes host/internal/sshcert/testdata/kotlin-cert.json for the Go verifier (YESSH_UPDATE_FIXTURES=1). */
    @Test
    fun goVerifierFixture() {
        val f = File(repoRoot, "host/internal/sshcert/testdata/kotlin-cert.json")
        if (System.getenv("YESSH_UPDATE_FIXTURES") != "1") {
            assumeTrue("fixture missing", f.exists())
            return
        }
        val ca = newCa()
        val ed = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val raw = ed.public.encoded.takeLast(32).toByteArray()
        val key = "ssh-ed25519 " + B64.encode(SshWriter().string("ssh-ed25519").string(raw).bytes())
        val now = 1790000000L
        val store = MemoryStore().apply { setPolicy(Protocol.Policy(allowedPrincipals = listOf("root"))) }
        val keys = Protocol.derive(randomBytes(32))
        val phone = Phone(store, Ntfy("http://127.0.0.1:1"), keys, ca.point()) { now }
        val req = """{"id":"${B64.urlEncode(randomBytes(16))}","ts":$now,"label":"fixture","who":"test@fixture","pubkey":"$key","principals":["root"],"ttl":3600}"""
        val item = phone.ingest(Protocol.seal(keys.encKey, Protocol.AAD_REQ, req))!!
        val prepared = phone.prepare(item.req.id)
        val cert = SshCert.assemble(prepared.unsigned, ca.signDer(prepared.toBeSigned))
        val ca64 = SshCert.caPublicKeyLine(ca.point())
        f.writeText(
            """{
  "ca": "$ca64",
  "key": "$key",
  "cert": "$cert",
  "principals": ["root"],
  "ttl": 3600,
  "now": $now
}
""",
        )
    }
}

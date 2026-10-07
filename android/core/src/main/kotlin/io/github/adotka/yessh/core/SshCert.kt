package io.github.adotka.yessh.core

import java.math.BigInteger
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * OpenSSH user certificates signed by an ECDSA P-256 CA (layout per OpenSSH PROTOCOL.certkeys).
 *
 * Signing is split in two so the private key can live in Android Keystore behind a biometric
 * prompt: [toBeSigned] produces the bytes, the caller signs them with SHA256withECDSA (DER
 * output), and [assemble] produces the final certificate line.
 */
object SshCert {
    const val CA_KEY_TYPE = "ecdsa-sha2-nistp256"
    private const val CURVE = "nistp256"
    private const val USER_CERT = 1L

    private val CERT_TYPES = mapOf(
        "ssh-ed25519" to "ssh-ed25519-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256" to "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    )

    // ---- public keys ----

    class PublicKey(val type: String, val blob: ByteArray, /** blob minus its leading type string */ val keyFields: ByteArray)

    fun parsePublicKey(line: String): PublicKey {
        val parts = line.trim().split(Regex("\\s+"))
        require(parts.size >= 2) { "malformed public key line" }
        val (type, b64) = parts
        require(type in CERT_TYPES) { "unsupported key type: $type" }
        val blob = try {
            B64.decode(b64)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("malformed public key base64")
        }
        val r = SshReader(blob)
        require(r.str() == type) { "key type mismatch" }
        val start = r.off
        if (type == "ssh-ed25519") {
            require(r.bytes().size == 32) { "bad ed25519 key length" }
        } else {
            require(r.str() == CURVE) { "bad ecdsa curve" }
            val q = r.bytes()
            require(q.size == 65 && q[0] == 0x04.toByte()) { "bad ecdsa point" }
            require(P256.isOnCurve(q)) { "ecdsa point not on curve" }
        }
        r.end()
        return PublicKey(type, blob, blob.copyOfRange(start, blob.size))
    }

    /** CA public key wire blob from the uncompressed point (0x04 || X || Y). */
    fun caPublicKeyBlob(point: ByteArray): ByteArray {
        require(point.size == 65 && point[0] == 0x04.toByte()) { "expected uncompressed P-256 point" }
        return SshWriter().string(CA_KEY_TYPE).string(CURVE).string(point).bytes()
    }

    fun caPublicKeyLine(point: ByteArray, comment: String = "yessh-ca"): String =
        "$CA_KEY_TYPE ${B64.encode(caPublicKeyBlob(point))} $comment"

    /** Uncompressed point of a Java EC public key. */
    fun point(pub: ECPublicKey): ByteArray =
        byteArrayOf(4) + pub.w.affineX.toFixed(32) + pub.w.affineY.toFixed(32)

    /** "SHA256:" + unpadded base64 of SHA-256(blob), as ssh-keygen -l prints it. */
    fun fingerprint(blob: ByteArray): String =
        "SHA256:" + B64.encode(MessageDigest.getInstance("SHA-256").digest(blob)).trimEnd('=')

    // ---- signatures ----

    /** DER SEQUENCE { INTEGER r, INTEGER s } -> (r, s) as unsigned magnitudes. */
    fun derToRs(der: ByteArray): Pair<BigInteger, BigInteger> {
        var i = 0
        fun len(): Int {
            val b = der[i++].toInt() and 0xff
            if (b < 0x80) return b
            val n = b and 0x7f
            require(n in 1..2) { "bad DER length" }
            var v = 0
            repeat(n) { v = (v shl 8) or (der[i++].toInt() and 0xff) }
            return v
        }
        require(der[i++] == 0x30.toByte()) { "expected DER sequence" }
        val seqLen = len()
        require(i + seqLen == der.size) { "bad DER sequence length" }
        fun int(): BigInteger {
            require(der[i++] == 0x02.toByte()) { "expected DER integer" }
            val n = len()
            val v = BigInteger(der.copyOfRange(i, i + n))
            i += n
            require(v.signum() > 0) { "non-positive signature value" }
            return v
        }
        val r = int()
        val s = int()
        require(i == der.size) { "trailing DER data" }
        return r to s
    }

    /** (r, s) -> SSH signature blob: string("ecdsa-sha2-nistp256"), string(mpint(r) || mpint(s)). */
    fun sshSignature(r: BigInteger, s: BigInteger): ByteArray {
        val inner = SshWriter().string(mpint(r.toFixed(32))).string(mpint(s.toFixed(32))).bytes()
        return SshWriter().string(CA_KEY_TYPE).string(inner).bytes()
    }

    fun sshSignatureFromDer(der: ByteArray): ByteArray = derToRs(der).let { (r, s) -> sshSignature(r, s) }

    /** SSH ECDSA signature blob -> DER, strict about minimal mpints. */
    fun sshSignatureToDer(blob: ByteArray): ByteArray {
        val r = SshReader(blob)
        require(r.str() == CA_KEY_TYPE) { "unexpected signature type" }
        val inner = SshReader(r.bytes())
        r.end()
        val vals = List(2) {
            val m = inner.bytes()
            require(m.isEmpty() || (m[0].toInt() and 0x80) == 0) { "negative mpint" }
            require(!(m.size > 1 && m[0] == 0.toByte() && (m[1].toInt() and 0x80) == 0)) { "non-minimal mpint" }
            require(m.size <= 33) { "mpint too large" }
            BigInteger(1, m)
        }
        inner.end()
        fun derInt(v: BigInteger): ByteArray = v.toByteArray().let { byteArrayOf(2, it.size.toByte()) + it }
        val body = derInt(vals[0]) + derInt(vals[1])
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    // ---- certificates ----

    data class Template(
        val subject: String,
        val keyId: String,
        val principals: List<String>,
        val validAfter: Long,
        val validBefore: Long,
        val serial: Long,
        val criticalOptions: Map<String, String> = emptyMap(),
        val extensions: List<String> = listOf("permit-pty"),
        val nonce: ByteArray = randomBytes(32),
    )

    private val TEXT_BAD = Regex("[\\x00-\\x20\\x7f,]")

    private fun checkText(what: String, s: String, max: Int) {
        require(s.isNotEmpty() && s.length <= max && !TEXT_BAD.containsMatchIn(s)) { "invalid $what: \"$s\"" }
    }

    private fun options(opts: Map<String, String>): ByteArray {
        val w = SshWriter()
        for (name in opts.keys.sorted()) {
            val v = opts.getValue(name)
            w.string(name).string(if (v.isEmpty()) ByteArray(0) else SshWriter().string(v).bytes())
        }
        return w.bytes()
    }

    class Unsigned(val type: String, val keyId: String, val tbs: ByteArray, val serial: Long)

    /** Everything up to (not including) the signature field. */
    fun toBeSigned(t: Template, caPoint: ByteArray): Unsigned {
        val subject = parsePublicKey(t.subject)
        val certType = CERT_TYPES.getValue(subject.type)
        checkText("key id", t.keyId, 256)
        require(t.principals.isNotEmpty()) { "no principals" }
        t.principals.forEach { checkText("principal", it, 64) }
        require(t.validBefore > t.validAfter) { "validBefore must be after validAfter" }
        require(t.nonce.size == 32) { "nonce must be 32 bytes" }
        val principals = SshWriter().apply { t.principals.forEach { string(it) } }.bytes()
        val tbs = SshWriter()
            .string(certType)
            .string(t.nonce)
            .raw(subject.keyFields)
            .u64(t.serial)
            .u32(USER_CERT)
            .string(t.keyId)
            .string(principals)
            .u64(t.validAfter)
            .u64(t.validBefore)
            .string(options(t.criticalOptions))
            .string(options(t.extensions.associateWith { "" }))
            .string(ByteArray(0))
            .string(caPublicKeyBlob(caPoint))
            .bytes()
        return Unsigned(certType, t.keyId, tbs, t.serial)
    }

    /** Append the signature (DER from SHA256withECDSA) and return "<type> <base64> <key id>". */
    fun assemble(u: Unsigned, derSignature: ByteArray): String {
        val blob = SshWriter().raw(u.tbs).string(sshSignatureFromDer(derSignature)).bytes()
        return "${u.type} ${B64.encode(blob)} ${u.keyId}"
    }

    /** Build and sign with a signer that returns DER signatures (software key, or an unlocked Keystore key). */
    fun sign(t: Template, caPoint: ByteArray, signDer: (ByteArray) -> ByteArray): String {
        val u = toBeSigned(t, caPoint)
        return assemble(u, signDer(u.tbs))
    }

    // ---- parsing / verification ----

    class Cert(
        val type: String,
        val subjectBlob: ByteArray,
        val serial: Long,
        val certType: Long,
        val keyId: String,
        val principals: List<String>,
        val validAfter: Long,
        val validBefore: Long,
        val criticalOptions: Map<String, String>,
        val extensions: Map<String, String>,
        val signatureKey: ByteArray,
        val signature: ByteArray,
        val signed: ByteArray,
    )

    private fun decodeOptions(buf: ByteArray): Map<String, String> {
        val r = SshReader(buf)
        val out = linkedMapOf<String, String>()
        while (!r.done) {
            val name = r.str()
            val data = r.bytes()
            out[name] = if (data.isEmpty()) "" else SshReader(data).str()
        }
        return out
    }

    fun parseCert(line: String, verify: Boolean = true): Cert {
        val blob = B64.decode(line.trim().split(Regex("\\s+"))[1])
        val r = SshReader(blob)
        val type = r.str()
        val subjectType = CERT_TYPES.entries.firstOrNull { it.value == type }?.key
            ?: throw IllegalArgumentException("unsupported cert type: $type")
        r.bytes() // nonce
        val keyStart = r.off
        if (subjectType == "ssh-ed25519") r.bytes() else { r.str(); r.bytes() }
        val keyFields = blob.copyOfRange(keyStart, r.off)
        val serial = r.u64()
        val certType = r.u32()
        val keyId = r.str()
        val pr = SshReader(r.bytes())
        val principals = mutableListOf<String>()
        while (!pr.done) principals += pr.str()
        val validAfter = r.u64()
        val validBefore = r.u64()
        val crit = decodeOptions(r.bytes())
        val ext = decodeOptions(r.bytes())
        r.bytes() // reserved
        val sigKey = r.bytes()
        val signedLen = r.off
        val sig = r.bytes()
        r.end()
        val cert = Cert(
            type, SshWriter().string(subjectType).raw(keyFields).bytes(), serial, certType, keyId, principals,
            validAfter, validBefore, crit, ext, sigKey, sig, blob.copyOfRange(0, signedLen),
        )
        if (verify) require(verifySignature(cert)) { "certificate signature invalid" }
        return cert
    }

    fun verifySignature(c: Cert): Boolean {
        val k = SshReader(c.signatureKey)
        require(k.str() == CA_KEY_TYPE && k.str() == CURVE) { "unsupported CA key" }
        val q = k.bytes()
        k.end()
        val pub = P256.publicKey(q)
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(pub)
            update(c.signed)
            verify(sshSignatureToDer(c.signature))
        }
    }
}

/** NIST P-256 helpers (curve check and key import) without third-party crypto. */
object P256 {
    private val p = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val b = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)

    fun isOnCurve(q: ByteArray): Boolean {
        if (q.size != 65 || q[0] != 0x04.toByte()) return false
        val x = BigInteger(1, q.copyOfRange(1, 33))
        val y = BigInteger(1, q.copyOfRange(33, 65))
        if (x >= p || y >= p) return false
        val lhs = y.modPow(BigInteger.valueOf(2), p)
        val rhs = x.pow(3).subtract(x.multiply(BigInteger.valueOf(3))).add(b).mod(p)
        return lhs == rhs
    }

    fun publicKey(q: ByteArray): ECPublicKey {
        require(isOnCurve(q)) { "point not on P-256" }
        val params = java.security.AlgorithmParameters.getInstance("EC").run {
            init(java.security.spec.ECGenParameterSpec("secp256r1"))
            getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        }
        val point = ECPoint(BigInteger(1, q.copyOfRange(1, 33)), BigInteger(1, q.copyOfRange(33, 65)))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, params)) as ECPublicKey
    }
}

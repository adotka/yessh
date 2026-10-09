package io.github.adotka.yessh.core

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.put
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** yessh wire protocol v1 (same as the Go host). */
object Protocol {
    const val VERSION = 1
    const val AAD_REQ = "yessh1|req"
    const val AAD_RESP = "yessh1|resp"
    const val PAIRING_PREFIX = "yessh1:"
    const val MAX_SKEW = 120L // seconds
    const val BACKDATE = 60L // seconds
    const val SEEN_TTL = 24 * 3600L // seconds

    internal val json = Json { ignoreUnknownKeys = true; explicitNulls = false }

    // ---- key derivation ----

    fun hkdf(psk: ByteArray, info: String, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // Empty salt = HashLen zero bytes (RFC 5869); identical HMAC key after padding.
        mac.init(SecretKeySpec(ByteArray(32), "HmacSHA256"))
        val prk = mac.doFinal(psk)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val out = java.io.ByteArrayOutputStream()
        var t = ByteArray(0)
        var i = 1
        while (out.size() < length) {
            mac.update(t)
            mac.update(info.toByteArray(Charsets.UTF_8))
            mac.update(i.toByte())
            t = mac.doFinal()
            out.write(t)
            i++
        }
        return out.toByteArray().copyOf(length)
    }

    class Keys(val encKey: ByteArray, val reqTopic: String, val respTopic: String)

    fun derive(psk: ByteArray): Keys {
        require(psk.size == 32) { "psk must be 32 bytes" }
        return Keys(
            hkdf(psk, "yessh1 enc", 32),
            "yessh-r-" + base32(hkdf(psk, "yessh1 req topic", 20)),
            "yessh-r-" + base32(hkdf(psk, "yessh1 resp topic", 20)),
        )
    }

    // ---- envelope ----

    /** Encrypt plaintext into the envelope JSON (field order and format identical to the Go host). */
    fun seal(encKey: ByteArray, aad: String, plaintext: String, nonce: ByteArray = randomBytes(12)): String {
        require(nonce.size == 12)
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(encKey, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad.toByteArray(Charsets.UTF_8))
        val ct = c.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return """{"v":$VERSION,"n":"${B64.urlEncode(nonce)}","c":"${B64.urlEncode(ct)}"}"""
    }

    /** Decrypt an envelope; null for anything invalid (callers drop it silently). */
    fun open(encKey: ByteArray, aad: String, body: String): String? = try {
        val env = json.parseToJsonElement(body) as JsonObject
        if (env["v"]?.jsonPrimitive?.intOrNull != VERSION) null else {
            val nonce = B64.urlDecode(env.getValue("n").jsonPrimitive.content)
            val ct = B64.urlDecode(env.getValue("c").jsonPrimitive.content)
            if (nonce.size != 12) null else {
                val c = Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.DECRYPT_MODE, SecretKeySpec(encKey, "AES"), GCMParameterSpec(128, nonce))
                c.updateAAD(aad.toByteArray(Charsets.UTF_8))
                String(c.doFinal(ct), Charsets.UTF_8)
            }
        }
    } catch (e: Exception) {
        null
    }

    // ---- pairing ----

    data class Pairing(val ntfy: String, val pwa: String, val psk: ByteArray, val ca: String, val token: String? = null)

    fun makePairing(p: Pairing): String {
        val obj = buildJsonObject {
            put("v", VERSION)
            put("ntfy", p.ntfy)
            put("pwa", p.pwa)
            put("psk", B64.urlEncode(p.psk))
            put("ca", p.ca)
            if (!p.token.isNullOrEmpty()) put("token", p.token)
        }
        return PAIRING_PREFIX + B64.urlEncode(obj.toString().toByteArray(Charsets.UTF_8))
    }

    fun parsePairing(s: String): Pairing {
        val t = s.trim()
        require(t.startsWith(PAIRING_PREFIX)) { "pairing string must start with $PAIRING_PREFIX" }
        val obj = json.parseToJsonElement(String(B64.urlDecode(t.removePrefix(PAIRING_PREFIX)), Charsets.UTF_8)) as JsonObject
        require(obj["v"]?.jsonPrimitive?.intOrNull == VERSION) { "unsupported pairing version" }
        fun str(k: String) = obj[k]?.jsonPrimitive?.content
        val psk = B64.urlDecode(str("psk") ?: "")
        require(psk.size == 32) { "psk must be 32 bytes" }
        return Pairing(str("ntfy") ?: "", str("pwa") ?: "", psk, str("ca") ?: "", str("token"))
    }

    // ---- messages ----

    class Request(
        val id: String,
        val ts: Long,
        val label: String,
        val who: String,
        val pubkey: String,
        val principals: List<String>,
        val ttl: Long,
        /** the decrypted plaintext, kept for persistence */
        val raw: String,
    )

    private val ID_RE = Regex("^[A-Za-z0-9_-]{22}$")
    private val LABEL_RE = Regex("^[A-Za-z0-9._-]{1,64}$")
    private val PRINCIPAL_RE = Regex("^[A-Za-z0-9._@+-]{1,64}$")
    private val CONTROL = Regex("[\\x00-\\x1f\\x7f]")

    /** Lenient decode of a decrypted request; fields may be missing or wrong (evaluate() says so). */
    fun parseRequest(plaintext: String): Request? = try {
        val o = json.parseToJsonElement(plaintext) as JsonObject
        fun s(k: String) = (o[k] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: ""
        fun n(k: String) = (o[k] as? JsonPrimitive)?.takeIf { !it.isString }?.let { p ->
            p.longOrNull ?: p.content.toDoubleOrNull()?.let { d -> if (d == Math.floor(d)) d.toLong() else Long.MIN_VALUE }
        } ?: Long.MIN_VALUE
        val pr = (o["principals"] as? JsonArray)?.map { (it as? JsonPrimitive)?.takeIf { p -> p.isString }?.content ?: "\u0000" }
        Request(s("id"), n("ts"), s("label"), s("who"), s("pubkey"), pr ?: emptyList(), n("ttl"), plaintext)
    } catch (e: Exception) {
        null
    }

    @Serializable
    data class Response(val id: String, val ts: Long, val status: String, val cert: String? = null)

    fun encodeResponse(r: Response): String = json.encodeToString(Response.serializer(), r)

    // ---- policy ----

    @Serializable
    data class Policy(
        val allowedPrincipals: List<String> = emptyList(),
        val maxTtl: Long = 8 * 3600,
        val defaultTtl: Long = 3600,
        val extensions: List<String> = listOf("permit-pty"),
        val sourceAddress: String = "",
    )

    sealed class Evaluation {
        data class Ok(val principals: List<String>, val maxTtl: Long, val ttl: Long) : Evaluation()
        data class Rejected(val reason: Reason, val detail: String = "", val principals: List<String> = emptyList()) : Evaluation()
    }

    enum class Reason { MALFORMED, STALE, REPLAY, PRINCIPALS_NOT_ALLOWED }

    fun evaluate(req: Request, policy: Policy, now: Long, seen: (String) -> Boolean): Evaluation {
        fun bad(detail: String) = Evaluation.Rejected(Reason.MALFORMED, detail)
        if (!ID_RE.matches(req.id)) return bad("id")
        if (req.ts == Long.MIN_VALUE) return bad("ts")
        if (!LABEL_RE.matches(req.label)) return bad("label")
        if (req.who.isEmpty() || req.who.length > 128 || CONTROL.containsMatchIn(req.who)) return bad("who")
        if (req.principals.isEmpty() || req.principals.size > 32 || !req.principals.all { PRINCIPAL_RE.matches(it) }) {
            return bad("principals")
        }
        if (req.ttl == Long.MIN_VALUE || req.ttl <= 0) return bad("ttl")
        try {
            SshCert.parsePublicKey(req.pubkey)
        } catch (e: IllegalArgumentException) {
            return bad("pubkey: ${e.message}")
        }
        if (Math.abs(now - req.ts) > MAX_SKEW) return Evaluation.Rejected(Reason.STALE, "${now - req.ts}")
        if (seen(req.id)) return Evaluation.Rejected(Reason.REPLAY)
        val requested = req.principals.distinct()
        val principals = requested.filter { it in policy.allowedPrincipals }
        if (principals.isEmpty()) return Evaluation.Rejected(Reason.PRINCIPALS_NOT_ALLOWED, principals = requested)
        val maxTtl = minOf(req.ttl, policy.maxTtl)
        return Evaluation.Ok(principals, maxTtl, minOf(maxTtl, policy.defaultTtl))
    }

    // ---- audit ----

    @Serializable
    data class AuditEntry(
        val at: Long,
        val decision: String,
        val id: String,
        val label: String,
        val who: String,
        val principals: List<String>,
        val ttl: Long,
        val fingerprint: String,
        val serial: String? = null,
        val keyId: String? = null,
    )

    fun fingerprintOf(pubkey: String): String = try {
        SshCert.fingerprint(SshCert.parsePublicKey(pubkey).blob)
    } catch (e: IllegalArgumentException) {
        ""
    }
}

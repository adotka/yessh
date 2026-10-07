package io.github.adotka.yessh.core

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

class ProtocolTest {
    private val vectors = Protocol.json.parseToJsonElement(
        File(repoRoot, "host/internal/protocol/testdata/vectors.json").readText(),
    ).jsonObject

    private fun v(k: String) = vectors.getValue(k).jsonPrimitive.content

    @Test
    fun goVectorsHkdfAndTopics() {
        val psk = hexBytes(v("psk_hex"))
        assertEquals(v("enc_key_hex"), Protocol.hkdf(psk, "yessh1 enc", 32).hex())
        val k = Protocol.derive(psk)
        assertEquals(v("req_topic"), k.reqTopic)
        assertEquals(v("resp_topic"), k.respTopic)
    }

    @Test
    fun goVectorsEnvelopes() {
        val k = Protocol.derive(hexBytes(v("psk_hex")))
        for (e in vectors.getValue("envelopes") as JsonArray) {
            val o = e as JsonObject
            fun f(n: String) = o.getValue(n).jsonPrimitive.content
            assertEquals(f("plaintext"), Protocol.open(k.encKey, f("aad"), f("envelope")))
            assertEquals(f("envelope"), Protocol.seal(k.encKey, f("aad"), f("plaintext"), hexBytes(f("nonce_hex"))))
        }
        for (e in vectors.getValue("reject") as JsonArray) {
            val o = e as JsonObject
            assertNull(Protocol.open(k.encKey, o.getValue("aad").jsonPrimitive.content, o.getValue("envelope").jsonPrimitive.content))
        }
    }

    @Test
    fun goVectorsPairing() {
        val p = vectors.getValue("pairing").jsonObject
        val s = p.getValue("string").jsonPrimitive.content
        val d = p.getValue("decoded").jsonObject
        val parsed = Protocol.parsePairing(s)
        assertEquals(d.getValue("ntfy").jsonPrimitive.content, parsed.ntfy)
        assertEquals(d.getValue("pwa").jsonPrimitive.content, parsed.pwa)
        assertEquals(d.getValue("ca").jsonPrimitive.content, parsed.ca)
        assertEquals(v("psk_hex"), parsed.psk.hex())
        assertEquals(s, Protocol.makePairing(parsed))
        assertFailsWith<IllegalArgumentException> { Protocol.parsePairing("nope") }
    }

    @Test
    fun openDropsWrongKeyOrDirection() {
        val a = Protocol.derive(randomBytes(32))
        val b = Protocol.derive(randomBytes(32))
        val env = Protocol.seal(a.encKey, Protocol.AAD_REQ, "{}")
        assertEquals("{}", Protocol.open(a.encKey, Protocol.AAD_REQ, env))
        assertNull(Protocol.open(b.encKey, Protocol.AAD_REQ, env))
        assertNull(Protocol.open(a.encKey, Protocol.AAD_RESP, env))
        assertNull(Protocol.open(a.encKey, Protocol.AAD_REQ, "garbage"))
        assertNotEquals(Protocol.seal(a.encKey, Protocol.AAD_REQ, "x"), Protocol.seal(a.encKey, Protocol.AAD_REQ, "x"))
        assertEquals("abcdefghijklmnopqrstuvwxyz234567".length, 32)
        assertEquals("mzxw6", base32("foo".toByteArray()))
    }

    private val now = 1790000000L
    private val policy = Protocol.Policy(allowedPrincipals = listOf("root", "deploy"))
    private val ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"

    private fun req(over: String = ""): Protocol.Request {
        val base = mutableMapOf(
            "id" to "\"${B64.urlEncode(randomBytes(16))}\"", "ts" to "$now", "label" to "\"mgmt-1\"",
            "who" to "\"claude@mgmt-1\"", "pubkey" to "\"$ed\"", "principals" to "[\"root\"]", "ttl" to "14400",
        )
        if (over.isNotEmpty()) over.split(";").forEach { kv -> val (k, v) = kv.split("=", limit = 2); base[k] = v }
        return Protocol.parseRequest(base.entries.joinToString(",", "{", "}") { "\"${it.key}\":${it.value}" })!!
    }

    private fun reason(r: Protocol.Request, p: Protocol.Policy = policy, seen: Boolean = false) =
        (Protocol.evaluate(r, p, now) { seen } as? Protocol.Evaluation.Rejected)?.reason

    @Test
    fun evaluateFreshnessReplayMalformed() {
        assertEquals(Protocol.Reason.STALE, reason(req("ts=${now - 121}")))
        assertEquals(Protocol.Reason.STALE, reason(req("ts=${now + 121}")))
        assertNull(reason(req("ts=${now - 120}")))
        assertEquals(Protocol.Reason.REPLAY, reason(req(), seen = true))
        for (bad in listOf(
            "id=\"short\"", "ts=\"1\"", "label=\"a:b\"", "label=\"\"", "who=\"a\\nb\"", "principals=[]",
            "principals=[\"a,b\"]", "principals=\"root\"", "ttl=0", "ttl=1.5", "pubkey=\"ssh-rsa AAAA\"", "principals=[1]",
        )) {
            assertEquals(Protocol.Reason.MALFORMED, reason(req(bad)), bad)
        }
    }

    @Test
    fun evaluateClamps() {
        val e = Protocol.evaluate(req("principals=[\"root\",\"admin\",\"root\"];ttl=${99 * 3600}"), policy, now) { false }
        assertEquals(Protocol.Evaluation.Ok(listOf("root"), 8 * 3600L, 3600L), e)
        val small = assertIs<Protocol.Evaluation.Ok>(Protocol.evaluate(req("ttl=600"), policy, now) { false })
        assertEquals(600, small.maxTtl)
        assertEquals(600, small.ttl)
        val none = assertIs<Protocol.Evaluation.Rejected>(Protocol.evaluate(req("principals=[\"admin\"]"), policy, now) { false })
        assertEquals(Protocol.Reason.PRINCIPALS_NOT_ALLOWED, none.reason)
        assertEquals(listOf("admin"), none.principals)
        assertEquals(Protocol.Reason.PRINCIPALS_NOT_ALLOWED, reason(req(), Protocol.Policy()))
    }

    @Test
    fun responseJsonOmitsCertWhenDenied() {
        assertEquals("""{"id":"x","ts":1,"status":"denied"}""", Protocol.encodeResponse(Protocol.Response("x", 1, "denied")))
    }
}

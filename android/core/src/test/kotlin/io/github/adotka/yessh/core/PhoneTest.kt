package io.github.adotka.yessh.core

import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PhoneTest {
    private val ed = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g"

    private class Env(val fake: FakeNtfy, val phone: Phone, val store: MemoryStore, val keys: Protocol.Keys, val ca: java.security.KeyPair, var now: Long)

    private fun env(): Env {
        val fake = FakeNtfy()
        val store = MemoryStore()
        val keys = Protocol.derive(randomBytes(32))
        val ca = newCa()
        lateinit var e: Env
        val phone = Phone(store, Ntfy(fake.url), keys, ca.point()) { e.now }
        e = Env(fake, phone, store, keys, ca, System.currentTimeMillis() / 1000)
        return e
    }

    private fun Env.send(principals: String = "[\"root\"]", ts: Long = now, ttl: Long = 7200): String {
        val id = B64.urlEncode(randomBytes(16))
        val body = """{"id":"$id","ts":$ts,"label":"mgmt-1","who":"claude@mgmt-1","pubkey":"$ed","principals":$principals,"ttl":$ttl}"""
        Ntfy(fake.url).publish(keys.reqTopic, Protocol.seal(keys.encKey, Protocol.AAD_REQ, body))
        return id
    }

    private fun Env.responses() = fake.on(keys.respTopic).map {
        Protocol.json.parseToJsonElement(Protocol.open(keys.encKey, Protocol.AAD_RESP, it.message)!!).jsonObject
    }

    @Test
    fun approveFlow(): Unit = env().run {
        fake.use {
            val id = send(principals = "[\"root\",\"admin\"]")
            // Noise under another key is ignored.
            Ntfy(fake.url).publish(keys.reqTopic, Protocol.seal(Protocol.derive(randomBytes(32)).encKey, Protocol.AAD_REQ, "{}"))
            var pending = phone.refresh()
            assertEquals(1, pending.size)
            assertFailsWith<Phone.RequestException> { phone.prepare(id) }

            phone.allowPrincipals(listOf("root"))
            pending = phone.pending()
            assertTrue(pending[0].ok)
            assertTrue(pending[0].fingerprint.startsWith("SHA256:"))

            val prepared = phone.prepare(id, principals = listOf("root", "admin"), ttl = 1800)
            assertEquals(listOf("root"), prepared.principals)
            val audit = phone.complete(prepared, ca.signDer(prepared.toBeSigned))
            assertEquals("approved", audit.decision)
            assertEquals(1800, audit.ttl)

            val resp = responses().single()
            assertEquals(id, resp.getValue("id").jsonPrimitive.content)
            assertEquals("approved", resp.getValue("status").jsonPrimitive.content)
            val cert = SshCert.parseCert(resp.getValue("cert").jsonPrimitive.content)
            assertEquals(listOf("root"), cert.principals)
            assertEquals(1800 + 60, cert.validBefore - cert.validAfter)
            assertEquals("yessh:mgmt-1:$id", cert.keyId)

            // Answered requests don't come back (replay), even after a fresh engine poll.
            assertEquals(0, phone.refresh().size)
            assertFailsWith<Phone.RequestException> { phone.prepare(id) }
            assertEquals(1, store.log().size)
        }
    }

    @Test
    fun denyAndStale(): Unit = env().run {
        fake.use {
            phone.allowPrincipals(listOf("root"))
            val fresh = send()
            val old = send(ts = now - 600)
            assertEquals(listOf(fresh), phone.refresh().map { it.req.id })
            val ex = assertFailsWith<Phone.RequestException> { phone.prepare(old) }
            assertEquals("request expired", ex.message)
            phone.deny(fresh)
            val resp = responses().single()
            assertEquals("denied", resp.getValue("status").jsonPrimitive.content)
            assertNull(resp["cert"])
            assertEquals("denied", store.log().single().decision)

            // Time passes: an approvable request expires before the tap.
            val later = send()
            phone.refresh()
            val prepared = phone.prepare(later)
            now += 121
            assertFailsWith<Phone.RequestException> { phone.prepare(later) }
            // A signature obtained earlier still completes (the host is the final judge of freshness).
            phone.complete(prepared, ca.signDer(prepared.toBeSigned))
        }
    }

    @Test
    fun findPollsWhenUnknown(): Unit = env().run {
        fake.use {
            phone.allowPrincipals(listOf("root"))
            val id = send()
            val item = phone.find(id)!!
            assertTrue(item.ok)
            assertTrue(item.expiresIn in 115..120)
            assertNull(phone.find("A".repeat(22)))
        }
    }
}

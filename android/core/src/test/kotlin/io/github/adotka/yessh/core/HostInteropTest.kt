package io.github.adotka.yessh.core

import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The Kotlin engine against the real Go host over a real ntfy, using the streaming client the
 * Android listener service uses. Runs when YESSH_E2E_NTFY (e.g. http://localhost:18080) and
 * YESSH_BIN (path to a built `yessh`) are set; e2e/run.sh sets both.
 */
class HostInteropTest {
    private val ntfyUrl = System.getenv("YESSH_E2E_NTFY")
    private val bin = System.getenv("YESSH_BIN")

    @Test
    fun approveAndDenyViaStream() {
        assumeTrue("set YESSH_E2E_NTFY and YESSH_BIN", ntfyUrl != null && bin != null)
        val work = Files.createTempDirectory("yessh-kt-e2e").toFile()
        val env = mapOf("YESSH_CONFIG" to File(work, "config.json").path, "YESSH_DIR" to File(work, "run").path)
        val ca = newCa()
        val psk = randomBytes(32)
        val keys = Protocol.derive(psk)
        val store = MemoryStore().apply { setPolicy(Protocol.Policy(allowedPrincipals = listOf("root"))) }
        val ntfy = Ntfy(ntfyUrl!!)
        val phone = Phone(store, ntfy, keys, ca.point())
        val pairing = Protocol.makePairing(Protocol.Pairing(ntfyUrl, "", psk, SshCert.caPublicKeyLine(ca.point())))
        assertEquals(0, run(bin!!, "pair", pairing, env = env).first)

        // Listener: the same loop shape as the Android service.
        val decisions = ArrayDeque(listOf("approve", "deny"))
        val opened = CountDownLatch(1)
        val stream = ntfy.Stream(keys.reqTopic, null)
        val listener = thread {
            stream.run(onOpen = { opened.countDown() }) { m ->
                val item = phone.ingest(m.message) ?: return@run
                if (!item.ok) return@run
                when (decisions.removeFirst()) {
                    "approve" -> phone.prepare(item.req.id).let { p -> phone.complete(p, ca.signDer(p.toBeSigned)) }
                    else -> phone.deny(item.req.id)
                }
            }
        }
        assertTrue(opened.await(10, TimeUnit.SECONDS))
        try {
            val (code, out) = run(bin, "request", "-p", "root", "-t", "10m", "--label", "kotlin", "--timeout", "20s", env = env)
            assertEquals(0, code, out)
            val (scode, status) = run(bin, "status", env = env)
            assertEquals(0, scode, status)
            assertTrue(Regex("Principals:\\s+root").containsMatchIn(status), status)
            assertTrue(status.contains("yessh:kotlin:"), status)

            val (dcode, dout) = run(bin, "request", "-p", "root", "--label", "kotlin", "--timeout", "20s", env = env)
            assertEquals(3, dcode, dout)
            assertEquals(listOf("approved", "denied"), store.log().map { it.decision })
        } finally {
            stream.cancel()
            listener.join(5000)
            work.deleteRecursively()
        }
    }
}

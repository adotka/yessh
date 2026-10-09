package io.github.adotka.yessh.core

import org.junit.AfterClass
import org.junit.Assume.assumeTrue
import org.junit.BeforeClass
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runners.MethodSorters
import java.io.File
import java.nio.file.Files
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * End-to-end: real ntfy, real `yessh` binary, this engine as the phone, real sshd.
 * Driven by e2e/run.sh. Environment:
 *   E2E_NTFY     ntfy base URL (e.g. http://localhost:18080)
 *   YESSH_BIN    path to a built `yessh`
 *   E2E_CA_DIR   directory sshd reads TrustedUserCAKeys from (ca.pub is written there)
 *   E2E_SSH_PORT sshd port on 127.0.0.1 (12222 for the compose sshd)
 *   E2E_SSHD     "local" to start /usr/sbin/sshd here instead (port 12223)
 *   E2E_EXPIRY   "0" to skip the ~70 s expiry check
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class EndToEndTest {
    companion object {
        private val ntfyUrl: String? = System.getenv("E2E_NTFY")
        private val bin: String? = System.getenv("YESSH_BIN")
        private val local = System.getenv("E2E_SSHD") == "local"
        private val sshPort = if (local) 12223 else (System.getenv("E2E_SSH_PORT") ?: "12222").toInt()

        private lateinit var work: File
        private lateinit var env: Map<String, String>
        private lateinit var ca: java.security.KeyPair
        private lateinit var keys: Protocol.Keys
        private lateinit var phone: Phone
        private lateinit var pairing: String
        private var sshd: Process? = null

        private val enabled get() = ntfyUrl != null && bin != null && System.getenv("E2E_CA_DIR") != null

        @BeforeClass @JvmStatic
        fun setUp() {
            if (!enabled) return
            work = Files.createTempDirectory("yessh-e2e").toFile()
            env = mapOf("YESSH_CONFIG" to File(work, "config/config.json").path, "YESSH_DIR" to File(work, "run").path)
            ca = newCa()
            val psk = randomBytes(32)
            keys = Protocol.derive(psk)
            phone = Phone(MemoryStore(), Ntfy(ntfyUrl!!), keys, ca.point())
            val caLine = SshCert.caPublicKeyLine(ca.point())
            pairing = Protocol.makePairing(Protocol.Pairing(ntfyUrl, "", psk, caLine))

            val caDir = File(System.getenv("E2E_CA_DIR")).apply { mkdirs() }
            File(caDir, "ca.pub").writeText(caLine + "\n")

            if (local) {
                val hostKey = File(work, "ssh_host_ed25519_key")
                run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hostKey.path)
                val cfg = File(work, "sshd_config")
                cfg.writeText(
                    listOf(
                        "Port $sshPort", "ListenAddress 127.0.0.1", "HostKey ${hostKey.path}",
                        "TrustedUserCAKeys ${File(caDir, "ca.pub").path}", "AuthorizedKeysFile none",
                        "PasswordAuthentication no", "KbdInteractiveAuthentication no",
                        "PermitRootLogin prohibit-password", "UsePAM no", "PidFile ${File(work, "sshd.pid").path}",
                    ).joinToString("\n", postfix = "\n"),
                )
                File("/run/sshd").mkdirs()
                sshd = ProcessBuilder("/usr/sbin/sshd", "-D", "-e", "-f", cfg.path).redirectErrorStream(true)
                    .redirectOutput(File(work, "sshd.log")).start()
                Thread.sleep(500)
            }
        }

        @AfterClass @JvmStatic
        fun tearDown() {
            sshd?.destroy()
            if (::work.isInitialized) work.deleteRecursively()
        }

        fun yessh(vararg args: String, envOverride: Map<String, String> = emptyMap()) = run(bin!!, *args, env = env + envOverride)

        /** Start `yessh` in the background; returns a function that waits for (exit code, output). */
        fun yesshAsync(vararg args: String, envOverride: Map<String, String> = emptyMap()): () -> Pair<Int, String> {
            val p = ProcessBuilder(bin!!, *args).redirectErrorStream(true).apply { environment().putAll(env + envOverride) }.start()
            return {
                val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
                p.waitFor(60, TimeUnit.SECONDS)
                p.exitValue() to out
            }
        }

        /** Poll the request topic until a request with this label shows up. */
        fun waitFor(label: String): Phone.Item {
            val end = System.currentTimeMillis() + 15_000
            while (System.currentTimeMillis() < end) {
                phone.refresh()
                phone.pending().firstOrNull { it.req.label == label }?.let { return it }
                Thread.sleep(300)
            }
            error("no request with label $label arrived")
        }

        fun ssh(cmd: String = "echo e2e-ok"): Pair<Int, String> = run(
            "ssh", "-p", "$sshPort", "-i", File(env.getValue("YESSH_DIR"), "id_yessh").path,
            "-o", "CertificateFile=${File(env.getValue("YESSH_DIR"), "id_yessh-cert.pub").path}",
            "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
            "root@127.0.0.1", cmd,
        )

        fun approve(item: Phone.Item, ttl: Long? = null) {
            val p = phone.prepare(item.req.id, ttl = ttl)
            phone.complete(p, ca.signDer(p.toBeSigned))
        }
    }

    private fun need() = assumeTrue("set E2E_NTFY, YESSH_BIN and E2E_CA_DIR (see e2e/run.sh)", enabled)

    @Test
    fun t1_pair() {
        need()
        val (code, out) = yessh("pair", pairing)
        assertEquals(0, code, out)
        assertTrue(out.contains("ecdsa-sha2-nistp256"))
        assertEquals(SshCert.caPublicKeyLine(ca.point()), yessh("ca").second.trim())
    }

    @Test
    fun t2_approveThenSshAndEnsureReuses() {
        need()
        val wait = yesshAsync("request", "-p", "root", "-t", "10m", "--label", "e2e")
        val t0 = System.currentTimeMillis()
        val item = waitFor("e2e")
        assertEquals(Protocol.Reason.PRINCIPALS_NOT_ALLOWED, (item.evaluation as Protocol.Evaluation.Rejected).reason)
        phone.allowPrincipals(listOf("root"))
        val ev = phone.evaluate(item.req.id)!!.evaluation as Protocol.Evaluation.Ok
        assertEquals(600, ev.maxTtl)
        approve(item, ttl = 600)
        val (code, out) = wait()
        assertEquals(0, code, out)
        assertTrue(System.currentTimeMillis() - t0 < 10_000, "round trip under 10 s")

        val status = yessh("status")
        assertEquals(0, status.first, status.second)
        assertTrue(Regex("Principals:\\s+root").containsMatchIn(status.second))

        val s = ssh()
        assertEquals(0, s.first, s.second)
        assertEquals("e2e-ok", s.second.trim())

        val ensure = yessh("ensure", "-p", "root", "--min-remaining", "1m")
        assertEquals(0, ensure.first, ensure.second)
        assertEquals("", ensure.second, "ensure should be silent when the cert is fine")
    }

    @Test
    fun t3_denyExits3AndKeepsPreviousCert() {
        need()
        val certFile = File(env.getValue("YESSH_DIR"), "id_yessh-cert.pub")
        val before = certFile.readText()
        val wait = yesshAsync("request", "-p", "root", "--label", "e2e-deny")
        phone.deny(waitFor("e2e-deny").req.id)
        val (code, out) = wait()
        assertEquals(3, code, out)
        assertEquals(before, certFile.readText())
    }

    @Test
    fun t4_timeoutExits2() {
        need()
        val (code, out) = yessh("request", "-p", "root", "--label", "e2e-timeout", "--timeout", "3s")
        assertEquals(2, code, out)
    }

    @Test
    fun t5_tamperedResponseRejected() {
        need()
        val dir = File(work, "tamper")
        val wait = yesshAsync("request", "-p", "root", "--label", "e2e-tamper", envOverride = mapOf("YESSH_DIR" to dir.path))
        val item = waitFor("e2e-tamper")
        // Someone with the PSK but not the CA key signs with their own CA.
        val rogue = newCa()
        val now = System.currentTimeMillis() / 1000
        val cert = SshCert.sign(SshCert.Template(item.req.pubkey, "evil", listOf("root"), now - 60, now + 600, 1), rogue.point(), rogue::signDer)
        val body = Protocol.encodeResponse(Protocol.Response(item.req.id, now, "approved", cert))
        Ntfy(ntfyUrl!!).publish(keys.respTopic, Protocol.seal(keys.encKey, Protocol.AAD_RESP, body))
        val (code, out) = wait()
        assertEquals(1, code, out)
        assertTrue(out.contains("rejected response: cert: signed by an unexpected CA"), out)
        assertFalse(File(dir, "id_yessh-cert.pub").exists())
    }

    @Test
    fun t6_wrongPskInvisibleAndReplayRejected() {
        need()
        val wrong = Protocol.derive(randomBytes(32))
        val forged = """{"id":"${"A".repeat(22)}","ts":${System.currentTimeMillis() / 1000}}"""
        Ntfy(ntfyUrl!!).publish(keys.reqTopic, Protocol.seal(wrong.encKey, Protocol.AAD_REQ, forged))
        val labels = phone.refresh().map { it.req.label }
        assertFalse("A".repeat(22) in phone.pending().map { it.req.id })
        // Answered requests are still in ntfy's cache but must not come back as pending.
        for (answered in listOf("e2e", "e2e-deny")) assertFalse(answered in labels, "$answered came back")
        // A fresh engine (e.g. after a restart) with the same store would also reject them as replays.
    }

    @Test
    fun t7_certStopsWorkingAfterExpiry() {
        need()
        assumeTrue("E2E_EXPIRY=0", System.getenv("E2E_EXPIRY") != "0")
        val wait = yesshAsync("request", "-p", "root", "-t", "1m", "--label", "e2e-expiry")
        approve(waitFor("e2e-expiry"))
        assertEquals(0, wait().first)
        assertEquals(0, ssh().first)
        Thread.sleep(62_000)
        assertNotEquals(0, ssh().first, "ssh must fail with an expired cert")
        val (code, out) = yessh("status")
        assertEquals(1, code)
        assertTrue(out.contains("EXPIRED"), out)
    }
}

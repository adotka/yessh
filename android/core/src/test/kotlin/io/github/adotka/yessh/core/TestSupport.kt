package io.github.adotka.yessh.core

import com.sun.net.httpserver.HttpServer
import java.io.File
import java.net.InetSocketAddress
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.util.concurrent.TimeUnit

val repoRoot: File = File(System.getProperty("yessh.repoRoot") ?: "../..")

fun newCa(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

fun KeyPair.point(): ByteArray = SshCert.point(public as ECPublicKey)

fun KeyPair.signDer(data: ByteArray): ByteArray =
    Signature.getInstance("SHA256withECDSA").run { initSign(private); update(data); sign() }

fun hasCommand(cmd: String): Boolean = try {
    ProcessBuilder(cmd, "-?").redirectErrorStream(true).start().run { inputStream.readBytes(); waitFor(10, TimeUnit.SECONDS) }
    true
} catch (e: Exception) {
    false
}

fun run(vararg cmd: String, env: Map<String, String> = emptyMap()): Pair<Int, String> {
    val p = ProcessBuilder(*cmd).redirectErrorStream(true).apply { environment().putAll(env) }.start()
    val out = p.inputStream.readBytes().toString(Charsets.UTF_8)
    p.waitFor(60, TimeUnit.SECONDS)
    return p.exitValue() to out
}

/** Tiny in-memory ntfy: POST /<topic>, GET /<topic>/json?poll=1 (all cached messages). */
class FakeNtfy : AutoCloseable {
    val messages = mutableListOf<Ntfy.Message>()
    private val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)

    init {
        server.createContext("/") { ex ->
            val path = ex.requestURI.path.trim('/')
            if (ex.requestMethod == "POST") {
                val body = ex.requestBody.readBytes().toString(Charsets.UTF_8)
                synchronized(messages) {
                    messages += Ntfy.Message((messages.size + 1).toString(), System.currentTimeMillis() / 1000, "message", path, body)
                }
                ex.sendResponseHeaders(200, -1)
            } else {
                val topic = path.removeSuffix("/json")
                val out = synchronized(messages) {
                    messages.filter { it.topic == topic }.joinToString("\n") {
                        Protocol.json.encodeToString(Ntfy.Message.serializer(), it)
                    }
                }.toByteArray()
                ex.sendResponseHeaders(200, out.size.toLong().coerceAtLeast(1).let { if (out.isEmpty()) -1 else it })
                if (out.isNotEmpty()) ex.responseBody.use { it.write(out) }
            }
            ex.close()
        }
        server.start()
    }

    val url get() = "http://127.0.0.1:${server.address.port}"

    fun on(topic: String) = synchronized(messages) { messages.filter { it.topic == topic } }

    override fun close() = server.stop(0)
}

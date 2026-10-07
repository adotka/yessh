package io.github.adotka.yessh.core

import kotlinx.serialization.Serializable
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/** Minimal ntfy client: poll, publish and a cancellable JSON stream. The relay is untrusted. */
class Ntfy(baseUrl: String, private val token: String? = null) {
    private val base = baseUrl.trimEnd('/')

    @Serializable
    data class Message(val id: String = "", val time: Long = 0, val event: String = "", val topic: String = "", val message: String = "")

    private fun topicUrl(topic: String) = "$base/${URLEncoder.encode(topic, "UTF-8")}"

    private fun open(url: String, method: String = "GET", readTimeoutMs: Int = 30_000): HttpURLConnection =
        (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = 15_000
            readTimeout = readTimeoutMs
            useCaches = false
            if (!token.isNullOrEmpty()) setRequestProperty("Authorization", "Bearer $token")
        }

    private fun parse(line: String): Message? = try {
        Protocol.json.decodeFromString(Message.serializer(), line)
    } catch (e: Exception) {
        null
    }

    /** Cached messages on a topic (default: last 10 minutes). */
    fun poll(topic: String, since: String = "10m"): List<Message> {
        val c = open("${topicUrl(topic)}/json?poll=1&since=${URLEncoder.encode(since, "UTF-8")}")
        try {
            if (c.responseCode / 100 != 2) throw IOException("ntfy poll: HTTP ${c.responseCode}")
            return c.inputStream.bufferedReader().readLines().mapNotNull { parse(it) }
                .filter { it.event == "message" }
        } finally {
            c.disconnect()
        }
    }

    fun publish(topic: String, body: String, headers: Map<String, String> = emptyMap()) {
        val c = open(topicUrl(topic), "POST")
        try {
            c.doOutput = true
            headers.forEach { (k, v) -> c.setRequestProperty(k, v) }
            c.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            if (c.responseCode / 100 != 2) throw IOException("ntfy publish: HTTP ${c.responseCode}")
        } finally {
            c.disconnect()
        }
    }

    /** A single streaming connection; [cancel] from another thread ends [run]. */
    inner class Stream(private val topic: String, private val since: String?) {
        @Volatile private var conn: HttpURLConnection? = null
        @Volatile private var cancelled = false

        /**
         * Blocks until the connection ends or is cancelled. Returns the id of the last message
         * delivered (to resume with), or null if none. ntfy sends keepalives every ~45 s, so the
         * read timeout detects dead connections.
         */
        fun run(onOpen: () -> Unit, onMessage: (Message) -> Unit): String? {
            var last: String? = null
            val q = if (since.isNullOrEmpty()) "" else "?since=${URLEncoder.encode(since, "UTF-8")}"
            val c = open("${topicUrl(topic)}/json$q", readTimeoutMs = 90_000)
            conn = c
            if (cancelled) c.disconnect()
            try {
                if (c.responseCode / 100 != 2) throw IOException("ntfy subscribe: HTTP ${c.responseCode}")
                BufferedReader(InputStreamReader(c.inputStream, Charsets.UTF_8)).use { r ->
                    while (!cancelled) {
                        val line = r.readLine() ?: break
                        val m = parse(line) ?: continue
                        when (m.event) {
                            "open" -> onOpen()
                            "message" -> {
                                last = m.id
                                onMessage(m)
                            }
                        }
                    }
                }
            } catch (e: IOException) {
                if (!cancelled) throw StreamException(last, e)
            } finally {
                c.disconnect()
            }
            return last
        }

        fun cancel() {
            cancelled = true
            conn?.disconnect()
        }
    }

    class StreamException(val lastId: String?, cause: Throwable) : IOException(cause.message, cause)
}

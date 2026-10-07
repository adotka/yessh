package io.github.adotka.yessh.data

import io.github.adotka.yessh.core.PhoneStore
import io.github.adotka.yessh.core.Protocol
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.Json
import java.io.File

@Serializable
data class Settings(
    val ntfy: String = "https://ntfy.sh",
    val token: String = "",
)

/** App data in noBackupFilesDir: settings, policy, answered ids, audit log (JSON lines). */
class FileStore(private val dir: File) : PhoneStore {
    private val json = Json { ignoreUnknownKeys = true; encodeDefaults = true }
    private val lock = Any()

    private fun file(name: String) = File(dir, name)

    private fun write(name: String, text: String) {
        val tmp = file("$name.tmp")
        tmp.writeText(text)
        check(tmp.renameTo(file(name))) { "could not write $name" }
    }

    fun settings(): Settings = synchronized(lock) {
        file("settings.json").takeIf { it.exists() }?.let { json.decodeFromString(Settings.serializer(), it.readText()) } ?: Settings()
    }

    fun setSettings(s: Settings) = synchronized(lock) { write("settings.json", json.encodeToString(Settings.serializer(), s)) }

    override fun policy(): Protocol.Policy = synchronized(lock) {
        file("policy.json").takeIf { it.exists() }?.let { json.decodeFromString(Protocol.Policy.serializer(), it.readText()) }
            ?: Protocol.Policy()
    }

    override fun setPolicy(p: Protocol.Policy) = synchronized(lock) { write("policy.json", json.encodeToString(Protocol.Policy.serializer(), p)) }

    private val seenSer = MapSerializer(String.serializer(), Long.serializer())

    override fun seen(now: Long): Set<String> = synchronized(lock) {
        val all = file("seen.json").takeIf { it.exists() }?.let { json.decodeFromString(seenSer, it.readText()) } ?: emptyMap()
        val fresh = all.filterValues { now - it <= Protocol.SEEN_TTL }
        if (fresh.size != all.size) write("seen.json", json.encodeToString(seenSer, fresh))
        fresh.keys
    }

    override fun markSeen(id: String, now: Long) = synchronized(lock) {
        val all = file("seen.json").takeIf { it.exists() }?.let { json.decodeFromString(seenSer, it.readText()) } ?: emptyMap()
        write("seen.json", json.encodeToString(seenSer, all + (id to now)))
    }

    override fun appendLog(e: Protocol.AuditEntry) = synchronized(lock) {
        file("log.jsonl").appendText(json.encodeToString(Protocol.AuditEntry.serializer(), e) + "\n")
    }

    override fun log(): List<Protocol.AuditEntry> = synchronized(lock) {
        val f = file("log.jsonl")
        if (!f.exists()) return emptyList()
        f.readLines().filter { it.isNotBlank() }.mapNotNull {
            try {
                json.decodeFromString(Protocol.AuditEntry.serializer(), it)
            } catch (e: Exception) {
                null
            }
        }
    }

    fun logJson(): String = synchronized(lock) {
        "[\n" + log().joinToString(",\n") { json.encodeToString(Protocol.AuditEntry.serializer(), it) } + "\n]\n"
    }

    fun wipe() = synchronized(lock) {
        listOf("settings.json", "policy.json", "seen.json", "log.jsonl").forEach { file(it).delete() }
    }
}

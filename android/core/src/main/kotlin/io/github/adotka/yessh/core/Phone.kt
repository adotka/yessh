package io.github.adotka.yessh.core

/** Persistence the engine needs. The Android app backs it with files; tests use [MemoryStore]. */
interface PhoneStore {
    fun policy(): Protocol.Policy
    fun setPolicy(p: Protocol.Policy)

    /** Request ids answered within [Protocol.SEEN_TTL] seconds of [now]; older ones are pruned. */
    fun seen(now: Long): Set<String>
    fun markSeen(id: String, now: Long)

    fun appendLog(e: Protocol.AuditEntry)
    fun log(): List<Protocol.AuditEntry>
}

class MemoryStore : PhoneStore {
    private var policy = Protocol.Policy()
    private val seen = mutableMapOf<String, Long>()
    private val log = mutableListOf<Protocol.AuditEntry>()

    @Synchronized override fun policy() = policy
    @Synchronized override fun setPolicy(p: Protocol.Policy) { policy = p }
    @Synchronized override fun seen(now: Long): Set<String> {
        seen.entries.removeIf { now - it.value > Protocol.SEEN_TTL }
        return seen.keys.toSet()
    }
    @Synchronized override fun markSeen(id: String, now: Long) { seen[id] = now }
    @Synchronized override fun appendLog(e: Protocol.AuditEntry) { log += e }
    @Synchronized override fun log() = log.toList()
}

/**
 * Phone-side engine: decrypts requests from the request topic, evaluates them against policy,
 * and builds/sends responses. UI- and Keystore-agnostic: approval is split into [prepare]
 * (bytes to sign) and [complete] (signature in, response out) so the signature can happen
 * after a biometric prompt.
 */
class Phone(
    private val store: PhoneStore,
    private val ntfy: Ntfy,
    val keys: Protocol.Keys,
    /** CA public point (0x04 || X || Y) */
    private val caPoint: ByteArray,
    private val clock: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    class Item(
        val req: Protocol.Request,
        val evaluation: Protocol.Evaluation,
        val fingerprint: String,
        val age: Long,
        val policy: Protocol.Policy,
    ) {
        val ok get() = evaluation is Protocol.Evaluation.Ok

        /** Worth showing to the user: approvable now, or approvable after adding principals. */
        val actionable get() = ok || (evaluation as? Protocol.Evaluation.Rejected)?.reason == Protocol.Reason.PRINCIPALS_NOT_ALLOWED

        /** Seconds until the request falls outside the freshness window. */
        val expiresIn get() = Protocol.MAX_SKEW - age
    }

    private val requests = LinkedHashMap<String, Protocol.Request>()

    /** Decrypt one ntfy message body. Returns the evaluated item if it is a new, well-formed request. */
    @Synchronized
    fun ingest(body: String): Item? {
        val pt = Protocol.open(keys.encKey, Protocol.AAD_REQ, body) ?: return null
        val req = Protocol.parseRequest(pt) ?: return null
        if (req.id.isEmpty() || requests.containsKey(req.id)) return null
        requests[req.id] = req
        while (requests.size > 200) requests.remove(requests.keys.first())
        return evaluate(req.id)
    }

    /** Poll the request topic (last 10 minutes) and return actionable items, newest first. */
    fun refresh(): List<Item> {
        for (m in ntfy.poll(keys.reqTopic, "10m")) ingest(m.message)
        return pending()
    }

    @Synchronized
    fun evaluate(id: String): Item? {
        val req = requests[id] ?: return null
        val now = clock()
        val seen = store.seen(now)
        val policy = store.policy()
        val ev = Protocol.evaluate(req, policy, now) { it in seen }
        return Item(req, ev, Protocol.fingerprintOf(req.pubkey), now - req.ts, policy)
    }

    /** Find a request by id, polling ntfy once if it isn't known yet (e.g. after process death). */
    fun find(id: String): Item? = evaluate(id) ?: run { refresh(); evaluate(id) }

    @Synchronized
    fun pending(): List<Item> = requests.keys.mapNotNull { evaluate(it) }.filter { it.actionable }.sortedByDescending { it.req.ts }

    class RequestException(message: String) : Exception(message)

    class Prepared internal constructor(
        val item: Item,
        val unsigned: SshCert.Unsigned,
        val principals: List<String>,
        val ttl: Long,
        internal val now: Long,
    ) {
        /** The bytes to sign with SHA256withECDSA. */
        val toBeSigned: ByteArray get() = unsigned.tbs
    }

    /**
     * Re-evaluate at tap time and build the unsigned certificate. [principals]/[ttl] are the user's
     * choice; they are clamped so the phone never grants more than requested and allowed.
     */
    fun prepare(id: String, principals: List<String>? = null, ttl: Long? = null): Prepared {
        val item = evaluate(id) ?: throw RequestException("unknown request")
        val ev = item.evaluation
        if (ev !is Protocol.Evaluation.Ok) {
            throw RequestException(
                when ((ev as Protocol.Evaluation.Rejected).reason) {
                    Protocol.Reason.STALE -> "request expired"
                    Protocol.Reason.REPLAY -> "request already answered"
                    Protocol.Reason.PRINCIPALS_NOT_ALLOWED -> "principals not allowed: ${ev.principals.joinToString(", ")}"
                    Protocol.Reason.MALFORMED -> "malformed request (${ev.detail})"
                },
            )
        }
        val chosen = (principals ?: ev.principals).filter { it in ev.principals }.distinct()
        if (chosen.isEmpty()) throw RequestException("no principals selected")
        val t = minOf(ttl ?: ev.ttl, ev.maxTtl)
        if (t <= 0) throw RequestException("bad ttl")
        val now = clock()
        val p = item.policy
        val template = SshCert.Template(
            subject = item.req.pubkey,
            keyId = "yessh:${item.req.label}:${item.req.id}",
            principals = chosen,
            validAfter = now - Protocol.BACKDATE,
            validBefore = now + t,
            serial = System.currentTimeMillis(),
            criticalOptions = if (p.sourceAddress.isNotEmpty()) mapOf("source-address" to p.sourceAddress) else emptyMap(),
            extensions = p.extensions,
        )
        return Prepared(item, SshCert.toBeSigned(template, caPoint), chosen, t, now)
    }

    /** Attach the DER signature, publish the response, and record it. */
    fun complete(prepared: Prepared, derSignature: ByteArray): Protocol.AuditEntry {
        val cert = SshCert.assemble(prepared.unsigned, derSignature)
        val req = prepared.item.req
        respond(Protocol.Response(req.id, prepared.now, "approved", cert))
        val audit = Protocol.AuditEntry(
            at = prepared.now, decision = "approved", id = req.id, label = req.label, who = req.who,
            principals = prepared.principals, ttl = prepared.ttl, fingerprint = prepared.item.fingerprint,
            serial = prepared.unsigned.serial.toString(), keyId = prepared.unsigned.keyId,
        )
        record(req.id, audit)
        return audit
    }

    fun deny(id: String): Protocol.AuditEntry {
        val item = evaluate(id) ?: throw RequestException("unknown request")
        val req = item.req
        val now = clock()
        respond(Protocol.Response(req.id, now, "denied"))
        val audit = Protocol.AuditEntry(
            at = now, decision = "denied", id = req.id, label = req.label, who = req.who,
            principals = req.principals, ttl = req.ttl, fingerprint = item.fingerprint,
        )
        record(req.id, audit)
        return audit
    }

    private fun respond(r: Protocol.Response) {
        ntfy.publish(keys.respTopic, Protocol.seal(keys.encKey, Protocol.AAD_RESP, Protocol.encodeResponse(r)))
    }

    @Synchronized
    private fun record(id: String, audit: Protocol.AuditEntry) {
        store.markSeen(id, clock())
        store.appendLog(audit)
    }

    /** Add principals to the allowlist (the "Allow root" button). */
    fun allowPrincipals(list: List<String>) {
        val p = store.policy()
        store.setPolicy(p.copy(allowedPrincipals = (p.allowedPrincipals + list).map { it.trim() }.filter { it.isNotEmpty() }.distinct()))
    }
}

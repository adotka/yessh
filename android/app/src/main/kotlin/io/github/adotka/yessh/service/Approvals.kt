package io.github.adotka.yessh.service

import android.content.Context
import io.github.adotka.yessh.appState
import io.github.adotka.yessh.core.Phone
import io.github.adotka.yessh.core.Protocol
import io.github.adotka.yessh.security.CaKey
import io.github.adotka.yessh.ui.fmtDuration
import java.security.Signature

/** Approve / deny plumbing shared by the notification actions, the quick-approve sheet and the UI. Call off the main thread. */
object Approvals {
    fun deny(context: Context, id: String): Protocol.AuditEntry {
        val phone = context.appState.requirePhone()
        phone.find(id) ?: throw Phone.RequestException("request not found (expired?)")
        val audit = phone.deny(id)
        Notifier.showOutcome(context, id, "Denied: ${audit.label}", "${audit.who} gets nothing")
        context.appState.logChanged()
        return audit
    }

    /** Re-evaluate and build the unsigned certificate. */
    fun prepare(context: Context, id: String, principals: List<String>?, ttl: Long?): Phone.Prepared {
        val phone = context.appState.requirePhone()
        phone.find(id) ?: throw Phone.RequestException("request not found (expired?)")
        return phone.prepare(id, principals, ttl)
    }

    /** Sign with an initialized (and, for per-approval keys, authenticated) Signature, then publish. */
    fun complete(context: Context, prepared: Phone.Prepared, signature: Signature): Protocol.AuditEntry {
        signature.update(prepared.toBeSigned)
        val der = signature.sign()
        val audit = context.appState.requirePhone().complete(prepared, der)
        Notifier.showOutcome(
            context, audit.id, "Approved: ${audit.label}",
            "${audit.principals.joinToString(", ")} for ${fmtDuration(audit.ttl)}",
        )
        context.appState.logChanged()
        return audit
    }

    /** One-tap path for [CaKey.Mode.UNLOCKED] keys. */
    fun approveUnlocked(context: Context, id: String, principals: List<String>?, ttl: Long?): Protocol.AuditEntry {
        val prepared = prepare(context, id, principals, ttl)
        return complete(context, prepared, CaKey.signature())
    }
}

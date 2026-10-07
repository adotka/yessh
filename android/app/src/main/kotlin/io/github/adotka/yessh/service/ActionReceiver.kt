package io.github.adotka.yessh.service

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import kotlin.concurrent.thread

/** Handles the notification's "nope" button, and "yessh" when the CA key is in one-tap mode. */
class ActionReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val id = intent.getStringExtra(Notifier.EXTRA_ID) ?: return
        val pending = goAsync()
        thread(name = "yessh-action") {
            try {
                when (intent.action) {
                    ACTION_DENY -> Approvals.deny(context, id)
                    ACTION_APPROVE -> Approvals.approveUnlocked(
                        context, id,
                        intent.getStringArrayExtra(Notifier.EXTRA_PRINCIPALS)?.toList(),
                        intent.getLongExtra(Notifier.EXTRA_TTL, -1).takeIf { it > 0 },
                    )
                }
            } catch (e: Exception) {
                Log.w("yessh", "action ${intent.action} failed: $e")
                Notifier.showOutcome(context, id, "yessh: not sent", e.message ?: e.toString())
            } finally {
                pending.finish()
            }
        }
    }

    companion object {
        const val ACTION_DENY = "io.github.adotka.yessh.DENY"
        const val ACTION_APPROVE = "io.github.adotka.yessh.APPROVE"
    }
}

class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED || intent.action == Intent.ACTION_MY_PACKAGE_REPLACED) {
            ListenerService.start(context)
        }
    }
}

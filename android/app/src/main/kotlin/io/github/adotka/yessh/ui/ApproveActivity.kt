package io.github.adotka.yessh.ui

import android.app.Activity
import android.os.Bundle
import android.widget.Toast
import io.github.adotka.yessh.service.Notifier

/**
 * Invisible activity behind the notification's "yessh" button (per-approval mode): shows only the
 * system biometric / PIN sheet over whatever is on screen, then finishes.
 */
class ApproveActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) return // the prompt survives config changes on its own
        val id = intent.getStringExtra(Notifier.EXTRA_ID)
        if (id == null) {
            finish()
            return
        }
        ApprovalFlow.approve(
            this, id,
            intent.getStringArrayExtra(Notifier.EXTRA_PRINCIPALS)?.toList(),
            intent.getLongExtra(Notifier.EXTRA_TTL, -1).takeIf { it > 0 },
        ) { r ->
            r.exceptionOrNull()?.let { e ->
                if (e !is ApprovalFlow.Cancelled) Toast.makeText(this, "yessh: ${e.message}", Toast.LENGTH_LONG).show()
            }
            finish()
        }
    }

    override fun finish() {
        super.finish()
        @Suppress("DEPRECATION")
        overridePendingTransition(0, 0)
    }
}

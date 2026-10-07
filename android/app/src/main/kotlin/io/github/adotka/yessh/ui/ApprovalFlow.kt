package io.github.adotka.yessh.ui

import android.app.Activity
import android.hardware.biometrics.BiometricManager.Authenticators
import android.hardware.biometrics.BiometricPrompt
import android.os.CancellationSignal
import io.github.adotka.yessh.core.Phone
import io.github.adotka.yessh.core.Protocol
import io.github.adotka.yessh.security.CaKey
import io.github.adotka.yessh.service.Approvals
import java.util.concurrent.Executors

fun fmtDuration(seconds: Long): String {
    val s = seconds.coerceAtLeast(0)
    return when {
        s < 90 -> "${s}s"
        s < 3600 -> "${(s + 30) / 60}m"
        else -> {
            val h = s / 3600
            val m = (s % 3600 + 30) / 60
            if (m == 0L) "${h}h" else "${h}h ${m}m"
        }
    }
}

/**
 * prepare (background) → biometric / PIN sheet when the key needs it (main thread) →
 * sign + publish (background). [done] is called on the main thread.
 */
object ApprovalFlow {
    private val io = Executors.newSingleThreadExecutor()

    fun approve(activity: Activity, id: String, principals: List<String>?, ttl: Long?, done: (Result<Protocol.AuditEntry>) -> Unit) {
        fun finish(r: Result<Protocol.AuditEntry>) = activity.runOnUiThread { done(r) }
        io.execute {
            val prepared = try {
                Approvals.prepare(activity, id, principals, ttl)
            } catch (e: Exception) {
                return@execute finish(Result.failure(e))
            }
            if (CaKey.mode() == CaKey.Mode.UNLOCKED) {
                return@execute finish(runCatching { Approvals.complete(activity, prepared, CaKey.signature()) })
            }
            val signature = try {
                CaKey.signature()
            } catch (e: Exception) {
                return@execute finish(Result.failure(e))
            }
            activity.runOnUiThread { prompt(activity, prepared, signature, ::finish) }
        }
    }

    private fun prompt(
        activity: Activity,
        prepared: Phone.Prepared,
        signature: java.security.Signature,
        finish: (Result<Protocol.AuditEntry>) -> Unit,
    ) {
        val req = prepared.item.req
        val prompt = BiometricPrompt.Builder(activity)
            .setTitle("yessh: ${req.label}")
            .setSubtitle("${prepared.principals.joinToString(", ")} for ${fmtDuration(prepared.ttl)}")
            .setDescription("${req.who}\nKey ${prepared.item.fingerprint}")
            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL)
            .setConfirmationRequired(false)
            .build()
        prompt.authenticate(
            BiometricPrompt.CryptoObject(signature),
            CancellationSignal(),
            activity.mainExecutor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val sig = result.cryptoObject?.signature ?: signature
                    io.execute { finish(runCatching { Approvals.complete(activity, prepared, sig) }) }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    finish(Result.failure(Cancelled(errString.toString())))
                }
            },
        )
    }

    fun deny(activity: Activity, id: String, done: (Result<Protocol.AuditEntry>) -> Unit) {
        io.execute {
            val r = runCatching { Approvals.deny(activity, id) }
            activity.runOnUiThread { done(r) }
        }
    }

    class Cancelled(message: String) : Exception(message)
}

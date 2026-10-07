package io.github.adotka.yessh.service

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import io.github.adotka.yessh.R
import io.github.adotka.yessh.core.Phone
import io.github.adotka.yessh.core.Protocol
import io.github.adotka.yessh.security.CaKey
import io.github.adotka.yessh.ui.ApproveActivity
import io.github.adotka.yessh.ui.MainActivity
import io.github.adotka.yessh.ui.fmtDuration

object Notifier {
    const val CHANNEL_REQUESTS = "requests"
    const val CHANNEL_LISTENER = "listener"
    const val LISTENER_ID = 1

    const val EXTRA_ID = "request_id"
    const val EXTRA_PRINCIPALS = "principals"
    const val EXTRA_TTL = "ttl"

    fun createChannels(context: Context) {
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_REQUESTS, "Certificate requests", NotificationManager.IMPORTANCE_HIGH).apply {
                description = "A host is asking for an SSH certificate. Shows yessh / nope buttons."
                lockscreenVisibility = Notification.VISIBILITY_PRIVATE
                enableVibration(true)
            },
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_LISTENER, "Background connection", NotificationManager.IMPORTANCE_MIN).apply {
                description = "Required by Android while yessh listens for requests. You can hide this channel."
                setShowBadge(false)
            },
        )
    }

    fun canPost(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED &&
            NotificationManagerCompat.from(context).areNotificationsEnabled()

    fun notificationId(requestId: String) = 1000 + (requestId.hashCode() and 0x3fffffff)

    private fun flags() = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT

    fun openAppIntent(context: Context, requestId: String?): PendingIntent {
        val i = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP
            if (requestId != null) putExtra(EXTRA_ID, requestId)
        }
        return PendingIntent.getActivity(context, requestId?.let { notificationId(it) } ?: 0, i, flags())
    }

    /** Heads-up notification for a new request, with nope / yessh actions when it is approvable. */
    fun showRequest(context: Context, item: Phone.Item) {
        if (!canPost(context)) return
        val req = item.req
        val nid = notificationId(req.id)
        val ev = item.evaluation
        val b = NotificationCompat.Builder(context, CHANNEL_REQUESTS)
            .setSmallIcon(R.drawable.ic_stat_key)
            .setContentTitle("yessh request from ${req.label}")
            .setCategory(NotificationCompat.CATEGORY_MESSAGE)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setVisibility(NotificationCompat.VISIBILITY_PRIVATE)
            .setPublicVersion(
                NotificationCompat.Builder(context, CHANNEL_REQUESTS)
                    .setSmallIcon(R.drawable.ic_stat_key)
                    .setContentTitle("yessh: certificate request")
                    .setContentText("Unlock to review")
                    .build(),
            )
            .setContentIntent(openAppIntent(context, req.id))
            .setAutoCancel(false)
            .setOnlyAlertOnce(true)
            .setTimeoutAfter(item.expiresIn.coerceAtLeast(1) * 1000)
            .setWhen(req.ts * 1000)
            .setShowWhen(true)

        if (ev is Protocol.Evaluation.Ok) {
            val summary = "${ev.principals.joinToString(", ")} for ${fmtDuration(ev.ttl)}"
            b.setContentText("${req.who} → $summary")
            b.setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    "${req.who} wants $summary" +
                        (if (ev.principals.size < req.principals.distinct().size) " (dropped: ${(req.principals - ev.principals.toSet()).joinToString(", ")})" else "") +
                        "\nKey ${item.fingerprint}" +
                        "\nTap the notification to change principals or TTL.",
                ),
            )
            b.addAction(action(context, R.drawable.ic_stat_key, "nope", denyIntent(context, req.id)))
            b.addAction(action(context, R.drawable.ic_stat_key, "yessh", approveIntent(context, req.id, ev.principals, ev.ttl)))
        } else {
            val missing = (ev as Protocol.Evaluation.Rejected).principals.joinToString(", ")
            b.setContentText("${req.who} wants $missing (not in your allowlist)")
            b.setStyle(
                NotificationCompat.BigTextStyle().bigText(
                    "${req.who} wants $missing for ${fmtDuration(req.ttl)}, but none of these principals are allowed yet.\nTap to review.",
                ),
            )
            b.addAction(action(context, R.drawable.ic_stat_key, "nope", denyIntent(context, req.id)))
        }
        post(context, nid, b.build())
    }

    private fun action(context: Context, icon: Int, title: String, pi: PendingIntent) =
        NotificationCompat.Action.Builder(icon, title, pi)
            // On the lock screen, Android asks the user to unlock before running the action.
            .setAuthenticationRequired(true)
            .build()

    private fun denyIntent(context: Context, id: String): PendingIntent {
        val i = Intent(context, ActionReceiver::class.java).setAction(ActionReceiver.ACTION_DENY).putExtra(EXTRA_ID, id)
        return PendingIntent.getBroadcast(context, notificationId(id) + 1, i, flags())
    }

    private fun approveIntent(context: Context, id: String, principals: List<String>, ttl: Long): PendingIntent {
        return if (CaKey.mode() == CaKey.Mode.PER_APPROVAL) {
            // Needs an activity to show the biometric / PIN sheet.
            val i = Intent(context, ApproveActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_NO_ANIMATION)
                .putExtra(EXTRA_ID, id)
                .putExtra(EXTRA_PRINCIPALS, principals.toTypedArray())
                .putExtra(EXTRA_TTL, ttl)
            PendingIntent.getActivity(context, notificationId(id) + 2, i, flags())
        } else {
            val i = Intent(context, ActionReceiver::class.java).setAction(ActionReceiver.ACTION_APPROVE)
                .putExtra(EXTRA_ID, id)
                .putExtra(EXTRA_PRINCIPALS, principals.toTypedArray())
                .putExtra(EXTRA_TTL, ttl)
            PendingIntent.getBroadcast(context, notificationId(id) + 2, i, flags())
        }
    }

    /** Replace the request notification with a short-lived outcome. */
    fun showOutcome(context: Context, requestId: String, title: String, text: String) {
        if (!canPost(context)) return
        val n = NotificationCompat.Builder(context, CHANNEL_REQUESTS)
            .setSmallIcon(R.drawable.ic_stat_key)
            .setContentTitle(title)
            .setContentText(text)
            .setContentIntent(openAppIntent(context, null))
            .setOnlyAlertOnce(true)
            .setSilent(true)
            .setAutoCancel(true)
            .setTimeoutAfter(8_000)
            .build()
        post(context, notificationId(requestId), n)
    }

    fun cancel(context: Context, requestId: String) = NotificationManagerCompat.from(context).cancel(notificationId(requestId))

    fun listener(context: Context, status: String): Notification =
        NotificationCompat.Builder(context, CHANNEL_LISTENER)
            .setSmallIcon(R.drawable.ic_stat_key)
            .setContentTitle("yessh is listening for requests")
            .setContentText(status)
            .setPriority(NotificationCompat.PRIORITY_MIN)
            .setOngoing(true)
            .setSilent(true)
            .setContentIntent(openAppIntent(context, null))
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_DEFERRED)
            .build()

    @Suppress("MissingPermission")
    private fun post(context: Context, id: Int, n: Notification) {
        if (canPost(context)) NotificationManagerCompat.from(context).notify(id, n)
    }
}

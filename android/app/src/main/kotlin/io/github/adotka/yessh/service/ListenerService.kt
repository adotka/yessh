package io.github.adotka.yessh.service

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.content.ContextCompat
import io.github.adotka.yessh.appState
import io.github.adotka.yessh.core.Ntfy
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * Foreground service holding a streaming connection to the request topic, so requests show up
 * as notifications within seconds. Requests are only valid for two minutes, so there is no
 * point in periodic polling; this is the push transport.
 */
class ListenerService : Service() {
    @Volatile private var running = false
    @Volatile private var stream: Ntfy.Stream? = null
    private var worker: Thread? = null
    private val wake = Object()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val n = Notifier.listener(this, "Connecting…")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(Notifier.LISTENER_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(Notifier.LISTENER_ID, n)
        }
        if (intent?.action == ACTION_RESTART) reconnectNow()
        if (!running) start()
        return START_STICKY
    }

    private fun start() {
        running = true
        val cm = getSystemService(ConnectivityManager::class.java)
        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = reconnectNow()
        }.also { cm.registerDefaultNetworkCallback(it) }
        worker = thread(name = "yessh-listener") { loop() }
    }

    private fun status(s: String) {
        appState.listenerStatus.value = s
        if (Notifier.canPost(this)) {
            getSystemService(android.app.NotificationManager::class.java).notify(Notifier.LISTENER_ID, Notifier.listener(this, s))
        }
    }

    /** Drop the current connection and skip the backoff (network change, settings change). */
    private fun reconnectNow() {
        stream?.cancel()
        synchronized(wake) { wake.notifyAll() }
    }

    private fun loop() {
        var backoff = 1L
        // Requests older than two minutes are useless; start there and resume by message id.
        var since: String? = "2m"
        while (running) {
            val state = appState
            val phone = state.phone()
            if (phone == null) {
                status("Not set up")
                stopSelf()
                return
            }
            val s = state.store.settings()
            val ntfy = Ntfy(s.ntfy, s.token.ifEmpty { null })
            val st = ntfy.Stream(phone.keys.reqTopic, since)
            stream = st
            try {
                val last = st.run(onOpen = {
                    backoff = 1
                    // `since` replays anything that arrived while we were offline.
                    status("Connected to ${s.ntfy.removePrefix("https://")}")
                }) { m ->
                    val item = phone.ingest(m.message)
                    if (item != null && item.actionable) Notifier.showRequest(this, item)
                    state.publishPending(phone.pending())
                }
                if (last != null) since = last
            } catch (e: Ntfy.StreamException) {
                if (e.lastId != null) since = e.lastId
                Log.w(TAG, "stream: ${e.message}")
            } catch (e: Exception) {
                Log.w(TAG, "stream: $e")
            }
            if (!running) break
            status("Reconnecting in ${backoff}s")
            synchronized(wake) { wake.wait(TimeUnit.SECONDS.toMillis(backoff)) }
            backoff = (backoff * 2).coerceAtMost(60)
        }
    }

    override fun onDestroy() {
        running = false
        stream?.cancel()
        networkCallback?.let { getSystemService(ConnectivityManager::class.java).unregisterNetworkCallback(it) }
        synchronized(wake) { wake.notifyAll() }
        appState.listenerStatus.value = "stopped"
        super.onDestroy()
    }

    companion object {
        private const val TAG = "yessh"
        const val ACTION_RESTART = "io.github.adotka.yessh.RESTART"

        fun start(context: Context) = launch(context, Intent(context, ListenerService::class.java))

        fun restart(context: Context) = launch(context, Intent(context, ListenerService::class.java).setAction(ACTION_RESTART))

        private fun launch(context: Context, intent: Intent) {
            if (!context.appState.paired) return
            try {
                ContextCompat.startForegroundService(context, intent)
            } catch (e: IllegalStateException) {
                // ForegroundServiceStartNotAllowedException (background start without an exemption).
                // The next app open or boot starts it again.
                Log.w(TAG, "listener not started: $e")
                context.appState.listenerStatus.value = "not running (open the app)"
            }
        }

        fun stop(context: Context) {
            context.stopService(Intent(context, ListenerService::class.java))
        }
    }
}

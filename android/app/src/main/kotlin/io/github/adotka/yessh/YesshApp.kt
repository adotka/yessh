package io.github.adotka.yessh

import android.app.Application
import android.content.Context
import io.github.adotka.yessh.core.Ntfy
import io.github.adotka.yessh.core.Phone
import io.github.adotka.yessh.core.Protocol
import io.github.adotka.yessh.core.SshCert
import io.github.adotka.yessh.core.randomBytes
import io.github.adotka.yessh.data.FileStore
import io.github.adotka.yessh.data.Settings
import io.github.adotka.yessh.security.CaKey
import io.github.adotka.yessh.security.PskVault
import io.github.adotka.yessh.service.ListenerService
import io.github.adotka.yessh.service.Notifier
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.File

class YesshApp : Application() {
    lateinit var state: AppState
        private set

    override fun onCreate() {
        super.onCreate()
        state = AppState(this)
        Notifier.createChannels(this)
    }
}

val Context.appState: AppState get() = (applicationContext as YesshApp).state

/** Process-wide state: storage, keys and the protocol engine. */
class AppState(private val context: Context) {
    val store = FileStore(context.noBackupFilesDir)
    private val vault = PskVault(File(context.noBackupFilesDir, "psk.bin"))

    @Volatile private var cached: Phone? = null

    /** Pending, actionable requests for the UI (refreshed by the listener and the UI). */
    private val _pending = MutableStateFlow<List<Phone.Item>>(emptyList())
    val pending: StateFlow<List<Phone.Item>> = _pending.asStateFlow()

    /** Listener connection status for the settings screen. */
    val listenerStatus = MutableStateFlow("stopped")

    /** Bumped when the log changes. */
    val logVersion = MutableStateFlow(0)

    val paired: Boolean get() = CaKey.exists() && vault.exists()

    /** The engine, or null before setup. */
    fun phone(): Phone? {
        cached?.let { return it }
        if (!paired) return null
        synchronized(this) {
            cached?.let { return it }
            val s = store.settings()
            val p = Phone(store, Ntfy(s.ntfy, s.token.ifEmpty { null }), Protocol.derive(vault.load()), CaKey.point())
            cached = p
            return p
        }
    }

    fun requirePhone(): Phone = phone() ?: error("not set up")

    fun createCa(settings: Settings, mode: CaKey.Mode): Boolean {
        check(!paired) { "a CA already exists" }
        CaKey.delete()
        val strongBox = CaKey.generate(mode)
        vault.store(randomBytes(32))
        store.setSettings(settings)
        cached = null
        return strongBox
    }

    fun caLine(): String = SshCert.caPublicKeyLine(CaKey.point())

    fun caFingerprint(): String = SshCert.fingerprint(SshCert.caPublicKeyBlob(CaKey.point()))

    fun pairingString(): String {
        val s = store.settings()
        // No PWA URL: the host then omits the ntfy Click header.
        return Protocol.makePairing(Protocol.Pairing(s.ntfy, "", vault.load(), caLine(), s.token.ifEmpty { null }))
    }

    fun updateSettings(s: Settings) {
        store.setSettings(s)
        cached = null
        ListenerService.restart(context)
    }

    fun publishPending(items: List<Phone.Item>) {
        _pending.value = items
    }

    /** Re-evaluate known requests (e.g. after a decision or policy change). */
    fun refreshPendingLocal() {
        phone()?.let { _pending.value = it.pending() }
    }

    fun logChanged() {
        logVersion.value++
        refreshPendingLocal()
    }

    fun reset() {
        ListenerService.stop(context)
        CaKey.delete()
        vault.delete()
        store.wipe()
        cached = null
        _pending.value = emptyList()
        logVersion.value++
    }
}

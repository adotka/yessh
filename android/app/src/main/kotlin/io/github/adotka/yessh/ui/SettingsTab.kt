package io.github.adotka.yessh.ui

import android.annotation.SuppressLint
import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.net.Uri
import android.os.Build
import android.os.PersistableBundle
import android.os.PowerManager
import android.provider.Settings as AndroidSettings
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.FilterQuality
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import io.github.adotka.yessh.appState
import io.github.adotka.yessh.data.Settings
import io.github.adotka.yessh.security.CaKey
import io.github.adotka.yessh.service.Notifier

private val EXTENSIONS = listOf("permit-pty", "permit-agent-forwarding", "permit-port-forwarding", "permit-X11-forwarding", "permit-user-rc")

fun copy(context: Context, text: String, sensitive: Boolean) {
    val clip = ClipData.newPlainText("yessh", text)
    if (sensitive) {
        clip.description.extras = PersistableBundle().apply {
            putBoolean(if (Build.VERSION.SDK_INT >= 33) ClipDescription.EXTRA_IS_SENSITIVE else "android.content.extra.IS_SENSITIVE", true)
        }
    }
    context.getSystemService(ClipboardManager::class.java).setPrimaryClip(clip)
    if (Build.VERSION.SDK_INT < 33) Toast.makeText(context, "Copied", Toast.LENGTH_SHORT).show()
}

fun qrBitmap(text: String): Bitmap {
    val m = QRCodeWriter().encode(
        text, BarcodeFormat.QR_CODE, 0, 0,
        mapOf(EncodeHintType.MARGIN to 2, EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.L),
    )
    val bmp = Bitmap.createBitmap(m.width, m.height, Bitmap.Config.ARGB_8888)
    for (y in 0 until m.height) for (x in 0 until m.width) bmp.setPixel(x, y, if (m[x, y]) 0xFF000000.toInt() else 0xFFFFFFFF.toInt())
    return bmp
}

@SuppressLint("BatteryLife")
@Composable
fun SettingsTab(activity: MainActivity, onReset: () -> Unit) {
    val context = LocalContext.current
    val state = context.appState
    val caLine = remember { state.caLine() }
    val fp = remember { state.caFingerprint() }
    val level = remember { runCatching { CaKey.securityLevel() }.getOrDefault("unknown") }
    val mode = remember { runCatching { CaKey.mode() }.getOrNull() }
    val keys = remember { state.requirePhone().keys }
    var settings by remember { mutableStateOf(state.store.settings()) }
    val status by state.listenerStatus.collectAsStateWithLifecycle()
    var showPairing by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(horizontal = 16.dp)) {
        Text("Setup", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(top = 8.dp))

        Section("1. CA public key")
        Text("Put this line in /etc/ssh/yessh_ca.pub on fleet hosts and set TrustedUserCAKeys to that file.", style = MaterialTheme.typography.bodySmall)
        Card(Modifier.fillMaxWidth().padding(vertical = 8.dp)) { SelectionContainer { Mono(caLine, Modifier.padding(12.dp)) } }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(onClick = { copy(context, caLine, sensitive = false) }) { Text("Copy") }
            OutlinedButton(onClick = {
                context.startActivity(Intent.createChooser(Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, caLine), "CA public key"))
            }) { Text("Share") }
        }
        Text("Fingerprint", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
        Mono(fp)
        Text("Key protection: $level", modifier = Modifier.padding(top = 8.dp))
        Text(
            "Approval: " + when (mode) {
                CaKey.Mode.PER_APPROVAL -> "fingerprint / PIN for every certificate"
                CaKey.Mode.UNLOCKED -> "one tap while the phone is unlocked"
                null -> "unknown"
            },
        )

        Section("2. Pair the management host")
        if (!showPairing) {
            OutlinedButton(onClick = { showPairing = true }) { Text("Show pairing string") }
        } else {
            val pairing = remember { state.pairingString() }
            val qr = remember(pairing) { qrBitmap(pairing).asImageBitmap() }
            Warn("Contains the shared secret. Type or paste it into a shell on your management host yourself. Never give it to a coding agent or paste it into chat.")
            Card(Modifier.fillMaxWidth()) { SelectionContainer { Mono(pairing, Modifier.padding(12.dp)) } }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(vertical = 8.dp)) {
                OutlinedButton(onClick = { copy(context, pairing, sensitive = true) }) { Text("Copy") }
                OutlinedButton(onClick = { showPairing = false }) { Text("Hide") }
            }
            Text("On the host:", style = MaterialTheme.typography.bodySmall)
            Mono("yessh pair '<pairing string>'")
            Image(
                qr, contentDescription = "Pairing QR code", filterQuality = FilterQuality.None,
                modifier = Modifier.padding(vertical = 12.dp).size(260.dp).background(Color.White),
            )
        }

        Section("3. Notifications and background")
        val pm = context.getSystemService(PowerManager::class.java)
        val unrestricted = pm.isIgnoringBatteryOptimizations(context.packageName)
        Text("Listener: $status")
        Text(if (Notifier.canPost(context)) "Notifications: on" else "Notifications: OFF (requests won't pop up)",
            color = if (Notifier.canPost(context)) MaterialTheme.colorScheme.onSurface else MaterialTheme.colorScheme.error)
        if (!Notifier.canPost(context)) {
            OutlinedButton(onClick = {
                context.startActivity(Intent(AndroidSettings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(AndroidSettings.EXTRA_APP_PACKAGE, context.packageName))
            }) { Text("Notification settings") }
        }
        Text(if (unrestricted) "Battery: unrestricted" else "Battery: optimized (Android may delay requests while idle)")
        if (!unrestricted) {
            OutlinedButton(onClick = {
                context.startActivity(Intent(AndroidSettings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS, Uri.parse("package:${context.packageName}")))
            }) { Text("Allow running in background") }
        }
        Text("Request topic", style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
        Mono(keys.reqTopic)
        Text(
            "If the ntfy app is subscribed to this topic too, unsubscribe it there, or you'll get two notifications.",
            style = MaterialTheme.typography.bodySmall,
        )
        ServerEditor(settings) { s ->
            state.updateSettings(s)
            settings = s
            Toast.makeText(context, "Saved. Re-pair the host: the pairing string changed.", Toast.LENGTH_LONG).show()
        }

        Section("4. Policy")
        PolicyEditor()

        Section("Danger zone")
        var confirm by remember { mutableStateOf("") }
        Text("Deleting the CA is permanent. Fleet hosts will need the new CA line and the host must be re-paired.", style = MaterialTheme.typography.bodySmall)
        OutlinedTextField(confirm, { confirm = it }, label = { Text("type: delete my CA") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        Button(
            onClick = {
                if (confirm.trim() == "delete my CA") {
                    state.reset()
                    onReset()
                }
            },
            enabled = confirm.trim() == "delete my CA",
            colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error),
            modifier = Modifier.padding(vertical = 12.dp),
        ) { Text("Delete CA and all data") }
    }
}

@Composable
private fun ServerEditor(current: Settings, onSave: (Settings) -> Unit) {
    var editing by remember { mutableStateOf(false) }
    var ntfy by remember(current) { mutableStateOf(current.ntfy) }
    var token by remember(current) { mutableStateOf(current.token) }
    Text("ntfy server: ${current.ntfy}", modifier = Modifier.padding(top = 8.dp))
    if (!editing) {
        OutlinedButton(onClick = { editing = true }) { Text("Change server") }
        return
    }
    OutlinedTextField(ntfy, { ntfy = it }, label = { Text("ntfy server") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(token, { token = it }, label = { Text("access token (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.padding(top = 8.dp)) {
        Button(onClick = {
            val url = ntfy.trim().trimEnd('/')
            if (url.startsWith("https://") || url.startsWith("http://")) {
                onSave(Settings(url, token.trim()))
                editing = false
            }
        }) { Text("Save") }
        OutlinedButton(onClick = { editing = false }) { Text("Cancel") }
    }
}

@Composable
private fun PolicyEditor() {
    val context = LocalContext.current
    val store = context.appState.store
    val p = remember { store.policy() }
    var principals by remember { mutableStateOf(p.allowedPrincipals.joinToString(", ")) }
    var maxTtl by remember { mutableStateOf((p.maxTtl / 3600.0).toString().removeSuffix(".0")) }
    var defTtl by remember { mutableStateOf((p.defaultTtl / 3600.0).toString().removeSuffix(".0")) }
    val ext = remember { mutableStateListOf<String>().apply { addAll(p.extensions) } }
    var src by remember { mutableStateOf(p.sourceAddress) }
    var msg by remember { mutableStateOf<String?>(null) }

    OutlinedTextField(principals, { principals = it }, label = { Text("Allowed principals") }, placeholder = { Text("root, deploy") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(maxTtl, { maxTtl = it }, label = { Text("Maximum TTL (hours)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    OutlinedTextField(defTtl, { defTtl = it }, label = { Text("Default TTL (hours)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    Text("Extensions", modifier = Modifier.padding(top = 8.dp))
    for (x in EXTENSIONS) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Checkbox(x in ext, { c -> if (c) ext.add(x) else ext.remove(x) })
            Text(x)
        }
    }
    OutlinedTextField(src, { src = it }, label = { Text("source-address (optional)") }, placeholder = { Text("203.0.113.7/32") }, singleLine = true, modifier = Modifier.fillMaxWidth())
    msg?.let { Text(it, modifier = Modifier.padding(top = 4.dp)) }
    Button(modifier = Modifier.padding(top = 8.dp), onClick = {
        val max = maxTtl.toDoubleOrNull()?.times(3600)?.toLong()
        val def = defTtl.toDoubleOrNull()?.times(3600)?.toLong()
        if (max == null || def == null || max <= 0 || def <= 0) {
            msg = "TTLs must be positive numbers of hours"
            return@Button
        }
        val list = principals.split(Regex("[\\s,]+")).map { it.trim() }.filter { it.isNotEmpty() }.distinct()
        if (list.any { !Regex("^[A-Za-z0-9._@+-]{1,64}$").matches(it) }) {
            msg = "Principals may contain letters, digits and . _ @ + -"
            return@Button
        }
        store.setPolicy(p.copy(allowedPrincipals = list, maxTtl = max, defaultTtl = minOf(def, max), extensions = EXTENSIONS.filter { it in ext }, sourceAddress = src.trim()))
        principals = list.joinToString(", ")
        context.appState.refreshPendingLocal()
        msg = "Saved."
    }) { Text("Save policy") }
}

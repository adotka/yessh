package io.github.adotka.yessh.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.github.adotka.yessh.appState
import io.github.adotka.yessh.core.Phone
import io.github.adotka.yessh.core.Protocol
import io.github.adotka.yessh.data.Settings
import io.github.adotka.yessh.security.CaKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.DateFormat
import java.util.Date

@Composable
fun Mono(text: String, modifier: Modifier = Modifier, bold: Boolean = false) {
    Text(text, modifier = modifier, fontFamily = FontFamily.Monospace, fontSize = 13.sp, fontWeight = if (bold) FontWeight.Bold else null)
}

@Composable
fun Section(title: String) {
    Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 20.dp, bottom = 8.dp))
}

@Composable
fun Warn(text: String) {
    Surface(color = MaterialTheme.colorScheme.errorContainer, shape = MaterialTheme.shapes.medium, modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp)) {
        Text(text, color = MaterialTheme.colorScheme.onErrorContainer, modifier = Modifier.padding(12.dp))
    }
}

// ---------------------------------------------------------------------------- setup

@Composable
fun SetupScreen(onCreated: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var ntfy by rememberSaveable { mutableStateOf("https://ntfy.sh") }
    var token by rememberSaveable { mutableStateOf("") }
    var mode by rememberSaveable { mutableStateOf(CaKey.Mode.PER_APPROVAL) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }

    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(16.dp)) {
        Text("Create your SSH CA", style = MaterialTheme.typography.headlineSmall)
        Text(
            "yessh generates an ECDSA P-256 certificate authority inside this phone's secure hardware " +
                "(StrongBox or TEE). The private key can't be exported, backed up or copied, even by this app.",
            modifier = Modifier.padding(vertical = 8.dp),
        )
        OutlinedTextField(ntfy, { ntfy = it }, label = { Text("ntfy server") }, singleLine = true, modifier = Modifier.fillMaxWidth())
        OutlinedTextField(token, { token = it }, label = { Text("ntfy access token (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth().padding(top = 8.dp))

        Section("Approval")
        ModeOption(mode == CaKey.Mode.PER_APPROVAL, "Fingerprint / PIN for every approval (recommended)",
            "Tap yessh on the notification, then confirm. The key itself refuses to sign without it.") { mode = CaKey.Mode.PER_APPROVAL }
        ModeOption(mode == CaKey.Mode.UNLOCKED, "One tap while unlocked",
            "Tap yessh on the notification and it's done. The key only works while the phone is unlocked.") { mode = CaKey.Mode.UNLOCKED }
        Text("This can't be changed later without creating a new CA.", style = MaterialTheme.typography.bodySmall)

        error?.let { Warn(it) }
        Button(
            enabled = !busy,
            modifier = Modifier.fillMaxWidth().padding(top = 16.dp).height(52.dp),
            onClick = {
                error = null
                if (!CaKey.deviceSecure(context)) {
                    error = "Set a screen lock (PIN, pattern or password) first. Keystore keys that need unlocking can't exist without one."
                    return@Button
                }
                val url = ntfy.trim().trimEnd('/')
                if (!url.startsWith("https://") && !url.startsWith("http://")) {
                    error = "ntfy server must be an https:// URL"
                    return@Button
                }
                busy = true
                scope.launch {
                    val r = withContext(Dispatchers.IO) { runCatching { context.appState.createCa(Settings(url, token.trim()), mode) } }
                    busy = false
                    r.onSuccess { onCreated() }.onFailure { error = "Could not create the CA: ${it.message}" }
                }
            },
        ) { if (busy) CircularProgressIndicator(Modifier.size(20.dp)) else Text("Create CA") }
        TextButton(onClick = { (context as? MainActivity)?.showLicenses?.value = true }, modifier = Modifier.padding(top = 8.dp)) {
            Text("Open-source licenses")
        }
    }
}

@Composable
private fun ModeOption(selected: Boolean, title: String, detail: String, onClick: () -> Unit) {
    Row(Modifier.fillMaxWidth().selectable(selected, onClick = onClick).padding(vertical = 6.dp), verticalAlignment = Alignment.Top) {
        RadioButton(selected, onClick)
        Column(Modifier.padding(start = 8.dp)) {
            Text(title, fontWeight = FontWeight.SemiBold)
            Text(detail, style = MaterialTheme.typography.bodySmall)
        }
    }
}

// ---------------------------------------------------------------------------- home

@Composable
fun HomeScreen(activity: MainActivity, onReset: () -> Unit) {
    val context = LocalContext.current
    var tab by rememberSaveable { mutableIntStateOf(0) }
    val notifLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) {}
    LaunchedEffect(Unit) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notifLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }
    val open by activity.openRequest
    val id = open
    if (id != null) {
        RequestScreen(activity, id, onClose = { activity.openRequest.value = null })
        return
    }
    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(tab == 0, { tab = 0 }, icon = { Icon(Icons.Default.Notifications, null) }, label = { Text("Requests") })
                NavigationBarItem(tab == 1, { tab = 1 }, icon = { Icon(Icons.Default.List, null) }, label = { Text("Log") })
                NavigationBarItem(tab == 2, { tab = 2 }, icon = { Icon(Icons.Default.Settings, null) }, label = { Text("Setup") })
            }
        },
    ) { pad ->
        Box(Modifier.padding(pad).fillMaxSize()) {
            when (tab) {
                0 -> RequestsTab(onOpen = { activity.openRequest.value = it })
                1 -> LogTab()
                else -> SettingsTab(activity, onReset)
            }
        }
    }
}

@Composable
fun RequestsTab(onOpen: (String) -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val items by context.appState.pending.collectAsStateWithLifecycle()
    val status by context.appState.listenerStatus.collectAsStateWithLifecycle()
    var busy by remember { mutableStateOf(false) }
    val refresh: () -> Unit = {
        busy = true
        scope.launch {
            val r = withContext(Dispatchers.IO) { runCatching { context.appState.requirePhone().refresh() } }
            busy = false
            r.onSuccess { context.appState.publishPending(it) }
                .onFailure { Toast.makeText(context, "Refresh failed: ${it.message}", Toast.LENGTH_LONG).show() }
        }
    }
    LaunchedEffect(Unit) {
        while (true) {
            context.appState.refreshPendingLocal() // ages and expiry
            delay(5_000)
        }
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 8.dp)) {
            Text("Pending requests", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
            OutlinedButton(onClick = refresh, enabled = !busy) { Text("Refresh") }
        }
        Text("Listener: $status", style = MaterialTheme.typography.bodySmall)
        if (items.isEmpty()) {
            Text("Nothing waiting. New requests appear here and as a notification.", modifier = Modifier.padding(top = 24.dp))
        }
        LazyColumn(contentPadding = PaddingValues(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(items, key = { p -> p.req.id }) { item ->
                Card(Modifier.fillMaxWidth().clickable { onOpen(item.req.id) }) {
                    Column(Modifier.padding(14.dp)) {
                        Row {
                            Text(item.req.label, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                            Text("${fmtDuration(item.age)} ago", style = MaterialTheme.typography.bodySmall)
                        }
                        Text("${item.req.who} → ${item.req.principals.joinToString(", ")} for ${fmtDuration(item.req.ttl)}")
                        Mono(item.fingerprint)
                        if (!item.ok) Text("Needs principals added to the allowlist", color = MaterialTheme.colorScheme.error)
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------- one request

@Composable
fun RequestScreen(activity: MainActivity, id: String, onClose: () -> Unit) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var item by remember { mutableStateOf<Phone.Item?>(null) }
    var loading by remember { mutableStateOf(true) }
    var busy by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    var outcome by remember { mutableStateOf<Protocol.AuditEntry?>(null) }
    var now by remember { mutableLongStateOf(System.currentTimeMillis() / 1000) }

    suspend fun load() {
        // The request may reach ntfy's cache a moment after the notification.
        repeat(8) {
            val r = withContext(Dispatchers.IO) { runCatching { context.appState.requirePhone().find(id) } }
            r.onFailure { error = it.message }
            r.getOrNull()?.let {
                item = it
                loading = false
                return
            }
            delay(1_500)
        }
        loading = false
    }
    LaunchedEffect(id) { load() }
    LaunchedEffect(Unit) {
        while (true) {
            now = System.currentTimeMillis() / 1000
            delay(1_000)
        }
    }

    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(16.dp)) {
        TextButton(onClick = onClose) { Text("← Back") }
        val current = item
        val done = outcome
        when {
            done != null -> {
                Text(if (done.decision == "approved") "Approved" else "Denied", style = MaterialTheme.typography.headlineSmall)
                Text(
                    if (done.decision == "approved") "${done.label}: ${done.principals.joinToString(", ")} for ${fmtDuration(done.ttl)} (serial ${done.serial})"
                    else "${done.label}: request denied.",
                )
            }
            loading -> CircularProgressIndicator(Modifier.padding(24.dp))
            current == null -> {
                Text("Request not found", style = MaterialTheme.typography.headlineSmall)
                Text(error ?: "It may have expired or been answered already.")
            }
            else -> RequestDetails(
                current, now, busy, error,
                onAllow = { list ->
                    scope.launch {
                        withContext(Dispatchers.IO) { context.appState.requirePhone().allowPrincipals(list) }
                        item = withContext(Dispatchers.IO) { context.appState.requirePhone().evaluate(id) }
                        context.appState.refreshPendingLocal()
                    }
                },
                onDeny = {
                    busy = true
                    ApprovalFlow.deny(activity, id) { r ->
                        busy = false
                        r.onSuccess { outcome = it }.onFailure { error = it.message }
                    }
                },
                onApprove = { principals, ttl ->
                    busy = true
                    error = null
                    ApprovalFlow.approve(activity, id, principals, ttl) { r ->
                        busy = false
                        r.onSuccess { outcome = it }.onFailure { e -> if (e !is ApprovalFlow.Cancelled) error = e.message }
                    }
                },
            )
        }
    }
}

private val TTL_CHOICES = listOf(5 * 60L, 15 * 60L, 30 * 60L, 3600L, 2 * 3600L, 4 * 3600L, 8 * 3600L, 12 * 3600L, 24 * 3600L)

@Composable
private fun RequestDetails(
    item: Phone.Item,
    now: Long,
    busy: Boolean,
    error: String?,
    onAllow: (List<String>) -> Unit,
    onDeny: () -> Unit,
    onApprove: (List<String>, Long) -> Unit,
) {
    val req = item.req
    val age = now - req.ts
    Text("Certificate for ${req.label}?", style = MaterialTheme.typography.headlineSmall)
    Spacer(Modifier.height(8.dp))
    KV("From", req.label)
    KV("Who", req.who)
    KV("Age", "${fmtDuration(age)} ago", error = age > Protocol.MAX_SKEW)
    KV("Requested", "${req.principals.joinToString(", ")} for ${fmtDuration(req.ttl)}")
    Card(Modifier.fillMaxWidth().padding(vertical = 12.dp), colors = CardDefaults.cardColors()) {
        Column(Modifier.padding(14.dp)) {
            Text("Ephemeral key fingerprint", style = MaterialTheme.typography.bodySmall)
            Mono(item.fingerprint.ifEmpty { "(invalid key)" }, bold = true)
        }
    }

    val ev = item.evaluation
    if (ev !is Protocol.Evaluation.Ok) {
        val rej = ev as Protocol.Evaluation.Rejected
        when (rej.reason) {
            Protocol.Reason.PRINCIPALS_NOT_ALLOWED -> {
                Warn("None of the requested principals are in your allowlist: ${rej.principals.joinToString(", ")}.")
                OutlinedButton(onClick = { onAllow(rej.principals) }) { Text("Allow ${rej.principals.joinToString(", ")}") }
            }
            Protocol.Reason.STALE -> Warn("This request is too old (or from the future). The host has given up on it.")
            Protocol.Reason.REPLAY -> Warn("This request was already answered.")
            Protocol.Reason.MALFORMED -> Warn("Malformed request (${rej.detail}).")
        }
        error?.let { Warn(it) }
        Row(Modifier.padding(top = 16.dp)) {
            OutlinedButton(onClick = onDeny, enabled = !busy, modifier = Modifier.weight(1f).height(56.dp)) { Text("nope", fontFamily = FontFamily.Monospace, fontSize = 20.sp) }
        }
        return
    }

    val selected = remember(item.req.id) { mutableStateListOf<String>().apply { addAll(ev.principals) } }
    var ttl by remember(item.req.id) { mutableLongStateOf(ev.ttl) }
    var menu by remember { mutableStateOf(false) }
    Section("Principals")
    for (p in ev.principals) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.fillMaxWidth().clickable {
            if (p in selected) selected.remove(p) else selected.add(p)
        }) {
            Checkbox(p in selected, { c -> if (c) selected.add(p) else selected.remove(p) })
            Text(p)
        }
    }
    val dropped = req.principals.distinct().filter { it !in ev.principals }
    if (dropped.isNotEmpty()) Text("Not allowed by policy, will be dropped: ${dropped.joinToString(", ")}", style = MaterialTheme.typography.bodySmall)
    Section("Valid for")
    Box {
        OutlinedButton(onClick = { menu = true }) { Text(fmtDuration(ttl)) }
        DropdownMenu(menu, onDismissRequest = { menu = false }) {
            (TTL_CHOICES.filter { it < ev.maxTtl } + ev.maxTtl).distinct().sorted().forEach { t ->
                DropdownMenuItem(text = { Text(fmtDuration(t)) }, onClick = { ttl = t; menu = false })
            }
        }
    }
    error?.let { Warn(it) }
    Row(Modifier.padding(top = 20.dp), horizontalArrangement = Arrangement.spacedBy(12.dp)) {
        OutlinedButton(
            onClick = onDeny, enabled = !busy, modifier = Modifier.weight(1f).height(56.dp),
            colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
        ) { Text("nope", fontFamily = FontFamily.Monospace, fontSize = 20.sp) }
        Button(
            onClick = { onApprove(selected.toList(), ttl) },
            enabled = !busy && selected.isNotEmpty(),
            modifier = Modifier.weight(1f).height(56.dp),
        ) { Text("yessh", fontFamily = FontFamily.Monospace, fontSize = 20.sp, fontWeight = FontWeight.Bold) }
    }
}

@Composable
private fun KV(k: String, v: String, error: Boolean = false) {
    Row(Modifier.padding(vertical = 2.dp)) {
        Text(k, modifier = Modifier.weight(0.3f), style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(v, modifier = Modifier.weight(0.7f), color = if (error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurface)
    }
}

// ---------------------------------------------------------------------------- log

@Composable
fun LogTab() {
    val context = LocalContext.current
    val version by context.appState.logVersion.collectAsStateWithLifecycle()
    val entries = remember(version) { context.appState.store.log().reversed() }
    val export = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/json")) { uri ->
        if (uri != null) {
            context.contentResolver.openOutputStream(uri)?.use { it.write(context.appState.store.logJson().toByteArray()) }
            Toast.makeText(context, "Log exported", Toast.LENGTH_SHORT).show()
        }
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding().padding(horizontal = 16.dp)) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.padding(top = 8.dp)) {
            Text("Log", style = MaterialTheme.typography.headlineSmall, modifier = Modifier.weight(1f))
            OutlinedButton(onClick = { export.launch("yessh-log.json") }, enabled = entries.isNotEmpty()) { Text("Export") }
        }
        if (entries.isEmpty()) Text("No issuances or denials yet.", modifier = Modifier.padding(top = 24.dp))
        LazyColumn(contentPadding = PaddingValues(vertical = 8.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(entries) { e ->
                Card(Modifier.fillMaxWidth()) {
                    SelectionContainer {
                        Column(Modifier.padding(14.dp)) {
                            Row {
                                Text(e.label, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                                Text(
                                    e.decision,
                                    color = if (e.decision == "approved") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error,
                                )
                            }
                            Text(DateFormat.getDateTimeInstance().format(Date(e.at * 1000)), style = MaterialTheme.typography.bodySmall)
                            Text("${e.principals.joinToString(", ")} for ${fmtDuration(e.ttl)} · ${e.who}")
                            e.serial?.let { Text("serial $it", style = MaterialTheme.typography.bodySmall) }
                            Mono(e.fingerprint)
                        }
                    }
                }
            }
        }
    }
}

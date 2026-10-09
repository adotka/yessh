package io.github.adotka.yessh.ui

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import io.github.adotka.yessh.R

/** Licenses of yessh itself and of the third-party code bundled in the APK. */
private data class Component(val name: String, val detail: String, val license: License)

private enum class License(val title: String, val raw: Int) {
    UNLICENSE("The Unlicense", R.raw.unlicense),
    APACHE_2("Apache License 2.0", R.raw.apache_2_0),
}

private val COMPONENTS = listOf(
    Component("yessh", "This app. Public domain.", License.UNLICENSE),
    Component("AndroidX", "Core, Activity, Lifecycle and their androidx.* dependencies (Android Open Source Project)", License.APACHE_2),
    Component("Jetpack Compose", "UI, Foundation, Runtime, Material 3, Material Icons (Android Open Source Project)", License.APACHE_2),
    Component("Kotlin standard library", "JetBrains", License.APACHE_2),
    Component("kotlinx.coroutines", "JetBrains", License.APACHE_2),
    Component("kotlinx.serialization", "JetBrains", License.APACHE_2),
    Component("ZXing core", "QR code generation (ZXing authors)", License.APACHE_2),
)

@Composable
fun LicensesScreen(onClose: () -> Unit) {
    val context = LocalContext.current
    var open by rememberSaveable { mutableStateOf<License?>(null) }
    BackHandler { if (open != null) open = null else onClose() }

    Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(16.dp)) {
        TextButton(onClick = { if (open != null) open = null else onClose() }) { Text("← Back") }
        val license = open
        if (license != null) {
            val text = remember(license) { context.resources.openRawResource(license.raw).bufferedReader().use { it.readText() } }
            Text(license.title, style = MaterialTheme.typography.headlineSmall, modifier = Modifier.padding(bottom = 12.dp))
            SelectionContainer { Text(text, style = MaterialTheme.typography.bodySmall) }
            return@Column
        }
        Text("Licenses", style = MaterialTheme.typography.headlineSmall)
        Text(
            "yessh is free and unencumbered software released into the public domain. " +
                "It includes the open-source components below, which keep their own licenses. Tap one to read it.",
            modifier = Modifier.padding(vertical = 8.dp),
        )
        for (c in COMPONENTS) {
            Card(Modifier.fillMaxWidth().padding(vertical = 4.dp).clickable { open = c.license }) {
                Column(Modifier.padding(14.dp)) {
                    Text(c.name, fontWeight = FontWeight.Bold)
                    Text(c.detail, style = MaterialTheme.typography.bodySmall)
                    Text(c.license.title, color = MaterialTheme.colorScheme.primary)
                }
            }
        }
    }
}

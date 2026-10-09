package io.github.adotka.yessh.ui

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.graphics.Color
import io.github.adotka.yessh.appState
import io.github.adotka.yessh.service.ListenerService
import io.github.adotka.yessh.service.Notifier
import kotlin.concurrent.thread

class MainActivity : ComponentActivity() {
    /** Request opened from a notification tap. */
    val openRequest = mutableStateOf<String?>(null)

    /** Open-source licenses screen, reachable before and after setup. */
    val showLicenses = mutableStateOf(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // The pairing string (PSK) and approval details stay out of screenshots and the recents view.
        window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        enableEdgeToEdge()
        openRequest.value = intent.getStringExtra(Notifier.EXTRA_ID)
        setContent {
            YesshTheme {
                var paired by remember { mutableStateOf(appState.paired) }
                if (showLicenses.value) {
                    LicensesScreen(onClose = { showLicenses.value = false })
                } else if (!paired) {
                    SetupScreen(onCreated = {
                        paired = true
                        ListenerService.start(this)
                    })
                } else {
                    HomeScreen(this, onReset = { paired = false })
                }
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        intent.getStringExtra(Notifier.EXTRA_ID)?.let { openRequest.value = it }
    }

    override fun onResume() {
        super.onResume()
        if (appState.paired) {
            ListenerService.start(this)
            thread { runCatching { appState.publishPending(appState.requirePhone().refresh()) } }
        }
    }
}

private val Green = Color(0xFF22C55E)
private val GreenDark = Color(0xFF16A34A)

@Composable
fun YesshTheme(content: @Composable () -> Unit) {
    val scheme = if (isSystemInDarkTheme()) {
        darkColorScheme(
            primary = Green, onPrimary = Color(0xFF052E16), background = Color(0xFF0F172A), surface = Color(0xFF0F172A),
            surfaceVariant = Color(0xFF1E293B), onBackground = Color(0xFFE2E8F0), onSurface = Color(0xFFE2E8F0),
            error = Color(0xFFF87171),
        )
    } else {
        lightColorScheme(primary = GreenDark, onPrimary = Color.White, error = Color(0xFFDC2626))
    }
    MaterialTheme(colorScheme = scheme, content = content)
}

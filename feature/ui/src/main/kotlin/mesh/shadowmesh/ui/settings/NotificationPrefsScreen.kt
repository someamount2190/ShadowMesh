package mesh.shadowmesh.ui.settings

import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

private const val PREFS_NAME    = "shadowmesh_notif_prefs"
private const val KEY_ENABLED   = "notif_enabled"
private const val KEY_PREVIEW   = "notif_preview"
private const val KEY_SOUND     = "notif_sound"

@Composable
fun NotificationPrefsScreen(onBack: () -> Unit) {
    val ctx   = LocalContext.current
    val prefs = remember { ctx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE) }

    var globalEnabled by remember { mutableStateOf(prefs.getBoolean(KEY_ENABLED, true)) }
    var showPreview   by remember { mutableStateOf(prefs.getBoolean(KEY_PREVIEW, false)) }
    var soundEnabled  by remember { mutableStateOf(prefs.getBoolean(KEY_SOUND, false)) }

    fun save() {
        prefs.edit()
            .putBoolean(KEY_ENABLED, globalEnabled)
            .putBoolean(KEY_PREVIEW, showPreview)
            .putBoolean(KEY_SOUND, soundEnabled)
            .apply()
    }

    Column(
        Modifier
            .fillMaxSize()
            .background(Clr.Bg0)
    ) {
        // ── Header ────────────────────────────────────────────────────────
        Row(
            Modifier
                .fillMaxWidth()
                .background(Clr.Bg1)
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(onClick = onBack) {
                Icon(Icons.Default.ArrowBack, null, tint = Clr.TextSec)
            }
            Text(
                "NOTIFICATIONS",
                fontFamily    = MonoFamily,
                fontWeight    = FontWeight.Bold,
                fontSize      = 13.sp,
                color         = Clr.TextPri,
                letterSpacing = 0.1.sp,
            )
        }

        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            NotifSection("GENERAL") {
                ToggleRow(
                    label       = "NOTIFICATIONS",
                    description = "Receive notifications for new messages and system events",
                    checked     = globalEnabled,
                    onToggle    = { globalEnabled = it; save() },
                )
            }

            NotifSection("PRIVACY") {
                ToggleRow(
                    label       = "SHOW MESSAGE PREVIEW",
                    description = "Display message content in the notification bar. DISABLED by default — showing content in a locked-screen notification defeats end-to-end encryption.",
                    checked     = showPreview,
                    enabled     = globalEnabled,
                    onToggle    = { showPreview = it; save() },
                )
            }

            NotifSection("SOUND & VIBRATION") {
                ToggleRow(
                    label       = "SOUND",
                    description = "Play a sound on new message. Vibration follows system settings.",
                    checked     = soundEnabled,
                    enabled     = globalEnabled,
                    onToggle    = { soundEnabled = it; save() },
                )
            }

            // Privacy note
            Column(
                Modifier
                    .fillMaxWidth()
                    .background(Clr.GreenMute, RoundedCornerShape(8.dp))
                    .border(1.dp, Clr.GreenDim, RoundedCornerShape(8.dp))
                    .padding(12.dp),
            ) {
                Text(
                    "PRIVACY NOTE",
                    fontFamily    = MonoFamily,
                    fontWeight    = FontWeight.Bold,
                    fontSize      = 9.sp,
                    color         = Clr.GreenDim,
                    letterSpacing = 0.1.sp,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Message preview is OFF by default. Showing message content in notifications exposes plaintext on the lock screen, in notification logs, and to apps with notification access permission.",
                    fontFamily = MonoFamily,
                    fontSize   = 10.sp,
                    color      = Clr.TextSec,
                    lineHeight = 15.sp,
                )
            }
        }
    }
}

@Composable
private fun NotifSection(label: String, content: @Composable ColumnScope.() -> Unit) {
    Text(
        label,
        fontFamily    = MonoFamily,
        fontWeight    = FontWeight.Bold,
        fontSize      = 9.sp,
        color         = Clr.TextMute,
        letterSpacing = 0.1.sp,
    )
    Spacer(Modifier.height(4.dp))
    Column(
        Modifier
            .fillMaxWidth()
            .background(Clr.Bg2, RoundedCornerShape(8.dp))
            .border(1.dp, Clr.Border, RoundedCornerShape(8.dp))
            .padding(horizontal = 12.dp, vertical = 4.dp),
        content = content,
    )
}

@Composable
private fun ToggleRow(
    label:       String,
    description: String,
    checked:     Boolean,
    enabled:     Boolean = true,
    onToggle:    (Boolean) -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 8.dp),
        verticalAlignment = Alignment.Top,
    ) {
        Column(Modifier.weight(1f).padding(end = 8.dp)) {
            Text(
                label,
                fontFamily    = MonoFamily,
                fontWeight    = FontWeight.Bold,
                fontSize      = 11.sp,
                color         = if (enabled) Clr.TextPri else Clr.TextMute,
                letterSpacing = 0.06.sp,
            )
            Text(
                description,
                fontFamily = MonoFamily,
                fontSize   = 9.sp,
                color      = Clr.TextMute,
                lineHeight = 13.sp,
            )
        }
        Switch(
            checked  = checked,
            onCheckedChange = onToggle,
            enabled  = enabled,
            colors   = SwitchDefaults.colors(
                checkedThumbColor   = Clr.Green,
                checkedTrackColor   = Clr.GreenMute,
                uncheckedThumbColor = Clr.TextMute,
                uncheckedTrackColor = Clr.Bg3,
            ),
        )
    }
}

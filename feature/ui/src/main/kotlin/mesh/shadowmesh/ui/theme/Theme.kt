package mesh.shadowmesh.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

// ── Design tokens ─────────────────────────────────────────────────────────────

object Clr {
    val Bg0        = Color(0xFF000000)
    val Bg1        = Color(0xFF0A0A0A)
    val Bg2        = Color(0xFF111111)
    val Bg3        = Color(0xFF1A1A1A)
    val Bg4        = Color(0xFF222222)
    val Border     = Color(0xFF2A2A2A)
    val BorderHi   = Color(0xFF3A3A3A)

    // Phosphor green — confirmed / liveness / COMPARTMENTED/CLOSED rail
    val Green      = Color(0xFF00FF7F)
    val GreenDim   = Color(0xFF00CC66)
    val GreenMute  = Color(0xFF003320)

    // Amber — DEGRADED / SYNCING / warnings / PENDING
    val Amber      = Color(0xFFFFB300)
    val AmberDim   = Color(0xFFCC8800)
    val AmberMute  = Color(0xFF2A1F00)

    // Red — FAILED / SURVIVAL / UNVERIFIED / unread badge
    val Red        = Color(0xFFFF3B3B)
    val RedDim     = Color(0xFFCC1111)
    val RedMute    = Color(0xFF1F0000)

    // Orange — CRITICAL network mode
    val Orange     = Color(0xFFFF6A00)
    val OrangeMute = Color(0xFF1A0F00)

    // Text
    val TextPri    = Color(0xFFE8E8E8)
    val TextSec    = Color(0xFF888888)
    val TextMute   = Color(0xFF555555)

    // Own-post bubble
    val SelfBg     = Color(0xFF0D1A0D)
    val SelfBord   = Color(0xFF00442A)
}

// JetBrains Mono — available via Google Fonts in XML; fall back to monospace
val MonoFamily: FontFamily = FontFamily.Monospace

val ShadowColorScheme = darkColorScheme(
    primary        = Clr.Green,
    secondary      = Clr.GreenDim,
    background     = Clr.Bg0,
    surface        = Clr.Bg2,
    surfaceVariant = Clr.Bg3,
    outline        = Clr.Border,
    onBackground   = Clr.TextPri,
    onSurface      = Clr.TextPri,
    error          = Clr.Red,
)

@Composable
fun ShadowMeshTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = ShadowColorScheme, content = content)
}

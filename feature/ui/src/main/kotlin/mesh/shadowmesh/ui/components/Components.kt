package mesh.shadowmesh.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.mesh.mode.NetworkMode
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.storage.PostState
import mesh.shadowmesh.storage.ReputationTier
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

// ── DHT signal-strength bars ─────────────────────────────────────────────────

/**
 * 5-bar signal-strength indicator for DHT popularity (0–100).
 * Color: green ≥70%, amber ≥40%, red <40%.
 * Each bar is taller than the previous to create the classic signal-bar shape.
 */
@Composable
fun DhtBars(pct: Int, modifier: Modifier = Modifier) {
    val barCount = 5
    val filled   = ((pct / 100f) * barCount).toInt().coerceIn(0, barCount)
    val color    = when {
        pct >= 70 -> Clr.Green
        pct >= 40 -> Clr.Amber
        else      -> Clr.Red
    }
    Row(
        modifier        = modifier,
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(2.dp)
    ) {
        repeat(barCount) { i ->
            val height: Dp = (5 + i * 2.5f).dp
            Box(
                Modifier
                    .width(3.dp)
                    .height(height)
                    .background(
                        color  = if (i < filled) color else Clr.Bg4,
                        shape  = RoundedCornerShape(1.dp)
                    )
            )
        }
    }
}

// ── Channel type icon ─────────────────────────────────────────────────────────

/** Shape-only diamond/circle icons — colorblind safe, no color-only signal. */
@Composable
fun TypeIcon(type: ChannelType, size: Int = 13, modifier: Modifier = Modifier) {
    val (glyph, color) = when (type) {
        ChannelType.COMPARTMENTED -> "◆" to Clr.Green
        ChannelType.CLOSED        -> "◈" to Clr.GreenDim
        ChannelType.OPEN          -> "◇" to Clr.TextSec
        ChannelType.ANONYMOUS     -> "○" to Clr.TextMute
        ChannelType.GLOBAL        -> "⬡" to Clr.Amber
    }
    Text(
        text       = glyph,
        color      = color,
        fontSize   = size.sp,
        fontFamily = MonoFamily,
        modifier   = modifier,
    )
}

// ── Network mode chip ─────────────────────────────────────────────────────────

/** Shown in status bar when network mode is not HEALTHY. Null/empty for HEALTHY. */
@Composable
fun NetworkChip(mode: NetworkMode, modifier: Modifier = Modifier) {
    if (mode == NetworkMode.HEALTHY) return
    val (label, fg, bg, dot) = when (mode) {
        NetworkMode.DEGRADED -> ChipSpec("DEGRADED", Clr.Amber,  Clr.AmberMute, "🟡")
        NetworkMode.CRITICAL -> ChipSpec("CRITICAL", Clr.Orange, Clr.OrangeMute,"🟠")
        NetworkMode.SURVIVAL -> ChipSpec("SURVIVAL", Clr.Red,    Clr.RedMute,   "🔴")
        else                 -> return
    }
    Row(
        modifier = modifier
            .background(bg, RoundedCornerShape(3.dp))
            .border(1.dp, fg.copy(alpha = 0.7f), RoundedCornerShape(3.dp))
            .padding(horizontal = 7.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(4.dp)
    ) {
        Text(dot, fontSize = 8.sp)
        Text(
            text       = label,
            color      = fg,
            fontSize   = 8.sp,
            fontWeight = FontWeight.Bold,
            fontFamily = MonoFamily,
            letterSpacing = 0.08.sp,
        )
    }
}

private data class ChipSpec(val label: String, val fg: Color, val bg: Color, val dot: String)

// ── Mesh liveness dot ─────────────────────────────────────────────────────────

enum class MeshLiveness { LIVE, POLLING, OFFLINE }

@Composable
fun LiveDot(state: MeshLiveness, modifier: Modifier = Modifier) {
    val color = when (state) {
        MeshLiveness.LIVE    -> Clr.Green
        MeshLiveness.POLLING -> Clr.Amber
        MeshLiveness.OFFLINE -> Clr.Bg4
    }
    Box(
        modifier = modifier
            .size(8.dp)
            .clip(CircleShape)
            .background(color)
    )
}

// ── Post state badge ──────────────────────────────────────────────────────────

@Composable
fun PostStateBadge(state: PostState, modifier: Modifier = Modifier) {
    val (text, color) = when (state) {
        PostState.CONFIRMED      -> "✓✓"        to Clr.Green
        PostState.SYNCING        -> "⟳ mesh"   to Clr.TextMute
        PostState.PENDING        -> "⟳ send"   to Clr.Amber
        PostState.FAILED         -> ""           to Clr.Red
        PostState.DRAFT          -> ""           to Color.Transparent
        PostState.OFFLINE_LOCAL  -> "offline"    to Clr.Amber
        PostState.PENDING_ONLINE -> "⟳ queued"  to Clr.Amber
    }
    if (text.isNotEmpty()) {
        Text(text, color = color, fontSize = 10.sp, fontFamily = MonoFamily, modifier = modifier)
    }
}

// ── Reputation badge ──────────────────────────────────────────────────────────

@Composable
fun RepBadge(tier: ReputationTier, modifier: Modifier = Modifier) {
    val (fg, bg) = when (tier) {
        ReputationTier.ESTABLISHED -> Clr.Green to Clr.GreenMute
        ReputationTier.KNOWN       -> Clr.Amber to Clr.AmberMute
        ReputationTier.NEW         -> Clr.Amber to Clr.AmberMute
        ReputationTier.UNVERIFIED  -> Clr.Red   to Clr.RedMute
    }
    Text(
        text       = tier.name,
        color      = fg,
        fontSize   = 9.sp,
        fontWeight = FontWeight.SemiBold,
        fontFamily = MonoFamily,
        modifier   = modifier
            .background(bg, RoundedCornerShape(2.dp))
            .border(1.dp, fg.copy(alpha = 0.3f), RoundedCornerShape(2.dp))
            .padding(horizontal = 5.dp, vertical = 1.dp),
    )
}

// ── Section divider ───────────────────────────────────────────────────────────

@Composable
fun SectionLabel(label: String, modifier: Modifier = Modifier) {
    Row(
        modifier          = modifier.padding(vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        Text(
            text          = label.uppercase(),
            color         = Clr.TextMute,
            fontSize       = 8.sp,
            fontWeight    = FontWeight.Bold,
            fontFamily    = MonoFamily,
            letterSpacing = 0.12.sp,
        )
        Box(Modifier.weight(1f).height(1.dp).background(Clr.Border))
    }
}

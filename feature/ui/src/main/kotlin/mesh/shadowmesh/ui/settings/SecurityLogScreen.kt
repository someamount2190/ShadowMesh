package mesh.shadowmesh.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.mesh.mode.NetworkMode
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

data class SecurityStatus(
    val nscHalted:       Boolean,
    val circuitActive:   Boolean,
    val activePeers:     Int,
    val networkMode:     NetworkMode,
    val integrityOk:     Boolean,
    val pinConfigured:   Boolean,
    val biometricOk:     Boolean,
    val lastCheckedMs:   Long,
)

@Composable
fun SecurityLogScreen(
    status: SecurityStatus,
    onBack: () -> Unit,
) {
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
                "SECURITY STATUS",
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
            // Overall health banner
            val allOk = !status.nscHalted && status.integrityOk && status.biometricOk
            Box(
                Modifier
                    .fillMaxWidth()
                    .background(
                        if (allOk) Clr.GreenMute else Clr.Red.copy(alpha = 0.15f),
                        RoundedCornerShape(8.dp),
                    )
                    .border(
                        1.dp,
                        if (allOk) Clr.GreenDim else Clr.Red,
                        RoundedCornerShape(8.dp),
                    )
                    .padding(16.dp),
            ) {
                Text(
                    if (allOk) "● ALL SYSTEMS NOMINAL" else "▲ ATTENTION REQUIRED",
                    fontFamily    = MonoFamily,
                    fontWeight    = FontWeight.Bold,
                    fontSize      = 12.sp,
                    color         = if (allOk) Clr.Green else Clr.Red,
                    letterSpacing = 0.08.sp,
                )
            }

            // ── Network coordinator ───────────────────────────────────────
            StatusSection("NETWORK STATE COORDINATOR") {
                StatusRow(
                    "NSC STATE",
                    if (status.nscHalted) "HALTED — app restart required" else "OPERATIONAL",
                    if (status.nscHalted) Clr.Red else Clr.Green,
                )
                StatusRow("NETWORK MODE", status.networkMode.name, modeColor(status.networkMode))
                StatusRow("ACTIVE PEERS", "${status.activePeers} known", Clr.TextSec)
            }

            // ── Circuit ───────────────────────────────────────────────────
            StatusSection("ONION CIRCUIT") {
                StatusRow(
                    "CIRCUIT",
                    if (status.circuitActive) "ACTIVE — traffic tunnelled" else "INACTIVE — direct mesh",
                    if (status.circuitActive) Clr.Green else Clr.TextMute,
                )
            }

            // ── Integrity ─────────────────────────────────────────────────
            StatusSection("INTEGRITY") {
                StatusRow(
                    "APK SIGNATURE",
                    if (status.integrityOk) "VERIFIED" else "TAMPER DETECTED",
                    if (status.integrityOk) Clr.Green else Clr.Red,
                )
                StatusRow(
                    "BIOMETRIC KEY",
                    if (status.biometricOk) "AVAILABLE" else "UNAVAILABLE",
                    if (status.biometricOk) Clr.Green else Clr.Amber,
                )
                StatusRow(
                    "DURESS PIN",
                    if (status.pinConfigured) "CONFIGURED" else "NOT SET — recommended",
                    if (status.pinConfigured) Clr.Green else Clr.Amber,
                )
            }

            // ── Last check ────────────────────────────────────────────────
            StatusSection("LAST CHECK") {
                StatusRow(
                    "TIMESTAMP",
                    if (status.lastCheckedMs > 0) formatEpoch(status.lastCheckedMs) else "Never",
                    Clr.TextSec,
                )
            }
        }
    }
}

@Composable
private fun StatusSection(label: String, content: @Composable ColumnScope.() -> Unit) {
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
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        content = content,
    )
}

@Composable
private fun StatusRow(label: String, value: String, valueColor: Color) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.Top) {
        Text(
            label,
            fontFamily = MonoFamily,
            fontSize   = 10.sp,
            color      = Clr.TextMute,
            modifier   = Modifier.width(110.dp),
        )
        Text(
            value,
            fontFamily = MonoFamily,
            fontSize   = 10.sp,
            color      = valueColor,
            modifier   = Modifier.weight(1f),
        )
    }
}

private fun modeColor(mode: NetworkMode) = when (mode) {
    NetworkMode.HEALTHY   -> Clr.Green
    NetworkMode.DEGRADED  -> Clr.Amber
    NetworkMode.CRITICAL  -> Clr.Orange
    NetworkMode.SURVIVAL  -> Clr.Red
    else                  -> Clr.TextMute
}

private fun formatEpoch(ms: Long): String {
    val sdf = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
    return sdf.format(java.util.Date(ms))
}

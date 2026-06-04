package mesh.shadowmesh.ui.channels

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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.storage.ChannelEntity
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

@Composable
fun ChannelSettingsScreen(
    channel:       ChannelEntity,
    onDepart:      () -> Unit,
    onRotateKey:   () -> Unit,
    onViewMembers: () -> Unit,
    onBack:        () -> Unit,
) {
    var showDepartDialog  by remember { mutableStateOf(false) }
    var showRotateDialog  by remember { mutableStateOf(false) }

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
                "CHANNEL SETTINGS",
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
        ) {
            // ── Channel info ──────────────────────────────────────────────
            SettingsSection("CHANNEL INFO") {
                InfoRow("NAME",    channel.name)
                InfoRow("TYPE",    channel.type.name)
                InfoRow("GENESIS", channel.genesisHash.take(16) + "…")
                InfoRow("CREATED", formatEpoch(channel.createdAtMs))
                InfoRow("DHT",     "${channel.dhtPopularity}% replication")
            }

            Spacer(Modifier.height(16.dp))

            // ── Members ───────────────────────────────────────────────────
            if (channel.type in setOf(ChannelType.CLOSED, ChannelType.COMPARTMENTED)) {
                SettingsSection("MEMBERSHIP") {
                    SettingsActionRow("VIEW MEMBERS", "See who participates in this channel", onClick = onViewMembers)
                }
                Spacer(Modifier.height(16.dp))
            }

            // ── Key management ────────────────────────────────────────────
            if (channel.type == ChannelType.CLOSED) {
                SettingsSection("KEY MANAGEMENT") {
                    SettingsActionRow(
                        label       = "ROTATE KEY",
                        description = "Generates new key — expels members who aren't re-invited",
                        color       = Clr.Amber,
                        onClick     = { showRotateDialog = true },
                    )
                }
                Spacer(Modifier.height(16.dp))
            }

            // ── Danger zone ───────────────────────────────────────────────
            SettingsSection("DANGER ZONE") {
                SettingsActionRow(
                    label       = "DEPART CHANNEL",
                    description = "Wipes local key blob. Rejoin requires out-of-band key exchange.",
                    color       = Clr.Red,
                    onClick     = { showDepartDialog = true },
                )
            }
        }
    }

    // ── Depart confirmation ───────────────────────────────────────────────
    if (showDepartDialog) {
        AlertDialog(
            onDismissRequest = { showDepartDialog = false },
            title = {
                Text(
                    "DEPART CHANNEL?",
                    fontFamily = MonoFamily,
                    fontWeight = FontWeight.Bold,
                    color      = Clr.TextPri,
                )
            },
            text = {
                Text(
                    "Your local key will be wiped. You cannot read new posts or send messages in \"${channel.name}\" without a new key exchange.",
                    fontFamily = MonoFamily,
                    fontSize   = 12.sp,
                    color      = Clr.TextSec,
                )
            },
            confirmButton = {
                TextButton(onClick = { showDepartDialog = false; onDepart() }) {
                    Text("DEPART", fontFamily = MonoFamily, color = Clr.Red, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showDepartDialog = false }) {
                    Text("CANCEL", fontFamily = MonoFamily, color = Clr.TextSec)
                }
            },
            containerColor = Clr.Bg2,
        )
    }

    // ── Rotate key confirmation ───────────────────────────────────────────
    if (showRotateDialog) {
        AlertDialog(
            onDismissRequest = { showRotateDialog = false },
            title = {
                Text(
                    "ROTATE CHANNEL KEY?",
                    fontFamily = MonoFamily,
                    fontWeight = FontWeight.Bold,
                    color      = Clr.TextPri,
                )
            },
            text = {
                Text(
                    "A new key will be generated. Members who are not re-invited will be expelled and cannot read future posts. Distribute the new key out-of-band.",
                    fontFamily = MonoFamily,
                    fontSize   = 12.sp,
                    color      = Clr.TextSec,
                )
            },
            confirmButton = {
                TextButton(onClick = { showRotateDialog = false; onRotateKey() }) {
                    Text("ROTATE", fontFamily = MonoFamily, color = Clr.Amber, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showRotateDialog = false }) {
                    Text("CANCEL", fontFamily = MonoFamily, color = Clr.TextSec)
                }
            },
            containerColor = Clr.Bg2,
        )
    }
}

@Composable
private fun SettingsSection(label: String, content: @Composable ColumnScope.() -> Unit) {
    Text(
        label,
        fontFamily    = MonoFamily,
        fontWeight    = FontWeight.Bold,
        fontSize      = 9.sp,
        color         = Clr.TextMute,
        letterSpacing = 0.1.sp,
    )
    Spacer(Modifier.height(6.dp))
    Column(
        Modifier
            .fillMaxWidth()
            .background(Clr.Bg2, RoundedCornerShape(8.dp))
            .border(1.dp, Clr.Border, RoundedCornerShape(8.dp))
            .padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
        content = content,
    )
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth()) {
        Text(
            label,
            fontFamily = MonoFamily,
            fontSize   = 10.sp,
            color      = Clr.TextMute,
            modifier   = Modifier.width(80.dp),
        )
        Text(
            value,
            fontFamily = MonoFamily,
            fontSize   = 10.sp,
            color      = Clr.TextSec,
            modifier   = Modifier.weight(1f),
        )
    }
}

@Composable
private fun SettingsActionRow(
    label:       String,
    description: String,
    color:       androidx.compose.ui.graphics.Color = Clr.TextPri,
    onClick:     () -> Unit,
) {
    TextButton(
        onClick  = onClick,
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(Modifier.fillMaxWidth()) {
            Text(
                label,
                fontFamily    = MonoFamily,
                fontWeight    = FontWeight.Bold,
                fontSize      = 11.sp,
                color         = color,
                letterSpacing = 0.06.sp,
            )
            Text(
                description,
                fontFamily = MonoFamily,
                fontSize   = 9.sp,
                color      = Clr.TextMute,
            )
        }
    }
}

private fun formatEpoch(ms: Long): String {
    val sdf = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
    return sdf.format(java.util.Date(ms))
}

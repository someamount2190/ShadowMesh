// TODO: [BLE Redesign] activeMeshMode + meshScanLabel added to SettingsUiState.
// onActiveMeshModeToggle param + confirmation dialog added to SettingsScreen.
// ASSUMPTION: meshScanLabel is supplied by NavGraph (derived from activeMeshModeFlow +
// charging state); SettingsScreen does not compute it internally.

package mesh.shadowmesh.ui.settings

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import mesh.shadowmesh.mesh.mode.NetworkMode
import mesh.shadowmesh.storage.EntryNodeMode
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

// ── Settings UI state ─────────────────────────────────────────────────────────

data class SettingsUiState(
    val callsign:            String        = "—",
    val nodeIdShort:         String        = "—",
    val nodeId:              String        = "—",
    val trustPhysicalCount:  Int           = 0,
    val securityMode:        String        = "Standard",
    val entryNodeLabel:      String        = "Random peer",
    val entryNodeMode:       EntryNodeMode = EntryNodeMode.AUTOMATIC,
    val circuitEnabled:      Boolean       = false,
    val duressPinConfigured: Boolean       = false,
    val pinConfigured:       Boolean       = false,
    val networkMode:         NetworkMode   = NetworkMode.SURVIVAL,
    val activePeers:         Int           = 0,
    val circuitHops:         String        = "—",
    val storageUsedPct:      Int           = 0,
    /** Whether the user's "Active Mesh Mode" setting is on. Off by default (BALANCED). */
    val activeMeshMode:      Boolean       = false,
    /** Display label for the scan mode row — e.g. "Mesh: Active" or "Mesh: Balanced". */
    val meshScanLabel:       String        = "Mesh: Balanced",
)

// ── Settings root ─────────────────────────────────────────────────────────────

@Composable
fun SettingsScreen(
    state:                  SettingsUiState,
    onBack:                 () -> Unit,
    onEntryNodeClick:       () -> Unit,
    onPrivacyClick:         () -> Unit,
    onSecurityClick:        () -> Unit,
    onIdentityClick:        () -> Unit = {},
    onSecurityLogClick:     () -> Unit = {},
    onNotifClick:           () -> Unit = {},
    onPanicWipe:            () -> Unit,
    onDebugConsoleClick:    (() -> Unit)? = null,
    onActiveMeshModeToggle: ((Boolean) -> Unit)? = null,
    modifier:               Modifier = Modifier,
) {
    Column(modifier.fillMaxSize().background(Clr.Bg0)) {
        Row(
            modifier          = Modifier.fillMaxWidth().background(Clr.Bg1)
                .padding(horizontal = 14.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text("Settings", color = Clr.TextPri, fontSize = 14.sp,
                fontWeight = FontWeight.Bold, fontFamily = MonoFamily)
        }
        HorizontalDivider(color = Clr.Border, thickness = 1.dp)

        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                .padding(horizontal = 14.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            // NODE IDENTITY
            Section("NODE IDENTITY") {
                InfoRow("Callsign",       state.callsign,    Clr.Green)
                Divider()
                InfoRow("Node ID",        state.nodeId.take(16) + "…", Clr.TextSec)
                Divider()
                NavRow("View full identity", "QR + fingerprint", onClick = onIdentityClick)
                Divider()
                InfoRow("Trust contacts",
                    "${state.trustPhysicalCount} TRUST_PHYSICAL",
                    if (state.trustPhysicalCount > 0) Clr.Green else Clr.Amber)
            }

            // PRIVACY
            Section("PRIVACY") {
                NavRow("Security mode", state.securityMode, onClick = onPrivacyClick)
                Divider()
                NavRow("Entry Node",
                    "${state.entryNodeLabel} (${state.entryNodeMode.name.lowercase().replace('_',' ')})",
                    onClick = onEntryNodeClick)
                Divider()
                InfoRow("Circuit tunnel",
                    if (state.circuitEnabled) "Enabled" else "Disabled",
                    if (state.circuitEnabled) Clr.Green else Clr.Amber)
            }

            // SECURITY
            Section("SECURITY") {
                NavRow("Notifications", "Alert preferences", onClick = onNotifClick)
                Divider()
                NavRow("Security status", "Integrity + NSC state", onClick = onSecurityLogClick)
                Divider()
                NavRow("Duress PIN",
                    if (state.pinConfigured) "Configured" else "Not set",
                    valueColor = if (state.pinConfigured) Clr.Green else Clr.Amber,
                    onClick = onSecurityClick)
                Divider()
                PanicWipeRow(onPanicWipe)
                if (onDebugConsoleClick != null) {
                    Divider()
                    NavRow("Debug Console", "Transport health + crypto tests",
                        valueColor = Clr.Red, onClick = onDebugConsoleClick)
                }
            }

            // MESH STATUS
            val modeColor = when (state.networkMode) {
                NetworkMode.HEALTHY  -> Clr.Green
                NetworkMode.DEGRADED -> Clr.Amber
                NetworkMode.CRITICAL -> Clr.Orange
                NetworkMode.SURVIVAL -> Clr.Red
            }
            var showActiveModeConfirm by remember { mutableStateOf(false) }
            Section("MESH STATUS") {
                InfoRow("Mode",    state.networkMode.name,  modeColor)
                Divider()
                InfoRow("Peers",   "${state.activePeers} active",
                    if (state.activePeers >= 8) Clr.Green else Clr.Amber)
                Divider()
                InfoRow("Circuit", state.circuitHops,
                    if (state.circuitEnabled) Clr.Green else Clr.TextMute)
                Divider()
                InfoRow("Storage", "${state.storageUsedPct}% (relay fragments)", Clr.TextSec)
                Divider()
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween,
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Scan mode", color = Clr.TextPri, fontSize = 13.sp,
                            fontFamily = MonoFamily)
                        Text(state.meshScanLabel,
                            color = if (state.activeMeshMode) Clr.Amber else Clr.TextMute,
                            fontSize = 11.sp, fontFamily = MonoFamily)
                    }
                    Switch(
                        checked = state.activeMeshMode,
                        onCheckedChange = { newVal ->
                            if (newVal) showActiveModeConfirm = true
                            else onActiveMeshModeToggle?.invoke(false)
                        },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor  = Clr.Amber,
                            checkedTrackColor  = Clr.AmberMute,
                            uncheckedThumbColor = Clr.TextMute,
                            uncheckedTrackColor = Clr.Bg0,
                        )
                    )
                }
            }
            if (showActiveModeConfirm) {
                AlertDialog(
                    onDismissRequest = { showActiveModeConfirm = false },
                    title  = { Text("Enable Active Mesh Mode?", color = Clr.TextPri,
                        fontFamily = MonoFamily, fontSize = 14.sp) },
                    text   = { Text(
                        "Active mode uses SCAN_MODE_LOW_LATENCY for maximum peer discovery. " +
                        "Battery usage increases significantly. It is automatically enabled " +
                        "whenever the device is charging.",
                        color = Clr.TextSec, fontSize = 12.sp, lineHeight = 18.sp,
                    ) },
                    confirmButton = {
                        TextButton(onClick = {
                            showActiveModeConfirm = false
                            onActiveMeshModeToggle?.invoke(true)
                        }) { Text("Enable", color = Clr.Amber, fontFamily = MonoFamily) }
                    },
                    dismissButton = {
                        TextButton(onClick = { showActiveModeConfirm = false }) {
                            Text("Cancel", color = Clr.TextMute, fontFamily = MonoFamily)
                        }
                    },
                    containerColor = Clr.Bg1,
                )
            }
        }
    }
}

// ── Entry Node sub-screen ─────────────────────────────────────────────────────

@Composable
fun EntryNodeScreen(
    preferences:  List<mesh.shadowmesh.storage.EntryNodePreference>,
    mode:         EntryNodeMode,
    onModeChange: (EntryNodeMode) -> Unit,
    onAddContact: () -> Unit,
    onRemove:     (Long) -> Unit,
    onBack:       () -> Unit,
    modifier:     Modifier = Modifier,
) {
    Column(modifier.fillMaxSize().background(Clr.Bg0)) {
        SubHeader("Entry Node", onBack)
        HorizontalDivider(color = Clr.Border, thickness = 1.dp)

        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                .padding(horizontal = 14.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Always-visible privacy disclosure
            Column(
                Modifier.fillMaxWidth()
                    .background(Clr.AmberMute, RoundedCornerShape(6.dp))
                    .border(1.dp, Clr.Amber.copy(0.3f), RoundedCornerShape(6.dp))
                    .padding(12.dp)
            ) {
                Text("⚠  Privacy note", color = Clr.Amber, fontSize = 11.sp,
                    fontWeight = FontWeight.Bold, fontFamily = MonoFamily,
                    modifier = Modifier.padding(bottom = 5.dp))
                Text(
                    "Your Entry Node will know your IP address and that you are active " +
                    "on the mesh. They will not know who you are communicating with, " +
                    "what you are saying, or any other details about your activity.",
                    color = Clr.TextSec, fontSize = 12.sp, lineHeight = 17.sp,
                )
            }

            // Mode
            Section("MODE") {
                EntryNodeMode.entries.forEachIndexed { i, m ->
                    Row(
                        Modifier.fillMaxWidth().clickable { onModeChange(m) }.padding(vertical = 10.dp),
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        RadioButton(selected = mode == m, onClick = { onModeChange(m) },
                            colors = RadioButtonDefaults.colors(
                                selectedColor = Clr.Green, unselectedColor = Clr.TextMute))
                        Column {
                            Text(if (m == EntryNodeMode.AUTOMATIC) "Automatic" else "Ask before each post",
                                color = Clr.TextPri, fontSize = 13.sp)
                            Text(if (m == EntryNodeMode.AUTOMATIC)
                                "Uses ranked preference list; falls back automatically"
                                else "Prompts before each post — maximum control",
                                color = Clr.TextMute, fontSize = 11.sp, lineHeight = 15.sp)
                        }
                    }
                    if (i < EntryNodeMode.entries.lastIndex) Divider()
                }
            }

            // Preference list
            Section("PREFERENCE LIST") {
                if (preferences.isEmpty()) {
                    Text("No Entry Node configured — random peer will be used.",
                        color = Clr.Amber, fontSize = 12.sp,
                        modifier = Modifier.padding(vertical = 8.dp))
                } else {
                    preferences.forEachIndexed { i, pref ->
                        Row(
                            Modifier.fillMaxWidth().padding(vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(10.dp),
                        ) {
                            Text("${i+1}", color = Clr.TextMute, fontSize = 11.sp,
                                fontFamily = MonoFamily, modifier = Modifier.width(16.dp))
                            Column(Modifier.weight(1f)) {
                                Text(pref.displayName, color = Clr.TextPri, fontSize = 13.sp)
                                Text(pref.nodeId.take(8) + "…", color = Clr.TextMute,
                                    fontSize = 10.sp, fontFamily = MonoFamily)
                            }
                            Text("✕", color = Clr.Red, fontSize = 14.sp,
                                modifier = Modifier.clickable { onRemove(pref.id) }.padding(6.dp))
                        }
                        if (i < preferences.lastIndex) Divider()
                    }
                }
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = onAddContact, modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(6.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Clr.Green)) {
                    Text("+ Add TRUST_PHYSICAL contact", fontSize = 13.sp)
                }
            }
        }
    }
}

// ── Privacy sub-screen ────────────────────────────────────────────────────────

@Composable
fun PrivacyScreen(
    currentMode:     String,
    circuitEnabled:  Boolean,
    onModeChange:    (String) -> Unit,
    onCircuitToggle: () -> Unit,
    onBack:          () -> Unit,
    modifier:        Modifier = Modifier,
) {
    var selected by remember { mutableStateOf(currentMode) }
    val modes = listOf(
        Triple("Standard", "4-hop circuit · SNDP 10% · packet normalization", "Recommended"),
        Triple("Maximum",  "4-hop circuit · SNDP 10% · in-mesh mix · padded delays", "Adversarial conditions"),
    )

    Column(modifier.fillMaxSize().background(Clr.Bg0)) {
        SubHeader("Privacy", onBack)
        HorizontalDivider(color = Clr.Border, thickness = 1.dp)

        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                .padding(horizontal = 14.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            Section("SECURITY MODE") {
                modes.forEachIndexed { i, (label, detail, note) ->
                    Row(
                        Modifier.fillMaxWidth().clickable { selected = label; onModeChange(label) }
                            .padding(vertical = 10.dp),
                        verticalAlignment = Alignment.Top,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        RadioButton(selected = selected == label,
                            onClick = { selected = label; onModeChange(label) },
                            colors = RadioButtonDefaults.colors(
                                selectedColor = Clr.Green, unselectedColor = Clr.TextMute))
                        Column {
                            Text(label, color = Clr.TextPri, fontSize = 13.sp,
                                fontWeight = FontWeight.SemiBold)
                            Text(detail, color = Clr.TextSec, fontSize = 11.sp,
                                lineHeight = 15.sp, fontFamily = MonoFamily,
                                modifier = Modifier.padding(top = 2.dp))
                            Text(note, color = Clr.TextMute, fontSize = 11.sp,
                                modifier = Modifier.padding(top = 1.dp))
                        }
                    }
                    if (i < modes.lastIndex) Divider()
                }
            }

            Section("CIRCUIT TUNNEL") {
                Row(Modifier.fillMaxWidth().padding(vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween) {
                    Column(Modifier.weight(1f)) {
                        Text("VPN circuit tunnel", color = Clr.TextPri, fontSize = 13.sp)
                        Text("Routes traffic through the mesh onion circuit.",
                            color = Clr.TextMute, fontSize = 11.sp, lineHeight = 15.sp)
                    }
                    Switch(checked = circuitEnabled, onCheckedChange = { onCircuitToggle() },
                        colors = SwitchDefaults.colors(
                            checkedTrackColor = Clr.Green, uncheckedTrackColor = Clr.Bg4,
                            checkedThumbColor = Color.Black))
                }
            }
        }
    }
}

// ── Security sub-screen ───────────────────────────────────────────────────────

@Composable
fun SecurityScreen(
    duressPinConfigured: Boolean,
    onSetupDuressPin:    () -> Unit,
    onPanicWipe:         () -> Unit,
    onBack:              () -> Unit,
    modifier:            Modifier = Modifier,
) {
    Column(modifier.fillMaxSize().background(Clr.Bg0)) {
        SubHeader("Security", onBack)
        HorizontalDivider(color = Clr.Border, thickness = 1.dp)

        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                .padding(horizontal = 14.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(20.dp),
        ) {
            Section("DURESS PIN") {
                Text("When forced to unlock, enter your duress PIN to show a decoy channel list.",
                    color = Clr.TextSec, fontSize = 12.sp, lineHeight = 17.sp,
                    modifier = Modifier.padding(vertical = 10.dp))
                Divider()
                InfoRow("Status",
                    if (duressPinConfigured) "Configured" else "Not set",
                    if (duressPinConfigured) Clr.Green else Clr.Amber)
                Spacer(Modifier.height(8.dp))
                OutlinedButton(onClick = onSetupDuressPin, modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(6.dp),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = Clr.TextSec)) {
                    Text(if (duressPinConfigured) "Change duress PIN" else "Set up duress PIN",
                        fontSize = 13.sp)
                }
                Spacer(Modifier.height(4.dp))
            }

            Section("PANIC WIPE") {
                Text(
                    "Immediately and permanently deletes all SHADOWMESH data. " +
                    "Completes in under 5 seconds. Cannot be undone.",
                    color = Clr.TextSec, fontSize = 12.sp, lineHeight = 17.sp,
                    modifier = Modifier.padding(vertical = 10.dp))
                Text("Wiped: DB keys, Keystore keys, encrypted prefs, ratchet keys, " +
                    "circuit session keys, relay fragments, WorkManager queue.",
                    color = Clr.TextMute, fontSize = 11.sp, lineHeight = 15.sp,
                    fontFamily = MonoFamily,
                    modifier = Modifier.padding(bottom = 12.dp))

                var showConfirm by remember { mutableStateOf(false) }
                Button(onClick = { showConfirm = true },
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape = RoundedCornerShape(6.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Clr.RedMute, contentColor = Clr.Red)) {
                    Text("Panic wipe", fontSize = 14.sp, fontWeight = FontWeight.Bold)
                }
                Spacer(Modifier.height(4.dp))

                if (showConfirm) {
                    AlertDialog(
                        onDismissRequest = { showConfirm = false },
                        containerColor   = Clr.Bg2,
                        title  = { Text("Wipe all data?", color = Clr.Red,
                            fontWeight = FontWeight.Bold, fontSize = 16.sp) },
                        text   = { Text(
                            "Permanently deletes all data. No recovery. " +
                            "Confirm only if you intend to wipe.",
                            color = Clr.TextSec, fontSize = 13.sp, lineHeight = 18.sp) },
                        confirmButton = {
                            TextButton(onClick = { showConfirm = false; onPanicWipe() }) {
                                Text("Wipe now", color = Clr.Red, fontWeight = FontWeight.Bold)
                            }
                        },
                        dismissButton = {
                            TextButton(onClick = { showConfirm = false }) {
                                Text("Cancel", color = Clr.TextSec)
                            }
                        },
                    )
                }
            }
        }
    }
}

// ── Shared ────────────────────────────────────────────────────────────────────

@Composable
private fun SubHeader(title: String, onBack: () -> Unit) {
    Row(
        modifier          = Modifier.fillMaxWidth().background(Clr.Bg1)
            .padding(horizontal = 10.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack, modifier = Modifier.size(28.dp)) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back",
                tint = Clr.TextSec, modifier = Modifier.size(16.dp))
        }
        Spacer(Modifier.width(4.dp))
        Text(title, color = Clr.TextPri, fontSize = 13.sp,
            fontWeight = FontWeight.Bold, fontFamily = MonoFamily)
    }
}

@Composable
private fun Section(label: String, content: @Composable ColumnScope.() -> Unit) {
    Column {
        Text(label, color = Clr.TextMute, fontSize = 10.sp, fontWeight = FontWeight.Bold,
            fontFamily = MonoFamily, letterSpacing = 0.1.sp,
            modifier = Modifier.padding(bottom = 8.dp))
        Column(
            Modifier.fillMaxWidth()
                .background(Clr.Bg2, RoundedCornerShape(8.dp))
                .border(1.dp, Clr.Border, RoundedCornerShape(8.dp))
                .padding(horizontal = 14.dp, vertical = 4.dp),
            content = content,
        )
    }
}

@Composable
private fun InfoRow(label: String, value: String, valueColor: Color = Clr.TextSec) {
    Row(
        Modifier.fillMaxWidth().padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, color = Clr.TextSec, fontSize = 13.sp)
        Text(value, color = valueColor, fontSize = 12.sp,
            fontFamily = MonoFamily, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun NavRow(
    label:      String,
    value:      String = "",
    valueColor: Color  = Clr.TextSec,
    onClick:    () -> Unit,
) {
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(4.dp)).clickable(onClick = onClick)
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(label, color = Clr.TextPri, fontSize = 13.sp)
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            if (value.isNotEmpty()) Text(value, color = valueColor, fontSize = 12.sp,
                fontFamily = MonoFamily)
            Icon(Icons.Default.ChevronRight, contentDescription = null,
                tint = Clr.TextMute, modifier = Modifier.size(16.dp))
        }
    }
}

@Composable
private fun PanicWipeRow(onPanicWipe: () -> Unit) {
    var showConfirm by remember { mutableStateOf(false) }
    Row(
        Modifier.fillMaxWidth().clip(RoundedCornerShape(4.dp)).clickable { showConfirm = true }
            .padding(vertical = 10.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column {
            Text("Panic wipe", color = Clr.Red, fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold)
            Text("Delete all data immediately and permanently",
                color = Clr.TextMute, fontSize = 11.sp)
        }
        Text("!", color = Clr.Red, fontSize = 14.sp, fontWeight = FontWeight.Bold,
            modifier = Modifier
                .background(Clr.RedMute, RoundedCornerShape(3.dp))
                .border(1.dp, Clr.Red.copy(0.4f), RoundedCornerShape(3.dp))
                .padding(horizontal = 8.dp, vertical = 3.dp))
    }
    if (showConfirm) {
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            containerColor   = Clr.Bg2,
            title  = { Text("Wipe all data?", color = Clr.Red,
                fontWeight = FontWeight.Bold, fontSize = 16.sp) },
            text   = { Text("Permanently deletes all SHADOWMESH data. No recovery.",
                color = Clr.TextSec, fontSize = 13.sp) },
            confirmButton = {
                TextButton(onClick = { showConfirm = false; onPanicWipe() }) {
                    Text("Wipe now", color = Clr.Red, fontWeight = FontWeight.Bold)
                }
            },
            dismissButton = {
                TextButton(onClick = { showConfirm = false }) {
                    Text("Cancel", color = Clr.TextSec)
                }
            },
        )
    }
}

@Composable
private fun Divider() = HorizontalDivider(color = Clr.Border, thickness = 1.dp)

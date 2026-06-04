// TODO: [BLE Redesign] activeMeshModeFlow + onActiveMeshModeToggle wired into ShadowMeshNavRoot.
// ASSUMPTION: AppModule.activeMeshModeFlow is the single source of truth for the user's
// explicit mesh mode preference. onActiveMeshModeToggle calls AppModule.nsc.setActiveMeshMode()
// which invokes the NSC callback that updates activeMeshModeFlow and bleGattTransport.

package mesh.shadowmesh.app

import mesh.shadowmesh.app.debug.DebugConsoleScreen
import mesh.shadowmesh.diagnostics.Diag

import android.Manifest
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.PackageManager
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.view.WindowManager
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import androidx.activity.compose.setContent
import mesh.shadowmesh.bootstrap.nfc.NfcTransport
import mesh.shadowmesh.mesh.health.MeshHealthState
import mesh.shadowmesh.ui.nav.Dest
import mesh.shadowmesh.ui.nav.ShadowMeshNavRoot
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily
import mesh.shadowmesh.ui.theme.ShadowMeshTheme

import dagger.hilt.android.AndroidEntryPoint

/**
 * Single Activity — hosts all navigation fragments via Jetpack Navigation.
 *
 * Responsibilities in the app module:
 *
 *   1. **Panic gate**: on every resume, checks [AppModule.panicWipeMgr.hasWiped()].
 *      If true, immediately starts [CoverActivity] and finishes. Also observes
 *      [AppModule.nsc.haltedFlow] — a halted NSC triggers the same cover redirect.
 *
 *   2. **NFC foreground dispatch**: when the bootstrap flow is active (user is on
 *      a bootstrap fragment), registers NFC foreground dispatch so that IsoDep
 *      taps are routed to [onNewIntent] rather than launching a new Activity.
 *      Only the QR-generator role (Device A, the NFC reader) uses this path.
 *      The HCE role (Device B) is handled by [ShadowMeshHceService] which runs
 *      independently of Activity state.
 *
 *   3. **Screen security**: [FLAG_SECURE] prevents the screen from being captured
 *      in screenshots, screen recordings, or the recent apps thumbnail — this is
 *      critical for the QR bootstrap flow and for the forum content.
 *
 * Navigation graph (defined in res/navigation/nav_graph.xml — not in this file):
 *   startDestination = onboarding_graph if first launch, else main_graph.
 *   The fragment backstack is managed by Jetpack Navigation; this Activity
 *   only hosts the NavHostFragment and observes application-level state.
 */
@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    private val TAG = "MainActivity"

    // Compose-observable state: false until AppModule.isInitialised is true.
    // ShadowMeshNavRoot (and its hiltViewModel() call) must not compose before this flips.
    private val appReady = mutableStateOf(false)
    // Computed in observeApplicationState() after init; ONBOARDING for new users.
    private val startDestination = mutableStateOf(Dest.CHANNELS)

    private var nfcAdapter: NfcAdapter? = null
    private var nfcPendingIntent: PendingIntent? = null

    // ── Runtime permissions ────────────────────────────────────────────────
    //
    // Dangerous permissions that require explicit runtime grants. Requested once
    // on first launch; subsequent launches skip the dialog for already-granted ones.
    // The launcher is registered here (before onCreate) so it's safe to call from onCreate.
    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        val denied = results.filterValues { !it }.keys
        if (denied.isNotEmpty()) {
            Log.w(TAG, "Permissions denied: $denied — affected features will be degraded")
        }
    }

    private fun requestRuntimePermissions() {
        val needed = buildList {
            // BLE — API 31+ only (pre-31 devices use legacy BLUETOOTH/BLUETOOTH_ADMIN declared in manifest)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                addIfMissing(Manifest.permission.BLUETOOTH_SCAN)
                addIfMissing(Manifest.permission.BLUETOOTH_CONNECT)
                addIfMissing(Manifest.permission.BLUETOOTH_ADVERTISE)
            }
            // WiFi Direct location coarse grant (and NEARBY_WIFI_DEVICES on API 33+)
            addIfMissing(Manifest.permission.ACCESS_FINE_LOCATION)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                addIfMissing(Manifest.permission.NEARBY_WIFI_DEVICES)
                addIfMissing(Manifest.permission.POST_NOTIFICATIONS)
            }
            // Camera for QR code scanning
            addIfMissing(Manifest.permission.CAMERA)
        }
        if (needed.isNotEmpty()) permissionLauncher.launch(needed.toTypedArray())
    }

    private fun MutableList<String>.addIfMissing(permission: String) {
        if (ContextCompat.checkSelfPermission(this@MainActivity, permission)
                != PackageManager.PERMISSION_GRANTED) {
            add(permission)
        }
    }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Prevent screenshots, screen recording, and recent-apps thumbnail
        // of any SHADOWMESH content (forum posts, QR codes, channel list).
        // Disabled in debug builds to allow emulator screencap during development.
        if (!BuildConfig.DEBUG) {
            window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        }

        setContent {
            ShadowMeshTheme {
                val ready by appReady
                var showDebugConsole by remember { mutableStateOf(false) }

                if (ready && AppModule.isInitialised) {
                    Box(Modifier.fillMaxSize()) {
                        ShadowMeshNavRoot(
                            startDestination     = startDestination.value,
                            onOnboardingComplete = { markOnboardingDone() },
                            onPanicWipe          = { AppModule.panicWipeMgr.triggerWipe() },
                            isNscHalted          = { AppModule.nsc.isHalted },
                            isCircuitActive      = { AppModule.circuitManager.isCircuitActive() },
                            vpnStart             = { AppModule.vpnBridge.start(this@MainActivity) },
                            vpnStop              = { AppModule.vpnBridge.stop(this@MainActivity) },
                            showDebugConsole     = BuildConfig.DEBUG,
                            onDebugConsoleClick  = if (BuildConfig.DEBUG) {
                                { showDebugConsole = true }
                            } else null,
                            entryNodeStore       = AppModule.entryNodeStore,
                            isPinConfigured      = { AppModule.duressPinMgr.isPinConfigured() },
                            onPrivacyModeChange  = { label ->
                                val mix = AppModule.inMeshMixProtocol
                                if (label == "Maximum") mix.enable() else mix.disable()
                            },
                            integrityAllOk       = {
                                AppModule.integrityChecker.failureCounts.values.all { it == 0 }
                            },
                            biometricOk          = {
                                mesh.shadowmesh.platform.BiometricEnrollmentChecker
                                    .canProceedWithKeyOps(this@MainActivity)
                            },
                            setupDuressPin       = { realPin, duressPin ->
                                // Runs on Dispatchers.IO from DuressPinSetupScreen
                                AppModule.duressPinMgr.setupPins(
                                    realPin      = realPin,
                                    duressPin    = duressPin,
                                    deviceSecret = AppModule.deviceSecret
                                )
                            },
                            registerNfcCoordinator = { coord ->
                                if (coord != null) ShadowMeshHceService.setCoordinator(coord)
                                else ShadowMeshHceService.clearCoordinator()
                            },
                            onPhysicalPeerBootstrapped = { peerNodeId ->
                                // Register the NFC-bootstrapped peer in the gossip engine with
                                // TRUST_PHYSICAL. Address is unknown at bootstrap time — the
                                // peer will be reachable once discovered via DHT or other transports.
                                AppModule.gossipEngine.registerPeer(
                                    mesh.shadowmesh.mesh.dht.DhtContact(
                                        nodeId  = mesh.shadowmesh.mesh.dht.NodeId(peerNodeId),
                                        address = mesh.shadowmesh.mesh.dht.PeerAddress("0.0.0.0", 0)
                                    ),
                                    mesh.shadowmesh.crypto.TrustLevel.TRUST_PHYSICAL
                                )
                            },
                            getTrustPhysicalContacts = {
                                // Return TRUST_PHYSICAL contacts as EntryNodePreference candidates.
                                // gossipEngine.activePeerIds() filtered to TRUST_PHYSICAL trust level;
                                // displayName falls back to the nodeId 8-char prefix.
                                AppModule.gossipEngine.activePeerIds()
                                    .filter { nodeId ->
                                        AppModule.gossipEngine.effectiveTrust(nodeId) ==
                                            mesh.shadowmesh.crypto.TrustLevel.TRUST_PHYSICAL
                                    }
                                    .mapNotNull { nodeId ->
                                        val contact = AppModule.gossipEngine.peerContact(nodeId)
                                            ?: return@mapNotNull null
                                        mesh.shadowmesh.storage.EntryNodePreference(
                                            id               = 0L,
                                            nodeId           = nodeId.toHex(),
                                            displayName      = contact.publicIdentity?.nodeId
                                                                   ?.toHex()?.take(8)?.plus("…")
                                                               ?: nodeId.toHex().take(8) + "…",
                                            rank             = 0,
                                            channelOverrideId = null
                                        )
                                    }
                            },
                            activeMeshModeFlow     = AppModule.activeMeshModeFlow,
                            onActiveMeshModeToggle = { active ->
                                AppModule.nsc.setActiveMeshMode(active)
                            },
                        )
                        MeshHealthIndicator(Modifier.align(Alignment.TopEnd).padding(top = 8.dp, end = 8.dp))
                        if (showDebugConsole) {
                            DebugConsoleScreen(onBack = { showDebugConsole = false })
                        }
                    }
                } else {
                    SplashScreen(
                        onSkipInitDebug = if (BuildConfig.DEBUG) {
                            {
                                startDestination.value = Dest.ONBOARDING
                                appReady.value = true
                            }
                        } else null,
                    )
                }
            }
        }

        requestRuntimePermissions()
        setupNfc()
        observeApplicationState()
    }

    override fun onResume() {
        super.onResume()

        // Panic gate: if a wipe has occurred, redirect to cover immediately.
        // This catches the case where onDestroy+onCreate sequence brings the
        // activity back after a wipe — we never show SHADOWMESH content post-wipe.
        if (AppModule.isInitialised && AppModule.panicWipeMgr.hasWiped()) {
            Log.w(TAG, "Wipe detected on resume — redirecting to cover")
            startCoverActivity()
            return
        }

        enableNfcForegroundDispatch()
    }

    override fun onPause() {
        super.onPause()
        disableNfcForegroundDispatch()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        // NFC foreground dispatch delivers IsoDep taps here when the activity
        // is in the foreground. Route to the active bootstrap coordinator.
        handleNfcIntent(intent)
    }

    // ── Application-state observers ────────────────────────────────────────

    private fun observeApplicationState() {
        lifecycleScope.launch {
            // Wait for the Application to finish (or fail) initializing.
            // The 120 s timeout is a last-resort guard for a completely silent hang;
            // normally the Application-level 15 s timeout on nsc.initialise() fires first.
            val finalPhase = withTimeoutOrNull(120_000L) {
                AppModule.initState.first {
                    it is AppModule.InitPhase.Ready || it is AppModule.InitPhase.Failed
                }
            }

            if (finalPhase !is AppModule.InitPhase.Ready) {
                // Failed or timed out — SplashScreen shows the error via initState.
                // Application.showCoverActivity() handles the CoverActivity redirect.
                Log.w(TAG, "Init did not reach Ready state: $finalPhase")
                return@launch
            }

            val prefs = getSharedPreferences("shadowmesh_prefs", MODE_PRIVATE)
            startDestination.value =
                if (prefs.getBoolean("onboarding_done", false)) Dest.CHANNELS
                else Dest.ONBOARDING
            appReady.value = true

            AppModule.nsc.haltedFlow.collectLatest { halted ->
                if (halted) {
                    Log.e(TAG, "NSC halted — redirecting to cover")
                    startCoverActivity()
                }
            }
        }
    }

    private fun markOnboardingDone() {
        getSharedPreferences("shadowmesh_prefs", MODE_PRIVATE)
            .edit().putBoolean("onboarding_done", true).apply()
    }

    // ── NFC foreground dispatch ────────────────────────────────────────────

    private fun setupNfc() {
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            Log.d(TAG, "No NFC adapter — bootstrap will use BLE or QR-only fallback")
            return
        }

        // PendingIntent to deliver NFC taps to onNewIntent() while foregrounded.
        nfcPendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, this::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            },
            PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
    }

    private fun enableNfcForegroundDispatch() {
        val adapter = nfcAdapter ?: return
        val pending = nfcPendingIntent ?: return
        if (!adapter.isEnabled) return

        // Filter for IsoDep technology — this is the APDU transport used by HCE peers.
        val techList = arrayOf(arrayOf(IsoDep::class.java.name))
        adapter.enableForegroundDispatch(this, pending, null, techList)
        Log.d(TAG, "NFC foreground dispatch enabled")
    }

    private fun disableNfcForegroundDispatch() {
        nfcAdapter?.disableForegroundDispatch(this)
    }

    private fun handleNfcIntent(intent: Intent) {
        if (intent.action != NfcAdapter.ACTION_TECH_DISCOVERED) return

        val tag = intent.getParcelableExtra<android.nfc.Tag>(NfcAdapter.EXTRA_TAG) ?: return
        val isoDep = IsoDep.get(tag) ?: run {
            Log.w(TAG, "NFC tap was not IsoDep — ignoring")
            return
        }

        // Deliver to the active bootstrap coordinator on the main scope.
        // The coordinator's verifyAndRespond() dispatches to Dispatchers.IO internally.
        val coordinator = ShadowMeshHceService.getCoordinator() ?: run {
            Log.w(TAG, "NFC tap received but no active bootstrap coordinator")
            return
        }

        lifecycleScope.launch {
            try {
                isoDep.connect()
                isoDep.timeout = NfcHandshakeConstants.ISO_DEP_TIMEOUT_MS

                // Step 1: SELECT AID to establish the HCE channel
                val selectApdu = NfcTransport.buildSelectAidApdu(NfcTransport.SHADOWMESH_AID)
                val selectResp = isoDep.transceive(selectApdu)
                if (!selectResp.contentEquals(NfcTransport.SW_OK)) {
                    Log.w(TAG, "SELECT AID rejected by peer — not a SHADOWMESH device")
                    return@launch
                }

                // Step 2: Send a GET command to retrieve B's NfcChallengeMessage.
                //
                // Protocol note: the SELECT response from ShadowMeshHceService is always
                // exactly SW_OK (2 bytes) — it does not carry payload. The challenge
                // message is retrieved with a second command/response exchange.
                //
                // We send a zero-byte payload GET; B's HCE service interprets any non-SELECT
                // APDU in WaitingForNfc state as the trigger to build and return the
                // NfcChallengeMessage.
                val challengePayload = NfcTransport.sendMessage(
                    isoDep,
                    NfcTransport.wrapPayloadApdu(byteArrayOf())  // empty payload = GET request
                )

                // Step 3: Process the challenge and get our response
                val responseBytes = coordinator.onNfcChallengeReceived(challengePayload)
                    ?: return@launch

                // Step 4: Send our response to B
                NfcTransport.sendMessage(isoDep, responseBytes)

                Log.d(TAG, "NFC handshake complete — TRUST_PHYSICAL_NFC established")
            } catch (e: Exception) {
                Log.e(TAG, "NFC exchange failed: ${e.message}")
            Diag.swallowed("main-activity", "catch", e)
            } finally {
                runCatching { isoDep.close() }
            }
        }
    }

    // ── Navigation helpers ─────────────────────────────────────────────────

    private fun startCoverActivity() {
        startActivity(
            Intent(this, CoverActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
            }
        )
        finish()
    }
}

// ── Splash screen ─────────────────────────────────────────────────────────────

private val SplashBg   = Color(0xFF0B0F1C)
private val SplashBlue = Color(0xFF4FC3F7)
private val SplashDim  = Color(0xFF4A6A8A)
private val SplashTrack= Color(0xFF1A2233)
private val SplashErr  = Color(0xFFEF5350)

@Composable
private fun SplashScreen(onSkipInitDebug: (() -> Unit)? = null) {
    val phase by AppModule.initState.collectAsStateWithLifecycle()

    var logoVisible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { logoVisible = true }
    val logoAlpha by animateFloatAsState(
        targetValue   = if (logoVisible) 1f else 0f,
        animationSpec = tween(durationMillis = 700, easing = FastOutSlowInEasing),
        label         = "splash-logo-fade",
    )

    Box(
        modifier         = Modifier.fillMaxSize().background(SplashBg),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 40.dp),
        ) {
            Image(
                painter            = painterResource(R.drawable.splash_logo),
                contentDescription = null,
                contentScale       = ContentScale.Fit,
                modifier           = Modifier.widthIn(max = 260.dp).alpha(logoAlpha),
            )

            Spacer(Modifier.height(48.dp))

            when (val p = phase) {
                is AppModule.InitPhase.Initializing -> {
                    LinearProgressIndicator(
                        modifier   = Modifier.fillMaxWidth().height(2.dp),
                        color      = SplashBlue,
                        trackColor = SplashTrack,
                    )
                    Spacer(Modifier.height(12.dp))
                    Text(
                        text       = p.phase,
                        color      = SplashDim,
                        fontSize   = 10.sp,
                        fontFamily = MonoFamily,
                        maxLines   = 1,
                        textAlign  = TextAlign.Center,
                        modifier   = Modifier.fillMaxWidth(),
                    )
                }

                is AppModule.InitPhase.Failed -> {
                    Text(
                        "INITIALIZATION FAILED",
                        color      = SplashErr,
                        fontSize   = 11.sp,
                        fontFamily = MonoFamily,
                        fontWeight = FontWeight.Bold,
                        textAlign  = TextAlign.Center,
                    )
                    Spacer(Modifier.height(8.dp))
                    Text(
                        p.reason,
                        color      = SplashDim,
                        fontSize   = 9.sp,
                        fontFamily = MonoFamily,
                        textAlign  = TextAlign.Center,
                        maxLines   = 3,
                        modifier   = Modifier.fillMaxWidth(),
                    )
                    if (onSkipInitDebug != null) {
                        Spacer(Modifier.height(20.dp))
                        Text(
                            "[ SKIP TO ONBOARDING ]",
                            color      = SplashBlue,
                            fontSize   = 10.sp,
                            fontFamily = MonoFamily,
                            modifier   = Modifier
                                .clickable { onSkipInitDebug() }
                                .padding(8.dp),
                        )
                    }
                }

                AppModule.InitPhase.Ready -> { /* transitioning — nothing to show */ }
            }
        }
    }
}

private object NfcHandshakeConstants {
    const val ISO_DEP_TIMEOUT_MS = 1000   // 1 second — generous for slow devices
}

// ── Mesh health indicator ─────────────────────────────────────────────────────

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MeshHealthIndicator(modifier: Modifier = Modifier) {
    if (!AppModule.isInitialised) return

    val state by AppModule.transportHealthMonitor.currentState.collectAsStateWithLifecycle()
    val healthMap by AppModule.transportHealthMonitor.perTransportHealth.collectAsStateWithLifecycle()
    var showSheet by remember { mutableStateOf(false) }

    val (icon, color) = when (state) {
        MeshHealthState.FULL_MESH       -> "🌐" to Clr.Green
        MeshHealthState.LOCAL_MESH      -> "📡" to Clr.Amber
        MeshHealthState.PROXIMITY_MESH  -> "📶" to Clr.Orange
        MeshHealthState.BLE_ONLY        -> "🔵" to Color(0xFF4FC3F7)
        MeshHealthState.ISOLATED        -> "🔴" to Clr.Red
    }

    Box(
        modifier
            .background(Clr.Bg2.copy(alpha = 0.9f), RoundedCornerShape(6.dp))
            .clickable { showSheet = true }
            .padding(horizontal = 6.dp, vertical = 3.dp),
        contentAlignment = Alignment.Center
    ) {
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(3.dp)) {
            Text(icon, fontSize = 12.sp)
            Text(state.name.replace('_', ' '), color = color,
                fontSize = 8.sp, fontFamily = MonoFamily, fontWeight = FontWeight.Bold,
                maxLines = 1)
        }
    }

    if (showSheet) {
        ModalBottomSheet(
            onDismissRequest = { showSheet = false },
            containerColor   = Clr.Bg1,
            sheetState       = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        ) {
            Column(Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 12.dp)) {
                Text("MESH HEALTH", color = Clr.TextPri, fontSize = 13.sp,
                    fontWeight = FontWeight.Bold, fontFamily = MonoFamily)
                Spacer(Modifier.height(8.dp))

                // State + time
                Row(verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(icon, fontSize = 22.sp)
                    Column {
                        Text(state.name, color = color, fontSize = 13.sp,
                            fontWeight = FontWeight.Bold, fontFamily = MonoFamily)
                        Text(
                            "Time in state: ${fmtHealthDuration(AppModule.transportHealthMonitor.timeInCurrentStateMs)}",
                            color = Clr.TextSec, fontSize = 10.sp, fontFamily = MonoFamily)
                    }
                }

                Spacer(Modifier.height(12.dp))

                // Per-transport status
                Text("TRANSPORT STATUS", color = Clr.TextMute, fontSize = 9.sp,
                    fontFamily = MonoFamily, fontWeight = FontWeight.Bold)
                Spacer(Modifier.height(6.dp))

                healthMap.forEach { (type, entry) ->
                    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically) {
                        Text(type.name, color = Clr.TextSec, fontSize = 11.sp,
                            fontFamily = MonoFamily, modifier = Modifier.weight(1f))
                        Text(
                            if (entry.isHealthy) "✓ ${entry.averageLatencyMs}ms" else "✗ ${entry.consecutiveFailures} fails",
                            color = if (entry.isHealthy) Clr.Green else Clr.Red,
                            fontSize = 10.sp, fontFamily = MonoFamily)
                    }
                }
                Spacer(Modifier.height(16.dp))
            }
        }
    }
}

private fun fmtHealthDuration(ms: Long): String = when {
    ms < 60_000   -> "${ms / 1000}s"
    ms < 3600_000 -> "${ms / 60_000}m ${(ms % 60_000) / 1000}s"
    else          -> "${ms / 3600_000}h ${(ms % 3600_000) / 60_000}m"
}

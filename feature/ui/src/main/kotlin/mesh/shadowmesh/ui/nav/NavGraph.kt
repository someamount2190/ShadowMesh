// TODO: [BLE Redesign] activeMeshModeFlow + onActiveMeshModeToggle params added.
// proximityConfirmed collected from onboardingVm and passed to AddContactSheet.
// ASSUMPTION: activeMeshModeFlow defaults to flowOf(false) so Settings works even
// when AppModule.activeMeshModeFlow is not yet connected by MainActivity.

@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package mesh.shadowmesh.ui.nav

import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import mesh.shadowmesh.ui.channels.ChannelListScreen
import mesh.shadowmesh.ui.channels.ChannelMembersScreen
import mesh.shadowmesh.ui.channels.ChannelSettingsScreen
import mesh.shadowmesh.ui.components.MeshLiveness
import mesh.shadowmesh.ui.contacts.AddContactSheet
import mesh.shadowmesh.ui.contacts.ContactListScreen
import mesh.shadowmesh.ui.detail.ChannelDetailScreen
import mesh.shadowmesh.ui.detail.PostDetailScreen
import mesh.shadowmesh.ui.detail.PollUiState
import mesh.shadowmesh.ui.feed.FeedScreen
import mesh.shadowmesh.ui.onboarding.OnboardingHost
import mesh.shadowmesh.ui.settings.*
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily
import mesh.shadowmesh.ui.viewmodel.ChannelListItem
import mesh.shadowmesh.ui.viewmodel.ForumUiViewModel
import mesh.shadowmesh.storage.ChannelType
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import mesh.shadowmesh.mesh.mode.NetworkMode
import mesh.shadowmesh.ui.settings.NotificationPrefsScreen
import mesh.shadowmesh.ui.settings.NodeIdentityScreen
import mesh.shadowmesh.ui.settings.SecurityLogScreen
import mesh.shadowmesh.ui.settings.SecurityStatus
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.compose.ui.Alignment
import kotlinx.coroutines.launch

// ── Destinations ──────────────────────────────────────────────────────────────

object Dest {
    const val ONBOARDING      = "onboarding"

    // Bottom-nav tabs
    const val CHANNELS        = "channels"
    const val CONTACTS        = "contacts"
    const val FEED            = "feed"
    const val SETTINGS        = "settings"

    // Detail (no bottom nav)
    const val DETAIL          = "detail/{channelId}"
    const val POST            = "post/{postId}"
    const val ADD_CONTACT     = "add_contact"
    const val CHANNEL_SETTINGS= "channel_settings/{channelId}"
    const val CHANNEL_MEMBERS = "channel_members/{channelId}"

    // Settings sub-screens
    const val ENTRY_NODE      = "settings/entry_node"
    const val PRIVACY         = "settings/privacy"
    const val SECURITY        = "settings/security"
    const val DURESS_PIN_SETUP= "settings/duress_pin_setup"
    const val NODE_IDENTITY   = "settings/identity"
    const val SECURITY_LOG    = "settings/security_log"
    const val NOTIF_PREFS     = "settings/notifications"
    const val DEBUG_CONSOLE   = "settings/debug_console"  // debug builds only

    fun detail(channelId: String)         = "detail/$channelId"
    fun post(postId: String)              = "post/$postId"
    fun channelSettings(channelId: String)= "channel_settings/$channelId"
    fun channelMembers(channelId: String) = "channel_members/$channelId"
}

// ── Top-level nav root ────────────────────────────────────────────────────────

@Composable
fun ShadowMeshNavRoot(
    startDestination:     String        = Dest.ONBOARDING,
    onOnboardingComplete: () -> Unit     = {},
    onPanicWipe:          () -> Unit     = {},
    isNscHalted:          () -> Boolean  = { false },
    isCircuitActive:      () -> Boolean  = { false },
    vpnStart:             () -> Unit     = {},
    vpnStop:              () -> Unit     = {},
    showDebugConsole:     Boolean        = false,
    onDebugConsoleClick:  (() -> Unit)?  = null,
    // Live app-module values — supplied by MainActivity which has access to AppModule.
    entryNodeStore:       mesh.shadowmesh.mesh.circuit.EntryNodeStore? = null,
    isPinConfigured:      () -> Boolean  = { false },
    integrityAllOk:       () -> Boolean  = { true },
    biometricOk:          () -> Boolean  = { true },
    /** Called when the user submits the duress PIN setup form. Runs on IO; must complete synchronously. */
    setupDuressPin:           ((realPin: ByteArray, duressPin: ByteArray) -> Unit)? = null,
    /** Returns the list of TRUST_PHYSICAL contacts available as Entry Node candidates. */
    getTrustPhysicalContacts: (() -> List<mesh.shadowmesh.storage.EntryNodePreference>)? = null,
    /**
     * Called when the user selects a privacy mode label ("Standard" or "Maximum").
     * Enable the in-mesh mix protocol for "Maximum"; disable it for "Standard".
     */
    onPrivacyModeChange:      ((modeLabel: String) -> Unit) = {},
    /**
     * Called with the active [NfcBootstrapCoordinator] when the Add Contact sheet opens
     * (so MainActivity can register it with ShadowMeshHceService), and with null when
     * the sheet closes or bootstrap completes (to unregister and block stale taps).
     */
    registerNfcCoordinator:   (mesh.shadowmesh.attestation.nfc.NfcBootstrapCoordinator?) -> Unit = {},
    /**
     * Called with the peer's raw nodeId after a successful NFC bootstrap so the host
     * (MainActivity) can register the peer in GossipEngine with TRUST_PHYSICAL.
     */
    onPhysicalPeerBootstrapped: (peerNodeId: ByteArray) -> Unit = {},
    /**
     * Flow of the user's "Active Mesh Mode" preference. Defaults to flowOf(false) so
     * the Settings screen renders correctly before MainActivity wires AppModule.activeMeshModeFlow.
     */
    activeMeshModeFlow: kotlinx.coroutines.flow.Flow<Boolean> = kotlinx.coroutines.flow.flowOf(false),
    /** Called when the user toggles the Active Mesh Mode switch in Settings. */
    onActiveMeshModeToggle: (Boolean) -> Unit = {},
    vm: ForumUiViewModel                 = hiltViewModel(),
) {
    val navController   = rememberNavController()
    val sortedChannels  by vm.sortedChannels.collectAsStateWithLifecycle()
    val networkMode     by vm.networkMode.collectAsStateWithLifecycle()
    val feedItems       by vm.feedItems.collectAsStateWithLifecycle()
    val contacts        by vm.contacts.collectAsStateWithLifecycle()
    val isCreating      by vm.isCreatingChannel.collectAsStateWithLifecycle()
    val createError     by vm.createChannelError.collectAsStateWithLifecycle()
    val activeMeshMode  by activeMeshModeFlow.collectAsStateWithLifecycle(initialValue = false)

    val navBackStack    by navController.currentBackStackEntryAsState()
    val currentRoute     = navBackStack?.destination?.route ?: startDestination
    val mainRoutes       = setOf(Dest.CHANNELS, Dest.CONTACTS, Dest.FEED, Dest.SETTINGS)
    val showBottomBar    = currentRoute in mainRoutes

    Scaffold(
        containerColor = Clr.Bg0,
        bottomBar = { if (showBottomBar) ShadowBottomNav(currentRoute, navController) },
    ) { padding ->
        NavHost(
            navController    = navController,
            startDestination = startDestination,
            modifier         = androidx.compose.ui.Modifier.padding(padding),
        ) {

            // ── Onboarding ────────────────────────────────────────────────
            composable(Dest.ONBOARDING) {
                OnboardingHost(
                    onComplete = {
                        onOnboardingComplete()
                        navController.navigate(Dest.CHANNELS) {
                            popUpTo(Dest.ONBOARDING) { inclusive = true }
                        }
                    }
                )
            }

            // ── Channel list ──────────────────────────────────────────────
            composable(Dest.CHANNELS) {
                ChannelListScreen(
                    items           = sortedChannels,
                    networkMode     = networkMode,
                    meshLiveness    = MeshLiveness.LIVE,
                    isCreating      = isCreating,
                    createError     = createError,
                    onChannelClick  = { ch ->
                        vm.selectChannel(ch.channelId)
                        navController.navigate(Dest.detail(ch.channelId))
                    },
                    onCreateChannel = { name, type -> vm.createChannel(name, type) },
                    onClearError    = vm::clearCreateChannelError,
                    onSettingsClick = { navController.navigate(Dest.SETTINGS) },
                    onChipClick     = { /* mode info sheet */ },
                )
            }

            // ── Contacts ──────────────────────────────────────────────────
            composable(Dest.CONTACTS) {
                val showAddSheet = remember { mutableStateOf(false) }
                val addError     = remember { mutableStateOf<String?>(null) }

                // OnboardingViewModel drives the bootstrap coordinator (QR generation,
                // NFC tap handling, responder flow). Scoped to this back-stack entry.
                val onboardingVm: mesh.shadowmesh.onboarding.OnboardingViewModel = hiltViewModel()
                val bootstrapState     by onboardingVm.bootstrapState.collectAsStateWithLifecycle()
                val bootstrapError     by onboardingVm.bootstrapError.collectAsStateWithLifecycle()
                val bootstrapQr        by onboardingVm.qrCode.collectAsStateWithLifecycle()
                val proximityConfirmed by onboardingVm.proximityConfirmed.collectAsStateWithLifecycle()
                // Peer label: set to first 8 chars of peer's hex node ID when responder QR is scanned.
                val peerLabel = remember { mutableStateOf<String?>(null) }

                // Register coordinator with ShadowMeshHceService and start initiator flow when sheet opens.
                androidx.compose.runtime.LaunchedEffect(showAddSheet.value) {
                    if (showAddSheet.value) {
                        // Register BEFORE startPhysicalExchangeAsInitiator so any NFC tap
                        // that arrives while startAsInitiator() is still running is queued
                        // by the HCE service and not silently dropped.
                        onboardingVm.activeCoordinator()?.let { registerNfcCoordinator(it) }
                        onboardingVm.startPhysicalExchangeAsInitiator()
                    } else {
                        registerNfcCoordinator(null)
                    }
                }

                // Auto-close sheet on successful NFC verification; surface errors.
                androidx.compose.runtime.LaunchedEffect(bootstrapState) {
                    when (bootstrapState) {
                        is mesh.shadowmesh.attestation.nfc.BootstrapState.NfcVerified -> {
                            onPhysicalPeerBootstrapped(
                                (bootstrapState as mesh.shadowmesh.attestation.nfc.BootstrapState.NfcVerified).peerNodeId
                            )
                            registerNfcCoordinator(null)
                            showAddSheet.value = false
                            addError.value = null
                        }
                        is mesh.shadowmesh.attestation.nfc.BootstrapState.Failed -> {
                            addError.value = (bootstrapState as
                                mesh.shadowmesh.attestation.nfc.BootstrapState.Failed).reason
                        }
                        else -> {}
                    }
                }

                // QR scanner for the responder path ("Scan QR Code" button).
                val qrScanLauncher = rememberLauncherForActivityResult(
                    com.journeyapps.barcodescanner.ScanContract()
                ) { result ->
                    val content = result.contents ?: return@rememberLauncherForActivityResult
                    addError.value = null
                    runCatching {
                        val qrBytes = android.util.Base64.decode(content, android.util.Base64.NO_WRAP)
                        // Extract a short peer label from the QR's nodeId for the proximity stage UI.
                        runCatching {
                            val qr = mesh.shadowmesh.bootstrap.QrIntroductionCode.fromBytes(qrBytes)
                            peerLabel.value = qr.nodeId.take(4).joinToString("") { "%02x".format(it) }
                        }
                        onboardingVm.startPhysicalExchangeAsResponder(qrBytes)
                    }.onFailure { addError.value = "Invalid QR code" }
                }

                ContactListScreen(
                    contacts     = contacts,
                    onAddContact = { showAddSheet.value = true },
                    onBack       = { navController.popBackStack() },
                )

                if (showAddSheet.value) {
                    ModalBottomSheet(
                        onDismissRequest = {
                            onboardingVm.resetBootstrap()
                            registerNfcCoordinator(null)
                            addError.value = null
                            showAddSheet.value = false
                        },
                        containerColor = Clr.Bg1,
                    ) {
                        AddContactSheet(
                            bootstrapQrBytes   = bootstrapQr?.rawBytes,
                            bootstrapState     = bootstrapState,
                            bootstrapError     = addError.value ?: bootstrapError,
                            myNodeId           = vm.localNodeId,
                            proximityConfirmed = proximityConfirmed,
                            peerLabel          = peerLabel.value,
                            onSubmitCode       = { code ->
                                addError.value = null
                                runCatching {
                                    val qrBytes = android.util.Base64.decode(
                                        code.trim(), android.util.Base64.NO_WRAP
                                    )
                                    runCatching {
                                        val qr = mesh.shadowmesh.bootstrap.QrIntroductionCode.fromBytes(qrBytes)
                                        peerLabel.value = qr.nodeId.take(4).joinToString("") { "%02x".format(it) }
                                    }
                                    onboardingVm.startPhysicalExchangeAsResponder(qrBytes)
                                }.onFailure { addError.value = "Invalid code — paste the base64 from the other device" }
                            },
                            onScanQr = {
                                qrScanLauncher.launch(
                                    com.journeyapps.barcodescanner.ScanOptions().apply {
                                        setDesiredBarcodeFormats(
                                            com.journeyapps.barcodescanner.ScanOptions.QR_CODE
                                        )
                                        setPrompt("Scan your contact's QR code")
                                        setBeepEnabled(false)
                                    }
                                )
                            },
                            onDismiss = {
                                onboardingVm.resetBootstrap()
                                registerNfcCoordinator(null)
                                addError.value = null
                                peerLabel.value = null
                                showAddSheet.value = false
                            },
                        )
                    }
                }
            }

            // ── Channel detail ────────────────────────────────────────────
            composable(Dest.DETAIL) { back ->
                val channelId = back.arguments?.getString("channelId") ?: return@composable
                val posts     by vm.posts.collectAsStateWithLifecycle()
                val channel   = sortedChannels
                    .filterIsInstance<ChannelListItem.Channel>()
                    .firstOrNull { it.entity.channelId == channelId }?.entity
                    ?: return@composable

                ChannelDetailScreen(
                    channel          = channel,
                    posts            = posts,
                    localNodeId      = vm.localNodeId,
                    onBack           = { navController.popBackStack() },
                    onPostTap        = { post -> navController.navigate(Dest.post(post.postId)) },
                    onSend           = { text, burn -> vm.sendPost(channelId, text, burn) },
                    onRetry          = vm::retryPost,
                    onDepart         = { vm.departChannel(channelId); navController.popBackStack() },
                    onRotateKey      = { vm.rotateChannelKey(channelId) },
                    onViewMembers    = { navController.navigate(Dest.channelMembers(channelId)) },
                    onChannelSettings= { navController.navigate(Dest.channelSettings(channelId)) },
                )
            }

            // ── Channel settings ──────────────────────────────────────────
            composable(Dest.CHANNEL_SETTINGS) { back ->
                val channelId = back.arguments?.getString("channelId") ?: return@composable
                val channel   = sortedChannels
                    .filterIsInstance<ChannelListItem.Channel>()
                    .firstOrNull { it.entity.channelId == channelId }?.entity
                    ?: return@composable

                ChannelSettingsScreen(
                    channel       = channel,
                    onDepart      = { vm.departChannel(channelId); navController.navigate(Dest.CHANNELS) { popUpTo(Dest.CHANNELS) } },
                    onRotateKey   = { vm.rotateChannelKey(channelId); navController.popBackStack() },
                    onViewMembers = { navController.navigate(Dest.channelMembers(channelId)) },
                    onBack        = { navController.popBackStack() },
                )
            }

            // ── Channel members ───────────────────────────────────────────
            composable(Dest.CHANNEL_MEMBERS) { back ->
                val channelId = back.arguments?.getString("channelId") ?: return@composable
                val channel   = sortedChannels
                    .filterIsInstance<ChannelListItem.Channel>()
                    .firstOrNull { it.entity.channelId == channelId }?.entity
                    ?: return@composable
                val members   by vm.channelMembers(channelId).collectAsStateWithLifecycle()

                ChannelMembersScreen(
                    channelName = channel.name,
                    members     = members,
                    onBack      = { navController.popBackStack() },
                )
            }

            // ── Post detail ───────────────────────────────────────────────
            composable(Dest.POST) { back ->
                val postId  = back.arguments?.getString("postId") ?: return@composable
                val posts   by vm.posts.collectAsStateWithLifecycle()
                val post    = posts.firstOrNull { it.postId == postId } ?: return@composable
                val channel = sortedChannels
                    .filterIsInstance<ChannelListItem.Channel>()
                    .firstOrNull { it.entity.channelId == post.channelId }?.entity
                    ?: return@composable

                PostDetailScreen(
                    post           = post,
                    channel        = channel,
                    displayText    = "(tap to decrypt — coming soon)",
                    repTier        = mesh.shadowmesh.storage.ReputationTier.NEW,
                    showReputation = false,
                    poll           = null,
                    onBack         = { navController.popBackStack() },
                    onVote         = { /* poll voting — coming soon */ },
                )
            }

            // ── Feed ──────────────────────────────────────────────────────
            composable(Dest.FEED) {
                FeedScreen(
                    items       = feedItems,
                    onItemClick = { ch ->
                        vm.selectChannel(ch.channelId)
                        navController.navigate(Dest.detail(ch.channelId))
                    },
                )
            }

            // ── Settings root ─────────────────────────────────────────────
            composable(Dest.SETTINGS) {
                SettingsScreen(
                    state            = SettingsUiState(
                        networkMode      = networkMode,
                        activePeers      = contacts.size,
                        nodeId           = vm.localNodeId.take(16) + "…",
                        pinConfigured    = isPinConfigured(),
                        circuitEnabled   = isCircuitActive(),
                        activeMeshMode   = activeMeshMode,
                        meshScanLabel    = if (activeMeshMode) "Mesh: Active" else "Mesh: Balanced",
                    ),
                    onBack                = { navController.popBackStack() },
                    onEntryNodeClick      = { navController.navigate(Dest.ENTRY_NODE) },
                    onPrivacyClick        = { navController.navigate(Dest.PRIVACY) },
                    onSecurityClick       = { navController.navigate(Dest.SECURITY) },
                    onIdentityClick       = { navController.navigate(Dest.NODE_IDENTITY) },
                    onSecurityLogClick    = { navController.navigate(Dest.SECURITY_LOG) },
                    onNotifClick          = { navController.navigate(Dest.NOTIF_PREFS) },
                    onPanicWipe           = onPanicWipe,
                    onDebugConsoleClick   = if (showDebugConsole) onDebugConsoleClick else null,
                    onActiveMeshModeToggle = onActiveMeshModeToggle,
                )
            }

            // ── Node identity ─────────────────────────────────────────────
            composable(Dest.NODE_IDENTITY) {
                val qrBitmap = remember { vm.generateNodeIdQr() }
                NodeIdentityScreen(
                    nodeId   = vm.localNodeId,
                    qrBitmap = qrBitmap,
                    onBack   = { navController.popBackStack() },
                )
            }

            // ── Security log ──────────────────────────────────────────────
            composable(Dest.SECURITY_LOG) {
                val status = SecurityStatus(
                    nscHalted     = isNscHalted(),
                    circuitActive = isCircuitActive(),
                    activePeers   = contacts.size,
                    networkMode   = networkMode,
                    integrityOk   = integrityAllOk(),
                    pinConfigured = isPinConfigured(),
                    biometricOk   = biometricOk(),
                    lastCheckedMs = System.currentTimeMillis(),
                )
                SecurityLogScreen(
                    status = status,
                    onBack = { navController.popBackStack() },
                )
            }

            // ── Notification preferences ──────────────────────────────────
            composable(Dest.NOTIF_PREFS) {
                NotificationPrefsScreen(onBack = { navController.popBackStack() })
            }

            // ── Entry Node sub-screen ─────────────────────────────────────
            composable(Dest.ENTRY_NODE) {
                val entryStore = entryNodeStore
                val entryPrefs by remember(entryStore) {
                    entryStore?.observeGlobalPreferences()
                        ?: kotlinx.coroutines.flow.flowOf(emptyList())
                }.collectAsStateWithLifecycle(emptyList())
                // getMode() is suspend; load once on composition.
                val entryMode  by produceState(mesh.shadowmesh.storage.EntryNodeMode.AUTOMATIC, entryStore) {
                    value = entryStore?.getMode() ?: mesh.shadowmesh.storage.EntryNodeMode.AUTOMATIC
                }
                val coroutineScope = rememberCoroutineScope()
                var showContactPicker by remember { mutableStateOf(false) }
                EntryNodeScreen(
                    preferences  = entryPrefs,
                    mode         = entryMode,
                    onModeChange = { mode ->
                        coroutineScope.launch { entryStore?.setMode(mode) }
                    },
                    onAddContact = { showContactPicker = true },
                    onRemove     = { prefId ->
                        coroutineScope.launch { entryStore?.removePreference(prefId) }
                    },
                    onBack       = { navController.popBackStack() },
                )
                // Entry Node contact picker — bottom sheet listing TRUST_PHYSICAL peers
                if (showContactPicker) {
                    // key = showContactPicker ensures the list is recomputed each time the
                    // picker opens, so newly-bootstrapped TRUST_PHYSICAL peers appear.
                    // remember {} without a key would return the list from the first opening
                    // even if new contacts were added between openings in the same session.
                    val available = remember(showContactPicker) {
                        getTrustPhysicalContacts?.invoke() ?: emptyList()
                    }
                    androidx.compose.material3.ModalBottomSheet(
                        onDismissRequest = { showContactPicker = false },
                    ) {
                        androidx.compose.foundation.layout.Column(
                            Modifier.fillMaxWidth().padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Text("Add Entry Node", color = Clr.TextPri,
                                fontSize = 15.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                            if (available.isEmpty()) {
                                Text("No TRUST_PHYSICAL contacts available. Complete a physical key exchange first.",
                                    color = Clr.Amber, fontSize = 12.sp,
                                    modifier = Modifier.padding(vertical = 8.dp))
                            } else {
                                available.forEach { pref ->
                                    androidx.compose.foundation.layout.Row(
                                        Modifier.fillMaxWidth()
                                            .clickable {
                                                coroutineScope.launch {
                                                    entryStore?.addPreference(
                                                        nodeId      = pref.nodeId,
                                                        displayName = pref.displayName,
                                                        channelId   = null
                                                    )
                                                }
                                                showContactPicker = false
                                            }
                                            .padding(vertical = 10.dp),
                                        verticalAlignment = Alignment.CenterVertically,
                                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                                    ) {
                                        androidx.compose.foundation.layout.Column(Modifier.weight(1f)) {
                                            Text(pref.displayName, color = Clr.TextPri, fontSize = 13.sp)
                                            Text(pref.nodeId.take(8) + "…", color = Clr.TextMute,
                                                fontSize = 10.sp, fontFamily = MonoFamily)
                                        }
                                        Text("Add →", color = Clr.Green, fontSize = 12.sp)
                                    }
                                    HorizontalDivider(color = Clr.Border, thickness = 0.5.dp)
                                }
                            }
                            Spacer(Modifier.height(16.dp))
                        }
                    }
                }
            }

            // ── Privacy sub-screen ────────────────────────────────────────
            composable(Dest.PRIVACY) {
                val circuitUp = isCircuitActive()
                PrivacyScreen(
                    currentMode     = networkMode.name,
                    circuitEnabled  = circuitUp,
                    onModeChange    = { label -> onPrivacyModeChange(label) },
                    onCircuitToggle = { if (!circuitUp) vpnStart() else vpnStop() },
                    onBack          = { navController.popBackStack() },
                )
            }

            // ── Security sub-screen ───────────────────────────────────────
            composable(Dest.SECURITY) {
                SecurityScreen(
                    duressPinConfigured = isPinConfigured(),
                    onSetupDuressPin    = { navController.navigate(Dest.DURESS_PIN_SETUP) },
                    onPanicWipe         = onPanicWipe,
                    onBack              = { navController.popBackStack() },
                )
            }

            // ── Duress PIN setup ──────────────────────────────────────────
            composable(Dest.DURESS_PIN_SETUP) {
                DuressPinSetupScreen(
                    onSetup = { realPin, duressPin ->
                        setupDuressPin?.invoke(realPin, duressPin)
                    },
                    onBack  = { navController.popBackStack() }
                )
            }
        }
    }
}

// ── Bottom nav bar ────────────────────────────────────────────────────────────

// ── Duress PIN setup screen ──────────────────────────────────────────────────

/**
 * Standalone duress PIN setup composable for use from the Security settings screen.
 * Mirrors the onboarding [DuressPinStep] but without the OnboardingViewModel.
 *
 * @param onSetup  Called with raw (realPin, duressPin) bytes; caller runs this on IO
 *                 and calls [DuressPinManager.setupPins]. Null = setup not available.
 * @param onBack   Pop back to the Security screen.
 */
@Composable
private fun DuressPinSetupScreen(
    onSetup: ((realPin: ByteArray, duressPin: ByteArray) -> Unit)?,
    onBack:  () -> Unit,
) {
    var realPin    by remember { mutableStateOf("") }
    var duressPin  by remember { mutableStateOf("") }
    var error      by remember { mutableStateOf<String?>(null) }
    var submitting by remember { mutableStateOf(false) }
    var success    by remember { mutableStateOf(false) }
    val scope      = rememberCoroutineScope()

    androidx.compose.foundation.layout.Column(
        Modifier.fillMaxSize().background(Clr.Bg0)
    ) {
        // header
        androidx.compose.foundation.layout.Row(
            Modifier.fillMaxWidth().background(Clr.Bg1)
                .padding(horizontal = 12.dp, vertical = 10.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            androidx.compose.material3.IconButton(onClick = onBack,
                modifier = Modifier.size(32.dp)) {
                androidx.compose.material3.Icon(
                    Icons.Filled.ArrowBack,
                    contentDescription = "Back", tint = Clr.TextPri)
            }
            Spacer(Modifier.width(8.dp))
            Text("DURESS PIN", color = Clr.Green, fontSize = 13.sp,
                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold,
                fontFamily = MonoFamily)
        }
        androidx.compose.material3.HorizontalDivider(color = Clr.Border, thickness = 1.dp)

        if (success) {
            androidx.compose.foundation.layout.Box(
                Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                androidx.compose.foundation.layout.Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text("✓", color = Clr.Green, fontSize = 32.sp)
                    Text("Duress PIN configured", color = Clr.TextPri, fontSize = 14.sp)
                }
            }
        } else {
            androidx.compose.foundation.layout.Column(
                Modifier.fillMaxSize().verticalScroll(
                    androidx.compose.foundation.rememberScrollState())
                    .padding(horizontal = 20.dp, vertical = 20.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    "When forced to unlock, enter your duress PIN instead of your real PIN. " +
                    "The app shows a decoy channel list — your real data stays hidden.",
                    color = Clr.TextSec, fontSize = 13.sp, lineHeight = 18.sp)

                // Real PIN field
                androidx.compose.material3.OutlinedTextField(
                    value = realPin,
                    onValueChange = { realPin = it; error = null },
                    label = { Text("Real PIN", fontSize = 12.sp) },
                    singleLine = true,
                    visualTransformation =
                        androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )

                // Duress PIN field
                androidx.compose.material3.OutlinedTextField(
                    value = duressPin,
                    onValueChange = { duressPin = it; error = null },
                    label = { Text("Duress PIN", fontSize = 12.sp) },
                    singleLine = true,
                    visualTransformation =
                        androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(
                        keyboardType = androidx.compose.ui.text.input.KeyboardType.NumberPassword),
                    modifier = Modifier.fillMaxWidth(),
                )

                if (error != null) {
                    Text("⚠ ${error!!}", color = Clr.Amber, fontSize = 12.sp)
                }

                val canSubmit = realPin.isNotEmpty() && duressPin.isNotEmpty() &&
                                realPin != duressPin && !submitting && onSetup != null
                androidx.compose.material3.Button(
                    onClick = {
                        if (realPin == duressPin) {
                            error = "Real and duress PINs must be different"
                            return@Button
                        }
                        submitting = true
                        scope.launch(kotlinx.coroutines.Dispatchers.IO) {
                            try {
                                onSetup?.invoke(realPin.toByteArray(), duressPin.toByteArray())
                                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                                    submitting = false
                                    success    = true
                                }
                            } catch (e: Exception) {
                                kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.Main) {
                                    submitting = false
                                    error = e.message ?: "Setup failed"
                                }
                            }
                        }
                    },
                    enabled  = canSubmit,
                    modifier = Modifier.fillMaxWidth().height(48.dp),
                    shape    = androidx.compose.foundation.shape.RoundedCornerShape(6.dp),
                    colors   = androidx.compose.material3.ButtonDefaults.buttonColors(
                        containerColor = Clr.Green)
                ) {
                    Text(if (submitting) "Configuring…" else "Set up duress PIN",
                        color = Clr.Bg0, fontSize = 14.sp,
                        fontWeight = androidx.compose.ui.text.font.FontWeight.SemiBold)
                }

                if (onSetup == null) {
                    Text("PIN setup is not available — app is not fully initialised.",
                        color = Clr.Amber, fontSize = 11.sp)
                }
            }
        }
    }
}

private data class NavItem(val route: String, val label: String, val icon: ImageVector)

private val NAV_ITEMS = listOf(
    NavItem(Dest.CHANNELS, "CHANNELS", Icons.Default.List),
    NavItem(Dest.CONTACTS, "CONTACTS", Icons.Default.People),
    NavItem(Dest.FEED,     "FEED",     Icons.Default.Visibility),
    NavItem(Dest.SETTINGS, "SETTINGS", Icons.Default.Settings),
)

@Composable
private fun ShadowBottomNav(currentRoute: String, navController: NavHostController) {
    NavigationBar(
        containerColor = Clr.Bg1,
        tonalElevation = 0.dp,
    ) {
        NAV_ITEMS.forEach { item ->
            val selected = currentRoute == item.route
            NavigationBarItem(
                selected = selected,
                onClick  = {
                    if (!selected) {
                        navController.navigate(item.route) {
                            popUpTo(Dest.CHANNELS) { saveState = true }
                            launchSingleTop = true
                            restoreState    = true
                        }
                    }
                },
                icon   = { Icon(item.icon, contentDescription = item.label,
                    modifier = Modifier.size(16.dp)) },
                label  = { Text(item.label, fontSize = 8.sp, fontFamily = MonoFamily,
                    fontWeight = FontWeight.Bold, letterSpacing = 0.06.sp) },
                colors = NavigationBarItemDefaults.colors(
                    selectedIconColor    = Clr.Green,
                    selectedTextColor    = Clr.Green,
                    unselectedIconColor  = Clr.TextMute,
                    unselectedTextColor  = Clr.TextMute,
                    indicatorColor       = Color.Transparent,
                ),
            )
        }
    }
}

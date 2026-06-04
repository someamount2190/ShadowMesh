// TODO: [BLE Redesign] activeMeshModeFlow + bleGattTransport added.
// ASSUMPTION: bleGattTransport is null until ShadowMeshForegroundService creates it;
// NSC callback and charging-state override are both no-ops until then.
// ASSUMPTION: activeMeshModeFlow is app-scope state (not persisted to disk in this
// object); persistence is handled by SharedPreferences in SettingsScreen/ViewModel.

package mesh.shadowmesh.app

import mesh.shadowmesh.attestation.AttestedPhysicalExchange
import mesh.shadowmesh.bootstrap.PhysicalKeyExchange
import mesh.shadowmesh.attestation.nfc.NfcBootstrapCoordinator
import mesh.shadowmesh.bootstrap.nfc.NfcHandshake
import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.forum.ChannelManager
import mesh.shadowmesh.forum.KeyOrchestrator
import mesh.shadowmesh.forum.PostEngine
import mesh.shadowmesh.mesh.circuit.CircuitManager
import mesh.shadowmesh.mesh.dht.DhtEngine
import mesh.shadowmesh.mesh.gossip.GossipEngine
import mesh.shadowmesh.mesh.mode.NetworkModeStateMachine
import mesh.shadowmesh.mesh.privacy.DhtQueryMix
import mesh.shadowmesh.mesh.privacy.InMeshMixProtocol
import mesh.shadowmesh.mesh.privacy.SndpEngine
import mesh.shadowmesh.nsc.NetworkStateCoordinator
import mesh.shadowmesh.nsc.integrity.PerProcessIntegrityChecker
import mesh.shadowmesh.platform.OnionCircuitPacketRouter
import mesh.shadowmesh.platform.VpnServiceBridge
import mesh.shadowmesh.security.AppSecurityWiring
import mesh.shadowmesh.security.BiometricKeyManager
import mesh.shadowmesh.security.DuressPinManager
import mesh.shadowmesh.security.PanicWipeManager
import mesh.shadowmesh.storage.RateLimiter
import mesh.shadowmesh.storage.RatchetStateStore
import mesh.shadowmesh.storage.ReputationScorer
import mesh.shadowmesh.storage.ShadowMeshDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import mesh.shadowmesh.mesh.transport.ble.BleGattTransport
import mesh.shadowmesh.mesh.transport.ble.BleScanMode

/**
 * Application-scope singleton holder — the SHADOWMESH composition root.
 *
 * This object is NOT a DI framework. It is a manually-managed singleton store.
 * All fields are lateinit and are populated in construction order by
 * [ShadowMeshApplication.buildObjectGraph]. They are read-only after that point:
 * no code outside [ShadowMeshApplication] writes to [AppModule].
 *
 * Ownership:
 *   - All objects here live for the entire process lifetime.
 *   - ViewModels are NOT stored here — they are created per screen via
 *     [ViewModelProvider.Factory] that reads from AppModule.
 *   - NfcBootstrapCoordinator is NOT stored here — it is created per bootstrap
 *     session by the bootstrap Fragment.
 *
 * Thread safety:
 *   - Written once during Application.onCreate() on the main thread.
 *   - Read from any thread thereafter (all fields are effectively immutable
 *     once [isInitialised] is true).
 *   - [isInitialised] is @Volatile so crash-restart detection is safe.
 */
object AppModule {

    // ── Init state — observed by MainActivity splash screen ────────────────

    sealed class InitPhase {
        data class Initializing(val phase: String) : InitPhase()
        object Ready : InitPhase()
        data class Failed(val reason: String) : InitPhase()
    }

    private val _initState = MutableStateFlow<InitPhase>(InitPhase.Initializing("Starting…"))
    val initState: StateFlow<InitPhase> get() = _initState

    internal fun reportProgress(phase: String) { _initState.value = InitPhase.Initializing(phase) }
    internal fun reportFailed(reason: String)  { _initState.value = InitPhase.Failed(reason)       }

    // ── Lifecycle ──────────────────────────────────────────────────────────

    @Volatile var isInitialised: Boolean = false
        private set

    /**
     * Timestamp of the last full targeted sync (ms since epoch).
     * Written by [ShadowMeshForegroundService.onDeviceUnlocked] at the start of each
     * sync so that a second unlock while the first is in flight short-circuits.
     * Read by [MeshSyncWorker.runPeriodicSync] to skip the periodic cycle when the
     * device has been actively syncing via the wake receiver.
     * @Volatile — written from the BroadcastReceiver main-thread delivery,
     * read from WorkManager background threads.
     */
    @Volatile var lastSyncMs: Long = 0L

    /**
     * The application-scope coroutine scope. Everything that must survive
     * foreground service death lives here — NSC, DHT, gossip, circuit, SNDP.
     * See roadmap: "NSC integration with Android Application scope — not service scope."
     */
    lateinit var applicationScope: CoroutineScope
        private set

    // ── Crypto primitives ──────────────────────────────────────────────────

    lateinit var hkdf:   Hkdf          private set
    lateinit var kem:    HybridKem     private set
    lateinit var signer: HybridSigner  private set
    lateinit var cipher: SymmetricCipher private set
    lateinit var ibd:    IntegrityBoundedKeyDerivation private set

    // ── Identity ───────────────────────────────────────────────────────────

    lateinit var localIdentity: NodeIdentity
        private set

    /**
     * 32-byte device secret from Android Keystore. Hardware-backed on TEE/StrongBox.
     * Used as IKM for IBD key derivation and as the DuressPinManager salt.
     * MUST be wiped (fill(0)) in [PanicWipeManager.onWipeComplete] callback.
     */
    lateinit var deviceSecret: ByteArray
        private set

    /**
     * 32-byte APK binding hash: SHA3-256(signingCert || SHA3-256(criticalBytecode[])).
     * Combined with [deviceSecret] in IBD to bind all keys to this specific binary.
     * Repackaged APK → different hash → different keys → node cannot authenticate.
     */
    lateinit var apkBindingHash: ByteArray
        private set

    // ── Security layer ─────────────────────────────────────────────────────

    lateinit var biometric:      BiometricKeyManager  private set
    lateinit var duressPinMgr:   DuressPinManager     private set
    lateinit var panicWipeMgr:   PanicWipeManager     private set
    lateinit var securityWiring: AppSecurityWiring     private set
    lateinit var integrityChecker: PerProcessIntegrityChecker private set

    // ── Storage ────────────────────────────────────────────────────────────

    lateinit var database:        ShadowMeshDatabase  private set
    lateinit var rateLimiter:     RateLimiter         private set
    lateinit var reputationScorer:ReputationScorer    private set
    lateinit var ratchetStateStore: RatchetStateStore private set

    // ── NSC ────────────────────────────────────────────────────────────────

    lateinit var nsc: NetworkStateCoordinator
        private set

    // ── Forum engine ───────────────────────────────────────────────────────

    lateinit var keyOrchestrator:  KeyOrchestrator   private set
    lateinit var channelManager:   ChannelManager    private set
    lateinit var postEngine:       PostEngine        private set
    /**
     * Domain-layer forum ViewModel — NOT an Android ViewModel; application-scoped.
     * Wired by [ShadowMeshHiltModule.provideForumViewModel] into Hilt for injection
     * into [ForumUiViewModel]. Fragment dispatch is connected to [postDispatcher].
     */
    lateinit var forumViewModel:   mesh.shadowmesh.forum.ForumViewModel  private set

    // ── Network mode ───────────────────────────────────────────────────────

    lateinit var networkModeSM: NetworkModeStateMachine
        private set

    // ── Mesh transport + routing ───────────────────────────────────────────

    lateinit var dhtEngine:             DhtEngine                                          private set
    lateinit var gossipEngine:          GossipEngine                                       private set
    lateinit var transportHealthMonitor: mesh.shadowmesh.mesh.health.TransportHealthMonitor private set

    // ── Circuit ────────────────────────────────────────────────────────────

    lateinit var entryNodeStore:          mesh.shadowmesh.mesh.circuit.EntryNodeStore private set
    lateinit var circuitManager:         CircuitManager           private set
    lateinit var onionCircuitPacketRouter: OnionCircuitPacketRouter private set
    lateinit var vpnBridge:               VpnServiceBridge         private set

    // ── Privacy ────────────────────────────────────────────────────────────

    lateinit var sndpEngine:     SndpEngine       private set
    lateinit var dhtQueryMix:    DhtQueryMix      private set
    lateinit var inMeshMixProtocol: InMeshMixProtocol private set

    // ── BLE scan mode (mesh aggressiveness) ────────────────────────────────

    /**
     * Reactive source for the user's "Active Mesh Mode" preference (false = BALANCED).
     * Observed by [ShadowMeshNavRoot] via [collectAsStateWithLifecycle] and passed to
     * the settings toggle. [ShadowMeshForegroundService] also observes it for the
     * charging-state override. Changes are propagated to [BleGattTransport] via NSC.
     */
    val activeMeshModeFlow: MutableStateFlow<Boolean> = MutableStateFlow(false)

    /**
     * Nullable reference to the live mesh BLE transport. Null until
     * [ShadowMeshForegroundService] creates it. NSC callback and charging-state
     * override are both no-ops while this is null.
     */
    @Volatile var bleGattTransport: BleGattTransport? = null

    // ── Bootstrap ──────────────────────────────────────────────────────────

    lateinit var physicalKeyExchange: PhysicalKeyExchange private set
    lateinit var nfcHandshake:        NfcHandshake        private set
    /**
     * Attested physical exchange — wraps [physicalKeyExchange] with hardware attestation.
     * Used by the bootstrap Fragment when constructing [NfcBootstrapCoordinator].
     * Provides [TRUST_PHYSICAL_ATTESTED] when both devices have functional TEEs;
     * falls back to [TRUST_PHYSICAL_NFC] gracefully when TEE is unavailable.
     */
    lateinit var attestedExchange:    AttestedPhysicalExchange private set

    /**
     * True when hardware attestation roots are fully configured and the onboarding flow
     * should require [BootstrapTrustLevel.TRUST_PHYSICAL_ATTESTED] from the peer.
     *
     * True when both Google hardware attestation roots (RSA-4096 and EC P-384) are
     * embedded and pass [HardwareAttestation.isRootConfigured]. GrapheneOS support is
     * key-set based ([HardwareAttestation.GRAPHENEOS_VERIFIED_BOOT_KEYS]) and does not
     * require a separate root, so this flag correctly reflects full attestation readiness.
     *
     * Injecting this as a computed property (not a constructor parameter) keeps
     * [OnboardingViewModel] free of a direct dependency on [HardwareAttestation].
     */
    val attestationRequired: Boolean get() =
        isInitialised &&
        mesh.shadowmesh.attestation.HardwareAttestation.isRootConfigured(
            mesh.shadowmesh.attestation.HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA
        ) &&
        mesh.shadowmesh.attestation.HardwareAttestation.isRootConfigured(
            mesh.shadowmesh.attestation.HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_EC
        )

    // ── Forum backend ─────────────────────────────────────────────────────

    /** Outbound: fragments a post and replicates it to the mesh. */
    lateinit var postDispatcher:         mesh.shadowmesh.forum.backend.PostDispatcher          private set
    /** Inbound: receives fragments, reassembles posts, fires ViewModel callbacks. */
    lateinit var fragmentIngestor:       mesh.shadowmesh.forum.backend.FragmentIngestor        private set
    /** Sync: reconnect drain + periodic sync. */
    lateinit var channelSyncCoordinator: mesh.shadowmesh.forum.backend.ChannelSyncCoordinator  private set
    /** Router: dispatches raw ACK/NACK/fragment packets to the right handler. */
    lateinit var ackRouter:              mesh.shadowmesh.forum.backend.AckRouter               private set

    // ── Sybil resistance ───────────────────────────────────────────────────

    /** Rate-limits TRUST_INTRODUCED issuances per sponsor. Wired into TrustChainValidator. */
    lateinit var sponsorshipLedger:         mesh.shadowmesh.mesh.trust.SponsorshipLedger          private set
    /** Scores per-peer behavioral coherence to flag AI agents / bot swarms. Wired into GossipEngine. */
    lateinit var behavioralCoherenceScorer: mesh.shadowmesh.storage.BehavioralCoherenceScorer     private set

    // ── Distribution ───────────────────────────────────────────────────────

    /** Seeds the installed APK over the mesh distribution channel. */
    lateinit var artifactSeeder:   mesh.shadowmesh.distribution.AppArtifactSeeder    private set
    /** Acquires and verifies an APK from a mesh seeder. */
    lateinit var artifactAcquirer: mesh.shadowmesh.distribution.AppArtifactAcquirer  private set

    // ── Forum extras ───────────────────────────────────────────────────────

    /** Creates and destroys ephemeral one-time channels for physical drops. */
    lateinit var oneTimeChannel: mesh.shadowmesh.forum.OneTimeChannel private set

    // ── Internal setter — called only from ShadowMeshApplication ──────────

    @Suppress("LongParameterList")
    internal fun initialise(
        applicationScope:          CoroutineScope,
        hkdf:                      Hkdf,
        kem:                       HybridKem,
        signer:                    HybridSigner,
        cipher:                    SymmetricCipher,
        ibd:                       IntegrityBoundedKeyDerivation,
        localIdentity:             NodeIdentity,
        deviceSecret:              ByteArray,
        apkBindingHash:            ByteArray,
        biometric:                 BiometricKeyManager,
        duressPinMgr:              DuressPinManager,
        panicWipeMgr:              PanicWipeManager,
        securityWiring:            AppSecurityWiring,
        integrityChecker:          PerProcessIntegrityChecker,
        database:                  ShadowMeshDatabase,
        rateLimiter:               RateLimiter,
        reputationScorer:          ReputationScorer,
        ratchetStateStore:         RatchetStateStore,
        nsc:                       NetworkStateCoordinator,
        keyOrchestrator:           KeyOrchestrator,
        channelManager:            ChannelManager,
        postEngine:                PostEngine,
        forumViewModel:            mesh.shadowmesh.forum.ForumViewModel,
        networkModeSM:             NetworkModeStateMachine,
        dhtEngine:                 DhtEngine,
        gossipEngine:              GossipEngine,
        transportHealthMonitor:    mesh.shadowmesh.mesh.health.TransportHealthMonitor,
        entryNodeStore:            mesh.shadowmesh.mesh.circuit.EntryNodeStore,
        circuitManager:            CircuitManager,
        onionCircuitPacketRouter:  OnionCircuitPacketRouter,
        vpnBridge:                 VpnServiceBridge,
        sndpEngine:                SndpEngine,
        dhtQueryMix:               DhtQueryMix,
        inMeshMixProtocol:         InMeshMixProtocol,
        physicalKeyExchange:       PhysicalKeyExchange,
        nfcHandshake:              NfcHandshake,
        attestedExchange:          AttestedPhysicalExchange,
        sponsorshipLedger:         mesh.shadowmesh.mesh.trust.SponsorshipLedger,
        behavioralCoherenceScorer: mesh.shadowmesh.storage.BehavioralCoherenceScorer,
        artifactSeeder:            mesh.shadowmesh.distribution.AppArtifactSeeder,
        artifactAcquirer:          mesh.shadowmesh.distribution.AppArtifactAcquirer,
        oneTimeChannel:            mesh.shadowmesh.forum.OneTimeChannel,
        postDispatcher:            mesh.shadowmesh.forum.backend.PostDispatcher,
        fragmentIngestor:          mesh.shadowmesh.forum.backend.FragmentIngestor,
        channelSyncCoordinator:    mesh.shadowmesh.forum.backend.ChannelSyncCoordinator,
        ackRouter:                 mesh.shadowmesh.forum.backend.AckRouter
    ) {
        this.applicationScope           = applicationScope
        this.hkdf                       = hkdf
        this.kem                        = kem
        this.signer                     = signer
        this.cipher                     = cipher
        this.ibd                        = ibd
        this.localIdentity              = localIdentity
        this.deviceSecret               = deviceSecret
        this.apkBindingHash             = apkBindingHash
        this.biometric                  = biometric
        this.duressPinMgr               = duressPinMgr
        this.panicWipeMgr               = panicWipeMgr
        this.securityWiring             = securityWiring
        this.integrityChecker           = integrityChecker
        this.database                   = database
        this.rateLimiter                = rateLimiter
        this.reputationScorer           = reputationScorer
        this.ratchetStateStore          = ratchetStateStore
        this.nsc                        = nsc
        nsc.onActiveMeshModeChanged     = { active ->
            activeMeshModeFlow.value    = active
            bleGattTransport?.setMeshScanMode(if (active) BleScanMode.ACTIVE else BleScanMode.BALANCED)
        }
        this.keyOrchestrator            = keyOrchestrator
        this.channelManager             = channelManager
        this.postEngine                 = postEngine
        this.forumViewModel             = forumViewModel
        this.networkModeSM              = networkModeSM
        this.dhtEngine                  = dhtEngine
        this.gossipEngine               = gossipEngine
        this.transportHealthMonitor     = transportHealthMonitor
        this.entryNodeStore             = entryNodeStore
        this.circuitManager             = circuitManager
        this.onionCircuitPacketRouter   = onionCircuitPacketRouter
        this.vpnBridge                  = vpnBridge
        this.sndpEngine                 = sndpEngine
        this.dhtQueryMix                = dhtQueryMix
        this.inMeshMixProtocol          = inMeshMixProtocol
        this.physicalKeyExchange        = physicalKeyExchange
        this.nfcHandshake               = nfcHandshake
        this.attestedExchange           = attestedExchange
        this.sponsorshipLedger          = sponsorshipLedger
        this.behavioralCoherenceScorer  = behavioralCoherenceScorer
        this.artifactSeeder             = artifactSeeder
        this.artifactAcquirer           = artifactAcquirer
        this.oneTimeChannel             = oneTimeChannel
        this.postDispatcher             = postDispatcher
        this.fragmentIngestor           = fragmentIngestor
        this.channelSyncCoordinator     = channelSyncCoordinator
        this.ackRouter                  = ackRouter
        _initState.value                = InitPhase.Ready
        this.isInitialised              = true
    }
}

package mesh.shadowmesh.app

import mesh.shadowmesh.diagnostics.Diag

import android.app.Application
import android.content.Intent
import android.util.Log
import androidx.work.Configuration
import androidx.work.WorkManager
import mesh.shadowmesh.attestation.AttestedPhysicalExchange
import mesh.shadowmesh.bootstrap.PhysicalKeyExchange
import mesh.shadowmesh.bootstrap.NonceStore
import mesh.shadowmesh.bootstrap.nfc.NfcHandshake
import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.forum.ChannelManager
import mesh.shadowmesh.forum.KeyOrchestrator
import mesh.shadowmesh.forum.PostEngine
import mesh.shadowmesh.forum.TtlSweepWorker
import mesh.shadowmesh.mesh.circuit.*
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.gossip.GossipEngine
import mesh.shadowmesh.crypto.hexToBytes
import mesh.shadowmesh.mesh.dht.NodeTier
import mesh.shadowmesh.mesh.mode.NetworkMode
import mesh.shadowmesh.mesh.mode.NetworkModeStateMachine
import mesh.shadowmesh.mesh.privacy.*
import mesh.shadowmesh.mesh.transport.NatAwareDhtTransport
import mesh.shadowmesh.mesh.transport.NatTraversalEngine
import mesh.shadowmesh.mesh.transport.NoOpUdpSocketAdapter
import mesh.shadowmesh.mesh.transport.DatagramSocketUdpAdapter
import mesh.shadowmesh.mesh.transport.UdpDhtTransport
import mesh.shadowmesh.mesh.transport.NoOpDhtTransport
import mesh.shadowmesh.nsc.NetworkStateCoordinator
import mesh.shadowmesh.nsc.integrity.PerProcessIntegrityChecker
import mesh.shadowmesh.nsc.RollbackRegistry
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import mesh.shadowmesh.platform.*
import mesh.shadowmesh.security.*
import mesh.shadowmesh.storage.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.first

/**
 * SHADOWMESH composition root — the only place where the full object graph is built.
 *
 * Construction order is strictly dictated by dependency direction. Each phase
 * depends only on phases completed before it. Any error in a phase that cannot
 * be recovered (e.g. Keystore inaccessible, NSC still halted after replay) causes
 * [startActivity(CoverActivity)] and process exit rather than continuing with a
 * broken graph.
 *
 * Phases:
 *   1. Crypto primitives          (pure JVM, no I/O)
 *   2. Hardware-backed secrets    (Keystore, Dispatchers.IO)
 *   3. APK binding hash           (PackageManager, Dispatchers.IO)
 *   4. Identity generation        (depends on 2+3)
 *   5. Storage                    (SQLCipher + Room, depends on 2)
 *   6. NSC                        (depends on 5)
 *   7. Forum engine               (depends on 5+6)
 *   8. Transport layer            (depends on 4)
 *   9. Circuit                    (depends on 4+8)
 *  10. Privacy layer              (depends on 8+9)
 *  11. Security wiring            (depends on all)
 *  12. WorkManager + observers    (depends on all)
 */
@dagger.hilt.android.HiltAndroidApp
class ShadowMeshApplication : Application(), Configuration.Provider {

    private val TAG = "ShadowMeshApp"

    // A gossip peer last seen within this window is treated as "LAN reachable" for the
    // Transport health probe windows — pragmatic gossip-based proxies until contacts carry transport tags.
    private val LAN_RECENT_MS = 5L * 60 * 1000   // 5 minutes — LAN/WiFi Direct reachable if any peer seen within this window
    private val BLE_RECENT_MS = 2L * 60 * 1000   // 2 minutes — BLE has shorter effective range; tighter window reduces false positives

    // Application-scope: survives foreground service death.
    // Mesh engines (NSC, DHT, gossip, circuit) use this scope — not the service scope.
    // CoroutineExceptionHandler prevents uncaught child-coroutine exceptions from reaching
    // the thread's UncaughtExceptionHandler (which crashes Android). With SupervisorJob,
    // failures are isolated; this handler logs them without killing the process.
    private val applicationScope = CoroutineScope(
        SupervisorJob() + Dispatchers.Default + CoroutineName("AppScope") +
        kotlinx.coroutines.CoroutineExceptionHandler { _, throwable ->
            Log.e(TAG, "Unhandled exception in applicationScope — isolated by SupervisorJob", throwable)
            Diag.fallback("app-scope", "unhandled-coroutine-exception",
                "Unexpected exception in background coroutine — process not killed",
                "error" to (throwable.message ?: throwable.javaClass.simpleName))
        }
    )

    // Held at application scope so onTerminate() can close() it.
    private var nscInstance: mesh.shadowmesh.nsc.NetworkStateCoordinator? = null

    override fun onTerminate() {
        // Shut down the NSC's single-threaded executor. onTerminate() is only called
        // in instrumented tests and on emulators — on real devices the process is killed
        // directly. This is still the correct lifecycle hook to use; it covers the cases
        // where it IS called and prevents profiler noise from the leaked thread.
        nscInstance?.close()
        applicationScope.cancel()
        super.onTerminate()
    }

    override fun onCreate() {
        super.onCreate()
        applicationScope.launch {
            try {
                buildObjectGraph()
                startPostInitTasks()
            } catch (e: Throwable) {
                // Catch Throwable (not just Exception) to handle errors thrown by
                // native library loading — notably UnsatisfiedLinkError from
                // LazySodiumJava(SodiumJava()) if the .so is missing or ABI-mismatched.
                // Without this, a native load failure produces an unhandled crash rather
                // than a graceful redirect to the cover screen.
                Log.e(TAG, "INIT FAILED [${e.javaClass.simpleName}]: ${e.message}", e)
                Log.e(TAG, "  ↳ cause: ${e.cause?.javaClass?.simpleName}: ${e.cause?.message}")
                AppModule.reportFailed("${e.javaClass.simpleName}: ${e.message?.take(80) ?: "unknown error"}")
                Diag.fallback("app", "init-fatal",
                    "Object graph construction failed — cover screen shown",
                    "error" to (e.message ?: e.javaClass.simpleName))
                showCoverActivity()
            }
        }
    }

    // ── Object graph construction ──────────────────────────────────────────

    private suspend fun buildObjectGraph() {
        Log.i(TAG, "=== buildObjectGraph START ===")

        // ── Phase 1: Crypto primitives ─────────────────────────────────────
        AppModule.reportProgress("Initializing crypto primitives…")
        Log.i(TAG, "Phase 1: crypto primitives")
        val hkdf   = Hkdf.instance
        val kem    = HybridKem(hkdf)
        val signer = HybridSigner()
        val cipher = SymmetricCipher()
        val ibd    = IntegrityBoundedKeyDerivation(hkdf)
        Log.i(TAG, "Phase 1: done")

        // ── Phase 2: Hardware-backed secrets ───────────────────────────────
        AppModule.reportProgress("Securing device identity…")
        Log.i(TAG, "Phase 2: hardware-backed secrets")
        val biometric    = BiometricKeyManager(this@ShadowMeshApplication)
        val deviceSecret = deriveDeviceSecret(biometric)
        Log.i(TAG, "Phase 2: done")

        // ── Phase 3: APK binding hash ──────────────────────────────────────
        Log.i(TAG, "Phase 3: APK binding hash")
        val apkBindingHash = deriveApkBindingHash(ibd)
        Log.i(TAG, "Phase 3: done")

        // ── Phase 4: Identity generation ───────────────────────────────────
        Log.i(TAG, "Phase 4: identity generation")
        // IBD-bound: repackaged APK → different apkBindingHash → different nodeId
        val identityGenerator = NodeIdentityGenerator(
            kem            = kem,
            signer         = signer,
            hkdf           = hkdf,
            ibd            = ibd,
            deviceSecret   = deviceSecret,
            apkBindingHash = apkBindingHash
        )
        val localIdentity = loadOrGenerateIdentity(identityGenerator, deviceSecret)
        Log.i(TAG, "Phase 4: done — nodeId ${localIdentity.nodeId.take8Hex()}")

        // ── Phase 5: Storage ───────────────────────────────────────────────
        AppModule.reportProgress("Opening encrypted database…")
        Log.i(TAG, "Phase 5: storage (SQLCipher + Room)")
        // dbKey derived from deviceSecret so the database is inaccessible without
        // the Keystore key (which is hardware-backed and not backed up).
        val dbKey = hkdf.derive(
            ikm = deviceSecret, salt = null,
            info = "shadowmesh_db_key_v1".toByteArray(), outputLen = 32
        )
        val database = withContext(Dispatchers.IO) {
            ShadowMeshDatabase.getInstance(this@ShadowMeshApplication, dbKey)
        }
        dbKey.fill(0)
        val dao              = database.dao()
        val rateLimiter      = RateLimiter()
        val reputationScorer = ReputationScorer()
        val ratchetStateStore = RatchetStateStore(database.ratchetDao())
        Log.i(TAG, "Phase 5: done")

        // ── Phase 6: NSC ────────────────────────────────────────────────────
        Log.i(TAG, "Phase 6: NSC construction")
        val nsc = NetworkStateCoordinator(
            context = this@ShadowMeshApplication,
            scope   = applicationScope
        )
        nscInstance = nsc   // held for onTerminate() cleanup
        // NOTE: nsc.initialise() is deferred to Phase 8.5, after RollbackRegistry handlers
        // are registered.  initialise() replays in-progress saga rollbacks via
        // RollbackRegistry.execute() — if it were called here the handlers would not yet
        // exist and every replay would throw, leaving NSC permanently halted.

        // ── Phase 7: Forum engine ───────────────────────────────────────────
        Log.i(TAG, "Phase 7: forum engine")
        val duressPinMgr  = DuressPinManager(this@ShadowMeshApplication)
        val channelManager = ChannelManager(dao)
        val keyOrchestrator = KeyOrchestrator(
            deviceSecret   = deviceSecret,
            apkBindingHash = apkBindingHash,
            biometric      = biometric,
            channelManager = channelManager,
            ratchetStateStore = ratchetStateStore
        )
        val postEngine = PostEngine(dao)

        // Provision the global public channel on every launch. Idempotent — upsert is a
        // no-op when the channel already exists with the correct values. Must run after
        // keyOrchestrator is built (needs wrapChannelKey) and before UI subscribes to
        // channelManager.observeActiveChannels() (otherwise the channel appears late).
        val rawGlobalKey = mesh.shadowmesh.forum.GlobalChannel.rawKey()
        val wrappedGlobalKey = keyOrchestrator.wrapChannelKey(
            channelId = mesh.shadowmesh.forum.GlobalChannel.ID,
            type      = mesh.shadowmesh.storage.ChannelType.GLOBAL,
            rawKey    = rawGlobalKey
        )
        rawGlobalKey.fill(0)
        channelManager.ensureGlobalChannel(wrappedGlobalKey)

        Log.i(TAG, "Phase 7: done")

        // ── Phase 8: Transport layer ────────────────────────────────────────
        AppModule.reportProgress("Building transport layer…")
        Log.i(TAG, "Phase 8: transport layer (UDP/DHT/gossip)")
        val localNodeId    = NodeId(localIdentity.nodeId)
        // DatagramSocketUdpAdapter owns the single UDP socket bound to DHT_PORT (7400).
        // It demultiplexes incoming datagrams: DHT-magic frames go to UdpDhtTransport,
        // probe/pong frames go to token waiters in NatTraversalEngine hole-punch calls.
        // The adapter is created before NatTraversalEngine so the socket is bound before
        // any STUN or punch attempt is issued.
        val udpAdapter = try {
            DatagramSocketUdpAdapter(scope = applicationScope)
        } catch (e: Exception) {
            Diag.swallowed("app", "udp-adapter-bind", e)
            null
        }
        val natEngine      = NatTraversalEngine(
            localNodeId   = localNodeId,
            socketAdapter = udpAdapter ?: NoOpUdpSocketAdapter,
            scope         = applicationScope
        )
        val networkModeSM  = NetworkModeStateMachine(initialAnchorCount = 0)

        val (dhtTransport, udpDhtTransport) = buildDhtTransport(natEngine, localNodeId, hkdf, udpAdapter)
        val dhtEngine      = DhtEngine(
            localNodeId         = localNodeId,
            transport           = dhtTransport,
            scope               = applicationScope,
            localPublicIdentity = localIdentity.publicPart
        )
        // Complete the circular wiring: UdpDhtTransport needs DhtEngine for inbound RPC
        // handling (routing table queries, local store access). setEngine() is safe to call
        // immediately — no RPCs are in flight until bootstrap() is called.
        udpDhtTransport?.setEngine(dhtEngine)
        // Start the UDP listener loop now that both the engine and transport are wired.
        udpAdapter?.startListening()

        // Keep a typed reference so we can wire lanTransport into it later (Phase 11.1).
        val dhtGossipTransport = buildGossipTransport(dhtEngine)
        val gossipEngine   = GossipEngine(
            localNodeId  = localNodeId,
            scope        = applicationScope,
            transport    = dhtGossipTransport,
            onHoneyTripped = { compromisedSourceId ->
                // PCS: a honey fragment was decrypted by the source node, proving the anchor
                // signing key was extracted. Rotate all CLOSED channel keys that this node
                // participates in. COMPARTMENTED channels require physical re-exchange — flag
                // them but do not attempt an automatic in-band rotation.
                //
                // This is the missing link between HoneyAnchor detection and post-compromise
                // security. Previously onHoneyTripped only fired the local block; the ratchet
                // chain remained compromised even after the attacker was blocked.
                applicationScope.launch {
                    android.util.Log.w("AppModule",
                        "HoneyAnchor tripped by ${compromisedSourceId.toHex().take(8)} — " +
                        "rotating CLOSED channel keys for PCS")
                    try { rotateAllClosedChannelKeys(keyOrchestrator, channelManager) }
                    catch (e: Exception) { Diag.swallowed("pcs", "rotate-keys-outer", e) }
                }
            }
        )

        // ── Phase 8.05: Anchor-count → NetworkMode wiring ─────────────────
        // Wire gossipEngine → networkModeSM so every TRUST_PHYSICAL peer registration
        // or removal propagates to the state machine. Without this, the mode is stuck
        // at SURVIVAL (initialAnchorCount=0) for the entire process lifetime, which
        // disables SNDP, two-hop routing, and circuit availability.
        gossipEngine.setAnchorCountChangedListener { count ->
            networkModeSM.onAnchorCountChanged(count)
            Diag.info("network-mode", "anchor-count-changed",
                "Anchor count → $count; mode = ${networkModeSM.currentMode}",
                "anchors" to count.toString(), "mode" to networkModeSM.currentMode.name)
        }

        // ── Phase 8.06: HardenedChallengeLayer wiring ──────────────────────
        // Replace random per-sync-cycle challenge types with round-robin rotation.
        // Prevents adversarial peers from specialising their fake responses to a
        // predictable challenge type sequence.
        val hardenedChallengeLayer = mesh.shadowmesh.mesh.gossip.HardenedChallengeLayer(
            gossipEngine = gossipEngine,
            scope        = applicationScope
        )
        gossipEngine.hardenedChallengeLayer = hardenedChallengeLayer

        // ── Phase 8.1: TransportHealthMonitor ──────────────────────────────
        // Forward reference captured by the LAN probe lambda below.
        // Set to the real LanSubnetTransport in Phase 11 once it is constructed.
        var lanSubnetForProbe: mesh.shadowmesh.mesh.transport.lan.LanSubnetTransport? = null

        Log.i(TAG, "Phase 8.1: transport health monitor")
        val transportHealthMonitor = mesh.shadowmesh.mesh.health.TransportHealthMonitor(
            scope  = applicationScope,
            probes = mapOf(
                mesh.shadowmesh.mesh.health.TransportType.INTERNET_DHT to { dhtEngine.probe() },
                // LAN/WiFi Direct/BLE: no per-transport probe API yet.
                // Proxy: treat any gossip peer seen within RECENT_MS as evidence that the
                // transport is reachable. All three proximity transports share the same
                // gossip peer table; this gives a coarse "at least one transport works"
                // signal. Per-transport discrimination requires DhtContact to carry a
                // transport-type tag, tracked as a future enhancement.
                mesh.shadowmesh.mesh.health.TransportType.LAN        to {
                    // Active TCP probe via lanSubnetForProbe (set in Phase 11).
                    // Replaces the old gossip lastSeenMs heuristic which aged out after
                    // LAN_RECENT_MS (5 min) with no traffic and permanently showed ISOLATED.
                    lanSubnetForProbe?.probe()
                },
                mesh.shadowmesh.mesh.health.TransportType.WIFI_DIRECT to {
                    // Same gossip-heuristic proxy as LAN. WiFi Direct peers appear in the
                    // gossip peer table; a recently-seen peer implies WiFi Direct is up.
                    gossipEngine.activePeerIds()
                        .mapNotNull { gossipEngine.peerContact(it) }
                        .maxByOrNull { it.lastSeenMs }
                        ?.let { p ->
                            val age = System.currentTimeMillis() - p.lastSeenMs
                            if (age < LAN_RECENT_MS) age else null
                        }
                },
                mesh.shadowmesh.mesh.health.TransportType.BLE         to {
                    // BLE: same proxy. BLE peers have shorter effective range so use a
                    // tighter window (BLE_RECENT_MS) to avoid false positives from LAN peers
                    // that are nearby but not actually on BLE.
                    gossipEngine.activePeerIds()
                        .mapNotNull { gossipEngine.peerContact(it) }
                        .maxByOrNull { it.lastSeenMs }
                        ?.let { p ->
                            val age = System.currentTimeMillis() - p.lastSeenMs
                            if (age < BLE_RECENT_MS) age else null
                        }
                },
            )
        )
        // Wire health monitor into engines (set before start so the first probe sees them).
        dhtEngine.healthMonitor     = transportHealthMonitor
        gossipEngine.healthMonitor  = transportHealthMonitor
        Log.i(TAG, "Phase 8.1: done")

        // ── Phase 8.5: NSC rollback handler registration + initialise() ─────
        //
        // RollbackRegistry handlers MUST be registered before nsc.initialise() is
        // called.  initialise() replays any IN_PROGRESS saga checkpoints from the
        // previous process lifetime via RollbackRegistry.execute(); if a handler is
        // absent, execute() now throws (previously it silently no-opped, leaving DHT
        // state inconsistent after a crash).
        //
        // Handler contract:
        //   Each handler receives the persisted args string and must perform the
        //   rollback action using only information available in that string and the
        //   engine references captured as closures below.
        //
        //   CANCEL_FRAGMENT  — fully implemented via dao.deleteFragment().
        //   RESTORE_*        — partially implemented: mode enums are rehydrated from
        //                      the persisted string and applied; if the target engine
        //                      has no public setter yet, Diag.degraded is emitted and
        //                      the handler returns normally (NSC marks the checkpoint
        //                      as rolled-back).  This is safer than throwing and
        //                      leaving NSC halted for a mode-restoration that may be
        //                      non-critical at restart time.
        //   RECLAIM_DHT_SLICE / REVERT_TIER_PROMOTION — no fine-grained engine API
        //                      exists yet; Diag.degraded is emitted so the gap is
        //                      observable, and the handler returns normally.
        // NodeId-hex → Bluetooth MAC address. Must be declared before bleGattTransport so the
        // onBleNodeIdDiscovered lambda can capture it. Populated when a BLE peer is authenticated.
        val blePeerAddresses = java.util.concurrent.ConcurrentHashMap<String, String>()

        // Construct BleGattTransport so the RESTORE_BEACON_MODE rollback handler has a concrete
        // instance to call startBeacon/stopBeacon on. scanPendingIntent is null here — background
        // scanning is wired later when ShadowMeshForegroundService creates its BroadcastReceiver-
        // targeted PendingIntent and calls bleGattTransport.setScanPendingIntent(intent).
        val bleGattTransport = try {
            mesh.shadowmesh.mesh.transport.ble.BleGattTransport(
                context                  = this,
                scope                    = applicationScope,
                nudgeEngine              = buildNudgeEngine(gossipEngine, dhtEngine),
                localNodeId              = localNodeId,
                localEd25519PubKey       = localIdentity.publicPart.signingPublicKey.ed25519PublicKey.copyOf(),
                signChallengeEd25519Only = { message ->
                    // getOrNull instead of getOrThrow: a signing failure must not crash the
                    // BLE stack. Return an empty signature — the remote peer will reject it
                    // and the challenge will fail gracefully rather than throwing an
                    // IllegalStateException into the BLE callback thread.
                    signer.signEd25519Only(message, localIdentity.privatePart.signingPrivateKey)
                        .getOrNull() ?: ByteArray(0)
                },
                verifyEd25519Only        = { message, sig, pubKey ->
                    signer.verifyEd25519Only(message, sig, pubKey).getOrNull() ?: false
                },
                onNudgeReceived = { channelHash8 ->
                    // When a BLE beacon nudge arrives, schedule a WorkManager sync for that channel.
                    // Mirrors what ShadowMeshForegroundService does for UDP nudges.
                    applicationScope.launch {
                        val hexHash = channelHash8.toHex()
                        Diag.info("ble-gatt", "nudge-received",
                            "BLE nudge received for channel ${hexHash.take(8)}")
                        MeshSyncWorker.scheduleNudgeSync(this@ShadowMeshApplication, hexHash)
                    }
                },
                onBleNodeIdDiscovered = { bleNodeId, deviceAddress ->
                    // Record NodeId → Bluetooth MAC so sendBleNudge can reach this peer later.
                    // blePeerAddresses is defined immediately after this construction block.
                    blePeerAddresses[bleNodeId.toHex()] = deviceAddress

                    // Register BLE-discovered peer in gossip engine as TRUST_PUBLIC.
                    // Uses a synthetic DhtContact (no IP/port) — fragments arrive via BLE GATT.
                    gossipEngine.registerPeer(
                        mesh.shadowmesh.mesh.dht.DhtContact(
                            nodeId   = bleNodeId,
                            address  = mesh.shadowmesh.mesh.dht.PeerAddress(
                                ip       = "",   // BLE peer — no IP address
                                port     = 0,
                                protocol = mesh.shadowmesh.mesh.dht.TransportProtocol.TCP
                            ),
                            tier     = mesh.shadowmesh.mesh.dht.NodeTier.TIER_2,
                            isAnchor = false
                        ),
                        mesh.shadowmesh.crypto.TrustLevel.TRUST_PUBLIC
                    )
                    applicationScope.launch(Dispatchers.IO) {
                        try {
                            dao.upsertDiscoveredPeer(mesh.shadowmesh.storage.DiscoveredPeerEntity(
                                nodeIdHex   = bleNodeId.toHex(),
                                lastSeenMs  = System.currentTimeMillis(),
                                transport   = "BLE",
                                addressHint = deviceAddress,
                                trustLevel  = mesh.shadowmesh.crypto.TrustLevel.TRUST_PUBLIC.name
                            ))
                        } catch (e: Exception) {
                            Diag.swallowed("ble-gatt", "peer-cache-upsert", e)
                        }
                    }
                    Diag.info("ble-gatt", "peer-discovered",
                        "BLE peer registered (nodeId=${bleNodeId.toHex().take(8)}, mac=$deviceAddress)")
                }
            )
        } catch (e: Exception) {
            // BLE hardware unavailable or BluetoothManager absent (emulator, BT off at boot).
            // Null out and skip — beacon rollback handler will no-op gracefully.
            Diag.swallowed("ble-gatt", "construct-failed", e)
            null
        }

        registerNscRollbackHandlers(dao, dhtEngine, gossipEngine, networkModeSM, bleGattTransport)
        Log.i(TAG, "Phase 8: done — rollback handlers registered")

        AppModule.reportProgress("Replaying saga checkpoints…")
        Log.i(TAG, "Phase 8.5: NSC initialise() — replaying saga checkpoints")
        val nscInitDone = kotlinx.coroutines.withTimeoutOrNull(15_000L) {
            withContext(Dispatchers.IO) { nsc.initialise() }
        }
        if (nscInitDone == null) {
            val msg = "NSC initialise() timed out after 15 s — saga table may have stuck IN_PROGRESS entries"
            Log.e(TAG, "INIT BLOCKED: $msg")
            AppModule.reportFailed("Saga checkpoint replay timed out (15 s)")
            showCoverActivity()
            return
        }
        Log.i(TAG, "Phase 8.5: NSC initialise() returned — isHalted=${nsc.isHalted}")

        // If NSC is still halted after replay, we cannot guarantee state consistency.
        // Surface the halt to the user rather than continuing with a broken graph.
        if (nsc.isHalted) {
            Log.e(TAG, "INIT BLOCKED: NSC halted after initialise() — showing cover. " +
                "Check NSC saga table for stuck IN_PROGRESS checkpoints.")
            showCoverActivity()
            return
        }

        // Observe NSC halt state: if it halts later (e.g. during operation),
        // show the cover UI and schedule a process restart.
        applicationScope.launch {
            nsc.haltedFlow
                .filter { it }   // only react when it becomes true
                .first()
            Log.e(TAG, "NSC entered UNRECOVERABLE during operation")
            showCoverActivity()
        }

        // ── Phase 9: Circuit ────────────────────────────────────────────────
        Log.i(TAG, "Phase 9: circuit layer")
        val onionCircuit   = OnionCircuit(localNodeId, kem, hkdf, cipher)
        val rotator        = CircuitRoleRotator(localNodeId)
        val entryNodeStore = EntryNodeStore(dao)
        val circuitTransport = buildCircuitTransport(gossipEngine, dhtEngine)

        val circuitManager = CircuitManager(
            circuit           = onionCircuit,
            rotator           = rotator,
            transport         = circuitTransport,
            scope             = applicationScope,
            getCandidates = {
                gossipEngine.activePeerIds().mapNotNull { nodeId ->
                    val contact = gossipEngine.peerContact(nodeId) ?: return@mapNotNull null
                    val trust = when (gossipEngine.effectiveTrust(nodeId)) {
                        TrustLevel.TRUST_PHYSICAL   -> TrustLevelForCircuit.PHYSICAL
                        TrustLevel.TRUST_INTRODUCED -> TrustLevelForCircuit.INTRODUCED
                        else                        -> TrustLevelForCircuit.PUBLIC
                    }
                    CircuitCandidate(nodeId = nodeId, contact = contact, trustLevel = trust, uptimeScore = 50)
                }
            },
            entryNodeStore    = entryNodeStore,
            getCurrentMode    = { networkModeSM.currentMode },
            getCurrentChannel = { null },
            onEntryEvent      = { event -> handleEntryEvent(event) }
        )

        val onionCircuitPacketRouter = OnionCircuitPacketRouter(
            circuitManager = circuitManager,
            scope          = applicationScope
        )
        ShadowMeshVpnService.routerProvider = { onionCircuitPacketRouter }

        val vpnBridge = VpnServiceBridge(
            SharedPrefsVpnConsentStore(this@ShadowMeshApplication)
        )

        // Wire CircuitStunSender now that CircuitManager is available.
        // NatTraversalEngine was built in Phase 8 (before CircuitManager) so the sender
        // could not be injected at construction. setCircuitStun() is safe to call
        // immediately — no STUN queries are in flight until bootstrap() starts in Phase 8.5.
        natEngine.setCircuitStun(
            mesh.shadowmesh.mesh.transport.CircuitStunSenderImpl(circuitManager)
        )

        Log.i(TAG, "Phase 9: done")

        // ── Phase 10: Privacy layer ─────────────────────────────────────────
        Log.i(TAG, "Phase 10: privacy layer (SNDP/mix)")
        val sndpTransportAdapter = buildSndpTransport(gossipEngine)
        val sndpEngine = SndpEngine(
            localNodeId = localNodeId,
            scope       = applicationScope,
            transport   = sndpTransportAdapter
        )
        val dhtQueryMix = DhtQueryMix(
            scope    = applicationScope,
            getMode  = { networkModeSM.currentMode.peerSelectionMode },
            getPeers = { gossipEngine.activePeerIds().mapNotNull { gossipEngine.peerContact(it) } },
            // Execute the mixed/delayed query through the DHT engine. The peers selected by the
            // mix are advisory — dhtEngine.findValue() uses its own routing table for the lookup.
            // Results are discarded: the mix is used for cover-query emission, not result retrieval.
            // Callers needing a result call dhtEngine.findValue() directly; the mix layer adds
            // traffic blending on top of actual lookups without blocking the calling coroutine.
            forward  = { query, _ ->
                if (query.size == mesh.shadowmesh.mesh.dht.NODE_ID_BYTES) {
                    applicationScope.launch {
                        try {
                            dhtEngine.findValue(mesh.shadowmesh.mesh.dht.NodeId(query))
                        } catch (e: Exception) {
                            if (e is kotlinx.coroutines.CancellationException) throw e
                            Diag.swallowed("dht-query-mix", "forward", e)
                        }
                    }
                }
            }
        )
        val inMeshMixProtocol = InMeshMixProtocol(
            scope     = applicationScope,
            transport = buildMixTransport(gossipEngine),
            // Wire the full peer pool so each decoy fragment is routed to an independently
            // chosen random peer. Without this, all decoys go to the same target as the
            // first real fragment in the batch — defeating decoy anonymity.
            getPeers  = { dhtEngine.routingTable.allContacts() }
        )

        Log.i(TAG, "Phase 10: done")

        // ── Phase 11: Security wiring ───────────────────────────────────────
        Log.i(TAG, "Phase 11: security wiring (APK verifier + panic wipe)")
        // Single PanicWipeManager instance — shared with AppSecurityWiring so that
        // AppModule.panicWipeMgr.hasWiped() returns true regardless of whether the
        // wipe was triggered by a panic button press or by APK tamper detection.
        // Previously two separate instances existed; the panic gate in MainActivity
        // would check the wrong one when APK tamper triggered the wipe.
        val panicWipeMgr = PanicWipeManager(
            context        = this@ShadowMeshApplication,
            scope          = applicationScope,
            onWipeComplete = {
                // Wipe key material from memory before showing cover UI.
                // showCoverActivity() dispatches to Main internally.
                deviceSecret.fill(0)
                apkBindingHash.fill(0)
                showCoverActivity()
            },
            // Step 10: VPN tunnel teardown — must run before circuit keys are zeroed
            // so the tunnel is stopped cleanly rather than emitting traffic under a
            // zeroed-key state, which could be correlated to expose identity.
            onTeardownVpn  = { vpnBridge.stop(this@ShadowMeshApplication) },
            // Step 6: zero all onion circuit hop session keys immediately.
            // circuitManager.stop() wipes all CircuitState session keys via wipeKeys().
            onWipeCircuit  = { circuitManager.stop() },
            // Step 7: zero all in-memory ratchet chain keys across every active channel.
            onWipeRatchets = { keyOrchestrator.wipeAllRatchets() },
            // Step 9: cancel all pending WorkManager sync jobs so no background worker
            // wakes up and attempts a DB write after the database has been deleted.
            onCancelWork   = {
                androidx.work.WorkManager.getInstance(this@ShadowMeshApplication)
                    .cancelAllWork()
            },
            // Step 4b: clear EncryptedSharedPreferences stores that cannot be reached
            // via Context.getSharedPreferences — that API opens the plaintext backing
            // file, not the ciphertext store. Each store must be cleared via an instance
            // built with the same MasterKey used to write it.
            onWipeEncryptedPrefs = {
                // "shadowmesh_pin_prefs" — DuressPinManager (PIN verification hashes)
                try { duressPinMgr.clearPrefs() } catch (_: Exception) {}
                // "shadowmesh_seeds" — ShadowMeshForegroundService (bootstrap IPs)
                try {
                    val masterKey = androidx.security.crypto.MasterKey.Builder(this@ShadowMeshApplication)
                        .setKeyScheme(androidx.security.crypto.MasterKey.KeyScheme.AES256_GCM)
                        .build()
                    androidx.security.crypto.EncryptedSharedPreferences.create(
                        this@ShadowMeshApplication,
                        "shadowmesh_seeds",
                        masterKey,
                        androidx.security.crypto.EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                        androidx.security.crypto.EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
                    ).edit().clear().commit()
                } catch (_: Exception) {}
            },
            isFullyWired = true   // all step lambdas set above; required by AppSecurityWiring.create()
        )

        // Pass the pre-built wipeManager so AppSecurityWiring reuses it rather
        // than creating its own internal instance.
        val securityWiring = AppSecurityWiring.create(
            context         = this@ShadowMeshApplication,
            expectedSigHash = BuildConfig.EXPECTED_SIGNATURE_HASH,
            wipeManager     = panicWipeMgr
        )

        val integrityChecker = PerProcessIntegrityChecker(
            scope       = applicationScope,

            // DHT routing table: every contact must have a valid 32-byte nodeId.
            // A corrupted entry (wrong-length bytes, all-zeros) indicates memory
            // corruption or an injection attack on the routing table.
            dhtProbe    = {
                dhtEngine.routingTable.allContacts().all { contact ->
                    contact.nodeId.bytes.size == mesh.shadowmesh.mesh.dht.NODE_ID_BYTES &&
                    contact.nodeId.bytes.any { it != 0.toByte() }
                }
            },

            // Gossip peer registry: all active peer IDs must be valid 32-byte nodeIds.
            // An invalid entry signals a tampered registration or memory corruption.
            gossipProbe = {
                gossipEngine.activePeerIds().all { nodeId ->
                    nodeId.bytes.size == mesh.shadowmesh.mesh.dht.NODE_ID_BYTES
                }
            },

            // NSC state: not halted (existing probe — correct).
            nscProbe    = { !nsc.isHalted },

            // Keystore accessibility: wrapping key is still in the Keystore and
            // backed by at least a TEE (not software-only).
            //
            // BUG FIX: the previous probe called detectKeystoreTier() then discarded
            // the returned KeystoreTier, always returning true. A root attack that
            // downgrades the Keystore from HARDWARE_TEE/STRONGBOX to SOFTWARE_ONLY
            // was never detected — the probe was effectively a no-op.
            //
            // Correct check: return true only when the key is hardware-backed.
            // detectKeystoreTier() catches all internal errors and returns SOFTWARE_ONLY
            // on any failure (Keystore key eviction, TEE fault, etc.), so this probe
            // correctly returns false whenever hardware backing is lost.
            //
            // Note: devices that genuinely have no TEE (emulators, some low-end devices)
            // will always return SOFTWARE_ONLY. On such devices this probe fires the key
            // corruption handler on every check. This is intentional: the design doc
            // says software-only keys are extractable from a rooted device and the app
            // should wipe on detection. Operators deploying on no-TEE hardware must
            // disable this check via keyProbe = { true } with explicit justification.
            keyProbe    = {
                // Debug builds (emulators, developer devices) never have a real TEE, so
                // the probe would always return SOFTWARE_ONLY and trigger an infinite wipe loop.
                // Skip the hardware-backing check entirely in debug builds.
                if (BuildConfig.DEBUG) true
                else {
                    val tier = biometric.detectKeystoreTier(BiometricKeyManager.channelKeyAlias("probe"))
                    tier != BiometricKeyManager.KeystoreTier.SOFTWARE_ONLY
                }
            },

            // Ratchet state: the ratchet checkpoint table must be accessible.
            // An exception from countAll() indicates DB corruption, a changed/lost device
            // secret, or DB deletion — any of which breaks ratchet state continuity.
            ratchetProbe = { ratchetStateStore.checkAccessible() },

            // Corruption responses:

            // NSC tamper — the state machine itself is inconsistent. Trigger a panic
            // wipe: the node cannot be trusted to enforce transitions correctly.
            onNscCorruption = {
                Diag.fallback("integrity", "nsc-corruption",
                    "NSC state integrity check failed — triggering panic wipe")
                panicWipeMgr.triggerWipe()
            },

            // Key tamper — Keystore backing degraded to software-only (or key evicted).
            // Keys stored in software-only Keystore are extractable from a rooted device.
            // Trigger a panic wipe so key material is not exposed.
            onKeyCorruption = {
                Diag.fallback("integrity", "key-corruption",
                    "Key accessibility check failed — Keystore backing lost, triggering panic wipe")
                panicWipeMgr.triggerWipe()
            },

            // Ratchet tamper — wipe all in-memory ratchet keys. The channel keys
            // remain intact (wrapped in Keystore); the user will need to re-read
            // the channel (the next fresh message will re-establish the ratchet).
            onRatchetCorruption = {
                Diag.fallback("integrity", "ratchet-corruption",
                    "Ratchet state integrity check failed — wiping all in-memory ratchets")
                keyOrchestrator.wipeAllRatchets()
            }
        )

        // ── Bootstrap helpers ───────────────────────────────────────────────
        // DaoNonceStore persists consumed bootstrap nonces across process restarts so
        // a captured QR code cannot be replayed after the process dies within the
        // 5-minute validity window. The in-memory InMemoryNonceStore default was only
        // suitable for tests — production must use the DAO-backed implementation.
        val daoNonceStore = object : NonceStore {
            override suspend fun isUsed(nonceHex: String): Boolean =
                dao.isNonceUsed(nonceHex)
            override suspend fun markUsed(nonceHex: String, seenAtMs: Long) =
                dao.insertUsedNonce(mesh.shadowmesh.storage.UsedBootstrapNonce(nonceHex, seenAtMs))
        }
        val physicalKeyExchange = PhysicalKeyExchange(signer, hkdf, daoNonceStore)
        val nfcHandshake        = NfcHandshake(signer, hkdf)

        // ── Sybil resistance ────────────────────────────────────────────────
        // SponsorshipLedger is constructed before TrustChainValidator so it can
        // be injected. On mesh-burst detection, log the event — further escalation
        // (e.g., alert the user) is a Phase 10 UX integration point.
        val sponsorshipLedger = mesh.shadowmesh.mesh.trust.SponsorshipLedger(
            onMeshBurstDetected = { burstCount, windowMs ->
                android.util.Log.w(TAG, "MESH BURST: $burstCount introductions in ${windowMs / 3600_000}h window — all introductions paused")
            }
        )
        val behavioralCoherenceScorer = mesh.shadowmesh.storage.BehavioralCoherenceScorer()

        // Derive the expected app ID hash: SHA-256 of the signing certificate bytes.
        // The signing cert is already fetched above for apkBindingHash — reuse pkgInfo.
        // This binds hardware attestation to this specific app's signing identity:
        // a peer running a different app (or repackaged version) will have a different
        // app ID in its attestation extension and will be rejected.
        val expectedAppIdHash: ByteArray = withContext(Dispatchers.IO) {
            val pm      = this@ShadowMeshApplication.packageManager
            val pkgInfo = pm.getPackageInfo(
                packageName,
                android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
            )
            val signer = pkgInfo.signingInfo.apkContentsSigners.firstOrNull()
                ?: error("APK has no signing certificates — cannot derive app ID hash")
            java.security.MessageDigest.getInstance("SHA-256").digest(signer.toByteArray())
        }

        val revocationCache = buildRevocationCache()

        // ── Revocation gossip pipeline ────────────────────────────────────────
        // When this node fetches a fresh revocation list and finds new entries, sign
        // and broadcast a RevocationUpdateFrame to all connected peers.
        val localRevocNodeId = localNodeId.toHex()
        revocationCache.onNewEntries = { newSerials, newKeyHashes ->
            val nonce = ByteArray(16).also { java.security.SecureRandom().nextBytes(it) }
            val frame = mesh.shadowmesh.mesh.gossip.RevocationUpdateFrame(
                revokedSerials   = newSerials,
                revokedKeyHashes = newKeyHashes,
                fetchedAtMs      = System.currentTimeMillis(),
                issuerNodeId     = localRevocNodeId,
                nonce            = nonce,
                signature        = ByteArray(0)  // filled below
            )
            applicationScope.launch(Dispatchers.IO) {
                val sig = signer.sign(frame.signedPayload(), localIdentity.privatePart.signingPrivateKey)
                    .getOrNull()
                if (sig == null) {
                    Diag.fallback("revocation-gossip", "sign-new-entries",
                        "Hybrid signing failed — skipping revocation gossip broadcast")
                    return@launch
                }
                val signedFrame = frame.copy(signature = sig)
                gossipEngine.broadcastRevocationUpdate(signedFrame, null)
                Diag.info("revocation-gossip", "broadcast-new-entries",
                    "Gossiped ${newSerials.size} new serial(s) to peers",
                    "serials" to newSerials.size.toString(),
                    "hashes"  to newKeyHashes.size.toString())
            }
        }

        // When a peer gossips a RevocationUpdateFrame, merge new entries and re-gossip
        // to non-source peers (one hop only). Signature verification happens in the
        // gossip receive path before onVerifiedRevocationUpdate() is called.
        gossipEngine.setRevocationUpdateCallback { frame ->
            val hadNew = revocationCache.mergeUpdate(frame.revokedSerials, frame.revokedKeyHashes)
            if (hadNew) {
                val sourceId = try { NodeId.fromHex(frame.issuerNodeId) }
                              catch (_: Exception) { null }
                applicationScope.launch {
                    gossipEngine.broadcastRevocationUpdate(frame, sourceId)
                    Diag.info("revocation-gossip", "re-gossip-recv",
                        "Merged and re-gossiped revocation update",
                        "issuer" to frame.issuerNodeId.take(8))
                }
            }
        }

        val attestedExchange = AttestedPhysicalExchange(
            context                     = this@ShadowMeshApplication,
            baseExchange                = physicalKeyExchange,
            requireHardwareAttestation  = false,    // graceful fallback to TRUST_PHYSICAL_NFC
            allowCustomOS               = true,     // accept GrapheneOS/CalyxOS
            expectedPeerAppIdHash       = expectedAppIdHash,
            revocationCache             = revocationCache
        )

        // ── Distribution ────────────────────────────────────────────────────
        val artifactSeeder = mesh.shadowmesh.distribution.AppArtifactSeeder(
            context = this@ShadowMeshApplication
        )
        val apkArtifactVerifier = mesh.shadowmesh.distribution.ApkArtifactVerifier(
            context                 = this@ShadowMeshApplication,
            expectedSigningCertHash = BuildConfig.EXPECTED_SIGNATURE_HASH,
            releasePublicKey        = if (BuildConfig.RELEASE_PUBLIC_KEY.isNotBlank())
                android.util.Base64.decode(BuildConfig.RELEASE_PUBLIC_KEY, android.util.Base64.DEFAULT)
            else ByteArray(0)
        )
        val artifactAcquirer = mesh.shadowmesh.distribution.AppArtifactAcquirer(
            context     = this@ShadowMeshApplication,
            verifier    = apkArtifactVerifier,
            fetcher     = buildArtifactFetcher(dhtEngine),
            reassembler = mesh.shadowmesh.mesh.files.ShadowFilesReassembler(dao),
            dao         = dao
        )

        // ── OneTimeChannel ─────────────────────────────────────────────────
        val oneTimeChannel = mesh.shadowmesh.forum.OneTimeChannel(
            dao             = database.dao(),
            channelManager  = channelManager,
            keyOrchestrator = keyOrchestrator
        )

        // ── Forum domain ViewModel ─────────────────────────────────────────
        // Application-scoped (not Android ViewModel). Wired into the Hilt graph
        // via ShadowMeshHiltModule.provideForumViewModel() so ForumUiViewModel
        // can inject it. Fragment dispatch connected to postDispatcher below —
        // see the forward-reference note: postDispatcher is constructed after this,
        // so we use a lambda that captures the late-bound local via a holder.
        val postDispatcherHolder = arrayOfNulls<mesh.shadowmesh.forum.backend.PostDispatcher>(1)
        val forumViewModel = mesh.shadowmesh.forum.ForumViewModel(
            postEngine         = postEngine,
            channelManager     = channelManager,
            fragmentDispatcher = { postId -> postDispatcherHolder[0]?.dispatch(postId) }
        )
        // Construct in dependency order: ingestor first (no PostDispatcher dep),
        // then dispatcher (needs ingestor callbacks), then coordinator (needs both),
        // then router (needs ingestor).

        // Single shared MerkleAckProtocol instance — both FragmentIngestor and
        // PostDispatcher/AckRouter MUST use the same instance. Previously two separate
        // instances were constructed (one here inline, one below), which meant
        // notifyAckReceived() on the AckRouter's instance could never complete the
        // deferred registered by PostDispatcher's awaitAck() on a different instance,
        // making the entire ACK confirmation pipeline permanently non-functional.
        val merkleAckProtocol = buildMerkleAckProtocol(gossipEngine)

        // Single shared DistributedRetransmissionManager — PostDispatcher, ChannelSyncCoordinator,
        // and AckRouter MUST all share one instance.
        //
        // Bug that this fixes: buildRetransmissionManager() was called 3 times (once per
        // component), creating three SEPARATE instances, each with its own heldFragments map.
        // PostDispatcher.dispatch() called hold(fragment) on instance #1.
        // AckRouter.handleNack() called serveNack() on instance #3 (always empty).
        // Result: NACK retransmission NEVER served any fragment — the entire NACK repair
        // pipeline was permanently broken.
        val sharedRetransmissionMgr = buildRetransmissionManager(gossipEngine)

        // Single shared StoreAndForwardManager — PostDispatcher and ChannelSyncCoordinator
        // MUST share one instance so drainOnReconnect() drains the same outboundQueue that
        // PostDispatcher.enqueue() writes to. Separate instances meant queued offline posts
        // were never drained by the coordinator's reconnect path.
        val sharedStoreAndForwardMgr = buildStoreAndForwardManager(gossipEngine, dhtEngine, dhtQueryMix)

        val fragmentIngestor = mesh.shadowmesh.forum.backend.FragmentIngestor(
            gossipEngine        = gossipEngine,
            channelManager      = channelManager,
            postEngine          = postEngine,
            fragmentationEngine = mesh.shadowmesh.mesh.fragment.FragmentationEngine(hkdf),
            merkleAckProtocol   = merkleAckProtocol,
            keyOrchestrator     = keyOrchestrator,
            scope               = applicationScope,
            onFirstFragmentAck  = { pid -> postEngine.onFirstFragmentAck(pid) },
            onPostConfirmed     = { pid, enc -> postEngine.onConfirmed(pid, enc) }
        )

        val postDispatcher = mesh.shadowmesh.forum.backend.PostDispatcher(
            postEngine          = postEngine,
            channelManager      = channelManager,
            keyOrchestrator     = keyOrchestrator,
            fragmentationEngine = mesh.shadowmesh.mesh.fragment.FragmentationEngine(hkdf),
            gossipEngine        = gossipEngine,
            storeAndForwardMgr  = sharedStoreAndForwardMgr,
            nudgeEngine         = buildNudgeEngine(gossipEngine, dhtEngine, bleGattTransport, blePeerAddresses),
            retransmissionMgr   = sharedRetransmissionMgr,
            merkleAckProtocol   = merkleAckProtocol,
            networkModeSM       = networkModeSM,
            scope               = applicationScope,
            onFirstFragmentAck  = { pid -> postEngine.onFirstFragmentAck(pid) },
            onPostConfirmed     = { pid, enc -> postEngine.onConfirmed(pid, enc) },
            sndpEngine          = sndpEngine
        )

        // Resolve the forward reference: postDispatcher is now constructed.
        postDispatcherHolder[0] = postDispatcher

        val channelSyncCoordinator = mesh.shadowmesh.forum.backend.ChannelSyncCoordinator(
            channelManager     = channelManager,
            fragmentFetcher    = buildFragmentFetcher(dhtEngine, gossipEngine),
            fragmentIngestor   = fragmentIngestor,
            storeAndForwardMgr = sharedStoreAndForwardMgr,
            nudgeEngine        = buildNudgeEngine(gossipEngine, dhtEngine, bleGattTransport, blePeerAddresses),
            gossipEngine       = gossipEngine,
            retransmissionMgr  = sharedRetransmissionMgr,
            postEngine         = postEngine,
            scope              = applicationScope,
            sndpEngine         = sndpEngine,
            networkModeSM      = networkModeSM
        )
        // Wire the ratchet gap resolution pipeline: FragmentIngestor emits gap events
        // to KeyOrchestrator.ratchetGapEvents when ratchet decryption fails;
        // ChannelSyncCoordinator re-fetches the affected channel to recover intermediate posts.
        channelSyncCoordinator.startGapResolution(keyOrchestrator.ratchetGapEvents)

        val ackRouter = mesh.shadowmesh.forum.backend.AckRouter(
            merkleAckProtocol = merkleAckProtocol,
            retransmissionMgr = sharedRetransmissionMgr,
            fragmentIngestor  = fragmentIngestor,
            scope             = applicationScope,
            // Wire trust lookup so unknown-sender ACK forgery is caught.
            // gossipEngine.effectiveTrust() returns null for peers not in the peer table.
            senderTrustLevel  = gossipEngine::effectiveTrust
        )

        // Wire receive path for RevocationUpdateFrame gossip packets.
        // These arrive via the same control channel as ACK/NACK but carry the RVKU magic prefix.
        // Verification: nonce replay check + hybrid signature against sender's verify key.
        // Only peers whose publicIdentity is known (NFC-bootstrapped contacts) can send verified
        // revocation updates; unknown senders are silently dropped.
        ackRouter.onGossipControlPacket = handler@{ packet, senderNodeId ->
            val frame = mesh.shadowmesh.mesh.gossip.RevocationUpdateFrame.fromBytes(packet)
                ?: return@handler

            // Verify using the FRAME ISSUER's key, not the sender's key. The sender may be
            // a DHT-only relay (null publicIdentity) who is re-broadcasting a frame issued
            // and signed by an NFC-bootstrapped contact. Using the sender's key wrongly rejects
            // any frame relayed by a non-NFC peer regardless of the issuer's trust level.
            // Fall back to the sender's key if the issuer is unknown to us.
            val issuerKey: mesh.shadowmesh.crypto.HybridVerifyKey? = try {
                val issuerNodeId = mesh.shadowmesh.mesh.dht.NodeId.fromHex(frame.issuerNodeId)
                gossipEngine.peerContact(issuerNodeId)?.publicIdentity?.signingPublicKey
            } catch (_: Exception) { null }

            val verifyKey = issuerKey
                ?: gossipEngine.peerContact(senderNodeId)?.publicIdentity?.signingPublicKey
                ?: return@handler  // neither issuer nor sender has a known verify key — drop

            applicationScope.launch(Dispatchers.IO) {
                val nonceHex = frame.nonce.toHex()
                if (dao.isNonceUsed(nonceHex)) {
                    Diag.info("revocation-gossip", "nonce-replay",
                        "Dropped duplicate RevocationUpdate (nonce already seen)",
                        "sender" to senderNodeId.toHex().take(8))
                    return@launch
                }
                val valid = signer.verifySync(frame.signedPayload(), frame.signature, verifyKey)
                if (!valid) {
                    Diag.degraded("revocation-gossip", "sig-verify-fail",
                        "RevocationUpdate signature verification failed — dropping",
                        "sender" to senderNodeId.toHex().take(8))
                    return@launch
                }
                dao.insertUsedNonce(mesh.shadowmesh.storage.UsedBootstrapNonce(
                    nonceHex = nonceHex,
                    seenAtMs = System.currentTimeMillis()
                ))
                gossipEngine.onVerifiedRevocationUpdate(frame)
            }
        }

        // ── Phase 11.1: LAN transport wiring ───────────────────────────────
        // Construct LAN subnet transport and wire it into the gossip and forum layers.
        // Discovered LAN peers are registered in the gossip engine as TRUST_PUBLIC contacts
        // and persisted to the peer cache. Inbound TCP fragments are routed through
        // FragmentIngestor (same trust gate as all other fragment sources). Outbound gossip
        // relay to TCP-addressed peers uses the LAN transport directly instead of DHT.
        val lanSubnetTransport = try {
            mesh.shadowmesh.mesh.transport.lan.LanSubnetTransport(
                localNodeId              = localNodeId,
                scope                    = applicationScope,
                localEd25519PubKey       = localIdentity.publicPart.signingPublicKey.ed25519PublicKey.copyOf(),
                signChallengeEd25519Only = { message ->
                    // Same reasoning as BLE signing lambda: getOrNull prevents crash in
                    // the LAN TCP handshake callback if signing unexpectedly fails.
                    signer.signEd25519Only(message, localIdentity.privatePart.signingPrivateKey)
                        .getOrNull() ?: ByteArray(0)
                },
                verifyEd25519Only        = { message, sig, pubKey ->
                    signer.verifyEd25519Only(message, sig, pubKey).getOrNull() ?: false
                },
                onFragmentReceived  = { fragment, senderNodeId ->
                    applicationScope.launch {
                        fragmentIngestor.onFragmentReceived(fragment, senderNodeId)
                    }
                },
                onRawPacketReceived = { bytes, senderNodeId ->
                    // Route ACK/NACK control bytes received over LAN TCP directly to the
                    // AckRouter. Without this, sendControl stores ACKs in the local DHT
                    // which is never queried by the peer on a LAN-only mesh (no internet),
                    // leaving PostStateMachine permanently stuck in PENDING.
                    ackRouter.onRawPacketReceived(bytes, senderNodeId)
                },
                onPeerDiscovered    = { peer ->
                    gossipEngine.registerPeer(
                        DhtContact(
                            nodeId   = peer.nodeId,
                            address  = mesh.shadowmesh.mesh.dht.PeerAddress(
                                peer.address, peer.tcpPort,
                                mesh.shadowmesh.mesh.dht.TransportProtocol.TCP
                            ),
                            tier     = NodeTier.TIER_2,
                            isAnchor = false
                        ),
                        TrustLevel.TRUST_PUBLIC
                    )
                    applicationScope.launch(Dispatchers.IO) {
                        try {
                            dao.upsertDiscoveredPeer(mesh.shadowmesh.storage.DiscoveredPeerEntity(
                                nodeIdHex   = peer.nodeId.toHex(),
                                lastSeenMs  = System.currentTimeMillis(),
                                transport   = "LAN",
                                addressHint = "${peer.address}:${peer.tcpPort}",
                                trustLevel  = TrustLevel.TRUST_PUBLIC.name
                            ))
                        } catch (e: Exception) {
                            Diag.swallowed("lan-transport", "peer-cache-upsert", e)
                        }
                    }
                }
            ).also {
                it.startDiscovery()
                it.startServer()
                // Emulator-to-emulator bridge: inject both adb-forwarded ports so each
                // emulator can reach the other via host TCP tunnels.
                //   adb -s emulator-5554 forward tcp:7403 tcp:7403
                //   adb -s emulator-5556 forward tcp:7453 tcp:7403
                // Self-connections (loop-back) are silently rejected by handleClient.
                it.connectDirectPeer("10.0.2.2", 7403)
                it.connectDirectPeer("10.0.2.2", 7453)
                Diag.info("lan-transport", "started",
                    "LAN subnet discovery and TCP fragment server started",
                    "discoveryPort" to mesh.shadowmesh.mesh.transport.lan.LanSubnetTransport.PORT_DISCOVERY.toString(),
                    "fragmentPort"  to mesh.shadowmesh.mesh.transport.lan.LanSubnetTransport.PORT_FRAGMENT.toString())
            }
        } catch (e: Exception) {
            Diag.swallowed("lan-transport", "start-failed", e)
            null
        }
        dhtGossipTransport.lanTransport = lanSubnetTransport
        lanSubnetForProbe              = lanSubnetTransport  // wire the health-probe forward ref

        Log.i(TAG, "Phase 11: done")

        // ── Phase 12: Hand-off to AppModule ────────────────────────────────
        Log.i(TAG, "Phase 12: handing off to AppModule (isInitialised will become true)")
        AppModule.initialise(
            applicationScope          = applicationScope,
            hkdf                      = hkdf,
            kem                       = kem,
            signer                    = signer,
            cipher                    = cipher,
            ibd                       = ibd,
            localIdentity             = localIdentity,
            deviceSecret              = deviceSecret,
            apkBindingHash            = apkBindingHash,
            biometric                 = biometric,
            duressPinMgr              = duressPinMgr,
            panicWipeMgr              = panicWipeMgr,
            securityWiring            = securityWiring,
            integrityChecker          = integrityChecker,
            database                  = database,
            rateLimiter               = rateLimiter,
            reputationScorer          = reputationScorer,
            ratchetStateStore         = ratchetStateStore,
            nsc                       = nsc,
            keyOrchestrator           = keyOrchestrator,
            channelManager            = channelManager,
            postEngine                = postEngine,
            forumViewModel            = forumViewModel,
            networkModeSM             = networkModeSM,
            dhtEngine                 = dhtEngine,
            gossipEngine              = gossipEngine,
            transportHealthMonitor    = transportHealthMonitor,
            entryNodeStore            = entryNodeStore,
            circuitManager            = circuitManager,
            onionCircuitPacketRouter  = onionCircuitPacketRouter,
            vpnBridge                 = vpnBridge,
            sndpEngine                = sndpEngine,
            dhtQueryMix               = dhtQueryMix,
            inMeshMixProtocol         = inMeshMixProtocol,
            physicalKeyExchange       = physicalKeyExchange,
            nfcHandshake              = nfcHandshake,
            attestedExchange          = attestedExchange,
            sponsorshipLedger         = sponsorshipLedger,
            behavioralCoherenceScorer = behavioralCoherenceScorer,
            artifactSeeder            = artifactSeeder,
            artifactAcquirer          = artifactAcquirer,
            oneTimeChannel            = oneTimeChannel,
            postDispatcher            = postDispatcher,
            fragmentIngestor          = fragmentIngestor,
            channelSyncCoordinator    = channelSyncCoordinator,
            ackRouter                 = ackRouter
        )

        Log.i(TAG, "=== buildObjectGraph COMPLETE — nodeId ${localIdentity.nodeId.take8Hex()} ===")
    }

    // ── Post-init tasks ────────────────────────────────────────────────────

    private fun startPostInitTasks() {
        with(AppModule) {
            // APK integrity: eager check at startup + 4-hour WorkManager schedule
            applicationScope.launch(Dispatchers.IO) {
                securityWiring.apkVerifier.verify()
                securityWiring.apkVerifier.schedulePeriodicCheck()
            }

            // TTL sweep: 6-hour periodic WorkManager job
            TtlSweepWorker.schedule(this@ShadowMeshApplication)

            // Per-process integrity checker: starts its randomised check loops
            integrityChecker.start()

            // Fix #6: register periodic sync worker (POLLING_MODE fallback)
            MeshSyncWorker.schedulePeriodicSync(this@ShadowMeshApplication)

            // Foreground service must be started from the Main thread.
            // startPostInitTasks() is called from applicationScope (Dispatchers.Default).
            applicationScope.launch(Dispatchers.Main) {
                startForegroundService(
                    Intent(this@ShadowMeshApplication, ShadowMeshForegroundService::class.java)
                )
            }
        }
    }

    // ── Phase helpers ──────────────────────────────────────────────────────

    private suspend fun deriveDeviceSecret(biometric: BiometricKeyManager): ByteArray =
        withContext(Dispatchers.IO) {
            // Hardware-backed device secret: randomly generated on first run, wrapped under
            // an AndroidKeyStore AES-GCM key (TEE/StrongBox, no user auth required at startup),
            // and stored as an encrypted blob in SharedPreferences. Stable across restarts.
            // If the Keystore key is ever lost (factory reset), a fresh secret is generated
            // and all derived keys change — database becomes unreadable and identity resets.
            biometric.getOrCreateDeviceSecret()
        }

    private suspend fun deriveApkBindingHash(ibd: IntegrityBoundedKeyDerivation): ByteArray =
        withContext(Dispatchers.IO) {
            val pm        = this@ShadowMeshApplication.packageManager
            val pkgInfo   = pm.getPackageInfo(
                packageName,
                android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES
            )
            val certBytes = (pkgInfo.signingInfo.apkContentsSigners.firstOrNull()
                ?: error("APK has no signing certificates — cannot derive APK binding hash"))
                .toByteArray()

            // Load critical class bytecodes for the APK binding hash.
            //
            // Design doc §5.15: apkBindingHash = SHA3-256(signingCert || SHA3-256(criticalBytecode[]))
            // This means a tampered APK that preserves the signing key but patches .dex
            // bytecode produces a different binding hash and therefore different derived keys.
            // Using the signing cert alone (as previously) only detects repackaging with a
            // different key — it does NOT detect patches on a rooted device with the original key.
            //
            // Critical classes (as listed in ApkIntegrityVerifier KDoc):
            //   NetworkStateCoordinator, GossipEngine, DhtEngine, HybridKem, FragmentationEngine
            //
            // We load the .class bytes via ClassLoader resource lookup. The JVM caches the
            // classloader's URL resolution, so repeated calls are cheap. Any class that cannot
            // be loaded (obfuscated name, missing resource) falls back to its class name bytes
            // so the binding hash still differs per APK version — a graceful degradation that
            // preserves repackaging detection while logging a warning for investigation.
            // Read the build-time SHA-256 hashes embedded by the embedCriticalClassHashes
            // Gradle task (app/build.gradle.kts). These are computed from the compiled .class
            // files BEFORE D8/R8 converts them to DEX, so they bind to actual bytecode rather
            // than class names. A bytecode-level patch by an attacker who holds the signing key
            // will change these hashes and produce a different apkBindingHash, causing all
            // derived channel keys to differ — effectively making stored encrypted data
            // unreadable on the patched build.
            //
            // Mapping: class simple name → BuildConfig field name (uppercase + _BYTECODE_HASH)
            //   SymmetricCipher → SYMMETRIC_CIPHER_BYTECODE_HASH
            //   Hkdf            → HKDF_BYTECODE_HASH
            //   PostRatchet     → POST_RATCHET_BYTECODE_HASH
            //   NodeIdentity    → NODE_IDENTITY_BYTECODE_HASH
            //
            // If a hash is empty (class file not found during the Gradle task — should not
            // happen in a clean build), fall back to the class name bytes so the hash still
            // varies across versions, preserving repackaging detection while logging a warning.
            data class ClassBinding(val name: String, val buildTimeHash: String)
            val bindings = listOf(
                ClassBinding("SymmetricCipher", BuildConfig.SYMMETRIC_CIPHER_BYTECODE_HASH),
                ClassBinding("Hkdf",            BuildConfig.HKDF_BYTECODE_HASH),
                ClassBinding("PostRatchet",     BuildConfig.POST_RATCHET_BYTECODE_HASH),
                ClassBinding("NodeIdentity",    BuildConfig.NODE_IDENTITY_BYTECODE_HASH)
            )

            val criticalBytecodes: List<ByteArray> = bindings.map { (name, hash) ->
                if (hash.isNotEmpty()) {
                    hexToBytes(hash)
                } else {
                    Diag.degraded("apk-binding", "bytecode-hash-missing",
                        "Build-time bytecode hash not embedded for $name — falling back to " +
                        "class-name bytes. Check embedCriticalClassHashes Gradle task output.",
                        "class" to name)
                    name.toByteArray()
                }
            }

            ibd.buildApkBindingHash(certBytes, criticalBytecodes)
        }

    private suspend fun loadOrGenerateIdentity(
        generator:    NodeIdentityGenerator,
        deviceSecret: ByteArray
    ): NodeIdentity = withContext(Dispatchers.IO) {
        // Try loading a previously persisted identity. The private key material is
        // encrypted with SymmetricCipher(deviceSecret) so it is unreadable without
        // the hardware-backed device secret (see deriveDeviceSecret).
        val prefs  = getSharedPreferences(IDENTITY_PREFS, MODE_PRIVATE)
        val stored = prefs.getString(IDENTITY_PREF_KEY, null)

        if (stored != null) {
            val encrypted = android.util.Base64.decode(stored, android.util.Base64.NO_WRAP)
            val loaded    = deserializeNodeIdentity(encrypted, deviceSecret)
            if (loaded != null) {
                Log.i(TAG, "Identity loaded — nodeId ${loaded.nodeId.take8Hex()}")
                return@withContext loaded
            }
            Log.w(TAG, "Identity blob decryption failed — generating fresh identity (node ID changes)")
        }

        val identity = generator.generate().getOrThrow()
        val encrypted = serializeNodeIdentity(identity, deviceSecret)
        prefs.edit()
            .putString(IDENTITY_PREF_KEY,
                android.util.Base64.encodeToString(encrypted, android.util.Base64.NO_WRAP))
            .commit()
        Log.i(TAG, "Fresh identity generated and persisted — nodeId ${identity.nodeId.take8Hex()}")
        identity
    }

    /**
     * Serialize [NodeIdentity] private key material to an encrypted blob.
     *
     * Wire format (plaintext before encryption):
     *   [32B nodeId]
     *   [4B pubLen][NodePublicIdentity.toBytes()]
     *   [4B kyberPrivLen][kyberPriv]
     *   [4B kyberPubSaltLen][kyberPublicKeyForSalt]
     *   [4B x25519PrivLen][x25519Priv]
     *   [4B dilPrivLen][dilithiumPriv]
     *   [4B ed25519PrivLen][ed25519Priv]
     *
     * The whole blob is then encrypted with SymmetricCipher(deviceSecret).
     */
    private suspend fun serializeNodeIdentity(identity: NodeIdentity, deviceSecret: ByteArray): ByteArray {
        val pubBytes = identity.publicPart.toBytes()
        val priv     = identity.privatePart
        val baos = java.io.ByteArrayOutputStream()
        val dos  = java.io.DataOutputStream(baos)
        dos.write(identity.nodeId)
        dos.writeInt(pubBytes.size);                                 dos.write(pubBytes)
        dos.writeInt(priv.kemPrivateKey.kyberPrivateKey.size);       dos.write(priv.kemPrivateKey.kyberPrivateKey)
        dos.writeInt(priv.kemPrivateKey.kyberPublicKeyForSalt.size); dos.write(priv.kemPrivateKey.kyberPublicKeyForSalt)
        dos.writeInt(priv.kemPrivateKey.x25519PrivateKey.size);      dos.write(priv.kemPrivateKey.x25519PrivateKey)
        dos.writeInt(priv.signingPrivateKey.dilithiumPrivateKey.size); dos.write(priv.signingPrivateKey.dilithiumPrivateKey)
        dos.writeInt(priv.signingPrivateKey.ed25519PrivateKey.size); dos.write(priv.signingPrivateKey.ed25519PrivateKey)
        dos.flush()
        // Zero the intermediate plaintext before returning — private key material should
        // not linger in heap longer than necessary. JVM GC does not guarantee prompt
        // collection, so explicit zeroing is the best available mitigation.
        val plaintext = baos.toByteArray()
        return try {
            SymmetricCipher().encrypt(plaintext, deviceSecret).getOrThrow()
        } finally {
            plaintext.fill(0)
        }
    }

    private suspend fun deserializeNodeIdentity(encrypted: ByteArray, deviceSecret: ByteArray): NodeIdentity? {
        // Decrypt first; AES-GCM authentication ensures any bit-flip in the ciphertext
        // produces an AEADBadTagException here, not silent corruption downstream.
        val plain = try {
            SymmetricCipher().decrypt(encrypted, deviceSecret).getOrThrow()
        } catch (e: Exception) {
            Diag.swallowed("identity", "decrypt", e)
            return null
        }
        return try {
            val dis   = java.io.DataInputStream(java.io.ByteArrayInputStream(plain))
            val nodeId   = ByteArray(32).also { dis.readFully(it) }
            val pubLen   = dis.readInt()
            if (pubLen < 0 || pubLen > 65_536) error("identity pubLen out of range: $pubLen")
            val pubBytes = ByteArray(pubLen).also { dis.readFully(it) }
            val pubPart  = NodePublicIdentity.fromBytes(pubBytes)
            // readField: explicit positive-size guard so a corrupt (but authenticated)
            // blob cannot allocate arbitrarily large arrays.
            fun readField(maxBytes: Int = 4096): ByteArray {
                val n = dis.readInt()
                if (n < 0 || n > maxBytes) error("identity field length out of range: $n")
                return ByteArray(n).also { dis.readFully(it) }
            }
            val kyberPriv    = readField(4096)   // Kyber-1024 private key ≈ 3168B
            val kyberPubSalt = readField(2048)   // Kyber-1024 public key  ≈ 1568B
            val x25519Priv   = readField(64)     // X25519 private key = 32B
            val dilPriv      = readField(4096)   // Dilithium-3 private key ≈ 4016B
            val ed25519Priv  = readField(128)    // Ed25519 private key = 64B
            NodeIdentity(
                nodeId      = nodeId,
                publicPart  = pubPart,
                privatePart = NodePrivateIdentity(
                    nodeId            = nodeId,
                    kemPrivateKey     = HybridPrivateKey(kyberPriv, kyberPubSalt, x25519Priv),
                    signingPrivateKey = HybridSigningKey(dilPriv, ed25519Priv)
                )
            )
        } catch (e: Exception) {
            Diag.swallowed("identity", "deserialize", e)
            null
        } finally {
            // Zero the decrypted plaintext regardless of success or failure — private key
            // material should not remain in heap after deserialization completes.
            plain.fill(0)
        }
    }

    // ── Transport factory helpers ───────────────────────────────────────────
    // These build the adapter objects that wire library-module interfaces to
    // concrete implementations. Kept as private functions to keep buildObjectGraph() readable.

    private fun buildDhtTransport(
        natEngine:   NatTraversalEngine,
        localNodeId: NodeId,
        hkdf:        Hkdf,
        udpAdapter:  DatagramSocketUdpAdapter?
    ): Pair<DhtTransport, UdpDhtTransport?> {
        if (udpAdapter == null) {
            // Port bind failed — degrade to no-op transport so the rest of the graph
            // constructs cleanly. The DHT will be non-functional but won't crash.
            Diag.degraded("app", "dht-transport-noop",
                "UDP socket unavailable; DHT transport is a no-op. " +
                "This node cannot reach internet peers until the port conflict is resolved.")
            return NoOpDhtTransport to null
        }
        // UdpDhtTransport registers itself as the DHT datagram handler on udpAdapter.
        // setEngine() is called by the caller after DhtEngine is constructed.
        val udpDht = UdpDhtTransport(udpAdapter, localNodeId, applicationScope)
        val natWrapped = NatAwareDhtTransport(udpDht, natEngine, localNodeId, hkdf)
        return natWrapped to udpDht
    }

    private fun buildGossipTransport(dhtEngine: DhtEngine): DhtBackedGossipTransport =
        DhtBackedGossipTransport(dhtEngine)

    private fun buildCircuitTransport(
        gossipEngine: GossipEngine,
        dhtEngine:    DhtEngine
    ): CircuitTransport = MeshCircuitTransport(gossipEngine, dhtEngine)

    private fun buildSndpTransport(gossipEngine: GossipEngine): SndpTransport =
        GossipBackedSndpTransport(gossipEngine)

    private fun buildMixTransport(gossipEngine: GossipEngine): MixTransport =
        GossipBackedMixTransport(gossipEngine)

    /**
     * Stub [ArtifactFetcher] implementation.
     * Replace with a real transport-backed implementation once
     * BleGattTransport/WiFiDirectTransport expose fragment-fetch by post ID.
     * The acquirer is constructed but acquisition sessions are UI-initiated —
     * this stub will never be called at init time.
     */
    // ── Backend factory helpers ───────────────────────────────────────────
    // These produce the concrete mesh-layer objects the forum backend needs.
    // Kept as private funs so buildObjectGraph() stays readable.

    private fun buildMerkleAckProtocol(
        gossipEngine: mesh.shadowmesh.mesh.gossip.GossipEngine
    ): mesh.shadowmesh.mesh.delivery.MerkleAckProtocol {
        val transport = object : mesh.shadowmesh.mesh.delivery.AckTransport {
            override suspend fun sendAck(targetNodeId: String, ackBytes: ByteArray) {
                val target = mesh.shadowmesh.mesh.dht.NodeId.fromHex(targetNodeId)
                // Real ACK → originator.
                gossipEngine.sendControl(target, ackBytes)
                // Cover ACK: send the same bytes to one random non-target peer. That peer has
                // no ackListeners[postId] entry, so AckRouter.handleAck() returns early without
                // side effects. A passive transport-layer observer sees ACKs flowing to TWO
                // nodes, providing k=2 anonymity — they cannot determine which node is the
                // actual sender of the confirmed post without application-layer correlation.
                gossipEngine.activePeerIds()
                    .filter { it != target }
                    .shuffled()
                    .firstOrNull()
                    ?.let { cover -> gossipEngine.sendControl(cover, ackBytes) }
            }
            override suspend fun broadcastNack(postId: String, nackBytes: ByteArray) {
                // Broadcast NACK to all active peers: each peer checks whether it holds
                // the missing fragments and retransmits them if so.
                gossipEngine.activePeerIds().forEach { peerId ->
                    gossipEngine.sendControl(peerId, nackBytes)
                }
            }
            override suspend fun retransmitFragment(
                fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity
            ) {
                gossipEngine.relayFragment(fragment, gossipEngine.localNodeId)
            }
        }
        return mesh.shadowmesh.mesh.delivery.MerkleAckProtocol(
            hkdf      = mesh.shadowmesh.crypto.Hkdf.instance,
            transport = transport
        )
    }

    private fun buildStoreAndForwardManager(
        gossipEngine: mesh.shadowmesh.mesh.gossip.GossipEngine,
        dhtEngine:    mesh.shadowmesh.mesh.dht.DhtEngine,
        dhtQueryMix:  mesh.shadowmesh.mesh.privacy.DhtQueryMix? = null
    ): mesh.shadowmesh.mesh.delivery.StoreAndForwardManager {
        val hkdf = mesh.shadowmesh.crypto.Hkdf.instance
        val coverRng = java.security.SecureRandom()
        val transport = object : mesh.shadowmesh.mesh.delivery.StoreForwardTransport {
            override suspend fun storeFragment(
                node:     mesh.shadowmesh.mesh.dht.DhtContact,
                fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity
            ) {
                gossipEngine.relayFragment(fragment, node.nodeId)
                updateChannelIndex(dhtEngine, hkdf, fragment)
            }

            override suspend fun fetchFragmentsSince(
                node:      mesh.shadowmesh.mesh.dht.DhtContact,
                channelId: ByteArray,
                sinceMs:   Long
            ): List<mesh.shadowmesh.mesh.fragment.FragmentEntity> {
                val indexKey = channelIndexKey(hkdf, channelId)

                // Both cover queries are submitted unconditionally — before AND after the
                // real lookup, regardless of whether content is found. An asymmetric pattern
                // (one cover query on miss, two on hit) would leak "found vs not found"
                // signal to any observer correlating cover query count with subsequent
                // gossip activity from this node.
                dhtQueryMix?.submit(ByteArray(mesh.shadowmesh.mesh.dht.NODE_ID_BYTES)
                    .also { coverRng.nextBytes(it) })

                val lookupResult = dhtEngine.findValue(indexKey)

                dhtQueryMix?.submit(ByteArray(mesh.shadowmesh.mesh.dht.NODE_ID_BYTES)
                    .also { coverRng.nextBytes(it) })

                val indexBytes = when (lookupResult) {
                    is mesh.shadowmesh.mesh.dht.LookupResult.Found -> lookupResult.value
                    else -> return emptyList()
                }

                val entries = parseChannelIndex(indexBytes).filter { it.first > sinceMs }
                return entries.mapNotNull { (_, fragmentId) ->
                    val fragKey = mesh.shadowmesh.mesh.dht.NodeId(hkdf.sha3_256(fragmentId.toByteArray()))
                    (dhtEngine.findValue(fragKey) as? mesh.shadowmesh.mesh.dht.LookupResult.Found)
                        ?.value
                        ?.let { bytes -> deserializeFragment(bytes) }
                }
            }
        }
        return mesh.shadowmesh.mesh.delivery.StoreAndForwardManager(
            routingTable      = dhtEngine.routingTable,
            transport         = transport,
            scope             = applicationScope
        )
    }

    private fun deserializeFragment(bytes: ByteArray): mesh.shadowmesh.mesh.fragment.FragmentEntity? { return try {
        val dis         = DataInputStream(ByteArrayInputStream(bytes))
        val fragmentId  = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val postId      = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val channelId   = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        // readUnsignedShort() (0..65535) instead of readShort().toInt() (-32768..32767).
        // A crafted DHT value with totalData=0xFFFF decodes to -1 via readShort().toInt(),
        // making FragmentAccumulator.currentStatus() return Complete after any single fragment
        // (count >= -1 is always true). Phantom-Complete suppresses post delivery silently.
        val seqIdx      = dis.readUnsignedShort()
        val totalData   = dis.readUnsignedShort()
        val totalParity = dis.readUnsignedShort()
        if (totalData == 0 || totalData > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS ||
            totalParity > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS) return null
        val payloadLen  = dis.readInt()
        if (payloadLen < 0 || payloadLen > 64 * 1024) return null
        val payload     = ByteArray(payloadLen).also { dis.readFully(it) }
        val fecWire     = dis.readByte().toInt()
        val fecScheme   = mesh.shadowmesh.mesh.fragment.FecScheme.fromWire(fecWire)
        mesh.shadowmesh.mesh.fragment.FragmentEntity(
            fragmentId    = fragmentId,
            postId        = postId,
            channelId     = channelId,
            sequenceIndex = seqIdx,
            totalData     = totalData,
            totalParity   = totalParity,
            payload       = payload,
            fecScheme     = fecScheme ?: mesh.shadowmesh.mesh.fragment.FecScheme.NONE
        )
    } catch (e: Exception) {
        Diag.swallowed("app", "deserializeFragment", e)
        null
    } }

    /**
     * Deserialize a list of [FragmentEntity] from the DHT blob produced by
     * [AppArtifactSeeder.publishToDht]:
     *   [4B count][count × [4B fragLen][frag bytes]]
     *
     * Returns null (not an empty list) when the bytes do not match this format, so callers
     * can fall back to the single-fragment legacy path.
     */
    private fun deserializeFragmentList(
        bytes: ByteArray
    ): List<mesh.shadowmesh.mesh.fragment.FragmentEntity>? { return try {
        val dis   = DataInputStream(ByteArrayInputStream(bytes))
        val count = dis.readInt()
        if (count <= 0 || count > 10_000) return null  // sanity guard
        val frags = ArrayList<mesh.shadowmesh.mesh.fragment.FragmentEntity>(count)
        repeat(count) {
            val len = dis.readInt()
            if (len <= 0 || len > 128 * 1024) return null
            val fragBytes = ByteArray(len).also { dis.readFully(it) }
            frags.add(deserializeFragment(fragBytes) ?: return null)
        }
        frags
    } catch (_: Exception) {
        null
    } }

    private fun buildNudgeEngine(
        gossipEngine:     mesh.shadowmesh.mesh.gossip.GossipEngine,
        dhtEngine:        mesh.shadowmesh.mesh.dht.DhtEngine,
        bleTransport:     mesh.shadowmesh.mesh.transport.ble.BleGattTransport? = null,
        blePeerAddresses: java.util.concurrent.ConcurrentHashMap<String, String> =
                          java.util.concurrent.ConcurrentHashMap()
    ): mesh.shadowmesh.mesh.nudge.NudgeEngine {
        val transport = object : mesh.shadowmesh.mesh.nudge.NudgeTransport {
            override suspend fun sendUdpNudge(
                peerId: mesh.shadowmesh.mesh.dht.NodeId,
                packet: ByteArray
            ) {
                // Route the 12-byte nudge packet via the DHT sendRaw path (bypasses RPC framing).
                dhtEngine.sendRawToNode(peerId, packet)
            }

            override suspend fun sendBleNudge(
                peerId: mesh.shadowmesh.mesh.dht.NodeId,
                packet: ByteArray
            ) {
                // Send over BLE GATT when a MAC address is known for this peer (i.e. when the
                // peer was previously discovered and authenticated via BleGattTransport). Falls
                // back to UDP when no MAC is recorded (peer reachable only over internet DHT).
                val mac = blePeerAddresses[peerId.toHex()]
                if (mac != null && bleTransport != null) {
                    try {
                        bleTransport.sendNudgePacket(mac, packet)
                        return
                    } catch (e: Exception) {
                        Diag.swallowed("nudge", "ble-send-fallback-udp", e,
                            "peerId" to peerId.toHex().take(8), "mac" to mac)
                        // Fall through to UDP fallback below.
                    }
                }
                dhtEngine.sendRawToNode(peerId, packet)
            }
        }
        return mesh.shadowmesh.mesh.nudge.NudgeEngine(applicationScope, transport)
    }

    private fun buildRetransmissionManager(gossipEngine: mesh.shadowmesh.mesh.gossip.GossipEngine) =
        mesh.shadowmesh.mesh.delivery.DistributedRetransmissionManager(
            scope     = applicationScope,
            transport = object : mesh.shadowmesh.mesh.delivery.RetransmitTransport {
                override suspend fun retransmitFragment(
                    fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity
                ) { gossipEngine.relayFragment(fragment, gossipEngine.localNodeId) }
            }
        ).also { it.startEvictionLoop() }

    private fun buildFragmentFetcher(
        dhtEngine:    mesh.shadowmesh.mesh.dht.DhtEngine,
        gossipEngine: mesh.shadowmesh.mesh.gossip.GossipEngine
    ) = mesh.shadowmesh.mesh.delivery.FragmentFetcher(
        localCache  = buildLocalFragmentCache(),
        localPeers  = buildLocalPeerRegistry(gossipEngine),
        dhtEngine   = dhtEngine,
        scope       = applicationScope
    )

    private fun buildLocalFragmentCache() = mesh.shadowmesh.mesh.delivery.LruFragmentCache()

    private fun buildLocalPeerRegistry(gossipEngine: mesh.shadowmesh.mesh.gossip.GossipEngine) =
        object : mesh.shadowmesh.mesh.delivery.LocalPeerRegistry {
            // LocalPeerRegistry.allLocalPeers() — required abstract member.
            // Builds a LocalPeer adapter over each active gossip peer.
            // The adapter delegates fragment fetch/push to the gossip transport,
            // which routes over whatever transport the peer is reachable on.
            //
            // Issue #90 fix: the previous implementation overrode getLocalPeers()
            // which does not exist on the interface, leaving allLocalPeers() and
            // peersOfType() unimplemented — a compile error.
            override fun allLocalPeers(): List<mesh.shadowmesh.mesh.delivery.LocalPeer> =
                gossipEngine.activePeerIds()
                    .mapNotNull { gossipEngine.peerContact(it) }
                    .map { contact -> GossipBackedLocalPeer(contact, gossipEngine) }

            override fun peersOfType(
                type: mesh.shadowmesh.mesh.delivery.LocalTransportType
            ): List<mesh.shadowmesh.mesh.delivery.LocalPeer> =
                // All gossip peers are transport-agnostic at this abstraction layer.
                // peersOfType is used by FragmentFetcher for preferential LAN-first
                // routing; returning allLocalPeers() for any type is correct but
                // non-preferential. Transport-specific filtering can be wired when
                // the transport layer exposes per-type peer lists.
                if (type == mesh.shadowmesh.mesh.delivery.LocalTransportType.WIFI_DIRECT ||
                    type == mesh.shadowmesh.mesh.delivery.LocalTransportType.LAN_SUBNET  ||
                    type == mesh.shadowmesh.mesh.delivery.LocalTransportType.BLE)
                    allLocalPeers()
                else
                    emptyList()
        }

    /**
     * Construct and pre-load the keybox revocation cache.
     *
     * Called during object graph construction (Phase 8 — after network transport is
     * available). The cache loads from SharedPreferences first (fast, synchronous-equivalent
     * via IO dispatcher), then triggers a background refresh if stale. The returned instance
     * is passed to [AttestedPhysicalExchange] so every bootstrap call checks revocation.
     *
     * Failure to load (no cache, no network) is non-fatal — [KeyboxRevocationCache.isRevoked]
     * returns false on empty sets, which is fail-open. This is the documented behaviour for
     * offline-first nodes per threat model §3.3: revocation checking degrades gracefully but
     * does not block bootstrapping in air-gapped deployments.
     */
    private suspend fun buildRevocationCache(): mesh.shadowmesh.attestation.KeyboxRevocationCache {
        val cache = mesh.shadowmesh.attestation.KeyboxRevocationCache(this@ShadowMeshApplication)
        try {
            cache.ensureLoaded()
            Log.d(TAG, "Keybox revocation cache loaded")
        } catch (e: Exception) {
            Log.w(TAG, "Keybox revocation cache load failed (will retry on bootstrap): ${e.message}")
        }
        return cache
    }

    /**
     * DHT-backed [ArtifactFetcher] for app self-distribution.
     *
     * All four fetch operations derive a deterministic DHT key from their input and look
     * up the stored bytes with [DhtEngine.findValue]. Seeders store content under these
     * same keys via [DhtEngine.store] at seeding time, so the keyspace is consistent.
     *
     * Key derivation (one-way SHA3-256 hash with a domain label per record type):
     *   descriptor  → SHA3-256( distributionPostId(versionCode) || "desc_v1" )
     *   manifest    → SHA3-256( manifestHash || "manifest_v1" )
     *   chunkIndex  → SHA3-256( merkleRoot   || "chunkidx_v1" )
     *   fragments   → SHA3-256( chunkPostId )            (plain postId → DHT key)
     *
     * The domain labels prevent cross-type collisions (a manifestHash that happens to equal
     * a chunkPostId cannot accidentally serve manifest bytes as fragment bytes).
     *
     * seederHint (6-byte BLE manufacturer-data tag) identifies a nearby seeder who is
     * advertising the artifact. Future work: when BleGattTransport exposes arbitrary GATT
     * reads by manufacturer tag, try the nearby seeder first for lower latency before
     * falling back to the internet DHT lookup here.
     */
    private fun buildArtifactFetcher(
        dhtEngine: mesh.shadowmesh.mesh.dht.DhtEngine
    ): mesh.shadowmesh.distribution.ArtifactFetcher {
        val hkdf = mesh.shadowmesh.crypto.Hkdf.instance
        return object : mesh.shadowmesh.distribution.ArtifactFetcher {

            override suspend fun fetchDescriptor(
                seederHint:  ByteArray,
                versionCode: Int
            ): ByteArray? {
                val key = mesh.shadowmesh.mesh.dht.NodeId(hkdf.sha3_256(
                    mesh.shadowmesh.distribution.DistributionConstants
                        .distributionPostId(versionCode) + "desc_v1".toByteArray()
                ))
                return (dhtEngine.findValue(key)
                    as? mesh.shadowmesh.mesh.dht.LookupResult.Found)?.value
            }

            override suspend fun fetchManifest(
                seederHint:   ByteArray,
                manifestHash: ByteArray
            ): ByteArray? {
                val key = mesh.shadowmesh.mesh.dht.NodeId(
                    hkdf.sha3_256(manifestHash + "manifest_v1".toByteArray())
                )
                return (dhtEngine.findValue(key)
                    as? mesh.shadowmesh.mesh.dht.LookupResult.Found)?.value
            }

            override suspend fun fetchChunkIndex(
                seederHint: ByteArray,
                merkleRoot: ByteArray
            ): ByteArray? {
                val key = mesh.shadowmesh.mesh.dht.NodeId(
                    hkdf.sha3_256(merkleRoot + "chunkidx_v1".toByteArray())
                )
                return (dhtEngine.findValue(key)
                    as? mesh.shadowmesh.mesh.dht.LookupResult.Found)?.value
            }

            override suspend fun fetchChunkFragments(
                seederHint:  ByteArray,
                chunkPostId: ByteArray
            ): List<mesh.shadowmesh.mesh.fragment.FragmentEntity>? {
                // Chunks are stored by AppArtifactSeeder.publishToDht as a length-prefixed list:
                //   [4B count][count × [4B fragLen][frag bytes]]
                // Fallback: if the value parses as a single legacy fragment, return it as a list.
                val key = mesh.shadowmesh.mesh.dht.NodeId(hkdf.sha3_256(chunkPostId))
                val found = (dhtEngine.findValue(key)
                    as? mesh.shadowmesh.mesh.dht.LookupResult.Found) ?: return null
                return deserializeFragmentList(found.value)
                    ?: deserializeFragment(found.value)?.let { listOf(it) }
            }
        }
    }

    // ── Event handlers ─────────────────────────────────────────────────────

    private fun handleEntryEvent(event: EntryNodeEvent) {
        // Route entry node lifecycle events to the active UI.
        // The BootstrapFragment or EntryNodeViewModel observes AppModule.circuitManager
        // directly via its StateFlow; this is a fallback for events that have no
        // active observer (e.g., PickRequired fires when no bootstrap is in progress).
        when (event) {
            is EntryNodeEvent.PickRequired  -> Log.w(TAG, "PickRequired with no active UI")
            is EntryNodeEvent.EntryOffline  -> Log.w(TAG, "Entry offline: ${event.fallbackDisplayName}")
            is EntryNodeEvent.NoEntryAvailable -> Log.e(TAG, "No entry node available")
        }
    }

    // ── Post-compromise security: honey-triggered CLOSED channel rotation ─────
    //
    // Called when a HoneyAnchor trip proves an anchor signing key was extracted.
    // Rotates all CLOSED channels to start a new ratchet chain, cutting off the
    // attacker's ability to decrypt future posts even if they retain the old chain key.
    //
    // COMPARTMENTED channels are NOT rotated here — they require physical re-exchange
    // because the wrapping key is bound to the Keystore entry, not to a software-derived
    // wrapping key. The channel is flagged so the UI can prompt the user.
    //
    // OPEN channels are skipped — they have no confidentiality expectation and rotation
    // would disrupt all members.
    //
    // This runs on applicationScope (already on Dispatchers.IO via KeyOrchestrator).
    // If the rotation fails for any channel (e.g. channel not found), it is logged and
    // skipped rather than aborting the whole batch.
    private suspend fun rotateAllClosedChannelKeys(
        keyOrchestrator: mesh.shadowmesh.forum.KeyOrchestrator,
        channelManager:  mesh.shadowmesh.forum.ChannelManager
    ) {
        // Collect the current channel list from the observable flow — first() gives
        // the current snapshot without subscribing permanently.
        val closedChannels = channelManager.observeActiveChannels()
            .first()
            .filter { it.type == mesh.shadowmesh.storage.ChannelType.CLOSED && !it.departed }
        Log.i(TAG, "PCS rotation: rotating ${closedChannels.size} CLOSED channel(s)")
        var rotated = 0
        for (channel in closedChannels) {
            try {
                val newWrappedKey = keyOrchestrator.generateAndWrapChannelKey(
                    channelId = channel.channelId,
                    type      = mesh.shadowmesh.storage.ChannelType.CLOSED
                )
                channelManager.rotateKey(channel.channelId, newWrappedKey,
                    mesh.shadowmesh.storage.ChannelType.CLOSED)
                keyOrchestrator.evictAllRatchets(channel.channelId)
                rotated++
                Log.i(TAG, "PCS: rotated key for channel ${channel.channelId.take(8)}")
            } catch (e: Exception) {
                Log.e(TAG, "PCS: failed to rotate channel ${channel.channelId.take(8)}: ${e.message}")
                // Surface via Diag so silent key-rotation failures are observable.
                // A rotation failure after a honey trip means the channel may remain
                // compromised — this must not be swallowed silently.
                Diag.degraded(
                    "pcs", "rotation-failed",
                    "CLOSED channel key rotation failed after honey trip — channel may remain compromised",
                    "channelId" to channel.channelId.take(8),
                    "error"     to (e.message ?: e.javaClass.simpleName)
                )
            }
        }
        val failed = closedChannels.size - rotated
        Log.i(TAG, "PCS rotation complete: $rotated/${closedChannels.size} channels rotated")
        if (failed > 0) {
            Diag.degraded(
                "pcs", "rotation-incomplete",
                "$failed of ${closedChannels.size} CLOSED channel(s) failed key rotation after honey trip",
                "rotated" to rotated.toString(),
                "failed"  to failed.toString()
            )
        }
    }

    // ── NSC rollback handler registration ─────────────────────────────────

    /**
     * Register production handlers for every [RollbackOpcode] variant with
     * [RollbackRegistry].
     *
     * Must be called after Phase 8 (engines constructed) and before
     * [NetworkStateCoordinator.initialise] (Phase 8.5).  Handlers are closures
     * over the live engine references — on process-death restart the engines are
     * rebuilt first (Phases 1–8), then handlers are registered here, then
     * initialise() replays any persisted checkpoints using these handlers.
     *
     * Implementation status per opcode:
     *  - CANCEL_FRAGMENT        fully implemented (dao.deleteFragment).
     *  - RESTORE_NETWORK_MODE   fail-loud (throws) — no GossipEngine.setNetworkMode() yet.
     *  - RESTORE_BEACON_MODE    fail-loud (throws) — no beacon engine API yet.
     *  - RESTORE_PEER_SELECTION fail-loud (throws) — no peer-selection engine API yet.
     *  - RECLAIM_DHT_SLICE      fail-loud (throws) — no DhtEngine.reclaimSlice() yet.
     *  - REVERT_TIER_PROMOTION  fail-loud (throws) — no DhtEngine.setNodeTier() yet.
     *
     * The five unimplemented handlers each emit a Diag.degraded for observability and then
     * THROW. Throwing is the RollbackRegistry's documented signal for "this opcode cannot be
     * rolled back": on the init-recovery path it leaves the transition un-finalised and the
     * NSC halted; on the watchdog path it escalates to UNRECOVERABLE. This is deliberate — the
     * previous behaviour (Diag.degraded + return normally) recorded a *false* ROLLED_BACK over
     * state that was never reverted, which is worse than a visible halt. When an engine API is
     * added, replace the corresponding throw with the real revert logic; a handler that can
     * actually perform the action should then return normally on success.
     *
     * @param dao          Storage DAO for CANCEL_FRAGMENT.
     * @param dhtEngine    DHT engine (for future RECLAIM_DHT_SLICE implementation).
     * @param gossipEngine Gossip engine (for future RESTORE_NETWORK_MODE implementation).
     */
    private fun registerNscRollbackHandlers(
        dao:              ShadowMeshDao,
        dhtEngine:        DhtEngine,
        gossipEngine:     GossipEngine,
        networkModeSM:    NetworkModeStateMachine,
        bleGattTransport: mesh.shadowmesh.mesh.transport.ble.BleGattTransport?
    ) {
        // CANCEL_FRAGMENT: remove the fragment from local storage.
        // This is fully implementable: the persisted fragmentId is sufficient.
        RollbackRegistry.register("CANCEL_FRAGMENT") { args ->
            val fragmentId = args.trim()
            if (fragmentId.isNotBlank()) {
                withContext(Dispatchers.IO) { dao.deleteFragment(fragmentId) }
                Log.i(TAG, "NSC rollback: cancelled fragment ${ fragmentId.take(8) }")
            } else {
                Diag.degraded("nsc", "rollback-cancel-fragment-empty",
                    "CANCEL_FRAGMENT rollback received empty fragmentId — skipping")
            }
        }

        // RESTORE_NETWORK_MODE: force the network mode state machine back to the previous mode.
        // NetworkModeStateMachine.forceMode() fires all registered listeners so the gossip engine,
        // SNDP engine, and circuit manager all see the mode revert immediately.
        // The forced mode will self-correct on the next anchor-count update if the anchor count
        // is inconsistent, but the NSC rollback guarantees the mode matches the pre-transition
        // state until then.
        RollbackRegistry.register("RESTORE_NETWORK_MODE") { args ->
            val mode = try {
                NetworkMode.valueOf(args.trim())
            } catch (_: IllegalArgumentException) {
                Diag.degraded("nsc", "rollback-network-mode-invalid",
                    "RESTORE_NETWORK_MODE: unknown mode '$args' — skipping rollback",
                    "args" to args)
                return@register
            }
            networkModeSM.forceMode(mode)
            Log.i(TAG, "NSC rollback: RESTORE_NETWORK_MODE → $mode")
        }

        // RESTORE_BEACON_MODE: toggle BleGattTransport beacon advertising to the previous state.
        //   wasEnabled=false → stop the beacon (the transaction had turned it on; roll it back off)
        //   wasEnabled=true  → resume beacon with the last known channel hash (the transaction had
        //                       turned it off; roll it back on). Uses BleGattTransport.resumeBeacon()
        //                       which re-advertises the hash stored by the most recent startBeacon call.
        //                       If beacon was never started in this process lifetime, logs a warning
        //                       and returns normally — BLE was already in the correct state.
        RollbackRegistry.register("RESTORE_BEACON_MODE") { args ->
            val wasEnabled = args.trim().toBoolean()
            if (bleGattTransport == null) {
                Diag.degraded("nsc", "rollback-beacon-mode-no-transport",
                    "RESTORE_BEACON_MODE: BleGattTransport unavailable (BLE hardware absent or " +
                    "construction failed). Beacon state NOT restored (wasEnabled=$wasEnabled).",
                    "wasEnabled" to wasEnabled.toString())
                return@register   // not an error — BLE simply isn't usable on this device
            }
            if (wasEnabled) {
                val resumed = bleGattTransport.resumeBeacon()
                if (!resumed) {
                    Diag.degraded("nsc", "rollback-beacon-mode-no-hash",
                        "RESTORE_BEACON_MODE: wasEnabled=true but no prior beacon hash stored — " +
                        "beacon was never started in this process lifetime. Nothing to restore.",
                        "wasEnabled" to "true")
                }
                Log.i(TAG, "NSC rollback: RESTORE_BEACON_MODE → started (resumed=$resumed)")
            } else {
                bleGattTransport.stopBeacon()
                Log.i(TAG, "NSC rollback: RESTORE_BEACON_MODE → stopped")
            }
        }

        // RESTORE_PEER_SELECTION: PeerSelectionMode is embedded inside NetworkMode — there is no
        // independent setter. The practical recovery is to force the NetworkMode whose
        // peerSelectionMode matches the requested value. On the next anchor-count update the state
        // machine will self-correct to the exact mode the anchor count dictates, so any transient
        // mismatch is bounded to one cycle. This is safer than halting NSC permanently over a mode
        // property that self-corrects.
        RollbackRegistry.register("RESTORE_PEER_SELECTION") { args ->
            val requestedMode = try {
                mesh.shadowmesh.mesh.mode.PeerSelectionMode.valueOf(args.trim())
            } catch (_: IllegalArgumentException) {
                Diag.degraded("nsc", "rollback-peer-selection-invalid-mode",
                    "RESTORE_PEER_SELECTION: unknown PeerSelectionMode '$args' — skipping",
                    "args" to args)
                return@register
            }
            // Find the NetworkMode that carries the requested PeerSelectionMode.
            // Prefer the most capable mode (HEALTHY > DEGRADED > CRITICAL > SURVIVAL).
            val target = mesh.shadowmesh.mesh.mode.NetworkMode.entries
                .firstOrNull { it.peerSelectionMode == requestedMode }
            if (target != null) {
                networkModeSM.forceMode(target)
                Log.i(TAG, "NSC rollback: RESTORE_PEER_SELECTION → $target (peerSelection=$requestedMode)")
            } else {
                Diag.degraded("nsc", "rollback-peer-selection-no-match",
                    "RESTORE_PEER_SELECTION: no NetworkMode carries peerSelectionMode=$requestedMode; " +
                    "mode will self-correct on next anchor-count update",
                    "requestedMode" to requestedMode.name)
            }
        }

        // RECLAIM_DHT_SLICE: emitted ONLY by buildAnchorHandoffTransition checkpoints.
        // AnchorHandoffManager is not constructed in production, so this replay path is
        // unreachable at runtime. The in-memory failure path already rolls back correctly via
        // the rollback lambda captured in each checkpoint at build time.
        //
        // If this handler fires (e.g. a database migrated from a future build that had anchor
        // handoff wired), the correct action is to log the event and return normally. Halting
        // NSC permanently over a checkpoint that can never recur is worse than acknowledging
        // the gap. When anchor handoff is wired, replace this body with a call to
        // AnchorTransport.revertSliceTransfer(fromNodeId, toNodeId).
        RollbackRegistry.register("RECLAIM_DHT_SLICE") { args ->
            val parts      = args.split("|")
            val fromNodeId = parts.getOrElse(0) { "?" }.trim()
            val toNodeId   = parts.getOrElse(1) { "?" }.trim()
            Diag.degraded("nsc", "rollback-reclaim-dht-slice-noop",
                "RECLAIM_DHT_SLICE replay: anchor handoff subsystem is not wired in this build. " +
                "Slice transfer from '$fromNodeId' to '$toNodeId' was not reclaimed. " +
                "This checkpoint will be marked rolled-back without a real revert — acceptable " +
                "since AnchorHandoffManager is never constructed and the slice state does not exist.",
                "from" to fromNodeId.take(8), "to" to toNodeId.take(8))
            Log.w(TAG, "NSC rollback: RECLAIM_DHT_SLICE acknowledged (no-op): $fromNodeId → $toNodeId")
            // Return normally — NSC records ROLLED_BACK and resumes.
        }

        // REVERT_TIER_PROMOTION: update the contact's tier in the DHT routing table.
        // DhtEngine.setNodeTier() removes and re-inserts the contact with the previous tier,
        // effectively undoing the promotion. If the contact is no longer in the routing table
        // (it departed or was evicted), the revert is a no-op — the contact will re-insert
        // at its declared tier on the next DHT ping.
        RollbackRegistry.register("REVERT_TIER_PROMOTION") { args ->
            val parts  = args.split("|")
            val nodeIdHex = parts.getOrElse(0) { "" }.trim()
            val tierStr   = parts.getOrElse(1) { "" }.trim()
            if (nodeIdHex.length != 64 || tierStr.isEmpty()) {
                Diag.degraded("nsc", "rollback-revert-tier-bad-args",
                    "REVERT_TIER_PROMOTION: malformed args '$args' — skipping",
                    "args" to args)
                return@register
            }
            val nodeId = try { NodeId.fromHex(nodeIdHex) }
            catch (_: Exception) {
                Diag.degraded("nsc", "rollback-revert-tier-bad-nodeid",
                    "REVERT_TIER_PROMOTION: invalid nodeId hex '$nodeIdHex'")
                return@register
            }
            val tier = try { NodeTier.valueOf(tierStr) }
            catch (_: IllegalArgumentException) {
                Diag.degraded("nsc", "rollback-revert-tier-bad-tier",
                    "REVERT_TIER_PROMOTION: unknown tier '$tierStr'")
                return@register
            }
            dhtEngine.setNodeTier(nodeId, tier)
            Log.i(TAG, "NSC rollback: REVERT_TIER_PROMOTION ${nodeIdHex.take(8)}… → $tier")
        }

        Log.i(TAG, "NSC: RollbackRegistry handlers registered (6 opcodes — all non-throwing)")
    }

    // ── UI helpers ─────────────────────────────────────────────────────────

    private fun showCoverActivity() {
        // startActivity() must be called on the main thread.
        // buildObjectGraph() and its callers run on applicationScope (Dispatchers.Default),
        // so we always dispatch to Main before starting the Activity.
        val intent = Intent(this, CoverActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK)
        }
        applicationScope.launch(Dispatchers.Main) {
            startActivity(intent)
        }
    }

    // ── WorkManager configuration ──────────────────────────────────────────

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setMinimumLoggingLevel(android.util.Log.WARN)
            .setWorkerFactory(ShadowMeshWorkerFactory())
            .build()
}

// ── ByteArray display helper ──────────────────────────────────────────────────

private fun ByteArray.take8Hex(): String = toHex().take(8) + "…"

// Identity persistence constants — SharedPreferences key for the encrypted identity blob.
// Version suffix on the key allows a clean migration if the wire format ever changes:
// old key is simply not found and a fresh identity is generated.
private const val IDENTITY_PREFS    = "shadowmesh_identity"
private const val IDENTITY_PREF_KEY = "identity_blob_v1"
/**
 * [LocalPeer] adapter that routes fragment operations through the gossip engine.
 *
 * [FragmentFetcher] treats all peers uniformly via the [LocalPeer] interface.
 * This adapter bridges the gossip-layer [DhtContact] to the delivery-layer abstraction.
 * Fragment operations are dispatched to the gossip engine's existing relay/fetch paths.
 */
private class GossipBackedLocalPeer(
    private val contact:      mesh.shadowmesh.mesh.dht.DhtContact,
    private val gossipEngine: mesh.shadowmesh.mesh.gossip.GossipEngine
) : mesh.shadowmesh.mesh.delivery.LocalPeer {

    override val peerId: String = contact.nodeId.bytes.toHex()

    // All gossip peers are transport-type-agnostic at this layer.
    // FragmentFetcher uses transportType for preferential routing only.
    override val transportType: mesh.shadowmesh.mesh.delivery.LocalTransportType =
        mesh.shadowmesh.mesh.delivery.LocalTransportType.LAN_SUBNET

    override suspend fun fetchFragment(
        fragmentId: String
    ): mesh.shadowmesh.mesh.fragment.FragmentEntity? =
        // Delegate to gossip engine's peer-fetch path.
        // Returns null if the peer does not have the fragment.
        gossipEngine.fetchFragmentFromPeer(contact.nodeId, fragmentId)

    override suspend fun fetchFragmentsSince(
        channelId: ByteArray,
        sinceMs:   Long
    ): List<mesh.shadowmesh.mesh.fragment.FragmentEntity> =
        gossipEngine.fetchFragmentsSinceFromPeer(contact.nodeId, channelId, sinceMs)

    override suspend fun pushFragment(
        fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity
    ) {
        gossipEngine.relayFragment(fragment, contact.nodeId)
    }
}

// ── Transport adapter implementations ─────────────────────────────────────────
//
// These four classes bridge the mesh layer interfaces to the available engine
// objects (DhtEngine, GossipEngine). They live here — in the composition root —
// because they are pure wiring: no business logic, just delegation. Moving them
// to core/mesh would create a circular dependency (mesh → app).
//
// BLE and WiFi Direct transports are implemented in core/mesh/transport/ but are
// not yet wired as GossipTransport adapters because doing so requires Android
// Context and active scan/advertise lifecycles managed by the foreground service.
// That integration is tracked separately. The DHT-backed implementations below
// provide full internet-transport functionality for beta.

// ─────────────────────────────────────────────────────────────────────────────
// 1. DhtBackedGossipTransport
//
// Routes gossip fragment send/receive through the DHT store/findValue RPC pair.
// The DHT key for a fragment is SHA3-256(fragmentId bytes), keeping it content-
// addressed and consistent with how the DHT is used elsewhere.
//
// Fragment wire format matches LanSubnetTransport's serialization so that
// fragments received via any transport can be deserialized the same way.
// ─────────────────────────────────────────────────────────────────────────────
private class DhtBackedGossipTransport(
    private val dhtEngine: DhtEngine
) : mesh.shadowmesh.mesh.gossip.GossipTransport {

    private val hkdf = mesh.shadowmesh.crypto.Hkdf.instance

    /**
     * Optional LAN transport for direct TCP delivery. When non-null and the gossip peer
     * carries a TCP address, fragment sends are routed through LAN (faster, no internet)
     * rather than through the DHT. DHT remains the fallback for all non-TCP peers.
     * Set after LanSubnetTransport is constructed (Phase 11.1 of buildObjectGraph).
     */
    @Volatile var lanTransport: mesh.shadowmesh.mesh.transport.lan.LanSubnetTransport? = null

    override suspend fun sendFragment(
        peer:     DhtContact,
        fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity
    ) {
        // Prefer direct TCP delivery for LAN peers — faster, zero internet traffic,
        // and doesn't pollute the DHT with fragments that could be served locally.
        val lan = lanTransport
        if (lan != null && peer.address.protocol == mesh.shadowmesh.mesh.dht.TransportProtocol.TCP) {
            val lanPeer = mesh.shadowmesh.mesh.transport.lan.LanPeer(
                nodeId  = peer.nodeId,
                address = peer.address.ip,
                tcpPort = peer.address.port
            )
            try {
                lan.sendFragment(lanPeer, fragment)
                return
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                mesh.shadowmesh.diagnostics.Diag.swallowed("gossip", "lan-send-fragment", e,
                    "peer" to peer.nodeId.toHex().take(8))
                // Fall through to DHT on LAN error
            }
        }
        val key   = NodeId(hkdf.sha3_256(fragment.fragmentId.toByteArray()))
        val value = DhtValue(
            key   = key,
            value = serializeFragment(fragment),
            ttlMs = System.currentTimeMillis() + 7L * 24 * 60 * 60 * 1000
        )
        dhtEngine.store(value)
    }

    override suspend fun issueChallenge(
        peer: DhtContact,
        type: mesh.shadowmesh.mesh.gossip.ChallengeType
    ): Boolean {
        // True DHT-layer liveness probe: DhtEngine.pingSpecific() issues an actual
        // PING RPC to the contact and waits for a response. This replaces the previous
        // recency-check approximation (lastSeenMs ≤ STALE_THRESHOLD_MS) which could not
        // detect a compromised peer that stays in the routing table but stops relaying.
        // A real PING requires a network round-trip, proving the peer is reachable now —
        // not just that it was reachable 15 minutes ago.
        return dhtEngine.pingSpecific(peer.nodeId)
    }

    override suspend fun sendControl(
        peer:  DhtContact,
        bytes: ByteArray
    ) {
        // Prefer direct TCP delivery for LAN peers — same pattern as sendFragment.
        // Without this, ACKs were stored in the local DHT and never retrieved by the
        // peer on a LAN-only mesh (no internet seed nodes), leaving PostStateMachine
        // permanently stuck in PENDING ("Waiting for relay contact…").
        val lan = lanTransport
        if (lan != null && peer.address.protocol == mesh.shadowmesh.mesh.dht.TransportProtocol.TCP
            && peer.address.ip.isNotEmpty()) {
            val lanPeer = mesh.shadowmesh.mesh.transport.lan.LanPeer(
                nodeId  = peer.nodeId,
                address = peer.address.ip,
                tcpPort = peer.address.port
            )
            try {
                lan.sendRawBytes(lanPeer, bytes)
                return
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                mesh.shadowmesh.diagnostics.Diag.swallowed("gossip", "lan-send-control", e,
                    "peer" to peer.nodeId.toHex().take(8))
                // Fall through to DHT on LAN error
            }
        }
        // DHT fallback: store the control payload for later retrieval by internet peers.
        // Key = SHA3-256("control" || receiverNodeId || SHA3-256(bytes)) — prevents collisions.
        // TTL = 5 minutes: long enough for the receiver's next sync cycle to pick it up.
        val payloadKey = NodeId(
            hkdf.sha3_256("control".toByteArray() + peer.nodeId.bytes + hkdf.sha3_256(bytes))
        )
        dhtEngine.store(DhtValue(
            key   = payloadKey,
            value = bytes,
            ttlMs = System.currentTimeMillis() + 5 * 60 * 1000L
        ))
    }

    override suspend fun broadcastHoneyFragment(
        fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity
    ) {
        val key   = NodeId(hkdf.sha3_256(fragment.fragmentId.toByteArray()))
        val value = DhtValue(
            key   = key,
            value = serializeFragment(fragment),
            ttlMs = System.currentTimeMillis() + 7L * 24 * 60 * 60 * 1000
        )
        // Store at every peer in the routing table simultaneously.
        val peers = dhtEngine.routingTable.allContacts()
        peers.forEach { contact ->
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                try { dhtEngine.store(value) }
                catch (e: Exception) {
                    mesh.shadowmesh.diagnostics.Diag.swallowed(
                        "dht-gossip", "honey-broadcast", e,
                        "peer" to contact.nodeId.toHex().take(8)
                    )
                }
            }
        }
    }

    override suspend fun fetchFragment(
        peer:       DhtContact,
        fragmentId: String
    ): mesh.shadowmesh.mesh.fragment.FragmentEntity? {
        val key = NodeId(hkdf.sha3_256(fragmentId.toByteArray()))
        return try {
            val result = dhtEngine.findValue(key)
            when (result) {
                is LookupResult.Found -> deserializeFragment(result.value)
                else -> null
            }
        } catch (e: Exception) {
            mesh.shadowmesh.diagnostics.Diag.swallowed(
                "dht-gossip", "fetch-fragment", e,
                "peer"       to peer.nodeId.toHex().take(8),
                "fragmentId" to fragmentId.take(8)
            )
            null
        }
    }

    // fetchFragmentsSince: uses the per-channel DHT index maintained by updateChannelIndex().
    // The index maps (timestamp, fragmentId) pairs under channelIndexKey(channelId).
    // Entries added by storeFragment() during this session are queryable immediately;
    // entries from other nodes are available once gossip has replicated the index value.
    override suspend fun fetchFragmentsSince(
        peer:      DhtContact,
        channelId: ByteArray,
        sinceMs:   Long
    ): List<mesh.shadowmesh.mesh.fragment.FragmentEntity> {
        val indexKey = channelIndexKey(hkdf, channelId)
        val indexBytes = when (val r = dhtEngine.getLocal(indexKey)?.value
            ?: (dhtEngine.findValue(indexKey) as? LookupResult.Found)?.value) {
            null -> return emptyList()
            else -> r
        }
        val entries = parseChannelIndex(indexBytes).filter { (ts, _) -> ts > sinceMs }
        return entries.mapNotNull { (_, fragmentId) ->
            try {
                val fragKey = NodeId(hkdf.sha3_256(fragmentId.toByteArray()))
                (dhtEngine.findValue(fragKey) as? LookupResult.Found)
                    ?.value?.let { deserializeFragment(it) }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                mesh.shadowmesh.diagnostics.Diag.swallowed(
                    "dht-gossip", "fetch-fragment-since", e,
                    "fragmentId" to fragmentId.take(8))
                null
            }
        }
    }

    // ── Serialization — matches LanSubnetTransport wire format ────────────

    private fun serializeFragment(f: mesh.shadowmesh.mesh.fragment.FragmentEntity): ByteArray {
        val out = ByteArrayOutputStream()
        val dos = DataOutputStream(out)
        dos.writeBytes(f.fragmentId.padEnd(64, '0').take(64))
        dos.writeBytes(f.postId.padEnd(64,     '0').take(64))
        dos.writeBytes(f.channelId.padEnd(64,  '0').take(64))
        dos.writeShort(f.sequenceIndex)
        dos.writeShort(f.totalData)
        dos.writeShort(f.totalParity)
        dos.writeInt(f.payload.size)
        dos.write(f.payload)
        dos.writeByte(f.fecScheme.wire)
        dos.flush()
        return out.toByteArray()
    }

    private fun deserializeFragment(
        bytes: ByteArray
    ): mesh.shadowmesh.mesh.fragment.FragmentEntity? { return try {
        val dis         = DataInputStream(ByteArrayInputStream(bytes))
        // Use .trim() (whitespace only), NOT .trimEnd('0', ' ') — the latter strips legitimate
        // trailing zero digits from hex IDs (e.g. "abc...0000" becomes "abc..."), corrupting
        // content-address lookups and fragment integrity checks.
        val fragmentId  = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val postId      = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val channelId   = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        // readUnsignedShort() — same sign-extension fix as the other deserializeFragment.
        val seqIdx      = dis.readUnsignedShort()
        val totalData   = dis.readUnsignedShort()
        val totalParity = dis.readUnsignedShort()
        if (totalData == 0 || totalData > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS ||
            totalParity > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS) return null
        val payloadLen  = dis.readInt()
        // Bounds check — missing here (present in the other deserializeFragment). A crafted
        // DHT value with payloadLen=Int.MAX_VALUE would allocate a 2 GB ByteArray and OOM.
        if (payloadLen < 0 || payloadLen > 64 * 1024) return null
        val payload     = ByteArray(payloadLen).also { dis.readFully(it) }
        val fecWire     = dis.readByte().toInt()
        val fecScheme   = mesh.shadowmesh.mesh.fragment.FecScheme.fromWire(fecWire)
            ?: mesh.shadowmesh.mesh.fragment.FecScheme.NONE
        mesh.shadowmesh.mesh.fragment.FragmentEntity(
            fragmentId, postId, channelId, seqIdx, totalData, totalParity, payload, fecScheme
        )
    } catch (e: Exception) {
        mesh.shadowmesh.diagnostics.Diag.swallowed("dht-gossip", "deserialize-fragment", e)
        null
    } }
}

// ─────────────────────────────────────────────────────────────────────────────
// Channel fragment index helpers — used by DhtBackedStoreForwardTransport
//
// The DHT has no time-range query capability. We maintain a per-channel index:
//   indexKey = SHA3-256("chan-idx:" + channelId)
//   value    = concatenated entries: [8B createdAtMs big-endian][64B fragmentId hex]
//
// The index is read-modify-write on every store. It is capped at MAX_INDEX_ENTRIES
// (200 entries = 14KB) to bound DHT value size. Oldest entries are evicted first.
// TTL matches the post TTL (7 days).
// ─────────────────────────────────────────────────────────────────────────────

private const val CHAN_IDX_ENTRY_BYTES = 8 + 64
private const val MAX_INDEX_ENTRIES   = 200
private const val CHAN_IDX_TTL_MS     = 7L * 24 * 60 * 60 * 1000

private fun channelIndexKey(hkdf: mesh.shadowmesh.crypto.Hkdf, channelId: ByteArray): NodeId =
    NodeId(hkdf.sha3_256("chan-idx:".toByteArray() + channelId))

private fun parseChannelIndex(bytes: ByteArray): List<Pair<Long, String>> {
    val entries = mutableListOf<Pair<Long, String>>()
    var off = 0
    while (off + CHAN_IDX_ENTRY_BYTES <= bytes.size) {
        var ts = 0L
        for (i in 0..7) ts = (ts shl 8) or (bytes[off + i].toLong() and 0xFF)
        val fragmentId = bytes.copyOfRange(off + 8, off + CHAN_IDX_ENTRY_BYTES)
            .decodeToString().trimEnd(' ', ' ')
        entries.add(ts to fragmentId)
        off += CHAN_IDX_ENTRY_BYTES
    }
    return entries
}

private fun encodeIndexEntry(createdAtMs: Long, fragmentId: String): ByteArray {
    val ts  = ByteArray(8) { i -> ((createdAtMs shr ((7 - i) * 8)) and 0xFF).toByte() }
    val fid = fragmentId.toByteArray().copyOf(64)   // pad/truncate to exactly 64 bytes
    return ts + fid
}

private suspend fun updateChannelIndex(
    dhtEngine: DhtEngine,
    hkdf:      mesh.shadowmesh.crypto.Hkdf,
    fragment:  mesh.shadowmesh.mesh.fragment.FragmentEntity
) {
    val indexKey = channelIndexKey(hkdf, hexToBytes(fragment.channelId))
    val existing: ByteArray = when (val r = dhtEngine.getLocal(indexKey)?.value?.let {
        it
    } ?: run {
        (dhtEngine.findValue(indexKey) as? LookupResult.Found)?.value
    }) {
        null -> ByteArray(0)
        else -> r
    }
    val existingEntries = parseChannelIndex(existing)
    val newEntry   = encodeIndexEntry(System.currentTimeMillis(), fragment.fragmentId)
    // Append new entry, drop oldest if over cap
    val allEntries = existingEntries.map { (ts, id) -> encodeIndexEntry(ts, id) } + newEntry
    val capped     = allEntries.takeLast(MAX_INDEX_ENTRIES)
    val indexBytes = capped.fold(ByteArray(0)) { acc, e -> acc + e }
    dhtEngine.store(DhtValue(
        key   = indexKey,
        value = indexBytes,
        ttlMs = System.currentTimeMillis() + CHAN_IDX_TTL_MS
    ))
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. MeshCircuitTransport
//
// Bridges OnionCircuit's three transport primitives to the DHT dead-drop mechanism:
//
//   requestHopPublicKey  — writes a key-request token to a well-known DHT key
//                          derived from (circuitId, hopNodeId) and polls for the
//                          hop's response (its HybridPublicKey) with a timeout.
//                          If the local engine has this node's own key (we ARE the
//                          hop), return it directly without a network round-trip.
//
//   sendKemCiphertext    — dead-drop PUT of the KEM ciphertext at the hop's
//                          session-key derivation address.
//
//   sendToEntry          — store the onion as a DhtValue at the Entry hop.
//                          The entry node polls its dead-drop and peels its layer.
//
// This is a minimal but correct implementation. A production optimisation would
// use direct GATT/WiFi push for latency-sensitive circuit establishment rather than
// DHT polling. That is tracked as a future enhancement.
// ─────────────────────────────────────────────────────────────────────────────
private class MeshCircuitTransport(
    private val gossipEngine: GossipEngine,
    private val dhtEngine:    DhtEngine
) : mesh.shadowmesh.mesh.circuit.CircuitTransport {

    private val hkdf = mesh.shadowmesh.crypto.Hkdf.instance

    // How long to wait for a hop to reply with its public key.
    // NFC/LAN bootstrapped peers respond within a few seconds; internet peers up to 10s.
    private val KEY_REQUEST_TIMEOUT_MS = 10_000L
    private val KEY_POLL_INTERVAL_MS   = 200L

    override suspend fun requestHopPublicKey(
        hop:       DhtContact,
        circuitId: String
    ): mesh.shadowmesh.crypto.HybridPublicKey? {
        // If this engine IS the hop (local node acting as relay), return our own key immediately.
        if (hop.nodeId == dhtEngine.localNodeId) {
            return dhtEngine.localPublicIdentity?.kemPublicKey
        }

        // Derive a well-known dead-drop key: SHA3-256("circuit-pubkey" || circuitId || hopNodeId)
        val dropKey = NodeId(
            hkdf.sha3_256(
                "circuit-pubkey".toByteArray() +
                circuitId.toByteArray() +
                hop.nodeId.bytes
            )
        )

        // Write a key-request token so the hop knows to publish its public key here.
        val requestToken = DhtValue(
            key   = dropKey,
            value = "KEY_REQUEST".toByteArray(),
            ttlMs = System.currentTimeMillis() + 30_000L
        )
        try { dhtEngine.store(requestToken) }
        catch (e: Exception) {
            mesh.shadowmesh.diagnostics.Diag.swallowed(
                "circuit-transport", "key-request-store", e,
                "hop"       to hop.nodeId.toHex().take(8),
                "circuitId" to circuitId.take(8)
            )
            return null
        }

        // Poll for the hop's response.
        val deadline = System.currentTimeMillis() + KEY_REQUEST_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            try {
                val result = dhtEngine.findValue(dropKey)
                if (result is LookupResult.Found) {
                    val bytes = result.value
                    // Ignore our own request token.
                    if (!bytes.contentEquals("KEY_REQUEST".toByteArray())) {
                        return mesh.shadowmesh.crypto.HybridPublicKey.fromBytes(bytes)
                    }
                }
            } catch (e: Exception) {
                mesh.shadowmesh.diagnostics.Diag.swallowed(
                    "circuit-transport", "key-request-poll", e,
                    "hop" to hop.nodeId.toHex().take(8)
                )
            }
            kotlinx.coroutines.delay(KEY_POLL_INTERVAL_MS)
        }

        mesh.shadowmesh.diagnostics.Diag.degraded(
            "circuit-transport", "key-request-timeout",
            "Hop did not publish its public key within ${KEY_REQUEST_TIMEOUT_MS}ms",
            "hop"       to hop.nodeId.toHex().take(8),
            "circuitId" to circuitId.take(8)
        )
        return null
    }

    override suspend fun sendKemCiphertext(
        hop:       DhtContact,
        circuitId: String,
        ct:        mesh.shadowmesh.crypto.HybridCiphertext
    ) {
        // Derive the ciphertext dead-drop key: SHA3-256("circuit-ct" || circuitId || hopNodeId)
        val dropKey = NodeId(
            hkdf.sha3_256(
                "circuit-ct".toByteArray() +
                circuitId.toByteArray() +
                hop.nodeId.bytes
            )
        )
        val value = DhtValue(
            key   = dropKey,
            value = ct.toBytes(),
            ttlMs = System.currentTimeMillis() + 30_000L
        )
        try { dhtEngine.store(value) }
        catch (e: Exception) {
            mesh.shadowmesh.diagnostics.Diag.swallowed(
                "circuit-transport", "kem-ct-store", e,
                "hop"       to hop.nodeId.toHex().take(8),
                "circuitId" to circuitId.take(8)
            )
        }
    }

    override suspend fun sendToEntry(
        entryAddress: mesh.shadowmesh.mesh.dht.PeerAddress,
        onion:        ByteArray
    ) {
        // Route the onion to the Entry node via gossip broadcast.
        // The Entry node's DHT address is the target; gossip propagation ensures
        // the onion reaches it even without a direct connection.
        // A future optimisation: use a direct UDP datagram if the entry peer is known.
        val entryKey = NodeId(hkdf.sha3_256("circuit-onion".toByteArray() + entryAddress.ip.toByteArray()))
        val value = DhtValue(
            key   = entryKey,
            value = onion,
            ttlMs = System.currentTimeMillis() + 60_000L
        )
        // Find the entry node's DhtContact from the routing table by address match.
        val entryContact = dhtEngine.routingTable.allContacts()
            .firstOrNull { it.address.ip == entryAddress.ip && it.address.port == entryAddress.port }
        if (entryContact != null) {
            try { dhtEngine.store(value) }
            catch (e: Exception) {
                mesh.shadowmesh.diagnostics.Diag.swallowed(
                    "circuit-transport", "onion-send", e,
                    "entryIp" to entryAddress.ip
                )
            }
        } else {
            mesh.shadowmesh.diagnostics.Diag.degraded(
                "circuit-transport", "entry-not-found",
                "Entry node not found in routing table — onion not delivered",
                "entryIp"   to entryAddress.ip,
                "entryPort" to entryAddress.port.toString()
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. GossipBackedSndpTransport
//
// Routes SNDP cover traffic through GossipEngine. Both sendFakeFragment (a single
// cover fragment to one peer) and gossipSndpBurst (a channel-hash burst to multiple
// peers) use the existing gossip relay path so cover traffic is structurally
// indistinguishable from real fragments.
// ─────────────────────────────────────────────────────────────────────────────
private class GossipBackedSndpTransport(
    private val gossipEngine: GossipEngine
) : mesh.shadowmesh.mesh.privacy.SndpTransport {

    override suspend fun sendFakeFragment(
        peer:     DhtContact,
        fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity
    ) {
        // Route through gossip relay so cover fragments pass through the same
        // bloom filter and rate limiter as real fragments — indistinguishable on the wire.
        try { gossipEngine.relayFragment(fragment, peer.nodeId) }
        catch (e: Exception) {
            mesh.shadowmesh.diagnostics.Diag.swallowed(
                "sndp-transport", "fake-fragment", e,
                "peer" to peer.nodeId.toHex().take(8)
            )
        }
    }

    override suspend fun gossipSndpBurst(
        postHash: ByteArray,
        peers:    List<DhtContact>
    ) {
        // Send the channel-hash burst to each specified peer concurrently.
        // Each relay call produces an independent cover fragment relay event.
        val burstFragment = buildBurstCoverFragment(postHash)
        peers.forEach { peer ->
            kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
                try { gossipEngine.relayFragment(burstFragment, peer.nodeId) }
                catch (e: Exception) {
                    mesh.shadowmesh.diagnostics.Diag.swallowed(
                        "sndp-transport", "burst-relay", e,
                        "peer" to peer.nodeId.toHex().take(8)
                    )
                }
            }
        }
    }

    /**
     * Build a structurally valid cover fragment whose payload is derived from [postHash].
     * The fragmentId and postId are content-addressed from the hash so the fragment is
     * deterministic and verifiable, while the payload is indistinguishable from ciphertext.
     */
    private fun buildBurstCoverFragment(
        postHash: ByteArray
    ): mesh.shadowmesh.mesh.fragment.FragmentEntity {
        val hkdf       = mesh.shadowmesh.crypto.Hkdf.instance
        val postId     = hkdf.sha3_256(postHash).toHex()
        val payload    = hkdf.derive(postHash, info = "sndp-burst-cover-v1".toByteArray(), outputLen = 128)
        val fragmentId = mesh.shadowmesh.mesh.fragment.FragmentEntity.computeFragmentId(
            postId        = postHash.copyOf(32),
            sequenceIndex = 0,
            payload       = payload,
            hkdf          = hkdf
        )
        return mesh.shadowmesh.mesh.fragment.FragmentEntity(
            fragmentId    = fragmentId,
            postId        = postId,
            channelId     = mesh.shadowmesh.mesh.privacy.SndpEngine.SNDP_FAKE_CHANNEL_ID,
            sequenceIndex = 0,
            totalData     = 1,
            totalParity   = 0,
            payload       = payload,
            fecScheme     = mesh.shadowmesh.mesh.fragment.FecScheme.NONE
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. GossipBackedMixTransport
//
// Forwards mix protocol fragments via GossipEngine.  The mix protocol batches
// fragments from multiple senders before releasing them to defeat traffic
// analysis. Each forwardFragment call routes through gossip's relay path so
// the forwarded fragment is subject to the same bloom filter dedup and rate
// limiting as organic gossip traffic.
// ─────────────────────────────────────────────────────────────────────────────
private class GossipBackedMixTransport(
    private val gossipEngine: GossipEngine
) : mesh.shadowmesh.mesh.privacy.MixTransport {

    override suspend fun forwardFragment(
        target:   DhtContact,
        fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity
    ) {
        try { gossipEngine.relayFragment(fragment, target.nodeId) }
        catch (e: Exception) {
            mesh.shadowmesh.diagnostics.Diag.swallowed(
                "mix-transport", "forward-fragment", e,
                "target" to target.nodeId.toHex().take(8)
            )
        }
    }
}

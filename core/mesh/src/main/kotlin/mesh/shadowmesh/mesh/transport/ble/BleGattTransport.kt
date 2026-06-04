// TODO: [BLE Redesign] setMeshScanMode() and adaptive LOW_POWER backoff added.
// ASSUMPTION: isForegroundScanActive tracks only the foreground (ScanCallback) path.
// Background scan (PendingIntent) always uses SCAN_MODE_LOW_POWER and is unaffected.
// ASSUMPTION: Adaptive backoff fires only when meshScanMode == BALANCED; in ACTIVE mode
// the scan never drops (charging/user opt-in is assumed to grant full battery permission).
// ASSUMPTION: restoreFromAdaptiveLowPower() relaunches the scan via scope.launch from the
// BLE scan callback thread — safe because scope is always active while foreground scan runs.

package mesh.shadowmesh.mesh.transport.ble

import android.app.PendingIntent
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import mesh.shadowmesh.mesh.dht.NodeId
import mesh.shadowmesh.mesh.dht.NODE_ID_BYTES
import mesh.shadowmesh.mesh.nudge.NudgeEngine
import kotlinx.coroutines.*
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.diagnostics.Diag

/**
 * BLE GATT nudge transport — design doc Phase 7.
 *
 * This class governs **mesh BLE only** — the always-on, trust-agnostic nudge and
 * peer-discovery transport. It has **no effect on bootstrap BLE**, which is handled
 * entirely by `BleProximityScanner` in `core:bootstrap`. The two transports are
 * independent and do not share scan callbacks, GATT connections, or lifecycle state.
 *
 * Provides two BLE functions:
 *
 *   1. GATT nudge: write the 12-byte NudgePacket to the remote GATT characteristic.
 *      Range: <10m. Triggers WorkManager sync on the receiving device.
 *
 *   2. Beacon mode: periodic BLE advertisement of channel hash (8 bytes).
 *      Nearby devices detect and trigger sync. Off by default.
 *
 * GATT characteristic UUIDs (fixed, compiled into APK):
 *   Service:        SHADOWMESH_SERVICE_UUID
 *   Nudge write:    NUDGE_CHARACTERISTIC_UUID  (WRITE_NO_RESPONSE)
 *   Beacon read:    BEACON_CHARACTERISTIC_UUID (READ | NOTIFY)
 *
 * Mesh BLE scan aggressiveness:
 *   Controlled by [meshScanMode] (default [BleScanMode.BALANCED]).
 *   - [BleScanMode.BALANCED] → `SCAN_MODE_BALANCED` (battery-safe default).
 *   - [BleScanMode.ACTIVE]   → `SCAN_MODE_LOW_LATENCY` (maximum discovery rate).
 *   Call [setMeshScanMode] to change at runtime; if the foreground scan is running
 *   it is restarted immediately with the new mode.
 *   Mode is propagated by [NetworkStateCoordinator] from the user's "Active Mesh Mode"
 *   setting and overridden to ACTIVE by [ShadowMeshForegroundService] while charging.
 *
 * Adaptive LOW_POWER fallback (BALANCED mode only):
 *   If no ShadowMesh peer advertisement is seen for [ADAPTIVE_NO_NODES_MS] (5 minutes),
 *   the scan temporarily drops to `SCAN_MODE_LOW_POWER` to save battery. The moment
 *   any peer advertisement is detected the scan is restored to BALANCED. The fallback
 *   never applies in ACTIVE mode.
 *
 * Background scanning:
 *   Uses PendingIntent callback (required for background scanning on Android 8+).
 *   The PendingIntent target receives scan results and dispatches to WorkManager.
 *   Background scan always uses SCAN_MODE_LOW_POWER and is unaffected by [meshScanMode].
 *   Foreground scanning uses the ScanCallback path governed by [meshScanMode].
 *
 * Beacon mode:
 *   Broadcasts channel hash (first 8 bytes of SHA3-256(channelId)) in the
 *   advertisement manufacturer data. Nearby devices detect and sync the channel.
 *   OFF by default — design doc notes: disabled for military use.
 *   When beacon is active with VPN circuit, the circuit masks the real IP.
 *
 * Thread-safety: [gattClients] uses ConcurrentHashMap. All BLE callbacks
 * are delivered on the BLE thread; processing is posted to [scope].
 *
 * Android permission requirements:
 *   BLUETOOTH, BLUETOOTH_ADMIN, BLUETOOTH_SCAN, BLUETOOTH_CONNECT,
 *   BLUETOOTH_ADVERTISE, ACCESS_FINE_LOCATION (Android 11 and below)
 */
class BleGattTransport(
    private val context:              Context,
    private val scope:                CoroutineScope,
    private val nudgeEngine:          NudgeEngine,
    /**
     * This node's 32-byte identity. Exposed as the BEACON_CHARACTERISTIC_UUID value so
     * connecting clients can read it and register us in their gossip peer table. Enables
     * BLE-discovered peers to participate in fragment relay without a separate DHT lookup.
     */
    private val localNodeId:          NodeId,
    private val onNudgeReceived:      (channelHash8: ByteArray) -> Unit,
    /**
     * PendingIntent for background BLE scanning (required for Android 8+ background scanning).
     * Null until [ShadowMeshForegroundService] creates and registers a [BroadcastReceiver]-
     * targeted intent — background scanning is no-op while this is null, but foreground
     * scanning and beacon advertising work from construction. Set via [setScanPendingIntent].
     */
    private var scanPendingIntent: PendingIntent? = null,
    /**
     * Called when a remote peer's NodeId is successfully read and authenticated during a GATT
     * nudge connection. The second parameter is the Bluetooth device address (MAC string, e.g.
     * "AA:BB:CC:DD:EE:FF") — callers that need to send BLE nudges back to this peer must record
     * the NodeId → MAC mapping here, since the NudgeTransport API only receives NodeId.
     * Null means BLE peer discovery is not wired (nudge-only mode).
     */
    private val onBleNodeIdDiscovered: ((NodeId, String) -> Unit)? = null,
    /**
     * Raw 32-byte Ed25519 public key component of this node's signing keypair.
     * Served on [ED25519_PUB_CHARACTERISTIC_UUID] so connecting clients can authenticate us.
     * Null disables BLE challenge-response (peers accepted without proof of key ownership).
     */
    private val localEd25519PubKey: ByteArray? = null,
    /**
     * Signs (challenge || localNodeId.bytes) with Ed25519. Output: exactly 64 bytes.
     * Called in Dispatchers.IO when a client writes a 32-byte challenge during auth.
     * Null disables server-side challenge signing.
     */
    private val signChallengeEd25519Only: (suspend (message: ByteArray) -> ByteArray)? = null,
    /**
     * Verifies a 64-byte Ed25519 [sig] over [message] against [pubKey].
     * Called from the GATT client coroutine during peer authentication.
     * Null disables client-side challenge verification.
     */
    private val verifyEd25519Only: (suspend (message: ByteArray, sig: ByteArray, pubKey: ByteArray) -> Boolean)? = null
) {
    private val bluetoothManager: BluetoothManager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
            ?: throw IllegalStateException("BluetoothManager not available on this device")
    private val adapter: BluetoothAdapter = bluetoothManager.adapter
        ?: throw IllegalStateException("BluetoothAdapter not available — device has no BLE hardware")
    private val leScanner: BluetoothLeScanner get() = adapter.bluetoothLeScanner

    // Per-connection challenge → signature map: signed by server, consumed by client READ.
    // Key = device MAC address; value = 64-byte Ed25519 signature over (challenge || nodeId).
    private val challengeResponseMap = ConcurrentHashMap<String, ByteArray>()

    init {
        if (onBleNodeIdDiscovered != null &&
            (localEd25519PubKey == null || signChallengeEd25519Only == null || verifyEd25519Only == null)) {
            Diag.degraded("ble-gatt", "auth-not-wired",
                "BLE peer discovery is active but Ed25519 challenge-response auth is not wired — " +
                "peers will be accepted without cryptographic proof of key ownership")
        }
    }
    private val leAdvertiser: BluetoothLeAdvertiser get() = adapter.bluetoothLeAdvertiser

    // Active GATT client connections keyed by device address
    private val gattClients = ConcurrentHashMap<String, BluetoothGatt>()

    // GATT server for receiving nudges from remote devices
    @Volatile private var gattServer: BluetoothGattServer? = null

    // Beacon state
    @Volatile private var beaconActive = false
    @Volatile private var beaconChannelHash: ByteArray? = null
    // Retained across stop() so resumeBeacon() can restart without the caller needing to
    // remember the hash (used by the NSC RESTORE_BEACON_MODE rollback handler).
    @Volatile private var lastBeaconChannelHash: ByteArray? = null

    // ── Mesh BLE scan mode ─────────────────────────────────────────────────

    /** User/charging-override scan aggressiveness for the foreground mesh scan. */
    @Volatile private var meshScanMode: BleScanMode = BleScanMode.BALANCED

    /** True while the foreground [ScanCallback] scan is running. */
    @Volatile private var isForegroundScanActive: Boolean = false

    /** Timestamp of the last ShadowMesh peer advertisement seen; used by adaptive backoff. */
    @Volatile private var lastPeerDiscoveryMs: Long = 0L

    /** True when the adaptive fallback has temporarily reduced to SCAN_MODE_LOW_POWER. */
    @Volatile private var adaptiveInLowPower: Boolean = false

    private var adaptiveBackoffJob: Job? = null

    // ── BLE scanning (PendingIntent path for background) ──────────────────

    /** Replace the background scan PendingIntent once ShadowMeshForegroundService has created it. */
    fun setScanPendingIntent(intent: PendingIntent) { scanPendingIntent = intent }

    /**
     * Start background BLE scanning via PendingIntent.
     * [scanPendingIntent] is delivered to a BroadcastReceiver which dispatches
     * to WorkManager. This path works even when the app is not in foreground.
     * No-op if [scanPendingIntent] has not been set yet.
     */
    fun startBackgroundScan() {
        val intent = scanPendingIntent ?: return
        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(SHADOWMESH_SERVICE_UUID))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
            .build()
        leScanner.startScan(listOf(filter), settings, intent)
    }

    fun stopBackgroundScan() {
        val intent = scanPendingIntent ?: return
        leScanner.stopScan(intent)
    }

    /**
     * Foreground scan callback — used when the app is visible.
     * Delivers scan results immediately to [onNudgeReceived].
     */
    private val foregroundScanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            processScanResult(result)
        }
        override fun onBatchScanResults(results: List<ScanResult>) {
            results.forEach { processScanResult(it) }
        }
    }

    fun startForegroundScan() {
        isForegroundScanActive = true
        adaptiveInLowPower = false
        lastPeerDiscoveryMs = System.currentTimeMillis()
        applyScanMode(meshScanMode)
        startAdaptiveBackoffJob()
    }

    fun stopForegroundScan() {
        isForegroundScanActive = false
        adaptiveInLowPower = false
        adaptiveBackoffJob?.cancel()
        adaptiveBackoffJob = null
        try { leScanner.stopScan(foregroundScanCallback) } catch (_: Exception) {}
    }

    /**
     * Change the mesh BLE scan aggressiveness at runtime.
     * If the foreground scan is currently running it is restarted immediately.
     * [BleScanMode.ACTIVE] maps to `SCAN_MODE_LOW_LATENCY`; [BleScanMode.BALANCED]
     * maps to `SCAN_MODE_BALANCED` (with adaptive LOW_POWER fallback after 5 min idle).
     * Does not affect the background PendingIntent scan.
     */
    fun setMeshScanMode(mode: BleScanMode) {
        meshScanMode = mode
        if (isForegroundScanActive) {
            adaptiveInLowPower = false
            try { leScanner.stopScan(foregroundScanCallback) } catch (_: Exception) {}
            applyScanMode(mode)
            adaptiveBackoffJob?.cancel()
            startAdaptiveBackoffJob()
        }
    }

    private fun applyScanMode(mode: BleScanMode) {
        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(SHADOWMESH_SERVICE_UUID))
            .build()
        val scanMode = when (mode) {
            BleScanMode.BALANCED -> ScanSettings.SCAN_MODE_BALANCED
            BleScanMode.ACTIVE   -> ScanSettings.SCAN_MODE_LOW_LATENCY
        }
        val settings = ScanSettings.Builder()
            .setScanMode(scanMode)
            .build()
        leScanner.startScan(listOf(filter), settings, foregroundScanCallback)
    }

    private fun startAdaptiveBackoffJob() {
        adaptiveBackoffJob = scope.launch {
            while (isForegroundScanActive) {
                delay(ADAPTIVE_CHECK_INTERVAL_MS)
                if (!isForegroundScanActive) break
                // Adaptive backoff applies only in BALANCED mode.
                if (meshScanMode != BleScanMode.BALANCED || adaptiveInLowPower) continue
                val idleMs = System.currentTimeMillis() - lastPeerDiscoveryMs
                if (idleMs >= ADAPTIVE_NO_NODES_MS) {
                    adaptiveInLowPower = true
                    try { leScanner.stopScan(foregroundScanCallback) } catch (_: Exception) {}
                    val settings = ScanSettings.Builder()
                        .setScanMode(ScanSettings.SCAN_MODE_LOW_POWER)
                        .build()
                    val filter = ScanFilter.Builder()
                        .setServiceUuid(ParcelUuid(SHADOWMESH_SERVICE_UUID))
                        .build()
                    try { leScanner.startScan(listOf(filter), settings, foregroundScanCallback) }
                    catch (_: Exception) { adaptiveInLowPower = false }
                }
            }
        }
    }

    private fun restoreFromAdaptiveLowPower() {
        if (!isForegroundScanActive || adaptiveInLowPower) return
        try { leScanner.stopScan(foregroundScanCallback) } catch (_: Exception) {}
        applyScanMode(meshScanMode)
    }

    private fun processScanResult(result: ScanResult) {
        // Update peer-activity timestamp for adaptive backoff tracking.
        lastPeerDiscoveryMs = System.currentTimeMillis()
        // Restore from adaptive LOW_POWER as soon as any peer is seen again.
        if (adaptiveInLowPower) {
            adaptiveInLowPower = false
            scope.launch { restoreFromAdaptiveLowPower() }
        }
        val manufacturerData = result.scanRecord?.getManufacturerSpecificData(MANUFACTURER_ID)
            ?: return
        if (manufacturerData.size >= NudgeEngine.CHANNEL_HASH_BYTES) {
            val channelHash8 = manufacturerData.copyOfRange(0, NudgeEngine.CHANNEL_HASH_BYTES)
            onNudgeReceived(channelHash8)
        }
    }

    // ── GATT nudge send ────────────────────────────────────────────────────

    /**
     * Send a 12-byte NudgePacket to [deviceAddress] via GATT WRITE_NO_RESPONSE.
     * Rate limiting is enforced by [NudgeEngine.sendBleNudge] — this method
     * executes the actual GATT write.
     *
     * Connection lifecycle:
     *   1. If a GATT connection to [deviceAddress] already exists → use it
     *   2. Otherwise: connect, discover services, write characteristic, disconnect
     *
     * WRITE_NO_RESPONSE is used (not WRITE) — no ACK, fire-and-forget.
     * Best-effort: failure is silent per design doc.
     */
    suspend fun sendNudgePacket(deviceAddress: String, packet: ByteArray) =
        withContext(Dispatchers.IO) {
            require(packet.size == NudgeEngine.NUDGE_PACKET_SIZE) {
                "Nudge packet must be ${NudgeEngine.NUDGE_PACKET_SIZE} bytes"
            }
            val existing = gattClients[deviceAddress]
            if (existing != null) {
                writeNudgeCharacteristic(existing, packet)
            } else {
                connectAndSendNudge(deviceAddress, packet)
            }
        }

    private suspend fun connectAndSendNudge(deviceAddress: String, packet: ByteArray) {
        val resultDeferred = CompletableDeferred<Boolean>()

        // Carries the remote peer's NodeId bytes read from BEACON_CHARACTERISTIC_UUID.
        // Completed (possibly with null) by onCharacteristicRead before the nudge write
        // proceeds so the discovery callback fires for every successful connection attempt.
        val beaconReadDeferred    = CompletableDeferred<ByteArray?>()
        // Auth deferreds — populated during BLE Ed25519 challenge-response.
        val ed25519PubDeferred    = CompletableDeferred<ByteArray?>()
        val challengeWriteDeferred = CompletableDeferred<Boolean>()
        val responseReadDeferred  = CompletableDeferred<ByteArray?>()

        // Guard: ensures gatt.close() is called at most once regardless of which code path
        // reaches it first (onConnectionStateChange callback vs timeout cleanup).
        // Without this, two paths can call close() concurrently:
        //   1. Timeout fires → gatt.disconnect() → onConnectionStateChange(DISCONNECTED) → close()
        //                                         AND timeout path also calls close() directly.
        //   2. scope.launch in onServicesDiscovered may call gatt.disconnect() after the timeout
        //      path has already called gatt.close(), which is undefined behaviour on Android.
        val closed = java.util.concurrent.atomic.AtomicBoolean(false)

        fun safeClose(gatt: BluetoothGatt) {
            if (closed.compareAndSet(false, true)) {
                try { gatt.close() } catch (e: Exception) {
                    Diag.swallowed("ble-gatt", "safe-close", e)
                }
            }
        }

        // Tracks the coroutine launched inside onServicesDiscovered so it can be cancelled
        // on timeout before it calls gatt.disconnect() on an already-closed GATT object.
        var serviceJob: kotlinx.coroutines.Job? = null

        val device = adapter.getRemoteDevice(deviceAddress)

        val gatt = device.connectGatt(context, false, object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    // (GATT_FAILURE, STATE_CONNECTED) is a real failure mode on some
                    // Qualcomm/MediaTek stacks. Calling discoverServices() on a broken
                    // connection can crash the BLE stack daemon on affected chipsets.
                    Diag.degraded("ble-gatt", "connection-error",
                        "GATT connection error: status=$status newState=$newState addr=$deviceAddress")
                    gattClients.remove(deviceAddress)
                    safeClose(gatt)
                    if (!beaconReadDeferred.isCompleted) beaconReadDeferred.complete(null)
                    if (!resultDeferred.isCompleted) resultDeferred.complete(false)
                    return
                }
                if (newState == BluetoothProfile.STATE_CONNECTED) {
                    gatt.discoverServices()
                } else if (newState == BluetoothProfile.STATE_DISCONNECTED) {
                    gattClients.remove(deviceAddress)
                    // Always call close() after disconnect() to release system BLE resources.
                    // Omitting close() leaks a native GATT client slot (Android has a fixed limit).
                    // safeClose() ensures this is a no-op if timeout already called close().
                    safeClose(gatt)
                    if (!beaconReadDeferred.isCompleted) beaconReadDeferred.complete(null)
                    if (!resultDeferred.isCompleted) resultDeferred.complete(false)
                }
            }

            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                val value = if (status == BluetoothGatt.GATT_SUCCESS)
                    characteristic.value?.copyOf() else null
                when (characteristic.uuid) {
                    BEACON_CHARACTERISTIC_UUID      ->
                        if (!beaconReadDeferred.isCompleted)  beaconReadDeferred.complete(value)
                    ED25519_PUB_CHARACTERISTIC_UUID ->
                        if (!ed25519PubDeferred.isCompleted)   ed25519PubDeferred.complete(value)
                    RESPONSE_CHARACTERISTIC_UUID    ->
                        if (!responseReadDeferred.isCompleted) responseReadDeferred.complete(value)
                }
            }

            override fun onCharacteristicWrite(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int
            ) {
                if (characteristic.uuid == CHALLENGE_CHARACTERISTIC_UUID &&
                    !challengeWriteDeferred.isCompleted) {
                    challengeWriteDeferred.complete(status == BluetoothGatt.GATT_SUCCESS)
                }
                // NUDGE uses WRITE_NO_RESPONSE — this callback may not fire for it.
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                if (status == BluetoothGatt.GATT_SUCCESS) {
                    gattClients[deviceAddress] = gatt
                    serviceJob = scope.launch {
                        // 1. Read remote peer's NodeId from BEACON_CHARACTERISTIC_UUID.
                        //    GATT operations must be sequential — read before write.
                        //    Best-effort: failure here does not abort the nudge send.
                        val service    = gatt.getService(SHADOWMESH_SERVICE_UUID)
                        val beaconChar = service?.getCharacteristic(BEACON_CHARACTERISTIC_UUID)
                        if (beaconChar != null && gatt.readCharacteristic(beaconChar)) {
                            val nodeIdBytes = withTimeoutOrNull(BEACON_READ_TIMEOUT_MS) {
                                beaconReadDeferred.await()
                            }
                            if (nodeIdBytes?.size == NODE_ID_BYTES && onBleNodeIdDiscovered != null) {
                                // Authenticate the peer before registering it.
                                // Requires: remote server exposes auth characteristics AND
                                // this node was constructed with Ed25519 auth parameters.
                                val authPassed = performBleAuthentication(
                                    gatt            = gatt,
                                    service         = service,
                                    remoteNodeBytes = nodeIdBytes,
                                    ed25519PubDeferred    = ed25519PubDeferred,
                                    challengeWriteDeferred = challengeWriteDeferred,
                                    responseReadDeferred  = responseReadDeferred
                                )
                                if (authPassed) {
                                    try {
                                        onBleNodeIdDiscovered.invoke(NodeId(nodeIdBytes), deviceAddress)
                                    } catch (e: Exception) {
                                        Diag.swallowed("ble-gatt", "node-id-discovered-cb", e)
                                    }
                                }
                            }
                        } else {
                            // Characteristic absent or read initiation failed — skip discovery.
                            if (!beaconReadDeferred.isCompleted) beaconReadDeferred.complete(null)
                        }

                        // 2. Send nudge characteristic.
                        val success = writeNudgeCharacteristic(gatt, packet)
                        resultDeferred.complete(success)
                        // Disconnect and close after send — nudges are stateless.
                        // close() is called in onConnectionStateChange(DISCONNECTED).
                        delay(500)
                        gatt.disconnect()
                        gattClients.remove(deviceAddress)
                    }
                } else {
                    if (!beaconReadDeferred.isCompleted) beaconReadDeferred.complete(null)
                    resultDeferred.complete(false)
                }
            }

        })

        val timedOut = withTimeoutOrNull(GATT_TIMEOUT_MS) { resultDeferred.await() } == null
        if (timedOut) {
            // Cancel the service-discovery coroutine first so it cannot call
            // gatt.disconnect() after we call gatt.close() below.
            serviceJob?.cancel()
            gattClients.remove(deviceAddress)
            // disconnect() attempts to trigger onConnectionStateChange(DISCONNECTED) which
            // would call safeClose(). We also call safeClose() directly as a backstop for
            // the case where the BLE stack is unresponsive and the callback never fires.
            try { gatt.disconnect() } catch (e: Exception) {
                Diag.swallowed("ble-gatt", "disconnect-timeout", e)
            }
            safeClose(gatt)
        }
    }

    /**
     * Ed25519 challenge-response handshake for BLE peer authentication.
     *
     * Flow:
     *   1. Read peer's 32-byte Ed25519 public key from ED25519_PUB_CHARACTERISTIC_UUID.
     *   2. Generate a 32-byte random challenge.
     *   3. Write challenge to CHALLENGE_CHARACTERISTIC_UUID (WRITE_WITH_RESPONSE).
     *   4. Wait [CHALLENGE_SIGN_DELAY_MS] for the server to compute Ed25519(challenge || nodeId).
     *   5. Read 64-byte signature from RESPONSE_CHARACTERISTIC_UUID.
     *   6. Verify signature against the peer's claimed public key.
     *
     * Returns true only when all steps succeed and the signature is valid.
     * Returns false and logs a Diag.degraded in all failure/absent-characteristic cases.
     * If auth is not wired on this node (verifyEd25519Only == null), returns true (fallback mode).
     */
    private suspend fun performBleAuthentication(
        gatt:                   BluetoothGatt,
        service:                BluetoothGattService?,
        remoteNodeBytes:        ByteArray,
        ed25519PubDeferred:     CompletableDeferred<ByteArray?>,
        challengeWriteDeferred: CompletableDeferred<Boolean>,
        responseReadDeferred:   CompletableDeferred<ByteArray?>
    ): Boolean {
        val verify = verifyEd25519Only
        if (verify == null) {
            // Auth not wired on our side — accept without verification (emits warning in init).
            return true
        }

        val ed25519PubChar = service?.getCharacteristic(ED25519_PUB_CHARACTERISTIC_UUID)
        val challengeChar  = service?.getCharacteristic(CHALLENGE_CHARACTERISTIC_UUID)
        val responseChar   = service?.getCharacteristic(RESPONSE_CHARACTERISTIC_UUID)

        if (ed25519PubChar == null || challengeChar == null || responseChar == null) {
            Diag.degraded("ble-gatt", "auth-characteristics-absent",
                "Remote peer does not expose BLE auth characteristics — " +
                "refusing peer registration (nodeId=${remoteNodeBytes.take(4).joinToString("") { "%02x".format(it) }}…)")
            return false
        }

        // Step 1: read remote Ed25519 public key
        if (!gatt.readCharacteristic(ed25519PubChar)) return false
        val ed25519Pub = withTimeoutOrNull(BEACON_READ_TIMEOUT_MS) { ed25519PubDeferred.await() }
        if (ed25519Pub?.size != 32) {
            Diag.degraded("ble-gatt", "auth-pub-invalid",
                "Peer returned invalid Ed25519 public key (size=${ed25519Pub?.size})")
            return false
        }

        // Step 2: generate challenge
        val challenge = ByteArray(CHALLENGE_BYTES).also { java.security.SecureRandom().nextBytes(it) }

        // Step 3: write challenge (WRITE_WITH_RESPONSE so we know server received it)
        challengeChar.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
        challengeChar.value     = challenge
        if (!gatt.writeCharacteristic(challengeChar)) return false
        val writeOk = withTimeoutOrNull(BEACON_READ_TIMEOUT_MS) { challengeWriteDeferred.await() } ?: false
        if (!writeOk) {
            Diag.degraded("ble-gatt", "auth-write-failed", "Challenge GATT write failed or timed out")
            return false
        }

        // Step 4: give server time to sign (Ed25519 is fast; margin for scheduler jitter)
        delay(CHALLENGE_SIGN_DELAY_MS)

        // Step 5: read signature
        if (!gatt.readCharacteristic(responseChar)) return false
        val sig = withTimeoutOrNull(BEACON_READ_TIMEOUT_MS) { responseReadDeferred.await() }
        if (sig?.size != 64) {
            Diag.degraded("ble-gatt", "auth-sig-invalid",
                "Peer returned invalid signature size (size=${sig?.size})")
            return false
        }

        // Step 6: verify Ed25519(challenge || nodeId, ed25519Pub)
        val message = challenge + remoteNodeBytes
        return try {
            val ok = verify(message, sig, ed25519Pub)
            if (!ok) Diag.degraded("ble-gatt", "auth-sig-mismatch",
                "BLE challenge-response failed — peer may be spoofing NodeId; registration rejected")
            ok
        } catch (e: Exception) {
            Diag.swallowed("ble-gatt", "auth-verify", e)
            false
        }
    }

    private fun writeNudgeCharacteristic(gatt: BluetoothGatt, packet: ByteArray): Boolean {
        val service = gatt.getService(SHADOWMESH_SERVICE_UUID) ?: return false
        val char    = service.getCharacteristic(NUDGE_CHARACTERISTIC_UUID) ?: return false
        char.value  = packet
        char.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
        return gatt.writeCharacteristic(char)
    }

    // ── GATT server (receive nudges) ───────────────────────────────────────

    /**
     * Start the GATT server to receive nudge writes from remote devices.
     */
    fun startGattServer() {
        val server = bluetoothManager.openGattServer(context, gattServerCallback)
        gattServer = server

        val service  = BluetoothGattService(
            SHADOWMESH_SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )
        val nudgeChar = BluetoothGattCharacteristic(
            NUDGE_CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        val beaconChar = BluetoothGattCharacteristic(
            BEACON_CHARACTERISTIC_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        // Pre-populate with local NodeId so connecting clients can read it without any
        // additional exchange. The value is static for the process lifetime.
        beaconChar.value = localNodeId.bytes.copyOf()
        service.addCharacteristic(nudgeChar)
        service.addCharacteristic(beaconChar)

        // BLE Ed25519 challenge-response characteristics — only added when auth is wired.
        // ED25519_PUB: serves the 32-byte Ed25519 public key component for peer identity verification.
        // CHALLENGE:   client writes a 32-byte random nonce; server signs (nonce || nodeId) with Ed25519.
        // RESPONSE:    client reads the 64-byte Ed25519 signature; single-use per connection.
        if (localEd25519PubKey != null && signChallengeEd25519Only != null) {
            val ed25519PubChar = BluetoothGattCharacteristic(
                ED25519_PUB_CHARACTERISTIC_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            ed25519PubChar.value = localEd25519PubKey.copyOf()
            service.addCharacteristic(ed25519PubChar)

            val challengeChar = BluetoothGattCharacteristic(
                CHALLENGE_CHARACTERISTIC_UUID,
                BluetoothGattCharacteristic.PROPERTY_WRITE,
                BluetoothGattCharacteristic.PERMISSION_WRITE
            )
            service.addCharacteristic(challengeChar)

            val responseChar = BluetoothGattCharacteristic(
                RESPONSE_CHARACTERISTIC_UUID,
                BluetoothGattCharacteristic.PROPERTY_READ,
                BluetoothGattCharacteristic.PERMISSION_READ
            )
            service.addCharacteristic(responseChar)
        }

        server.addService(service)
    }

    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice, requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean, responseNeeded: Boolean,
            offset: Int, value: ByteArray
        ) {
            // Respond on the Binder thread immediately — sendResponse must not be deferred.
            if (responseNeeded) {
                gattServer?.sendResponse(device, requestId,
                    BluetoothGatt.GATT_SUCCESS, offset, null)
            }
            // Dispatch all further processing off the Binder thread.
            // onNudgeReceived and the onNudgeReceived lambda may do non-trivial
            // work (DB lookups, coroutine dispatch) that must not block the Binder pool.
            if (characteristic.uuid == NUDGE_CHARACTERISTIC_UUID &&
                (value.size == NudgeEngine.NUDGE_PACKET_SIZE ||
                 value.size == NudgeEngine.NUDGE_AUTHENTICATED_SIZE)) {
                // Accept both unauthenticated (12 B) and HMAC-authenticated (28 B) nudge packets.
                // The old check only accepted 12 bytes, silently dropping authenticated nudges
                // from upgraded peers and preventing rollout of the HMAC scheme over BLE.
                val valueCopy = value.copyOf()  // capture before Binder recycles the buffer
                scope.launch {
                    val channelHash8 = nudgeEngine.onNudgeReceived(valueCopy)
                    if (channelHash8 != null) onNudgeReceived(channelHash8)
                }
            } else if (characteristic.uuid == CHALLENGE_CHARACTERISTIC_UUID &&
                       value.size == CHALLENGE_BYTES && signChallengeEd25519Only != null) {
                // Client is authenticating us: sign (challenge || nodeId) with Ed25519.
                // Dispatch off the Binder thread — JNI crypto must not block the Binder pool.
                // Store the signature in challengeResponseMap; client reads RESPONSE_CHAR next.
                val challengeCopy = value.copyOf()
                val devAddr       = device.address
                scope.launch(Dispatchers.IO) {
                    try {
                        // Cap challengeResponseMap to prevent memory growth if many peers
                        // connect and write challenges without completing the handshake.
                        // Android's BLE stack limits concurrent connections to ~7-10, but
                        // a flood of reconnects can leave stale entries between prune cycles.
                        if (challengeResponseMap.size >= MAX_CHALLENGE_MAP_ENTRIES) {
                            Diag.fallback("ble-gatt", "challenge-map-full",
                                "challengeResponseMap full — discarding oldest entry to make room")
                            challengeResponseMap.keys.firstOrNull()
                                ?.let { challengeResponseMap.remove(it) }
                        }
                        val sig = signChallengeEd25519Only.invoke(challengeCopy + localNodeId.bytes)
                        if (sig.size == 64) challengeResponseMap[devAddr] = sig
                    } catch (e: Exception) {
                        Diag.swallowed("ble-gatt", "challenge-sign", e)
                    }
                }
            }
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice, requestId: Int, offset: Int,
            characteristic: BluetoothGattCharacteristic
        ) {
            // Respond on the Binder thread — sendResponse must not be deferred.
            when (characteristic.uuid) {
                BEACON_CHARACTERISTIC_UUID -> {
                    // Serve local NodeId bytes. Support partial reads (offset > 0) as required
                    // by the GATT spec when the value exceeds ATT_MTU - 1 bytes.
                    val value = localNodeId.bytes
                    val slice = if (offset >= value.size) ByteArray(0)
                                else value.copyOfRange(offset, value.size)
                    gattServer?.sendResponse(device, requestId,
                        BluetoothGatt.GATT_SUCCESS, offset, slice)
                }
                ED25519_PUB_CHARACTERISTIC_UUID -> {
                    // Serve the 32-byte Ed25519 public key for client-side identity verification.
                    val value = localEd25519PubKey
                    if (value != null) {
                        val slice = if (offset >= value.size) ByteArray(0)
                                    else value.copyOfRange(offset, value.size)
                        gattServer?.sendResponse(device, requestId,
                            BluetoothGatt.GATT_SUCCESS, offset, slice)
                    } else {
                        gattServer?.sendResponse(device, requestId,
                            BluetoothGatt.GATT_READ_NOT_PERMITTED, 0, null)
                    }
                }
                RESPONSE_CHARACTERISTIC_UUID -> {
                    // Return the 64-byte Ed25519 signature produced by the CHALLENGE_CHAR write.
                    // Single-use: remove so a second read returns failure (replay prevention).
                    val sig = challengeResponseMap.remove(device.address)
                    gattServer?.sendResponse(device, requestId,
                        if (sig != null) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,
                        0, sig)
                }
                else -> {
                    gattServer?.sendResponse(device, requestId,
                        BluetoothGatt.GATT_READ_NOT_PERMITTED, 0, null)
                }
            }
        }
    }

    fun stopGattServer() {
        gattServer?.close()
        gattServer = null
    }

    // ── Beacon mode ────────────────────────────────────────────────────────

    /**
     * Start beacon mode: broadcast [channelHash8] (first 8 bytes of SHA3-256(channelId))
     * in manufacturer-specific advertisement data.
     *
     * OFF by default — must be explicitly enabled by the user.
     * Design doc: disabled for military use.
     *
     * Note: when beacon is active alongside the VPN circuit, the circuit masks
     * the real IP so the beacon does not reveal network-level identity.
     */
    fun startBeacon(channelHash8: ByteArray) {
        require(channelHash8.size == NudgeEngine.CHANNEL_HASH_BYTES) {
            "Beacon channel hash must be ${NudgeEngine.CHANNEL_HASH_BYTES} bytes"
        }
        beaconChannelHash     = channelHash8
        lastBeaconChannelHash = channelHash8   // persist for resumeBeacon()
        beaconActive = true

        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
            .setConnectable(true)
            .setTimeout(0)  // advertise indefinitely
            .build()

        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(SHADOWMESH_SERVICE_UUID))
            .addManufacturerData(MANUFACTURER_ID, channelHash8)
            .setIncludeDeviceName(false)  // never include device name — privacy
            .build()

        leAdvertiser.startAdvertising(settings, data, beaconAdvertiseCallback)
    }

    fun stopBeacon() {
        beaconActive = false
        beaconChannelHash = null
        // lastBeaconChannelHash is intentionally kept — resumeBeacon() needs it.
        leAdvertiser.stopAdvertising(beaconAdvertiseCallback)
    }

    /**
     * Restart beacon using the last channel hash passed to [startBeacon].
     * Used by the NSC [RESTORE_BEACON_MODE] rollback handler to re-enable advertising
     * after a failed or rolled-back transaction that had stopped it.
     *
     * @return true if beacon was restarted; false if [startBeacon] was never called
     *         (no channel hash to advertise) or BLE hardware is unavailable.
     */
    fun resumeBeacon(): Boolean {
        val hash = lastBeaconChannelHash ?: return false
        startBeacon(hash)
        return true
    }

    private val beaconAdvertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {}
        override fun onStartFailure(errorCode: Int) {
            beaconActive = false
            Diag.degraded("ble-gatt", "beacon-start-failed",
                "BLE beacon advertise failed: errorCode=$errorCode " +
                "(1=DATA_TOO_LARGE, 2=TOO_MANY_ADVERTISERS, 3=ALREADY_STARTED, " +
                "4=INTERNAL_ERROR, 5=FEATURE_UNSUPPORTED)")
        }
    }

    fun isBeaconActive(): Boolean = beaconActive

    // ── Lifecycle ─────────────────────────────────────────────────────────

    fun close() {
        stopForegroundScan()
        stopBeacon()
        stopBackgroundScan()
        stopGattServer()
        gattClients.values.forEach { it.disconnect(); it.close() }
        gattClients.clear()
    }

    companion object {
        // Fixed UUIDs permanently assigned to SHADOWMESH. These are app-specific
        // randomly-generated v4 UUIDs (not the sequential 12345678 test pattern) and
        // MUST stay constant across versions — both peers match on the service UUID, so
        // changing them breaks discovery between different app versions. They share a
        // common high prefix purely for readability; the values are otherwise random and
        // do not collide with the well-known SIG base UUID range.
        val SHADOWMESH_SERVICE_UUID         = UUID.fromString("5d3a1f60-7c8e-4b2a-9f14-2e6b0a9c4d71")
        val NUDGE_CHARACTERISTIC_UUID       = UUID.fromString("5d3a1f61-7c8e-4b2a-9f14-2e6b0a9c4d71")
        val BEACON_CHARACTERISTIC_UUID      = UUID.fromString("5d3a1f62-7c8e-4b2a-9f14-2e6b0a9c4d71")
        // BLE Ed25519 challenge-response auth characteristics (Phase 12).
        // Absent on servers that predate this version — clients fall back to refusing registration.
        val ED25519_PUB_CHARACTERISTIC_UUID = UUID.fromString("5d3a1f63-7c8e-4b2a-9f14-2e6b0a9c4d71")
        val CHALLENGE_CHARACTERISTIC_UUID   = UUID.fromString("5d3a1f64-7c8e-4b2a-9f14-2e6b0a9c4d71")
        val RESPONSE_CHARACTERISTIC_UUID    = UUID.fromString("5d3a1f65-7c8e-4b2a-9f14-2e6b0a9c4d71")
        /** Size of the random challenge written to CHALLENGE_CHARACTERISTIC. */
        const val CHALLENGE_BYTES           = 32
        /** Margin (ms) given to the GATT server to compute Ed25519(challenge || nodeId). */
        const val CHALLENGE_SIGN_DELAY_MS   = 200L
        /**
         * Maximum entries in [challengeResponseMap].
         * Android BLE limits concurrent connections (~7-10), but repeated connect/disconnect
         * cycles can leave stale entries if the client disconnects after writing the challenge
         * but before reading the response (single-use remove in onCharacteristicReadRequest).
         * At 64 bytes/entry, 64 entries = 4 KB — well bounded.
         */
        const val MAX_CHALLENGE_MAP_ENTRIES = 64
        // 0xFFFF is the Bluetooth SIG "not assigned / for internal & testing" company
        // identifier — it never collides with a real registered vendor. Replace with a
        // member-allocated company ID only if SHADOWMESH ever registers with the SIG;
        // for an unregistered P2P app 0xFFFF is the correct, conflict-free choice.
        const val MANUFACTURER_ID         = 0xFFFF
        const val GATT_TIMEOUT_MS         = 8_000L
        /** Timeout for reading the peer's NodeId from BEACON_CHARACTERISTIC_UUID. */
        const val BEACON_READ_TIMEOUT_MS  = 2_000L
        /**
         * Duration of peer-advertisement silence (in BALANCED mode) before the foreground
         * scan drops to SCAN_MODE_LOW_POWER. Restored immediately on next peer sighting.
         */
        const val ADAPTIVE_NO_NODES_MS    = 5 * 60 * 1_000L
        /** How often the adaptive backoff job evaluates the idle window. */
        const val ADAPTIVE_CHECK_INTERVAL_MS = 60_000L
    }
}

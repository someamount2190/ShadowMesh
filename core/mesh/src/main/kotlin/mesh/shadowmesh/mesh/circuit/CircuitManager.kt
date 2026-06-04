package mesh.shadowmesh.mesh.circuit

import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.mode.NetworkMode
import mesh.shadowmesh.storage.EntryNodeMode
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference
import mesh.shadowmesh.crypto.toHex
import java.security.SecureRandom

/**
 * Circuit manager — orchestrates build, rotation, and teardown of the onion circuit.
 *
 * Entry Node Split architecture (design doc §13c.3, Phase 8):
 *   Sender → Entry → Guard → Middle → Exit → Destination
 *
 *   Entry is sender-chosen. [entryNodeStore] resolves the effective ranked preference
 *   list for the current channel — per-channel override if configured, otherwise
 *   the global list. In ASK_EACH_TIME mode, a temporary one-shot selection set by
 *   the UI via [EntryNodeStore.setTemporarySelection] is consumed instead.
 *
 *   When all preferred Entry nodes are offline and the rotator falls back to an
 *   arbitrary TRUST_PHYSICAL peer, [onEntryEvent] is called with [EntryNodeEvent.EntryOffline]
 *   so the UI can surface a notification. When no TRUST_PHYSICAL peer exists at all,
 *   [EntryNodeEvent.NoEntryAvailable] is emitted and circuit build is skipped.
 *
 * Rotation cycle: every [ROTATION_INTERVAL_MS] (10 minutes), a new circuit is built
 * BEFORE the current one is torn down.
 *
 * Degraded mode fallbacks:
 *   HEALTHY  — Entry + Guard + Middle + Exit (4-hop)
 *   DEGRADED — Entry + Guard + Exit          (3-hop, middle null)
 *   CRITICAL — Entry + Exit                  (2-hop, guard null)
 *   SURVIVAL — no circuit, direct routing
 *
 * Thread-safety: [_activeCircuit] uses AtomicReference.
 * Rotation serialised by [rotationJob].
 */
class CircuitManager(
    private val circuit:            OnionCircuit,
    private val rotator:            CircuitRoleRotator,
    private val transport:          CircuitTransport,
    private val scope:              CoroutineScope,
    private val getCandidates:      () -> List<CircuitCandidate>,
    private val entryNodeStore:     EntryNodeStore,
    private val getCurrentMode:     () -> NetworkMode,
    private val getCurrentChannel:  () -> String?,
    /** Called when an entry-node lifecycle event needs surfacing in the UI. */
    private val onEntryEvent:       (EntryNodeEvent) -> Unit = {},
    /**
     * When non-null, [rotateNow] uses [OnionCircuit.buildTelescoping] instead of
     * [OnionCircuit.build]. The telescoping path negotiates each hop's session key
     * through the already-built tunnel, hiding the circuit path from network observers.
     *
     * Set to true once all relay nodes in the deployment have been updated to support
     * telescoping (i.e. their [CircuitRelayProcessor] handles EXTEND_REQ cells).
     */
    private val telescopingEnabled: Boolean = false
) {
    private val _activeCircuit = AtomicReference<OnionCircuit.CircuitState?>(null)
    val activeCircuit: OnionCircuit.CircuitState? get() = _activeCircuit.get()

    private var rotationJob: Job? = null

    // ── Request-reply matching ────────────────────────────────────────────────
    //
    // sendWithReply() prepends an 8-byte nonce to every payload it sends and registers
    // a CompletableDeferred keyed by the nonce's hex. When the exit node processes the
    // payload and sends a reply back through the inbound path, OnionCircuitPacketRouter
    // calls onReply(nonceHex, data) which completes the deferred. The caller receives
    // the response or null on timeout.

    private val pendingReplies = ConcurrentHashMap<String, CompletableDeferred<ByteArray>>()
    private val rng = SecureRandom()

    // ── Lifecycle ─────────────────────────────────────────────────────────

    fun start() {
        rotationJob = scope.launch {
            rotateNow()
            while (isActive) {
                delay(ROTATION_INTERVAL_MS)
                rotateNow()
            }
        }
    }

    fun stop() {
        rotationJob?.cancel()
        rotationJob = null
        _activeCircuit.getAndSet(null)?.let { circuit.teardown(it) }
    }

    suspend fun forceRotate() = rotateNow()

    // ── Send ──────────────────────────────────────────────────────────────

    suspend fun send(payload: ByteArray): SendResult {
        // twoHopAvailable is false only in SURVIVAL — matches the build condition in
        // rotateNow(). Using circuitAvailable here would block 2-hop circuits built
        // during CRITICAL mode, since circuitAvailable is false in CRITICAL.
        if (!getCurrentMode().twoHopAvailable) return SendResult.NoCircuit
        val state = _activeCircuit.get() ?: return SendResult.NoCircuit
        return circuit.send(payload, state, transport)
    }

    // ── Request-reply ─────────────────────────────────────────────────────

    /**
     * Send [payload] through the circuit and wait up to [timeoutMs] for a reply.
     *
     * Prepends an 8-byte nonce to the payload. The exit node is expected to read the
     * nonce, process the request, and send a reply prefixed with the same nonce back
     * through the inbound path. [OnionCircuitPacketRouter.onCircuitResponse] strips the
     * nonce and delivers the body to the awaiting deferred by calling [onReply].
     *
     * Returns the reply body (without nonce prefix) or null on timeout/no-circuit.
     */
    suspend fun sendWithReply(payload: ByteArray, timeoutMs: Long = 10_000L): ByteArray? {
        val nonce = ByteArray(REPLY_NONCE_BYTES).also { rng.nextBytes(it) }
        val nonceHex = nonce.toHex()
        val deferred = CompletableDeferred<ByteArray>()
        pendingReplies[nonceHex] = deferred
        val framed = nonce + payload
        val result = send(framed)
        if (result !is SendResult.Sent) {
            pendingReplies.remove(nonceHex)
            return null
        }
        return try {
            withTimeout(timeoutMs) { deferred.await() }
        } catch (_: TimeoutCancellationException) {
            null
        } finally {
            pendingReplies.remove(nonceHex)
        }
    }

    /**
     * Called by [OnionCircuitPacketRouter] when an inbound circuit packet begins with
     * a nonce that matches a pending [sendWithReply] call.
     *
     * @return true if the nonce matched and the reply was consumed; false if the packet
     *         should be forwarded to the TUN sink as a normal IP response.
     */
    fun onReply(nonceHex: String, data: ByteArray): Boolean {
        val deferred = pendingReplies.remove(nonceHex) ?: return false
        deferred.complete(data)
        return true
    }

    /**
     * Register a deferred keyed by [nonce] and wait up to [timeoutMs] for a matching reply.
     *
     * Used by [OnionCircuit.buildTelescoping] for the EXTEND_ACK and EXTEND_DONE reply steps.
     * When a relay sends a CTRL_REPLY containing the same [nonce], [onReply] is called by
     * [OnionCircuitPacketRouter.onCircuitResponse] which completes this deferred.
     *
     * Unlike [sendWithReply], this method only waits — the caller is responsible for
     * sending the request cell through the circuit separately.
     *
     * Returns the reply body (bytes after the nonce prefix) or null on timeout.
     */
    suspend fun waitForReply(nonce: ByteArray, timeoutMs: Long): ByteArray? {
        val nonceHex = nonce.toHex()
        val deferred = CompletableDeferred<ByteArray>()
        pendingReplies[nonceHex] = deferred
        return try {
            withTimeout(timeoutMs) { deferred.await() }
        } catch (_: TimeoutCancellationException) {
            null
        } finally {
            pendingReplies.remove(nonceHex)
        }
    }

    // ── Internal rotation ─────────────────────────────────────────────────

    private suspend fun rotateNow() {
        val mode = getCurrentMode()
        if (!mode.twoHopAvailable) return

        val allCandidates = getCandidates()
        val channelId     = getCurrentChannel()
        val entryMode     = entryNodeStore.getMode()

        // Resolve entry preferences
        val entryPreferences: List<CircuitCandidate> = when (entryMode) {
            EntryNodeMode.ASK_EACH_TIME -> {
                val temp = entryNodeStore.consumeTemporarySelection()
                if (temp != null) {
                    listOf(temp)
                } else {
                    // No temporary selection — emit PickRequired with the actual stored
                    // preferences so the picker UI shows names the user assigned
                    // ("Alice"), not hex-truncated node IDs ("1a2b3c4d…").
                    val storedPrefs = entryNodeStore.effectiveStoredPreferencesForChannel(channelId)
                    onEntryEvent(EntryNodeEvent.PickRequired(storedPrefs))
                    return
                }
            }
            EntryNodeMode.AUTOMATIC -> {
                entryNodeStore.effectivePreferencesForChannel(
                    channelId,
                    allCandidates.associateBy { it.nodeId.bytes.toHex() }
                )
            }
        }

        // Mode-driven topology:
        //   HEALTHY / DEGRADED: circuitAvailable=true → 4-hop (rotator decides 3-hop
        //                       if middle pool is empty)
        //   CRITICAL:           circuitAvailable=false, twoHopAvailable=true → 2-hop
        //                       forceNoGuard=true ensures guard=null regardless of pool size
        //   SURVIVAL:           twoHopAvailable=false → already returned above
        val selection = rotator.selectNextCircuit(
            candidates       = allCandidates,
            entryPreferences = entryPreferences,
            forceNoGuard     = !mode.circuitAvailable,
            forceNoMiddle    = !mode.circuitAvailable
        )

        if (selection == null) {
            onEntryEvent(EntryNodeEvent.NoEntryAvailable)
            return
        }

        val preferredIds    = entryPreferences.map { it.nodeId.bytes.toHex() }.toSet()
        val selectedEntryId = selection.entry.nodeId.bytes.toHex()
        if (preferredIds.isNotEmpty() && selectedEntryId !in preferredIds) {
            val fallbackName = allCandidates.find { it.nodeId.bytes.toHex() == selectedEntryId }
                ?.nodeId?.toHex()?.take(8)?.plus("…") ?: "unknown"
            onEntryEvent(EntryNodeEvent.EntryOffline(fallbackName))
        }

        val result = if (telescopingEnabled) {
            // Telescoping: each hop beyond Entry is negotiated through the tunnel.
            // awaitReply is backed by waitForReply — the relay's CTRL_REPLY fires onReply
            // which completes the deferred registered here.
            circuit.buildTelescoping(
                entry      = selection.entry,
                guard      = selection.guard,
                middle     = selection.middle,
                exit       = selection.exit,
                transport  = transport,
                awaitReply = { nonce, timeoutMs -> waitForReply(nonce, timeoutMs) }
            )
        } else {
            // Non-telescoping (legacy): all hop KEM handshakes are performed directly.
            circuit.build(
                entry     = selection.entry,
                guard     = selection.guard,
                middle    = selection.middle,
                exit      = selection.exit,
                transport = transport
            )
        }

        if (result is BuildResult.Success) {
            val old = _activeCircuit.getAndSet(result.circuit)
            old?.let { circuit.teardown(it) }
        }
    }

    fun isCircuitActive(): Boolean = _activeCircuit.get() != null
    fun currentCircuitId(): String? = _activeCircuit.get()?.id

    fun currentTopology(): String = when {
        !isCircuitActive()                       -> "none"
        _activeCircuit.get()?.is4Hop == true     -> "4-hop"
        _activeCircuit.get()?.is3Hop == true     -> "3-hop"
        else                                     -> "2-hop"
    }

    // Extension on NodeId for hex conversion used in this file

    companion object {
        const val ROTATION_INTERVAL_MS = 10 * 60 * 1000L  // 10 minutes
        /** Size of the per-reply nonce prepended by [sendWithReply]. Must match the extraction
         *  offset in [OnionCircuitPacketRouter.onCircuitResponse]. 16 bytes = 128-bit collision
         *  resistance; 8 bytes (old) was safe for low concurrency but unnecessarily tight. */
        const val REPLY_NONCE_BYTES = 16
    }
}

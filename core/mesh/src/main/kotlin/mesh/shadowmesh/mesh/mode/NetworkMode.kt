package mesh.shadowmesh.mesh.mode

/**
 * Network mode state machine — design doc Phase 6.
 *
 * Four modes based on active anchor node count:
 *
 *   HEALTHY   — ≥15 anchors: full DHT, 4-hop circuit (Entry+Guard+Middle+Exit), SNDP enabled, replication 3
 *   DEGRADED  — 8–14 anchors: reduced features, replication 5, SNDP at 5% (vs 10%)
 *   CRITICAL  — 4–7  anchors: no full circuit, 2-hop fallback (Entry+Exit only), replication all available
 *   SURVIVAL  — 1–3  anchors: direct only, no cover traffic, SNDP disabled
 *
 * Transitions are hysteretic: a 20% hysteresis band prevents rapid oscillation
 * when node count hovers near a threshold. Entry threshold < exit threshold.
 *
 * Thread-safety: all mutations synchronized on [this]. Reads are @Volatile.
 */
class NetworkModeStateMachine(
    initialAnchorCount: Int = 0
) {
    @Volatile var currentMode: NetworkMode = computeMode(initialAnchorCount)
        private set

    @Volatile var anchorCount: Int = initialAnchorCount
        private set

    // Listeners notified on every mode transition
    private val listeners = mutableListOf<(from: NetworkMode, to: NetworkMode) -> Unit>()

    // ── Mode update ────────────────────────────────────────────────────────

    /**
     * Update the anchor count and recompute mode.
     * Returns the new mode; fires listeners if a transition occurred.
     */
    @Synchronized
    fun onAnchorCountChanged(newCount: Int): NetworkMode {
        val prev = currentMode
        anchorCount = newCount
        val next = computeMode(newCount, prev)
        if (next != prev) {
            currentMode = next
            // Snapshot the listener list before iterating. A listener that calls
            // addListener() during dispatch would modify the underlying ArrayList while
            // the iterator is active, causing ConcurrentModificationException. The
            // snapshot ensures iteration is safe even under reentrant addListener calls.
            val snapshot = listeners.toList()
            snapshot.forEach { it(prev, next) }
        }
        return currentMode
    }

    fun addListener(listener: (from: NetworkMode, to: NetworkMode) -> Unit) {
        synchronized(this) { listeners.add(listener) }
    }

    /**
     * Force a specific mode regardless of the anchor count.
     * Used by NSC rollback handlers (RESTORE_NETWORK_MODE opcode) to revert a previously
     * committed network-mode transition. Fires mode listeners just like [onAnchorCountChanged].
     *
     * Note: the forced mode will be overwritten by the next [onAnchorCountChanged] call.
     * The NSC rollback assumes the anchor count state will be consistent with the reverted mode;
     * if it is not, the mode will self-correct on the next anchor-count update.
     */
    @Synchronized
    fun forceMode(mode: NetworkMode) {
        val prev = currentMode
        if (mode == prev) return
        currentMode = mode
        listeners.toList().forEach { it(prev, mode) }
    }

    // ── Mode capabilities ──────────────────────────────────────────────────

    /** Current replication factor — increases as mode degrades. */
    val replicationFactor: Int get() = currentMode.replicationFactor

    /** Whether the full 4-hop circuit (Entry+Guard+Middle+Exit) is available. False in CRITICAL/SURVIVAL. */
    val circuitAvailable: Boolean get() = currentMode.circuitAvailable

    /** Whether a 2-hop fallback circuit (Entry+Exit) is available. False only in SURVIVAL. */
    val twoHopAvailable: Boolean get() = currentMode.twoHopAvailable

    /** Whether SNDP cover traffic is enabled. */
    val sndpEnabled: Boolean get() = currentMode.sndpEnabled

    /** SNDP fire rate per sync cycle (fraction of posts that trigger fake traffic). */
    val sndpRate: Float get() = currentMode.sndpRate

    /** Whether the DHT is operational in current mode. */
    val dhtOperational: Boolean get() = currentMode.dhtOperational

    /** Peer selection mode for current network mode. */
    val peerSelectionMode: PeerSelectionMode get() = currentMode.peerSelectionMode

    // ── Threshold computation with hysteresis ─────────────────────────────

    /**
     * Compute the mode for [count] anchors, given [prev] mode for hysteresis.
     *
     * Threshold table (entry = transition INTO mode on drop, exit = transition OUT on rise):
     *
     *   Mode      | Entry (drop below) | Exit (rise to)
     *   ----------|--------------------|----------------
     *   HEALTHY   |        15          |       15
     *   DEGRADED  |         8          |       10
     *   CRITICAL  |         4          |        6
     *   SURVIVAL  |         1          |        2
     *
     * Hysteresis: to leave a lower mode UPWARD, the count must reach the EXIT threshold,
     * which is higher than the ENTRY threshold that caused the descent. This prevents
     * rapid oscillation near a boundary.
     *
     * Downward transitions (degradation): intentionally unrestricted — a sudden drop
     * from 15 anchors to 0 (network partition, mass node failure) must immediately
     * move to SURVIVAL. Gradual step-down would leave the node in HEALTHY mode trying
     * to use DHT routing that no longer exists. The SNDP/circuit teardown on SURVIVAL
     * entry is the correct emergency response.
     *
     * Upward transitions (recovery): monotone per call — never skip more than one mode
     * up per [onAnchorCountChanged] call. This prevents a brief count spike from
     * prematurely re-enabling features that need time to stabilize.
     */
    private fun computeMode(count: Int, prev: NetworkMode = NetworkMode.SURVIVAL): NetworkMode {
        return when (prev) {
            NetworkMode.SURVIVAL  -> when {
                // Upward recovery: one step at a time (SURVIVAL → CRITICAL → DEGRADED → HEALTHY).
                // A sudden anchor count spike must not re-enable full DHT/circuit until the mesh
                // has demonstrated stability at each intermediate level.
                count >= SURVIVAL_EXIT_THRESHOLD  -> NetworkMode.CRITICAL  // one step up
                else                              -> NetworkMode.SURVIVAL
            }
            NetworkMode.CRITICAL  -> when {
                count >= DEGRADED_EXIT_THRESHOLD  -> NetworkMode.DEGRADED  // one step up
                count >= CRITICAL_ENTRY_THRESHOLD -> NetworkMode.CRITICAL
                else                              -> NetworkMode.SURVIVAL
            }
            NetworkMode.DEGRADED  -> when {
                count >= HEALTHY_EXIT_THRESHOLD   -> NetworkMode.HEALTHY
                count >= DEGRADED_ENTRY_THRESHOLD -> NetworkMode.DEGRADED
                count >= CRITICAL_EXIT_THRESHOLD  -> NetworkMode.CRITICAL
                else                              -> NetworkMode.SURVIVAL
            }
            NetworkMode.HEALTHY   -> when {
                count >= HEALTHY_EXIT_THRESHOLD   -> NetworkMode.HEALTHY
                count >= DEGRADED_EXIT_THRESHOLD  -> NetworkMode.DEGRADED
                count >= CRITICAL_EXIT_THRESHOLD  -> NetworkMode.CRITICAL
                else                              -> NetworkMode.SURVIVAL
            }
        }
    }

    companion object {
        // Entry thresholds (transition INTO this mode when dropping below)
        const val HEALTHY_ENTRY_THRESHOLD   = 15
        const val DEGRADED_ENTRY_THRESHOLD  = 8
        const val CRITICAL_ENTRY_THRESHOLD  = 4
        const val SURVIVAL_ENTRY_THRESHOLD  = 1

        // Exit thresholds (hysteresis — must reach this to leave the mode upward)
        const val HEALTHY_EXIT_THRESHOLD    = 15
        const val DEGRADED_EXIT_THRESHOLD   = 10  // 25% hysteresis above 8
        const val CRITICAL_EXIT_THRESHOLD   = 6   // 50% hysteresis above 4
        const val SURVIVAL_EXIT_THRESHOLD   = 2   // 100% hysteresis above 1
    }
}

// ── Mode definitions ──────────────────────────────────────────────────────────

enum class NetworkMode(
    val replicationFactor:  Int,
    val circuitAvailable:   Boolean,
    val twoHopAvailable:    Boolean,
    val sndpEnabled:        Boolean,
    val sndpRate:           Float,
    val dhtOperational:     Boolean,
    val peerSelectionMode:  PeerSelectionMode
) {
    HEALTHY(
        replicationFactor  = 3,
        circuitAvailable   = true,
        twoHopAvailable    = true,
        sndpEnabled        = true,
        sndpRate           = 0.10f,
        dhtOperational     = true,
        peerSelectionMode  = PeerSelectionMode.STANDARD
    ),
    DEGRADED(
        replicationFactor  = 5,
        circuitAvailable   = true,
        twoHopAvailable    = true,
        sndpEnabled        = true,
        sndpRate           = 0.05f,
        dhtOperational     = true,
        peerSelectionMode  = PeerSelectionMode.STANDARD
    ),
    CRITICAL(
        replicationFactor  = Int.MAX_VALUE,  // all available nodes
        circuitAvailable   = false,
        twoHopAvailable    = true,
        sndpEnabled        = false,
        sndpRate           = 0f,
        dhtOperational     = true,           // degraded DHT only
        peerSelectionMode  = PeerSelectionMode.OPERATIONAL
    ),
    SURVIVAL(
        replicationFactor  = Int.MAX_VALUE,
        circuitAvailable   = false,
        twoHopAvailable    = false,
        sndpEnabled        = false,
        sndpRate           = 0f,
        dhtOperational     = false,
        peerSelectionMode  = PeerSelectionMode.OPERATIONAL
    );

    /** Human-readable description of what's disabled in this mode. */
    fun degradationSummary(): String = buildString {
        if (!circuitAvailable) append("Circuit unavailable. ")
        if (!twoHopAvailable)  append("2-hop fallback unavailable. ")
        if (!sndpEnabled)      append("Cover traffic disabled. ")
        if (!dhtOperational)   append("DHT unavailable — direct peers only. ")
        if (isEmpty()) append("All features operational.")
    }
}

enum class PeerSelectionMode {
    /** Pure random + cover traffic, 0-500ms delay. Full anonymity. */
    OPERATIONAL,
    /** Latency-weighted top 50% + 20% random. Balanced. */
    STANDARD,
    /** Pure random + mix enabled. Maximum anonymity, higher latency. */
    MAXIMUM_SECURITY,
    /** Fastest available peers. No cover. Anonymity sacrificed. */
    EMERGENCY
}

package mesh.shadowmesh.mesh.delivery

import mesh.shadowmesh.mesh.mode.NetworkMode

/**
 * Density-aware replication policy — Phase 8 extension.
 *
 * Problem:
 *   [NetworkMode.replicationFactor] is purely mode-based: HEALTHY=3, DEGRADED=5.
 *   It does not account for local peer density. In a dense cluster (10+ devices
 *   on the same LAN or within WiFi Direct range), fragments already exist on many
 *   nearby nodes naturally. Replicating to 5 DHT anchors in that scenario wastes
 *   bandwidth and storage on remote nodes that will rarely be the fastest path.
 *
 *   In a sparse deployment (2 devices, no local peers), the mode-based factor
 *   correctly forces high replication to ensure durability. In a dense deployment,
 *   it over-replicates to the DHT at the expense of local capacity.
 *
 * Solution:
 *   Observe the number of locally-visible peers (WiFi Direct + LAN + BLE) and
 *   reduce the DHT replication factor when local density is high. The local peers
 *   implicitly hold copies because the [FragmentFetcher] pushes fragments to them
 *   proactively and gossip propagates further.
 *
 * Density signal:
 *   Local peer count from [LocalPeerRegistry.allLocalPeers()].
 *   These are only peers reachable via radio/LAN — no IP inference, no geolocation.
 *   A count of N means N devices are physically within radio range.
 *
 * Replication factor table:
 *
 *   Network mode │ Local peers │ Effective factor │ Rationale
 *   ─────────────┼─────────────┼──────────────────┼────────────────────────────────
 *   HEALTHY      │ 0           │ 3                │ No local density — full DHT
 *   HEALTHY      │ 1–4         │ 3                │ Small cluster — keep full DHT
 *   HEALTHY      │ 5–9         │ 2                │ Medium cluster — local holds copies
 *   HEALTHY      │ ≥10         │ 1                │ Dense cluster — one DHT anchor backup
 *   DEGRADED     │ 0           │ 5                │ Sparse — maximum DHT replication
 *   DEGRADED     │ 1–4         │ 4                │ Small cluster — slight reduction
 *   DEGRADED     │ 5–9         │ 3                │ Medium cluster
 *   DEGRADED     │ ≥10         │ 2                │ Dense cluster — still keep 2 DHT backups
 *   CRITICAL     │ any         │ all available    │ Durability overrides density
 *   SURVIVAL     │ any         │ all available    │ Durability overrides density
 *
 * Hysteresis:
 *   Density is smoothed with an exponential moving average (EMA) over
 *   [SMOOTHING_FACTOR] observations. This prevents rapid oscillation when a
 *   single device briefly disconnects and reconnects.
 *
 *   EMA formula:  smoothed = α × new_count + (1 − α) × smoothed
 *   where α = [SMOOTHING_FACTOR] = 0.3 (lower = slower response, higher = faster)
 *
 *   The smoothed count is used for threshold comparisons, not the raw count.
 *   This means the factor changes gradually when peer count changes, not
 *   instantaneously on every observation.
 *
 * Privacy:
 *   The density observation is strictly local — only this node's radio neighbourhood.
 *   The computed replication factor is never gossiped. Each node computes its own
 *   factor independently from its own local peer list.
 *
 * Thread-safety: [update] updates [smoothedDensity] and is called from the sync
 * coordinator. If called concurrently, the EMA update is not atomic — two concurrent
 * updates could both read the same [smoothedDensity] and write different results.
 * Since density updates happen once per sync cycle (15s) from a single coordinator,
 * concurrent calls are not expected. Documented for clarity.
 */
class DensityAwareReplicationPolicy(
    /** EMA smoothing factor α — lower = slower response to density changes. */
    private val smoothingFactor: Double = SMOOTHING_FACTOR
) {
    /** EMA-smoothed local peer count. Starts at 0 (no density observed). */
    @Volatile private var smoothedDensity: Double = 0.0

    // ── Primary API ───────────────────────────────────────────────────────

    /**
     * Compute the effective replication factor for this sync cycle.
     *
     * @param mode           Current [NetworkMode].
     * @param localPeerCount Raw count of locally-visible peers from [LocalPeerRegistry].
     *                       This is the number of devices reachable via WiFi Direct, LAN,
     *                       or BLE — no IP inference required.
     * @return The replication factor to use for [StoreAndForwardManager.replicate].
     */
    fun effectiveFactor(mode: NetworkMode, localPeerCount: Int): Int {
        // CRITICAL and SURVIVAL: durability always overrides density
        if (mode == NetworkMode.CRITICAL || mode == NetworkMode.SURVIVAL) {
            return mode.replicationFactor  // Int.MAX_VALUE = all available
        }

        // Update EMA
        smoothedDensity = smoothingFactor * localPeerCount + (1.0 - smoothingFactor) * smoothedDensity
        val density = smoothedDensity.toInt()

        return when (mode) {
            NetworkMode.HEALTHY -> when {
                density >= DENSE_THRESHOLD  -> HEALTHY_DENSE_FACTOR
                density >= MEDIUM_THRESHOLD -> HEALTHY_MEDIUM_FACTOR
                else                        -> HEALTHY_SPARSE_FACTOR
            }
            NetworkMode.DEGRADED -> when {
                density >= DENSE_THRESHOLD  -> DEGRADED_DENSE_FACTOR
                density >= MEDIUM_THRESHOLD -> DEGRADED_MEDIUM_FACTOR
                density >= SMALL_THRESHOLD  -> DEGRADED_SMALL_FACTOR
                else                        -> DEGRADED_SPARSE_FACTOR
            }
            else -> mode.replicationFactor  // CRITICAL/SURVIVAL already handled above
        }
    }

    /**
     * Update the smoothed density without computing a factor.
     * Call at the start of each sync cycle to keep the EMA current even when
     * no replication is happening (e.g., no posts published this cycle).
     */
    fun updateDensity(localPeerCount: Int) {
        smoothedDensity = smoothingFactor * localPeerCount + (1.0 - smoothingFactor) * smoothedDensity
    }

    /** Current smoothed density value — for diagnostics and tests. */
    fun smoothedPeerCount(): Double = smoothedDensity

    /** Reset smoothed density to zero — call on first launch or after a long offline period. */
    fun reset() { smoothedDensity = 0.0 }

    companion object {
        const val SMOOTHING_FACTOR     = 0.3   // EMA α

        // Density thresholds (smoothed peer count)
        const val DENSE_THRESHOLD      = 10
        const val MEDIUM_THRESHOLD     = 5
        const val SMALL_THRESHOLD      = 1

        // HEALTHY mode factors
        const val HEALTHY_DENSE_FACTOR  = 1   // Dense: one DHT backup; local has many copies
        const val HEALTHY_MEDIUM_FACTOR = 2   // Medium cluster
        const val HEALTHY_SPARSE_FACTOR = 3   // Default: no local density (matches NetworkMode.HEALTHY)

        // DEGRADED mode factors (always ≥ 2 — keep two DHT backups even in dense clusters)
        const val DEGRADED_DENSE_FACTOR   = 2
        const val DEGRADED_MEDIUM_FACTOR  = 3
        const val DEGRADED_SMALL_FACTOR   = 4
        const val DEGRADED_SPARSE_FACTOR  = 5  // Default (matches NetworkMode.DEGRADED)

        // Minimum guaranteed replication — never go below this regardless of density
        const val MINIMUM_FACTOR = 1
    }
}

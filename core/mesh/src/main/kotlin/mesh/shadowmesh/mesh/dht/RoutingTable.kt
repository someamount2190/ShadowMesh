package mesh.shadowmesh.mesh.dht

/**
 * Kademlia routing table — design doc §4 "Custom Kademlia DHT, Tier 1 anchor nodes only".
 *
 * Maintains 256 k-buckets indexed by XOR distance from [localNodeId].
 * Only Tier 1 anchor nodes are admitted to the routing table — Tier 2/3
 * nodes may be used for direct communication but do not get routing slots.
 *
 * Bucket index = position of the highest set bit in XOR(localId, peerId).
 * Bucket 0 = furthest peers (first bit differs), bucket 255 = closest (last bit).
 *
 * Eclipse defence: [RoutingTableDiversityGuard] checks XOR density before
 * each insertion. Contacts that create a soft density spike are admitted as
 * Probationary and excluded from primary routing preference. Contacts that
 * create an extreme density spike are hard-rejected and trigger [onEclipseAlert].
 *
 * Thread-safety: synchronized on [this] for all mutations.
 * Read operations (findClosest, contains) also synchronized for consistency.
 */
class RoutingTable(
    val localNodeId:    NodeId,
    /**
     * Called when [RoutingTableDiversityGuard] detects an extreme XOR density spike.
     * The caller should log, escalate to HardenedChallengeLayer, and optionally
     * trigger a DHT lookup over disjoint paths to verify the local routing table
     * is not already partially eclipsed.
     */
    private val onEclipseAlert: (candidate: DhtContact, verdict: DiversityVerdict.Rejected) -> Unit = { _, _ -> }
) {

    private val buckets       = Array(NUM_BUCKETS) { KBucket() }
    // Tracks probationary contacts: present in routing table but excluded from
    // primary routing. Cleared when the contact is removed or promoted.
    private val probationary  = mutableSetOf<NodeId>()

    // ── Sequence number replay protection ─────────────────────────────────
    //
    // Maps nodeId → highest seq observed for that node. A contact update with a seq
    // lower than or equal to the recorded value is a replay (stale or forged) and is
    // rejected before any bucket logic runs.
    //
    // The map is keyed by NodeId using content-based equality (NodeId.equals is content-based).
    // Entries are removed when the contact is removed from the routing table.
    private val seqTable = HashMap<NodeId, Long>()

    // ── Insert / update ───────────────────────────────────────────────────

    /**
     * Attempt to insert [contact] into the routing table.
     *
     * Only Tier 1 anchors are accepted (design doc §4 constraint).
     * Runs [RoutingTableDiversityGuard] before inserting — see [DiversityVerdict].
     *
     * Returns [InsertResult] indicating whether the contact was inserted,
     * updated, flagged as probationary, rejected by the diversity guard,
     * or whether a ping is needed for the LRS contact.
     */
    /**
     * Attempt to insert [contact] into the routing table.
     *
     * The [onEclipseAlert] callback is invoked OUTSIDE the internal lock to prevent
     * deadlock: if the callback acquires any lock that is also held by a thread calling
     * insert(), a deadlock would result. Splitting the lock scope from the callback scope
     * ensures the two do not interact.
     */
    fun insert(contact: DhtContact): InsertResult {
        // Phase 1: all routing-table mutations under the lock.
        var eclipseRejection: Pair<DhtContact, DiversityVerdict.Rejected>? = null
        val result = synchronized(this) { insertLocked(contact).also { r ->
            // If the diversity guard rejected the contact, capture it for the callback.
            // We cannot fire onEclipseAlert inside the lock (deadlock risk), so we capture
            // the rejection data and fire it below after the lock is released.
            if (r is InsertResult._EclipseRejected) {
                @Suppress("UNCHECKED_CAST")
                eclipseRejection = r.contact to r.verdict
            }
        }}
        // Phase 2: fire alert outside the lock.
        eclipseRejection?.let { (c, v) -> onEclipseAlert(c, v) }
        // Unwrap internal marker type to the public result type.
        return if (result is InsertResult._EclipseRejected)
            InsertResult.Rejected(result.reason) else result
    }

    @Synchronized
    private fun insertLocked(contact: DhtContact): InsertResult {
        if (!contact.isTier1Anchor()) return InsertResult.Rejected("Not a Tier 1 anchor")

        val idx = localNodeId.bucketIndex(contact.nodeId)
        if (idx < 0) return InsertResult.Rejected("Cannot insert self")

        // ── Sequence number replay protection ──────────────────────────────
        val knownSeq = seqTable[contact.nodeId]
        if (knownSeq != null && contact.seq <= knownSeq) {
            return InsertResult.Rejected(
                "Stale seq ${contact.seq} ≤ known seq $knownSeq for ${contact.nodeId}"
            )
        }

        // ── Eclipse defence ───────────────────────────────────────────────
        val verdict = RoutingTableDiversityGuard.check(this, contact)
        when (verdict) {
            is DiversityVerdict.Rejected -> {
                val reason = "XOR density spike: ${verdict.observed} contacts in " +
                    "${verdict.prefixBits}-bit prefix region " +
                    "(expected ${String.format("%.1f", verdict.expected)}, " +
                    "${String.format("%.1f", verdict.sigmasAbove)}σ above)"
                // Use _EclipseRejected sentinel so insert() can fire the callback outside the lock.
                return InsertResult._EclipseRejected(contact, verdict, reason)
            }
            is DiversityVerdict.Probationary -> probationary.add(contact.nodeId)
            DiversityVerdict.OK             -> probationary.remove(contact.nodeId)
        }

        val bucket     = buckets[idx]
        val pingTarget = bucket.insertOrUpdate(contact)
        seqTable[contact.nodeId] = contact.seq
        return if (pingTarget == null) {
            if (verdict is DiversityVerdict.Probationary)
                InsertResult.InsertedProbationary(verdict)
            else
                InsertResult.Inserted
        } else {
            InsertResult.PingRequired(pingTarget)
        }
    }

    /**
     * Called when a ping to [lrsContact] times out — evict and insert [newContact].
     *
     * Returns true if the eviction proceeded, false if aborted. Aborts when:
     *   - [lrsContact] is no longer the LRS in the bucket (it was evicted by a
     *     concurrent [remove] or a prior [evictAndInsert] during the ping window).
     *
     * Without this guard, a contact that responded to a ping (or was removed) between
     * the [InsertResult.PingRequired] return and this call would be displaced without
     * a liveness check, silently losing an active route.
     */
    @Synchronized
    fun evictAndInsert(bucketIdx: Int, lrsContact: DhtContact, newContact: DhtContact): Boolean {
        val currentLrs = buckets[bucketIdx].lrsContact()
        if (currentLrs?.nodeId != lrsContact.nodeId) return false

        seqTable.remove(lrsContact.nodeId)
        probationary.remove(lrsContact.nodeId)
        buckets[bucketIdx].evictAndInsert(newContact)
        return true
    }

    // ── Lookup ────────────────────────────────────────────────────────────

    /**
     * Find the [count] contacts closest to [target] in XOR space.
     * Returns at most [count] contacts sorted by increasing XOR distance.
     *
     * Probationary contacts are deprioritised: non-probationary contacts fill
     * the result first; probationary contacts are appended only if needed to
     * reach [count]. This implements S/Kademlia's disjoint-path strategy —
     * probationary contacts can still serve as alternate path candidates but
     * don't dominate primary routing.
     */
    @Synchronized
    fun findClosest(target: NodeId, count: Int = K): List<DhtContact> {
        val all = buckets.flatMap { it.getAll() }
        val sorted = all.sortedWith(XorDistanceComparator(target))
        // Primary contacts first, then probationary backfill
        val primary      = sorted.filter { it.nodeId !in probationary }
        val probationaries = sorted.filter { it.nodeId in probationary }
        return (primary + probationaries).take(count)
    }

    /**
     * Find closest contacts using [disjointPaths] independent paths, as per S/Kademlia.
     * Each path starts from a distinct seed contact and claims contacts exclusively —
     * a contact used by one path cannot be used by another. This ensures lookup
     * success even when some fraction of routing table contacts are adversarial.
     *
     * Returns up to [count] contacts per path, deduplicated across paths.
     * The union of all path results is returned sorted by distance.
     *
     * @param disjointPaths Number of independent paths (S/Kademlia recommends d=4).
     */
    @Synchronized
    fun findClosestDisjoint(
        target:        NodeId,
        count:         Int = K,
        disjointPaths: Int = DISJOINT_PATHS
    ): List<DhtContact> {
        // FIX (Bug 4): true S/Kademlia disjoint paths.
        //
        // Original bug: all paths walked the globally-sorted list from the front,
        // so path 2 always started at position K/disjointPaths in the same list as
        // path 1. An eclipse attacker filling the top positions still dominated all
        // paths simultaneously.
        //
        // Fix: assign each path a distinct seed drawn from different XOR distance
        // quantiles. Each path then claims contacts closest to ITS seed, walking
        // a different region of the key space. An attacker must eclipse all
        // disjointPaths quantiles simultaneously — much harder.
        val primaryContacts = buckets.flatMap { it.getAll() }
            .filter { it.nodeId !in probationary }
            .sortedWith(XorDistanceComparator(target))
        val probationaryContacts = buckets.flatMap { it.getAll() }
            .filter { it.nodeId in probationary }
            .sortedWith(XorDistanceComparator(target))

        if (primaryContacts.isEmpty()) {
            return probationaryContacts.take(count)
        }

        val claimed = mutableSetOf<NodeId>()
        val results = mutableListOf<DhtContact>()

        // Select seeds from evenly-spaced quantile positions in the primary list.
        // Each seed represents a distinct starting point in the key-space ordering.
        val perPath = (count / disjointPaths).coerceAtLeast(1)
        val stride  = (primaryContacts.size / disjointPaths).coerceAtLeast(1)

        for (pathIdx in 0 until disjointPaths) {
            // Seed: pick from a quantile of the sorted list to spread starting points
            val seedIdx = (pathIdx * stride).coerceAtMost(primaryContacts.size - 1)
            val seed = primaryContacts[seedIdx]
            if (seed.nodeId in claimed) continue

            claimed.add(seed.nodeId)
            results.add(seed)

            // Walk outward from the seed's XOR distance — take the next closest
            // unclaimed contacts using a comparator anchored on the seed's distance.
            // This makes each path's selection independent of other paths' starting points.
            val pathComparator = XorDistanceComparator(seed.nodeId)
            val remaining = primaryContacts
                .filter { it.nodeId !in claimed }
                .sortedWith(pathComparator)

            var taken = 1
            for (c in remaining) {
                if (taken >= perPath) break
                if (c.nodeId !in claimed) {
                    claimed.add(c.nodeId)
                    results.add(c)
                    taken++
                }
            }
        }

        // Backfill with probationary contacts if needed to reach [count]
        if (results.size < count) {
            probationaryContacts
                .filter { it.nodeId !in claimed }
                .take(count - results.size)
                .forEach { results.add(it) }
        }

        return results.sortedWith(XorDistanceComparator(target)).take(count)
    }

    /** Returns true if [nodeId] is probationary (density-flagged). */
    @Synchronized
    fun isProbationary(nodeId: NodeId): Boolean = nodeId in probationary

    /** Returns the [K] contacts in the bucket for [target]. */
    @Synchronized
    fun bucket(target: NodeId): List<DhtContact> {
        val idx = localNodeId.bucketIndex(target)
        return if (idx < 0) emptyList() else buckets[idx].getAll()
    }

    // ── Maintenance ───────────────────────────────────────────────────────

    /** Mark a contact as recently seen (moves to tail of its bucket). */
    @Synchronized
    fun touch(nodeId: NodeId, nowMs: Long = System.currentTimeMillis()) {
        val idx = localNodeId.bucketIndex(nodeId)
        if (idx >= 0) buckets[idx].touch(nodeId, nowMs)
    }

    /** Remove a contact (confirmed dead / demoted from Tier 1). */
    @Synchronized
    fun remove(nodeId: NodeId) {
        val idx = localNodeId.bucketIndex(nodeId)
        if (idx >= 0) buckets[idx].remove(nodeId)
        probationary.remove(nodeId)
        seqTable.remove(nodeId)
    }

    /** Returns true if [nodeId] is in the routing table. */
    @Synchronized
    fun contains(nodeId: NodeId): Boolean {
        val idx = localNodeId.bucketIndex(nodeId)
        return idx >= 0 && buckets[idx].contains(nodeId)
    }

    /** Total number of contacts across all buckets. */
    @Synchronized
    fun size(): Int = buckets.sumOf { it.size() }

    /** All contacts in the routing table. */
    @Synchronized
    fun allContacts(): List<DhtContact> = buckets.flatMap { it.getAll() }

    /** Contacts whose lastSeen is older than [staleThresholdMs] ago. */
    @Synchronized
    fun staleContacts(
        nowMs:            Long = System.currentTimeMillis(),
        staleThresholdMs: Long = STALE_THRESHOLD_MS
    ): List<DhtContact> =
        allContacts().filter { nowMs - it.lastSeenMs > staleThresholdMs }

    /**
     * Atomically verify staleness and remove. Eliminates the TOCTOU between calling
     * [staleContacts] and a separate [remove]: if a contact was touched (refreshed)
     * between the snapshot and the eviction, this method sees the fresh [lastSeenMs]
     * and leaves the contact in place.
     *
     * Callers should replace the staleContacts+remove pattern with this method.
     *
     * @return true if the contact was stale and removed; false if absent or still fresh.
     */
    @Synchronized
    fun removeIfStale(
        nodeId:           NodeId,
        nowMs:            Long = System.currentTimeMillis(),
        staleThresholdMs: Long = STALE_THRESHOLD_MS
    ): Boolean {
        val idx = localNodeId.bucketIndex(nodeId)
        if (idx < 0) return false
        val contact = buckets[idx].find(nodeId) ?: return false
        if (nowMs - contact.lastSeenMs <= staleThresholdMs) return false
        buckets[idx].remove(nodeId)
        probationary.remove(nodeId)
        seqTable.remove(nodeId)
        return true
    }

    companion object {
        const val STALE_THRESHOLD_MS = 15 * 60 * 1000L  // 15 minutes
        /** S/Kademlia recommended disjoint path count for 99% lookup success at 20% adversarial nodes. */
        const val DISJOINT_PATHS = 4
    }
}

sealed class InsertResult {
    object Inserted                                             : InsertResult()
    /** Inserted but flagged as probationary due to XOR density spike. */
    data class InsertedProbationary(val verdict: DiversityVerdict.Probationary) : InsertResult()
    data class PingRequired(val lrs: DhtContact)               : InsertResult()
    data class Rejected(val reason: String)                    : InsertResult()

    /**
     * Internal sentinel: eclipse-rejected. Used by [RoutingTable.insertLocked] to signal
     * that the diversity guard hard-rejected the contact AND that [RoutingTable.insert]
     * must fire [RoutingTable.onEclipseAlert] OUTSIDE the synchronized lock before returning
     * a public [Rejected] result to the caller. Never exposed beyond RoutingTable.
     */
    internal data class _EclipseRejected(
        val contact: DhtContact,
        val verdict: DiversityVerdict.Rejected,
        val reason:  String
    ) : InsertResult()
}


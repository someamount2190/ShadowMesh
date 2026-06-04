package mesh.shadowmesh.mesh.delivery

import mesh.shadowmesh.mesh.fragment.FragmentEntity
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.diagnostics.Diag

/**
 * Distributed retransmission manager — design doc §8.
 *
 * Relay nodes retain a copy of every fragment they forward for
 * [FragmentEntity.RELAY_HOLD_MS] (2 hours). When a NACK arrives,
 * relay nodes serve the missing fragments without requiring the
 * original sender to be online.
 *
 * This decouples fragment delivery from sender availability:
 *   - Sender can go offline after dispatch
 *   - Any relay node that held the fragment can serve the NACK
 *   - Retransmit is rate-limited to [MAX_RETRANSMITS_PER_POST] per relay
 *
 * Storage model:
 *   - Fragments stored in memory during the hold window
 *   - Evicted after [FragmentEntity.RELAY_HOLD_MS] or on storage pressure
 *   - Max [MAX_HELD_FRAGMENTS] fragments in memory — LRU eviction beyond limit
 *
 * Thread-safety: [heldFragments] uses ConcurrentHashMap.
 * Eviction loop is a coroutine on the provided scope.
 */
class DistributedRetransmissionManager(
    private val scope:     CoroutineScope,
    private val transport: RetransmitTransport
) {
    // postId → (sequenceIndex → FragmentHold)
    private val heldFragments = ConcurrentHashMap<String, ConcurrentHashMap<Int, FragmentHold>>()

    // Per-post retransmit count — rate limiting.
    // AtomicInteger per post so concurrent NACKs for the same postId cannot both pass
    // the `current >= MAX_RETRANSMITS_PER_POST` check and together exceed the budget.
    // With a plain Int, two threads reading current=0 would each serve 3 fragments
    // and both write 3, netting 6 retransmits instead of the intended maximum of 3.
    private val retransmitCounts = ConcurrentHashMap<String, java.util.concurrent.atomic.AtomicInteger>()

    // ── Store ─────────────────────────────────────────────────────────────

    /**
     * Store a fragment for potential retransmission.
     * Called whenever this relay node forwards a fragment.
     */
    fun hold(fragment: FragmentEntity) {
        if (totalHeldCount() >= MAX_HELD_FRAGMENTS) evictOldest()

        val postFragments = heldFragments.computeIfAbsent(fragment.postId) { ConcurrentHashMap() }

        // Per-post cap: prevent a single attacker-controlled postId from growing unbounded.
        // Without this cap, an attacker flooding sequenceIndex 0..N for one postId can consume
        // MAX_HELD_FRAGMENTS entries while the global limit stays just at the threshold —
        // the global evictOldest() evicts 1 slot per add, keeping totalHeldCount constant
        // while the per-post map grows indefinitely.
        if (postFragments.size >= MAX_FRAGMENTS_PER_POST) {
            Diag.degraded("retransmit", "per-post-limit-exceeded",
                "Per-post fragment hold limit reached for postId ${fragment.postId.take(8)} " +
                "(limit ${MAX_FRAGMENTS_PER_POST}) — fragment not held for retransmit",
                "seq" to fragment.sequenceIndex.toString())
            return
        }

        postFragments[fragment.sequenceIndex] = FragmentHold(
            fragment    = fragment,
            heldSinceMs = System.currentTimeMillis()
        )
    }

    // ── Serve NACKs ───────────────────────────────────────────────────────

    /**
     * Serve missing fragments in response to a NACK.
     * Returns the number of fragments retransmitted.
     */
    suspend fun serveNack(postId: String, missingSequences: List<Int>): Int {
        val counter = retransmitCounts.computeIfAbsent(postId) {
            java.util.concurrent.atomic.AtomicInteger(0)
        }
        // Atomically reserve `toServe` slots from the remaining budget.
        // getAndUpdate reads the current count and, if under budget, increments by
        // min(remaining, missingSequences.size). Only the delta actually reserved
        // is used — no other concurrent caller can take the same slots.
        val postFragments = heldFragments[postId] ?: return 0
        val availableSeqs = missingSequences.count { postFragments.containsKey(it) }
        if (availableSeqs == 0) return 0

        // Atomically claim up to `availableSeqs` slots from the budget.
        var reserved = 0
        counter.getAndUpdate { current ->
            if (current >= MAX_RETRANSMITS_PER_POST) {
                reserved = 0; current
            } else {
                val canTake = minOf(MAX_RETRANSMITS_PER_POST - current, availableSeqs)
                reserved = canTake
                current + canTake
            }
        }
        if (reserved == 0) return 0

        var served = 0
        for (seq in missingSequences) {
            if (served >= reserved) break
            val hold = postFragments[seq] ?: continue
            if (hold.isExpired()) { postFragments.remove(seq); continue }
            transport.retransmitFragment(hold.fragment)
            served++
        }
        // If fewer fragments were actually served (some expired), return the unused slots.
        if (served < reserved) counter.addAndGet(served - reserved)
        return served
    }

    // ── Eviction ──────────────────────────────────────────────────────────

    /** Remove all expired fragment holds. Called periodically. */
    fun evictExpired() {
        val now = System.currentTimeMillis()
        heldFragments.entries.removeIf { (_, postFragments) ->
            postFragments.entries.removeIf { (_, hold) -> hold.isExpired(now) }
            postFragments.isEmpty()
        }
        // Clear retransmit counters for posts with no held fragments
        retransmitCounts.keys.removeIf { postId -> heldFragments[postId] == null }
    }

    private fun evictOldest() {
        // Find and remove the oldest single fragment across all posts
        var oldestTime = Long.MAX_VALUE
        var oldestPost: String? = null
        var oldestSeq:  Int?    = null

        heldFragments.forEach { (postId, seqMap) ->
            seqMap.forEach { (seq, hold) ->
                if (hold.heldSinceMs < oldestTime) {
                    oldestTime = hold.heldSinceMs
                    oldestPost = postId
                    oldestSeq  = seq
                }
            }
        }
        oldestPost?.let { p -> oldestSeq?.let { s -> heldFragments[p]?.remove(s) } }
    }

    fun startEvictionLoop(intervalMs: Long = EVICTION_INTERVAL_MS) {
        scope.launch {
            while (isActive) {
                delay(intervalMs)
                evictExpired()
            }
        }
    }

    // ── Queries ───────────────────────────────────────────────────────────

    fun heldFragmentsForPost(postId: String): Map<Int, FragmentEntity> =
        heldFragments[postId]
            ?.filterValues { !it.isExpired() }
            ?.mapValues { it.value.fragment }
            ?: emptyMap()

    fun totalHeldCount(): Int = heldFragments.values.sumOf { it.size }

    fun hasFragment(postId: String, sequenceIndex: Int): Boolean =
        heldFragments[postId]?.get(sequenceIndex)?.isExpired()?.not() ?: false

    companion object {
        const val MAX_HELD_FRAGMENTS      = 10_000
        const val MAX_RETRANSMITS_PER_POST = 3
        const val EVICTION_INTERVAL_MS    = 5 * 60 * 1000L  // 5 minutes
        /**
         * Maximum fragments held per postId.
         * ShadowMesh's largest RS scheme is RS_10_10 (20 fragments total). A generous cap
         * of 100 allows for multiple RS schemes per post and noisy network conditions while
         * preventing a single attacker-controlled postId from consuming the entire hold map.
         * Beyond this limit new fragments for that post are silently dropped.
         */
        const val MAX_FRAGMENTS_PER_POST  = 100
    }
}

data class FragmentHold(
    val fragment:    FragmentEntity,
    val heldSinceMs: Long
) {
    fun isExpired(nowMs: Long = System.currentTimeMillis()): Boolean =
        nowMs > fragment.heldUntilMs
}

interface RetransmitTransport {
    suspend fun retransmitFragment(fragment: FragmentEntity)
}

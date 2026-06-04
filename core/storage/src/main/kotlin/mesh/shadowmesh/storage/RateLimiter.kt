package mesh.shadowmesh.storage

import java.util.concurrent.ConcurrentHashMap

/**
 * Per-key token bucket rate limiter — design doc §5.10b.
 *
 * Limits per source key per 60-second window:
 *   Fragment relay:  50
 *   Post submission:  5
 *   Nudge relay:     10
 *
 * Excess silently dropped — sending node cannot distinguish rate-limiting
 * from normal mesh propagation delay.
 *
 * Thread-safety: ConcurrentHashMap for bucket map.
 *   FIX (Issue 6): getBucket now uses computeIfAbsent (atomic) instead of
 *   getOrPut (non-atomic Kotlin extension — two threads can both see absent,
 *   both create a bucket, one silently overwrites the other losing tokens).
 *   consume() then synchronizes on the bucket for the read-modify-write on tokens.
 *
 * State is in-memory only — resets on app restart (per spec).
 * Never gossiped — each node enforces independently.
 */
class RateLimiter {

    private val buckets = ConcurrentHashMap<String, RateLimitBucket>()

    fun consumeFragment(nodeId: String): Boolean = consume(nodeId, TokenType.FRAGMENT)
    fun consumePost    (nodeId: String): Boolean = consume(nodeId, TokenType.POST)
    fun consumeNudge   (nodeId: String): Boolean = consume(nodeId, TokenType.NUDGE)

    // Advisory reads — intentionally unsynchronised.
    //
    // remainingFragments/Posts/Nudges are used for diagnostic logging and UI display
    // only, never for access-control decisions (consume() is the authoritative gate,
    // and it is synchronised). A stale or torn read here is harmless — the worst
    // outcome is a slightly inaccurate token count in a log line. Synchronising these
    // reads would add contention on the hot path with no safety benefit.
    fun remainingFragments(nodeId: String): Int = getBucket(nodeId).fragmentTokens
    fun remainingPosts    (nodeId: String): Int = getBucket(nodeId).postTokens
    fun remainingNudges   (nodeId: String): Int = getBucket(nodeId).nudgeTokens

    fun reset() { buckets.clear() }

    private enum class TokenType { FRAGMENT, POST, NUDGE }

    private fun consume(nodeId: String, type: TokenType): Boolean {
        val bucket = getBucket(nodeId)
        synchronized(bucket) {
            refillIfNeeded(bucket)
            return when (type) {
                TokenType.FRAGMENT -> if (bucket.fragmentTokens > 0) { bucket.fragmentTokens--; true } else false
                TokenType.POST     -> if (bucket.postTokens     > 0) { bucket.postTokens--;     true } else false
                TokenType.NUDGE    -> if (bucket.nudgeTokens    > 0) { bucket.nudgeTokens--;    true } else false
            }
        }
    }

    // FIX (Issue 6): computeIfAbsent is atomic on ConcurrentHashMap.
    // getOrPut (Kotlin extension) is NOT — it calls get() then put() separately,
    // allowing two threads to both observe absent and both create a new bucket.
    //
    // Size cap: without a limit, an attacker spoofing many distinct nodeIds creates
    // one bucket per fake ID — unbounded heap growth. Cap at MAX_TRACKED_NODES;
    // once full, new nodeIds are silently rejected (consume() returns false = blocked).
    // Legitimate traffic rarely exceeds a few hundred distinct active peers.
    private fun getBucket(nodeId: String): RateLimitBucket {
        // Fast path: already tracked.
        buckets[nodeId]?.let { return it }
        // New ID: only admit if under cap.
        if (buckets.size >= MAX_TRACKED_NODES) {
            // Return a permanently-empty bucket — all tokens consumed, will refill
            // at the normal interval, but the entry is never stored in the map.
            return RateLimitBucket(nodeId).also { b ->
                b.fragmentTokens = 0; b.postTokens = 0; b.nudgeTokens = 0
            }
        }
        return buckets.computeIfAbsent(nodeId) { RateLimitBucket(it) }
    }

    private fun refillIfNeeded(bucket: RateLimitBucket) {
        val nowMs = System.currentTimeMillis()
        if (nowMs - bucket.lastRefillMs >= RateLimitBucket.REFILL_INTERVAL_MS) {
            bucket.fragmentTokens = RateLimitBucket.MAX_FRAGMENT_TOKENS
            bucket.postTokens     = RateLimitBucket.MAX_POST_TOKENS
            bucket.nudgeTokens    = RateLimitBucket.MAX_NUDGE_TOKENS
            bucket.lastRefillMs   = nowMs
        }
    }
}

class RateLimitBucket(val nodeId: String) {
    var fragmentTokens: Int  = MAX_FRAGMENT_TOKENS
    var postTokens:     Int  = MAX_POST_TOKENS
    var nudgeTokens:    Int  = MAX_NUDGE_TOKENS
    var lastRefillMs:   Long = System.currentTimeMillis()

    companion object {
        const val MAX_FRAGMENT_TOKENS  = 50
        const val MAX_POST_TOKENS      = 5
        const val MAX_NUDGE_TOKENS     = 10
        const val REFILL_INTERVAL_MS   = 60_000L
    }
}

private const val MAX_TRACKED_NODES = 10_000

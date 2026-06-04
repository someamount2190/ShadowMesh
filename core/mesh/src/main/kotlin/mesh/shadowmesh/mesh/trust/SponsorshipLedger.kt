package mesh.shadowmesh.mesh.trust

import mesh.shadowmesh.mesh.dht.NodeId
import java.util.concurrent.ConcurrentHashMap

/**
 * Sponsorship ledger — time-windowed introduction rate limiting.
 *
 * ## The problem
 *
 * The trust chain caps depth at 1 remote hop (TRUST_PHYSICAL → introduces →
 * TRUST_INTRODUCED; TRUST_INTRODUCED cannot introduce further). But the cap is
 * on depth only, not breadth. A single compromised TRUST_PHYSICAL node — or an
 * AI agent that obtained one physical bootstrap — can still introduce an
 * unlimited number of TRUST_INTRODUCED nodes. 500 introductions from one physical
 * contact is not human behaviour.
 *
 * ## What this does
 *
 * Inspired by SybilGuard/SybilLimit's insight that the honest-to-sybil cut in a
 * trust graph is narrow: honest users create few trust edges; attackers create many.
 * SybilGuard exploits the small cut by bounding how many sybil identities can be
 * accepted per attack edge. We apply the same principle but locally — we bound
 * how many TRUST_INTRODUCED nodes a single TRUST_PHYSICAL sponsor can create per
 * time window without global graph traversal.
 *
 * Two orthogonal bounds:
 *
 * 1. **Rate window**: a sponsor can introduce at most [MAX_INTRODUCTIONS_PER_WINDOW]
 *    nodes in any rolling [WINDOW_MS] window. This catches burst attacks (spin up 500
 *    nodes in 20 minutes) while allowing a community organiser to introduce 50 people
 *    over 6 months.
 *
 * 2. **Lifetime cap**: a sponsor cannot accumulate more than [MAX_LIFETIME_INTRODUCTIONS]
 *    active TRUST_INTRODUCED descendants total. Active = not expired, not blocked.
 *    This prevents slow-drip attacks that stay below the rate threshold.
 *
 * 3. **Mesh-wide burst detection**: if multiple sponsors each introduce nodes in the
 *    same short window, and the aggregate mesh-level introduction rate exceeds
 *    [MAX_MESH_INTRODUCTIONS_PER_WINDOW], all further introductions are paused and
 *    the event is escalated to [onMeshBurstDetected]. This catches colluding physical
 *    contacts each introducing 9 nodes simultaneously to bypass per-node caps.
 *
 * ## What happens on violation
 *
 * - Per-sponsor violation: the introduction is rejected locally. The introduced node
 *   is admitted only at TRUST_PUBLIC instead of TRUST_INTRODUCED. The sponsor's
 *   rate state is not reset — they remain rate-limited.
 * - Mesh burst: all introductions are paused for [MESH_BURST_COOLDOWN_MS]. The
 *   [onMeshBurstDetected] callback is fired so the caller can log, alert, or trigger
 *   further defensive action.
 *
 * ## What this does NOT do
 *
 * This is a local heuristic. A globally distributed attacker who obtained many
 * physical contacts could still spread introductions across sponsors to stay below
 * per-sponsor limits. The mesh burst detector addresses collusion within a time window
 * but cannot detect perfectly distributed slow-drip multi-sponsor attacks.
 * SybilLimit's formal guarantees require a fast-mixing social graph — SHADOWMESH's
 * physical-contact graph is small and may not mix as assumed. Treat this as a
 * meaningful speed bump, not a proof-of-sybil-freedom.
 *
 * Thread-safety: all public methods are @Synchronized.
 */
class SponsorshipLedger(
    private val onMeshBurstDetected: (burstCount: Int, windowMs: Long) -> Unit = { _, _ -> }
) {

    // Per-sponsor state
    private val sponsorState = ConcurrentHashMap<NodeId, SponsorState>()

    // Mesh-wide introduction timestamps for burst detection
    private val meshIntroductionTimestamps = ArrayDeque<Long>()

    // Whether mesh-burst cooldown is active
    @Volatile private var meshBurstCooldownUntilMs: Long = 0L

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Check whether [sponsorId] (a TRUST_PHYSICAL node) may introduce [candidateId].
     *
     * Returns [IntroductionDecision.Allowed] if the introduction is within limits.
     * Returns [IntroductionDecision.Downgraded] if the rate limit is exceeded —
     * the candidate should be admitted at TRUST_PUBLIC rather than TRUST_INTRODUCED.
     * Returns [IntroductionDecision.MeshBurst] if the mesh-wide burst detector fired.
     *
     * Call this BEFORE issuing a TRUST_INTRODUCED credential. If the result is
     * not [IntroductionDecision.Allowed], do NOT issue TRUST_INTRODUCED.
     */
    @Synchronized
    fun checkIntroduction(
        sponsorId:   NodeId,
        candidateId: NodeId,
        nowMs:       Long = System.currentTimeMillis()
    ): IntroductionDecision {

        // Mesh burst cooldown — all introductions paused
        if (nowMs < meshBurstCooldownUntilMs) {
            return IntroductionDecision.MeshBurst(
                cooldownRemainingMs = meshBurstCooldownUntilMs - nowMs
            )
        }

        val state = sponsorState.getOrPut(sponsorId) { SponsorState() }

        // Prune expired timestamps from the rolling window
        state.pruneWindow(nowMs)

        // Check per-window rate
        if (state.windowIntroductions.size >= MAX_INTRODUCTIONS_PER_WINDOW) {
            return IntroductionDecision.Downgraded(
                reason = "Sponsor ${sponsorId.toHex().take(8)} exceeded rate limit: " +
                         "${state.windowIntroductions.size} introductions in ${WINDOW_MS / 60_000}min window"
            )
        }

        // Check lifetime cap
        if (state.lifetimeActiveCount >= MAX_LIFETIME_INTRODUCTIONS) {
            return IntroductionDecision.Downgraded(
                reason = "Sponsor ${sponsorId.toHex().take(8)} exceeded lifetime cap: " +
                         "${state.lifetimeActiveCount} active descendants"
            )
        }

        // Check mesh-wide burst
        pruneGlobalWindow(nowMs)
        if (meshIntroductionTimestamps.size >= MAX_MESH_INTRODUCTIONS_PER_WINDOW) {
            meshBurstCooldownUntilMs = nowMs + MESH_BURST_COOLDOWN_MS
            val burstCount = meshIntroductionTimestamps.size
            onMeshBurstDetected(burstCount, WINDOW_MS)
            return IntroductionDecision.MeshBurst(
                cooldownRemainingMs = MESH_BURST_COOLDOWN_MS
            )
        }

        // All checks passed — record the introduction
        state.windowIntroductions.addLast(nowMs)
        state.lifetimeActiveCount++
        state.introduced.add(candidateId)
        meshIntroductionTimestamps.addLast(nowMs)

        return IntroductionDecision.Allowed
    }

    /**
     * Notify the ledger that a previously introduced node has been blocked or
     * has expired. Decrements the sponsor's [SponsorState.lifetimeActiveCount]
     * so they can introduce a replacement.
     */
    @Synchronized
    fun onIntroducedNodeRemoved(sponsorId: NodeId, removedNodeId: NodeId) {
        val state = sponsorState[sponsorId] ?: return
        if (state.introduced.remove(removedNodeId)) {
            state.lifetimeActiveCount = maxOf(0, state.lifetimeActiveCount - 1)
        }
    }

    /**
     * Returns the current sponsorship stats for [sponsorId].
     * Useful for diagnostics and the relay indicator UI.
     */
    @Synchronized
    fun statsFor(
        sponsorId: NodeId,
        nowMs:     Long = System.currentTimeMillis()
    ): SponsorshipStats {
        val state = sponsorState[sponsorId] ?: return SponsorshipStats(0, 0, 0)
        state.pruneWindow(nowMs)
        return SponsorshipStats(
            windowCount   = state.windowIntroductions.size,
            lifetimeCount = state.lifetimeActiveCount,
            windowCapacity = MAX_INTRODUCTIONS_PER_WINDOW - state.windowIntroductions.size
        )
    }

    /** Returns mesh-wide introduction count in the current window. */
    @Synchronized
    fun meshWindowCount(nowMs: Long = System.currentTimeMillis()): Int {
        pruneGlobalWindow(nowMs)
        return meshIntroductionTimestamps.size
    }

    // ── Internal ──────────────────────────────────────────────────────────

    private fun pruneGlobalWindow(nowMs: Long) {
        val cutoff = nowMs - WINDOW_MS
        while (meshIntroductionTimestamps.isNotEmpty() &&
               meshIntroductionTimestamps.first() < cutoff) {
            meshIntroductionTimestamps.removeFirst()
        }
    }

    private inner class SponsorState {
        // Timestamps of introductions within the current rolling window.
        // Capped at MAX_INTRODUCTIONS_PER_WINDOW * WINDOW_SIZE_MULTIPLIER entries
        // so the deque cannot grow unboundedly under sustained legitimate use.
        // Entries are pruned by time (in pruneWindow) and by this hard cap
        // (oldest removed when the cap is hit, before the time-based prune).
        val windowIntroductions = ArrayDeque<Long>(MAX_WINDOW_HARD_CAP)
        // Count of currently active (not removed) introduced nodes
        var lifetimeActiveCount = 0
        // Set of introduced node IDs for removal tracking
        val introduced = mutableSetOf<NodeId>()

        fun pruneWindow(nowMs: Long) {
            val cutoff = nowMs - WINDOW_MS
            while (windowIntroductions.isNotEmpty() &&
                   windowIntroductions.first() < cutoff) {
                windowIntroductions.removeFirst()
            }
            // Hard cap: if still over limit after time pruning, drop oldest entries.
            // This is a defence against clock skew or a paused process replaying
            // many timestamps with a future nowMs that keeps them all in-window.
            while (windowIntroductions.size > MAX_WINDOW_HARD_CAP) {
                windowIntroductions.removeFirst()
            }
        }
    }

    companion object {
        /**
         * Max introductions per sponsor per rolling window.
         * Rationale: a real person introducing new contacts does so over days/weeks,
         * not minutes. 10 per 24-hour window is generous for legitimate use and
         * orders of magnitude below an automated attack.
         */
        const val MAX_INTRODUCTIONS_PER_WINDOW = 10

        /**
         * Rolling window duration. 24 hours captures daily burst patterns.
         * An attacker introducing 10 nodes/day would take 50 days to reach the
         * lifetime cap — at which point they're blocked regardless of rate.
         */
        const val WINDOW_MS = 24L * 60 * 60 * 1000   // 24 hours

        /**
         * Maximum number of active TRUST_INTRODUCED descendants per sponsor.
         * Rationale: a real person's social trust network is bounded. 50 active
         * introductions is already a large human network. Raising the cost of
         * a Sybil swarm from "one physical contact" to "one physical contact +
         * 50 real Android devices + 50 days" is a qualitatively different attack.
         */
        const val MAX_LIFETIME_INTRODUCTIONS = 50

        /**
         * Mesh-wide introduction burst threshold per window.
         * If the total introduction count across ALL sponsors in the window
         * exceeds this, the colluding-sponsors attack pattern is firing.
         * Sized at 3× the per-sponsor window limit so normal mesh growth
         * (a few sponsors each introducing a few people) is well within bounds.
         */
        const val MAX_MESH_INTRODUCTIONS_PER_WINDOW = 30

        /**
         * How long to pause all introductions after a mesh burst is detected.
         * Long enough to disrupt a coordinated automated attack; short enough
         * not to permanently disrupt legitimate mesh bootstrapping.
         *
         * Tuning note: 1 hour is conservative. During real-world testing, if legitimate
         * mesh growth events (e.g., a conference where many people bootstrap) trigger
         * the burst detector, reduce this to 15–30 minutes. The burst threshold
         * (MAX_MESH_INTRODUCTIONS_PER_WINDOW = 30) should be tuned first — a higher
         * threshold reduces false positives before touching the cooldown duration.
         */
        const val MESH_BURST_COOLDOWN_MS = 60L * 60 * 1000   // 1 hour

        /**
         * Hard size cap on the per-sponsor windowIntroductions deque.
         * Time-based pruning is the primary mechanism, but without a size cap
         * the deque grows unboundedly if introductions are made while nowMs is
         * artificially advanced (clock skew, process suspension) so that old
         * entries never fall outside the window. Set to 5× the per-window rate
         * limit — large enough for legitimate use, bounded against abuse.
         */
        const val MAX_WINDOW_HARD_CAP = MAX_INTRODUCTIONS_PER_WINDOW * 5
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

sealed class IntroductionDecision {
    /** Introduction is within all limits — proceed to issue TRUST_INTRODUCED. */
    object Allowed : IntroductionDecision()

    /**
     * Per-sponsor limit exceeded. Issue TRUST_PUBLIC instead of TRUST_INTRODUCED.
     * The [reason] is for local logging only — never transmit it.
     */
    data class Downgraded(val reason: String) : IntroductionDecision()

    /**
     * Mesh-wide burst detected. All introductions paused.
     * [cooldownRemainingMs] is how long until introductions resume.
     */
    data class MeshBurst(val cooldownRemainingMs: Long) : IntroductionDecision()
}

data class SponsorshipStats(
    val windowCount:    Int,    // introductions in current window
    val lifetimeCount:  Int,    // total active descendants
    val windowCapacity: Int     // remaining introductions in current window
)

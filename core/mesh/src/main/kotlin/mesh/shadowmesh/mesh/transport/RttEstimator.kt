package mesh.shadowmesh.mesh.transport

import java.util.concurrent.ConcurrentHashMap

/**
 * Per-peer RTT estimator for the DHT rendezvous path, used to size the adaptive hole-punch
 * window (see NatTraversalEngine.estimateAdaptivePunchPlan). This is the rendezvous-skew
 * estimate the punch schedule is built around — NOT the STUN RTT, which measures the wrong
 * (you ↔ public anycast) path and systematically under-estimates the mesh path.
 *
 * Algorithm: Jacobson/Karels (RFC 6298), the same smoothing TCP uses for its RTO. We keep
 * SRTT (smoothed RTT) and RTTVAR (RTT variation) and derive a timeout of SRTT + K·RTTVAR.
 * The variance term is the point: what kills a hole punch is the TAIL of the skew, not the
 * mean. A stable LAN path converges to a tight window automatically; a jittery relayed path
 * gets a wide one — without hand-tuning a flat multiplier.
 *
 * PRIVACY: this state is RAM-only and per-process, exactly like ActiveEncounterSession's
 * sessionStartMs. A persisted per-peer RTT distribution would be a timing fingerprint, which
 * the peer-memory design explicitly keeps off disk. Nothing here is written to PeerModelEntity.
 *
 * Karn's algorithm: an RTT sample taken from a RETRIED rendezvous is ambiguous (you can't
 * tell which attempt a response answers), so callers must only feed samples from FIRST-try
 * exchanges. [recordSample] takes a `retried` flag and discards ambiguous samples.
 *
 * Thread-safety: per-peer state guarded by a ConcurrentHashMap of small synchronized holders.
 */
class RttEstimator(
    private val clampMinMs: Long = MIN_RTO_MS,
    private val clampMaxMs: Long = MAX_RTO_MS,
    /** Injectable clock (ms) so staleness widening is unit-testable without real time. */
    private val nowMs: () -> Long = { System.currentTimeMillis() }
) {
    /** Latency class of the path a peer is reached over — seeds a sane initial RTO. */
    enum class PathClass(val seedRttMs: Long) {
        LAN(40),        // WiFi-Direct / same-subnet — sub-50ms typical
        INTERNET(500),  // reached via public IP / relay — hundreds of ms, high variance
        UNKNOWN(800)    // conservative cold-start prior (cf. TCP's 1s initial RTO)
    }

    private class State(val seedRttMs: Long) {
        // RFC 6298 init: on the FIRST measurement we set SRTT=R, RTTVAR=R/2. Until then we
        // run off the seed so a cold peer still gets a sensible RTO.
        var srtt:   Double = seedRttMs.toDouble()
        var rttvar: Double = seedRttMs / 2.0
        var hasSample = false
        var lastSampleMs: Long = 0L   // 0 = never sampled (cold)
    }

    private val byPeer = ConcurrentHashMap<String, State>()

    /**
     * Feed an RTT measurement (ms) for [peerKey] reached over [path].
     * @param retried true if this sample came from a retransmitted/duplicated rendezvous —
     *                discarded per Karn's algorithm to avoid ambiguous attribution.
     */
    fun recordSample(peerKey: String, rttMs: Long, path: PathClass, retried: Boolean = false) {
        if (retried || rttMs < 0) return
        val st = byPeer.getOrPut(peerKey) { State(path.seedRttMs) }
        synchronized(st) {
            val r = rttMs.toDouble()
            if (!st.hasSample) {
                st.srtt = r
                st.rttvar = r / 2.0
                st.hasSample = true
            } else {
                // RFC 6298 §2: RTTVAR = (1-β)·RTTVAR + β·|SRTT − R|;  SRTT = (1-α)·SRTT + α·R
                st.rttvar = (1 - BETA) * st.rttvar + BETA * Math.abs(st.srtt - r)
                st.srtt   = (1 - ALPHA) * st.srtt + ALPHA * r
            }
            st.lastSampleMs = nowMs()
        }
    }

    /**
     * Current retransmission-timeout-style estimate for [peerKey]: SRTT + K·RTTVAR, clamped,
     * then WIDENED for staleness. Falls back to [path]'s seed when no peer state exists yet.
     *
     * Staleness widening (the realistic-handoff case): a peer that vanished and returns —
     * very possibly on a different network — has stale SRTT/RTTVAR. Rather than reseed on a
     * forgeable signal (see DESIGN doc: reseed-on-handoff was rejected — an attacker can fake
     * a path-class flip but cannot choose the value), we simply grow the window with the time
     * since the last accepted sample. This only ever WIDENS (the safe direction): old state
     * means "be more cautious," never "use a smaller window." It is not usefully attackable —
     * the most an adversary could do is make you wait longer before reusing a peer, which is
     * not an attack. The widened value is capped so a long-idle peer reverts toward its
     * conservative seed RTO rather than growing unbounded.
     *
     * Multiplier: 1.0 up to STALENESS_GRACE_MS, then linear in elapsed time up to
     * STALENESS_MAX_MULT at STALENESS_FULL_MS and beyond. Fresh peers are unaffected.
     */
    fun rtoMs(peerKey: String, path: PathClass = PathClass.UNKNOWN): Long {
        val st = byPeer[peerKey] ?: return path.seedRttMs.coerceIn(clampMinMs, clampMaxMs)
        val (fresh, mult, seedFloorCap) = synchronized(st) {
            val base    = st.srtt + K * st.rttvar
            val elapsed = if (st.lastSampleMs == 0L) 0L else (nowMs() - st.lastSampleMs)
            Triple(base, stalenessMultiplier(elapsed), maxOf(st.seedRttMs.toDouble(), base))
        }
        // Widen, but never exceed the peer's own conservative seed-RTO ceiling by much:
        // a very stale peer should behave like a cold peer on that path, not balloon past it.
        val widened = (fresh * mult).coerceAtMost(seedFloorCap * STALENESS_MAX_MULT)
        return widened.toLong().coerceIn(clampMinMs, clampMaxMs)
    }

    /** 1.0 while fresh, ramping linearly to STALENESS_MAX_MULT as state ages. */
    private fun stalenessMultiplier(elapsedMs: Long): Double = when {
        elapsedMs <= STALENESS_GRACE_MS -> 1.0
        elapsedMs >= STALENESS_FULL_MS  -> STALENESS_MAX_MULT
        else -> {
            val span = (STALENESS_FULL_MS - STALENESS_GRACE_MS).toDouble()
            val frac = (elapsedMs - STALENESS_GRACE_MS) / span
            1.0 + frac * (STALENESS_MAX_MULT - 1.0)
        }
    }

    /** Exponential backoff on a confirmed timeout (RFC 6298 §5.5): double until the next sample. */
    fun onTimeout(peerKey: String, path: PathClass = PathClass.UNKNOWN) {
        val st = byPeer.getOrPut(peerKey) { State(path.seedRttMs) }
        synchronized(st) {
            st.srtt = (st.srtt * 2).coerceAtMost(clampMaxMs.toDouble())
            // RTTVAR intentionally untouched — only SRTT is backed off, per RFC 6298.
        }
    }

    fun forget(peerKey: String) { byPeer.remove(peerKey) }
    fun clear() { byPeer.clear() }

    companion object {
        // RFC 6298 recommended gains.
        const val ALPHA = 0.125   // SRTT gain (1/8)
        const val BETA  = 0.25    // RTTVAR gain (1/4)
        const val K     = 4.0     // RTO = SRTT + K·RTTVAR

        const val MIN_RTO_MS = 50L
        const val MAX_RTO_MS = 8_000L

        // ── Staleness widening (realistic vanish-and-return / handoff case) ──
        const val STALENESS_GRACE_MS = 30_000L    // <30s idle: estimate still fresh, mult 1.0
        const val STALENESS_FULL_MS  = 300_000L   // >=5min idle: full widening
        const val STALENESS_MAX_MULT = 3.0        // cap: a stale peer behaves ~like a cold one
    }
}

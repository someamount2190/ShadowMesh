package mesh.shadowmesh.storage

import kotlin.math.ln
import kotlin.math.sqrt
import kotlin.random.Random

/**
 * Behavioral coherence scorer — AI swarm / bot detection.
 *
 * ## The problem
 *
 * Behavioral heuristics for bot detection fall into two categories:
 *
 * 1. **Timing regularity**: AI agents respond at machine speed with low jitter.
 *    Human-operated Android devices have enormous latency variance from OS scheduling,
 *    Doze mode, OEM battery killers, network handoffs, and user interaction patterns.
 *    A node that always responds in 5–10ms with near-zero variance is anomalous
 *    regardless of trust level.
 *
 * 2. **Query pattern entropy**: Humans read content organically — they access channels
 *    they're subscribed to, in temporal bursts matching their activity schedule, with
 *    semantic clustering (related channels, same author). An AI agent probing the DHT
 *    systematically produces a query distribution that is either too uniform (covering
 *    key-space evenly) or too regular (fixed inter-arrival times).
 *
 * ## What this does NOT do
 *
 * This is a heuristic, not a cryptographic guarantee. It is explicitly labeled as
 * local intelligence that must never be transmitted. Modern AI agents can introduce
 * artificial jitter and non-uniform query patterns to evade timing-based detection
 * (see: bot detection literature, 2024–2026). The score is one signal among several —
 * not a decision gate.
 *
 * The existing [ReputationScorer] handles trust-level and relay-reliability dimensions.
 * This class handles the orthogonal behavioral dimension. Both feed into a combined
 * [BehavioralReputationSignal] that callers may incorporate into their local decision.
 *
 * ## Implementation choices vs literature
 *
 * - **Latency jitter**: coefficient of variation (CV = stddev/mean) rather than raw
 *   stddev, because absolute latency varies by transport and device capability.
 *   CV < [CV_BOT_THRESHOLD] with sufficient samples → suspicious.
 *
 * - **Query entropy**: Shannon entropy over the distribution of queried DHT key
 *   prefixes. Perfectly uniform → maximum entropy (suspicious for a human).
 *   Perfectly clustered → low entropy (suspicious for a systematically scanning bot).
 *   Human queries cluster in a mid-entropy regime — familiar channels, occasional
 *   exploration. We flag both extremes.
 *
 * - **Inter-arrival time (IAT) regularity**: coefficient of variation of time between
 *   queries. Humans query in bursts (app open → read → close → hours of silence).
 *   Bots query at fixed intervals. CV_IAT < [IAT_CV_BOT_THRESHOLD] → suspicious.
 *
 * Thread-safety: [NodeBehaviorWindow] is not thread-safe. Callers must synchronize
 * if observing from multiple threads (gossip engine handles this).
 *
 * @param random  Source of randomness for latency jitter. Injectable so tests can pass
 *                [Random(seed)] for deterministic output. Production callers use the
 *                default [Random.Default].
 */
class BehavioralCoherenceScorer(
    private val random: Random = Random.Default
) {

    /**
     * Score the behavioral coherence of a node based on its observed [window].
     *
     * Returns [BehavioralSignal] indicating whether behavior is consistent with
     * a real human-operated Android device or suspicious of automated operation.
     *
     * Requires at least [MIN_SAMPLES_FOR_SCORING] observations per dimension
     * before scoring that dimension — returns [BehavioralSignal.Insufficient]
     * if not enough data is available yet.
     */
    fun score(window: NodeBehaviorWindow): BehavioralSignal {
        val flags = mutableListOf<SuspicionFlag>()
        var dimensionsScored = 0

        // ── Dimension 1: Response latency jitter ──────────────────────────
        if (window.responseLatenciesMs.size >= MIN_SAMPLES_FOR_SCORING) {
            dimensionsScored++
            // Jitter is applied per-scoring-call (not at record time) so it is ephemeral
            // and does not bake noise into the stored window. A peer who can precisely
            // time their own responses cannot infer their CV as we computed it.
            val cv = coefficientOfVariation(jitteredLatencies(window.responseLatenciesMs))
            if (cv != null && cv < CV_BOT_THRESHOLD) {
                flags.add(
                    SuspicionFlag.LowLatencyJitter(
                        cv             = cv,
                        sampleCount    = window.responseLatenciesMs.size,
                        threshold      = CV_BOT_THRESHOLD
                    )
                )
            }
        }

        // ── Dimension 2: Query inter-arrival time regularity ──────────────
        if (window.queryTimestampsMs.size >= MIN_SAMPLES_FOR_SCORING + 1) {
            dimensionsScored++
            val iats = window.queryTimestampsMs
                .zipWithNext { a, b -> (b - a).toDouble() }
                .filter { it > 0 }   // skip same-ms duplicates
            if (iats.size >= MIN_SAMPLES_FOR_SCORING) {
                val iatCv = coefficientOfVariation(iats)
                if (iatCv != null && iatCv < IAT_CV_BOT_THRESHOLD) {
                    flags.add(
                        SuspicionFlag.RegularQueryTiming(
                            cv          = iatCv,
                            sampleCount = iats.size,
                            threshold   = IAT_CV_BOT_THRESHOLD
                        )
                    )
                }
            }
        }

        // ── Dimension 3: Query prefix entropy ─────────────────────────────
        if (window.queriedKeyPrefixes.size >= MIN_SAMPLES_FOR_SCORING) {
            dimensionsScored++
            val entropy = shannonEntropy(window.queriedKeyPrefixes)
            val maxEntropy = ln(window.queriedKeyPrefixes.distinctBy { it }.size.toDouble())

            // Normalised entropy: 0 = all same prefix, 1 = perfectly uniform
            val normEntropy = if (maxEntropy > 0) entropy / maxEntropy else 0.0

            when {
                normEntropy > ENTROPY_UNIFORM_THRESHOLD ->
                    flags.add(SuspicionFlag.UniformQueryDistribution(
                        normalizedEntropy = normEntropy,
                        sampleCount       = window.queriedKeyPrefixes.size
                    ))
                normEntropy < ENTROPY_SCAN_THRESHOLD && window.queriedKeyPrefixes.size > MIN_SAMPLES_FOR_SCORING * 3 ->
                    // Only flag low entropy after many samples — early reads are naturally clustered
                    flags.add(SuspicionFlag.SequentialScanPattern(
                        normalizedEntropy = normEntropy,
                        sampleCount       = window.queriedKeyPrefixes.size
                    ))
            }
        }

        if (dimensionsScored == 0) return BehavioralSignal.Insufficient

        // Weight: each flag contributes to a suspicion score
        val suspicionScore = flags.sumOf { it.weight }

        return when {
            suspicionScore == 0 -> BehavioralSignal.Coherent(dimensionsScored)
            suspicionScore <= SCORE_SUSPICIOUS_THRESHOLD ->
                BehavioralSignal.Suspicious(flags, suspicionScore, dimensionsScored)
            else ->
                BehavioralSignal.HighlySuspicious(flags, suspicionScore, dimensionsScored)
        }
    }

    // ── Jitter ────────────────────────────────────────────────────────────

    /**
     * Returns a copy of [raw] with symmetric uniform noise in [-JITTER_CAP_MS, +JITTER_CAP_MS]
     * applied to each sample. Noise is ephemeral — applied per scoring call, never stored.
     *
     * Purpose: prevent a peer who can precisely control their own response latency from
     * inferring the CV we computed for them (by observing what triggers a behavioral
     * downgrade). At CV_BOT_THRESHOLD=0.20 and typical latencies of 50–500ms, ±5ms jitter
     * shifts CV by ≤ 0.03 — well below the gap between bot regime (CV < 0.10) and the
     * threshold (0.20), so scoring accuracy is not materially affected.
     */
    private fun jitteredLatencies(raw: Collection<Double>): List<Double> =
        raw.map { sample ->
            (sample + random.nextDouble(-JITTER_CAP_MS, JITTER_CAP_MS)).coerceAtLeast(1.0)
        }

    // ── Statistics helpers ────────────────────────────────────────────────

    private fun coefficientOfVariation(values: List<Double>): Double? {
        if (values.size < 2) return null
        val mean = values.average()
        if (mean == 0.0) return null
        val variance = values.sumOf { (it - mean) * (it - mean) } / (values.size - 1)
        return sqrt(variance) / mean
    }

    private fun shannonEntropy(items: List<String>): Double {
        val total = items.size.toDouble()
        return items.groupBy { it }
            .values
            .map { it.size / total }
            .filter { it > 0 }
            .sumOf { p -> -p * ln(p) }
    }

    companion object {
        /** Minimum observations per dimension before that dimension is scored. */
        const val MIN_SAMPLES_FOR_SCORING = 15

        /**
         * Half-width of the symmetric uniform latency jitter applied per scoring call.
         * At ±5ms the CV shift is ≤ 0.03 across typical 50–500ms latency ranges —
         * negligible relative to the 0.10 gap between the bot regime and CV_BOT_THRESHOLD.
         */
        const val JITTER_CAP_MS = 5.0

        /**
         * CV threshold for response latency. Human Android devices show CV > 0.5
         * due to Doze, OEM scheduling, and network variance. Bots often show CV < 0.1.
         * Threshold at 0.2 catches the clearly machine-like regime.
         */
        const val CV_BOT_THRESHOLD = 0.20

        /**
         * CV threshold for query inter-arrival time. Human query patterns are bursty
         * (open app → queries burst → silence for hours → repeat). CV > 1.0 is typical
         * for a human; fixed-interval bots show CV approaching 0 (perfectly regular timing).
         * Threshold at 0.20 catches the clearly machine-like regime (bots at CV < 0.15
         * are well below this; human variance at CV > 1.0 is well above it).
         */
        const val IAT_CV_BOT_THRESHOLD = 0.20

        /**
         * Normalised entropy threshold above which query distribution is "too uniform".
         * A human querying 20 channels over time produces entropy well below maximum.
         * A bot probing key-space uniformly approaches 1.0.
         */
        const val ENTROPY_UNIFORM_THRESHOLD = 0.92

        /**
         * Normalised entropy threshold below which a sequential scan is suspected.
         * Very low entropy means the node is repeatedly querying the same or adjacent
         * prefix — typical of a systematic DHT scan targeting a specific key range.
         */
        const val ENTROPY_SCAN_THRESHOLD = 0.05

        /**
         * Cumulative suspicion score above which [BehavioralSignal.HighlySuspicious] fires.
         * Each flag has a weight (see [SuspicionFlag.weight]). A single strong signal
         * or two moderate signals together cross this threshold.
         */
        const val SCORE_SUSPICIOUS_THRESHOLD = 3
    }
}

// ── Observation window ────────────────────────────────────────────────────────

/**
 * Sliding observation window for a single peer node.
 *
 * The window is bounded to avoid unbounded memory growth. Each list is capped
 * at [MAX_WINDOW_SIZE] — oldest entries are dropped as new ones arrive.
 *
 * All times are absolute milliseconds (System.currentTimeMillis()).
 *
 * Thread-safety: NOT thread-safe. The caller (GossipEngine / ReputationScorer
 * integration) must hold the appropriate lock when calling [record*] methods.
 */
class NodeBehaviorWindow(val nodeId: String) {

    /** Monotonic timestamp (System.currentTimeMillis) of the last recorded observation.
     *  Used for staleness eviction — see [isStale]. Never persisted. */
    var lastObservationMs: Long = System.currentTimeMillis()
        private set

    /** Response latencies in milliseconds, capped at [MAX_WINDOW_SIZE]. */
    val responseLatenciesMs = ArrayDeque<Double>(MAX_WINDOW_SIZE)

    /** Absolute timestamps of outbound DHT/gossip queries, in arrival order. */
    val queryTimestampsMs   = ArrayDeque<Long>(MAX_WINDOW_SIZE)

    /**
     * 8-bit XOR prefix of each queried DHT key (first byte as hex string).
     * Used for Shannon entropy computation. Coarser than the full key to avoid
     * treating every unique channel query as a distinct "pattern" — we care about
     * key-space coverage, not per-channel identity.
     */
    val queriedKeyPrefixes  = ArrayDeque<String>(MAX_WINDOW_SIZE)

    /** Record a response latency observation. Drops oldest if window is full. */
    fun recordLatency(latencyMs: Long) {
        lastObservationMs = System.currentTimeMillis()
        if (responseLatenciesMs.size >= MAX_WINDOW_SIZE) responseLatenciesMs.removeFirst()
        responseLatenciesMs.addLast(latencyMs.toDouble())
    }

    /** Record a query event at [timestampMs] for key with first byte [keyPrefixByte]. */
    fun recordQuery(timestampMs: Long, keyPrefixByte: Byte) {
        lastObservationMs = System.currentTimeMillis()
        if (queryTimestampsMs.size >= MAX_WINDOW_SIZE) queryTimestampsMs.removeFirst()
        queryTimestampsMs.addLast(timestampMs)

        val prefix = "%02x".format(keyPrefixByte.toInt() and 0xFF)
        if (queriedKeyPrefixes.size >= MAX_WINDOW_SIZE) queriedKeyPrefixes.removeFirst()
        queriedKeyPrefixes.addLast(prefix)
    }

    /** Reset all observations (e.g. after a long connectivity gap or staleness expiry). */
    fun reset() {
        responseLatenciesMs.clear()
        queryTimestampsMs.clear()
        queriedKeyPrefixes.clear()
        lastObservationMs = System.currentTimeMillis()
    }

    /**
     * Returns true if no observation has been recorded within [idleTtlMs].
     *
     * Stale windows are evicted by [GossipEngine.removePeer] (explicit departure) and
     * lazily reset inside [GossipEngine.recordPeerLatency] / [GossipEngine.recordPeerQuery]
     * (re-encounter after a gap). This prevents behavioral profiles from accumulating across
     * multiple disconnected sessions and limits the temporal correlation window available to
     * an attacker trying to link sessions via fingerprint.
     */
    fun isStale(nowMs: Long = System.currentTimeMillis(), idleTtlMs: Long = IDLE_TTL_MS): Boolean =
        (nowMs - lastObservationMs) > idleTtlMs

    companion object {
        /** Maximum observations per dimension per node. ~15 minutes of activity at 1 query/5s. */
        const val MAX_WINDOW_SIZE = 200

        /**
         * Idle TTL after which a window is considered stale and eligible for eviction.
         * 10 minutes: enough to survive typical Android Doze cycles (where the peer goes
         * quiet) without accumulating across clearly separate sessions (hours apart).
         */
        const val IDLE_TTL_MS = 10L * 60 * 1000  // 10 minutes
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

sealed class BehavioralSignal {
    /** Not enough data to score any dimension yet. */
    object Insufficient : BehavioralSignal()

    /** Behavior is consistent with a real human-operated Android device. */
    data class Coherent(val dimensionsScored: Int) : BehavioralSignal()

    /**
     * One or more suspicious signals detected. Below the high-suspicion threshold.
     * Incorporate into reputation scoring but do not block.
     */
    data class Suspicious(
        val flags:            List<SuspicionFlag>,
        val score:            Int,
        val dimensionsScored: Int
    ) : BehavioralSignal()

    /**
     * Multiple strong suspicious signals. Consider:
     * - Blocking locally via [blocklist]
     * - Reporting to HardenedChallengeLayer for verification
     * - Escalating to GossipEngine for watchdog action
     * Never block automatically — this is a local heuristic, not a proof.
     */
    data class HighlySuspicious(
        val flags:            List<SuspicionFlag>,
        val score:            Int,
        val dimensionsScored: Int
    ) : BehavioralSignal()
}

sealed class SuspicionFlag {
    abstract val weight: Int

    /** Response latency coefficient of variation is too low — machine-like consistency. */
    data class LowLatencyJitter(
        val cv:          Double,
        val sampleCount: Int,
        val threshold:   Double
    ) : SuspicionFlag() {
        override val weight = 2
    }

    /** Query inter-arrival time CV is too low — fixed-interval querying. */
    data class RegularQueryTiming(
        val cv:          Double,
        val sampleCount: Int,
        val threshold:   Double
    ) : SuspicionFlag() {
        override val weight = 3
    }

    /** Query key prefix distribution is too uniform — systematic key-space probing. */
    data class UniformQueryDistribution(
        val normalizedEntropy: Double,
        val sampleCount:       Int
    ) : SuspicionFlag() {
        override val weight = 2
    }

    /** Query key prefix distribution is too clustered and sequential — targeted DHT scan. */
    data class SequentialScanPattern(
        val normalizedEntropy: Double,
        val sampleCount:       Int
    ) : SuspicionFlag() {
        override val weight = 2
    }
}

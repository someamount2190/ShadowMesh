package mesh.shadowmesh.nsc.integrity

import android.util.Log
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

/**
 * Per-process flexible integrity checks — Phase 2, roadmap task:
 * "Per-process flexible integrity checks — 5 subsystems, random intervals.
 * Each subsystem detects injected tamper in its domain. Failure responses
 * match spec (wipe, silent drop, garbage output, etc.)."
 *
 * Design decisions:
 *
 * Five subsystems are checked independently, each on its own randomised
 * coroutine schedule. Randomised intervals (not a fixed heartbeat) prevent
 * an attacker from predicting when checks run and timing a tamper window
 * between them.
 *
 * Each subsystem has a distinct failure response matching the design spec:
 *   1. DHT routing table   — silent drop: tampered routes are discarded,
 *                            node appears to forward but does not.
 *   2. Gossip integrity    — silent drop: tampered fragment is not relayed.
 *   3. NSC state machine   — NSC UNRECOVERABLE escalation via the registered
 *                            callback. Causes process restart.
 *   4. Key accessibility   — garbage output: all encrypt/decrypt calls return
 *                            garbled bytes until restart.
 *   5. Ratchet state       — wipe: ratchet state is purged, channel left.
 *
 * Failure responses are taken locally — no network signal is emitted. The
 * checked node remains unaware its output is being suppressed or garbled.
 * This satisfies the "no global kick" architectural constraint.
 *
 * Intervals: each subsystem selects a fresh random delay in [minMs, maxMs]
 * after each check completes. This means checks are not phase-locked across
 * subsystems and the combined check density is unpredictable.
 *
 * Usage (in Application.onCreate or DI module):
 *
 *   val checker = PerProcessIntegrityChecker(
 *       scope          = applicationScope,
 *       dhtProbe       = { routingTable.verifySample() },
 *       gossipProbe    = { gossipEngine.verifyLastFragment() },
 *       nscProbe       = { nsc.verifyInternalState() },
 *       keyProbe       = { keystore.verifyAccessibility() },
 *       ratchetProbe   = { ratchetStore.verifyCurrentChain() },
 *       onNscCorruption     = { nsc.escalateUnrecoverable("integrity-checker") },
 *       onKeyCorruption     = { cipherEngine.enableGarbageMode() },
 *       onRatchetCorruption = { ratchetStore.wipeAndLeave(channelId) }
 *   )
 *   checker.start()
 *
 * @param scope              Long-lived CoroutineScope (Application scope).
 * @param dhtProbe           Returns true if DHT routing table is intact.
 * @param gossipProbe        Returns true if last gossip fragment is intact.
 * @param nscProbe           Returns true if NSC internal state is consistent.
 * @param keyProbe           Returns true if key material is accessible and unmodified.
 * @param ratchetProbe       Returns true if ratchet chain is intact.
 * @param onDhtCorruption    Called on DHT tamper detection. Default: silent drop.
 * @param onGossipCorruption Called on gossip tamper detection. Default: silent drop.
 * @param onNscCorruption    Called on NSC state tamper detection.
 * @param onKeyCorruption    Called on key material tamper detection.
 * @param onRatchetCorruption Called on ratchet state tamper detection.
 * @param minIntervalMs      Lower bound of random check interval (default 45s).
 * @param maxIntervalMs      Upper bound of random check interval (default 120s).
 */
class PerProcessIntegrityChecker(
    private val scope:               CoroutineScope,
    private val dhtProbe:            suspend () -> Boolean,
    private val gossipProbe:         suspend () -> Boolean,
    private val nscProbe:            suspend () -> Boolean,
    private val keyProbe:            suspend () -> Boolean,
    private val ratchetProbe:        suspend () -> Boolean,
    private val onDhtCorruption:     suspend () -> Unit = { /* silent drop — implemented at call site */ },
    private val onGossipCorruption:  suspend () -> Unit = { /* silent drop — implemented at call site */ },
    private val onNscCorruption:     suspend () -> Unit,
    private val onKeyCorruption:     suspend () -> Unit,
    private val onRatchetCorruption: suspend () -> Unit,
    private val minIntervalMs: Long = DEFAULT_MIN_INTERVAL_MS,
    private val maxIntervalMs: Long = DEFAULT_MAX_INTERVAL_MS
) {
    private val TAG = "IntegrityChecker"

    // Tracks the number of consecutive failures per subsystem.
    // Exposed for testing; not transmitted over the network.
    val failureCounts: Map<Subsystem, Int>
        get() = _failureCounts.toMap()

    private val _failureCounts = ConcurrentHashMap<Subsystem, Int>().also { m ->
        Subsystem.values().forEach { m[it] = 0 }
    }

    enum class Subsystem {
        DHT_ROUTING_TABLE,
        GOSSIP_INTEGRITY,
        NSC_STATE_MACHINE,
        KEY_ACCESSIBILITY,
        RATCHET_STATE
    }

    // Per-subsystem Job handles — enforces start() idempotency.
    private val jobs = ConcurrentHashMap<Subsystem, Job>()

    /**
     * Start all five subsystem checkers. Each runs independently on the
     * provided scope with its own randomised interval schedule.
     *
     * Idempotent — if a checker for a given subsystem is already running
     * (its [Job] is active), that subsystem is skipped. This prevents
     * duplicate checker coroutines when start() is called more than once
     * (e.g. on Application crash-restart via START_STICKY).
     */
    fun start() {
        launchChecker(Subsystem.DHT_ROUTING_TABLE,  dhtProbe,     onDhtCorruption)
        launchChecker(Subsystem.GOSSIP_INTEGRITY,   gossipProbe,  onGossipCorruption)
        launchChecker(Subsystem.NSC_STATE_MACHINE,  nscProbe,     onNscCorruption)
        launchChecker(Subsystem.KEY_ACCESSIBILITY,  keyProbe,     onKeyCorruption)
        launchChecker(Subsystem.RATCHET_STATE,      ratchetProbe, onRatchetCorruption)
    }

    /** Cancel all running checkers. Safe to call at any time. */
    fun stop() {
        jobs.values.forEach { it.cancel() }
        jobs.clear()
    }

    private fun launchChecker(
        subsystem:    Subsystem,
        probe:        suspend () -> Boolean,
        onCorruption: suspend () -> Unit
    ) {
        // Idempotency guard — skip if this subsystem's checker is already active.
        val existing = jobs[subsystem]
        if (existing != null && existing.isActive) return

        jobs[subsystem] = scope.launch {
            while (isActive) {
                // Randomise the delay before each check, not after, so the very
                // first check is also offset (prevents all five subsystems from
                // probing simultaneously on startup, which would be detectable).
                delay(randomInterval())

                // runCatching must NOT swallow CancellationException — that would treat a
                // cancelled scope (normal shutdown, WorkManager timeout) as an integrity
                // failure and call onCorruption() → potential panic wipe on teardown.
                val intact = try {
                    probe()
                } catch (e: CancellationException) {
                    throw e   // propagate normally — not an integrity failure
                } catch (e: Exception) {
                    // Probe threw a non-cancellation exception — treat as failure.
                    // The probe can't access its subsystem, which is itself suspicious.
                    Log.w(TAG, "Probe threw for $subsystem: ${e.message}")
                    false
                }

                if (!intact) {
                    val count = _failureCounts.merge(subsystem, 1, Int::plus) ?: 1
                    Log.e(TAG, "INTEGRITY FAILURE: $subsystem (consecutive failures: $count)")
                    runCatching { onCorruption() }.onFailure { ex ->
                        Log.e(TAG, "Corruption handler threw for $subsystem: ${ex.message}")
                    }
                } else {
                    // Reset consecutive failure count on a clean check.
                    _failureCounts[subsystem] = 0
                }
            }
        }
    }

    private fun randomInterval(): Long =
        minIntervalMs + Random.nextLong(maxIntervalMs - minIntervalMs)

    companion object {
        // Default range: 45–120 seconds. Wide enough to be unpredictable;
        // narrow enough that a 7-day operation sees ~4,000–11,000 checks
        // per subsystem — sufficient coverage without battery impact.
        const val DEFAULT_MIN_INTERVAL_MS = 45_000L
        const val DEFAULT_MAX_INTERVAL_MS = 120_000L
    }
}

package mesh.shadowmesh.mesh.privacy

import mesh.shadowmesh.mesh.dht.DhtContact
import mesh.shadowmesh.mesh.mode.PeerSelectionMode
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.random.Random

/**
 * DHT Query Mix — design doc Phase 8, "DHT Query Mix".
 *
 * Defends DHT lookups against timing/correlation analysis. A raw DHT query reveals *when*
 * a user is reading and *which* slice they are interested in. The mix breaks the link between
 * a user action and the on-wire query by:
 *
 *   1. HOLD     — buffer each query for a randomized delay inside an adaptive window
 *                 (window chosen by the current [PeerSelectionMode]).
 *   2. SHUFFLE  — when a batch flushes, reorder it so emission order ≠ submission order.
 *   3. FAN-OUT  — forward each query to [FANOUT] independently-chosen random peers rather
 *                 than the single closest peer, so no one peer sees the user's full pattern.
 *   4. BUDGET   — cap total emitted queries at [MAX_QUERIES_PER_MINUTE] across all threads
 *                 (sliding 60s window). Excess queries are dropped (caller may retry later).
 *
 * Adaptive window by mode (per design doc):
 *   STANDARD / OPERATIONAL  →  0–500 ms       (low latency, light mixing)
 *   MAXIMUM_SECURITY        →  1000–3000 ms   (heavy mixing, higher latency)
 *   EMERGENCY               →  0 ms           (no hold — anonymity sacrificed for speed)
 *
 * First-hop limitation (documented, not solvable here): the first peer a query is forwarded
 * to still observes that *some* query was emitted in this window. The mix ensures that peer
 * cannot tie the query to the originating user action or to the rest of the user's pattern;
 * it does not hide that a query happened. This matches the roadmap exit-gate note.
 *
 * Thread-safety: [submit] is safe to call from any thread. Holding is driven on [scope];
 * the pure helpers ([windowFor], [pickPeers], budget accounting) are side-effect free and unit-tested.
 */
class DhtQueryMix(
    private val scope:           CoroutineScope,
    private val getMode:         () -> PeerSelectionMode,
    private val getPeers:        () -> List<DhtContact>,
    /** Emit a single mixed query to the chosen peers. Called once per query at flush time. */
    private val forward:         suspend (query: ByteArray, peers: List<DhtContact>) -> Unit,
    private val rng:             Random = Random.Default,
    private val clockMs:         () -> Long = { System.currentTimeMillis() }
) {
    private data class Pending(val query: ByteArray, val releaseAtMs: Long)

    private val queue   = ConcurrentLinkedQueue<Pending>()

    // AtomicReference ensures at most one pump job is ever active.
    //
    // Plain `var pumpJob: Job?` has two problems under concurrent submit() calls:
    //   (a) No visibility guarantee: a write from one thread may not be seen by
    //       another thread without @Volatile — both see null and both launch a job.
    //   (b) Even with @Volatile, the check-then-set (`if isActive → launch → assign`)
    //       is not atomic: two threads both pass the check before either assigns.
    //
    // With AtomicReference, ensurePump() uses compareAndSet(null, newJob): only the
    // first caller wins; the loser immediately cancels its freshly-launched job.
    // emissionTimestamps remains single-threaded (only the winner's job touches it).
    private val pumpJobRef = java.util.concurrent.atomic.AtomicReference<Job?>(null)

    // Budget tracking lives EXCLUSIVELY in the pump loop (single-threaded coroutine).
    // Moving it here eliminates the race between submit() (caller thread) and the pump
    // (coroutine dispatcher) that existed when ArrayDeque was used for timestamps.
    // submit() uses pendingCount as a cheap pre-flight — the pump enforces the real limit.
    private val emissionTimestamps = ArrayDeque<Long>()   // only touched inside the winning pumpJob

    // ── Public API ───────────────────────────────────────────────────────────

    /**
     * Submit a DHT query for mixed emission. Assigns a randomized release time inside the
     * current mode's window, enqueues it, and ensures the pump loop is running.
     *
     * Returns false (and drops the query) if the queue already holds
     * [MAX_QUERIES_PER_MINUTE] pending entries — a conservative pre-flight that avoids
     * unbounded queue growth. The real per-minute budget is enforced inside the pump loop.
     *
     * Thread-safe: [queue] is a [ConcurrentLinkedQueue]. Budget accounting is confined to
     * the single-threaded pump loop; [submit] only reads the queue size for a cheap bound.
     */
    fun submit(query: ByteArray): Boolean {
        // Pre-flight: reject if the queue is already saturated. This is intentionally
        // conservative — it rejects early to prevent queue growth, not to enforce the
        // exact sliding-window budget (the pump does that).
        if (queue.size >= MAX_QUERIES_PER_MINUTE) return false
        val window = windowFor(getMode())
        val holdMs = if (window.last <= 0) 0L else rng.nextLong(window.first.toLong(), window.last.toLong() + 1L)
        queue.add(Pending(query, clockMs() + holdMs))
        ensurePump()
        return true
    }

    fun pendingCount(): Int = queue.size

    fun stop() { pumpJobRef.getAndSet(null)?.cancel() }

    // ── Pump loop ──────────────────────────────────────────────────────────
    //
    // All budget accounting (emissionTimestamps) runs exclusively here.
    // This is the only coroutine that reads or writes emissionTimestamps,
    // eliminating the thread-safety concern with ArrayDeque.

    private fun ensurePump() {
        // Fast-path: a job is already active — nothing to do.
        if (pumpJobRef.get()?.isActive == true) return

        // Launch a candidate job, then attempt to install it atomically.
        // compareAndSet(null, candidate) succeeds only if no other thread installed a job
        // between the check above and here. The loser cancels its candidate immediately,
        // ensuring emissionTimestamps is only ever touched by one active pump job.
        val candidate = scope.launch {
            try {
                while (isActive && queue.isNotEmpty()) {
                    val now = clockMs()
                    val due = mutableListOf<Pending>()
                    val it  = queue.iterator()
                    while (it.hasNext()) {
                        val p = it.next()
                        if (p.releaseAtMs <= now) { due.add(p); it.remove() }
                    }
                    if (due.isNotEmpty()) {
                        due.shuffle(rng)
                        for (p in due) {
                            // Budget check and record are both inside the pump — no race.
                            if (!pumpBudgetAvailable(clockMs())) break
                            pumpRecordEmission(clockMs())
                            forward(p.query, pickPeers(getPeers(), rng))
                        }
                    }
                    if (queue.isEmpty()) break
                    delay(POLL_MS)
                }
            } finally {
                // Clear the reference on any exit (normal completion OR cancellation via stop()).
                // Without this, stop() → getAndSet(null)?.cancel() clears the ref, then the
                // next submit() → ensurePump() sees a null ref and installs a new job correctly.
                // But if the job completes naturally without stop(), the ref would linger as a
                // completed (non-active) job. The next submit() passes the isActive check and
                // launches another job — so natural completion cleanup is belt-and-suspenders.
                pumpJobRef.compareAndSet(coroutineContext[kotlinx.coroutines.Job], null)
            }
        }

        if (!pumpJobRef.compareAndSet(null, candidate)) {
            // Another concurrent ensurePump() already installed a job — cancel ours.
            candidate.cancel()
        }
    }

    // Budget helpers — ONLY called from inside pumpJob (single-threaded).
    private fun pumpBudgetAvailable(nowMs: Long): Boolean {
        pumpPruneBudget(nowMs)
        return emissionTimestamps.size < MAX_QUERIES_PER_MINUTE
    }
    private fun pumpRecordEmission(nowMs: Long) {
        pumpPruneBudget(nowMs)
        emissionTimestamps.addLast(nowMs)
    }
    private fun pumpPruneBudget(nowMs: Long) {
        val cutoff = nowMs - BUDGET_WINDOW_MS
        while (emissionTimestamps.isNotEmpty() && emissionTimestamps.first() < cutoff) {
            emissionTimestamps.removeFirst()
        }
    }

    // ── Pure helpers (unit-tested) ───────────────────────────────────────────

    /** Hold-window (inclusive ms range) for a peer-selection mode. */
    fun windowFor(mode: PeerSelectionMode): IntRange = when (mode) {
        PeerSelectionMode.MAXIMUM_SECURITY -> MAX_SECURITY_WINDOW_MS
        PeerSelectionMode.EMERGENCY        -> 0..0
        PeerSelectionMode.STANDARD,
        PeerSelectionMode.OPERATIONAL      -> STANDARD_WINDOW_MS
    }

    /** Choose up to [FANOUT] distinct random peers. Fewer if the pool is smaller. */
    fun pickPeers(all: List<DhtContact>, random: Random = rng): List<DhtContact> =
        if (all.size <= FANOUT) all else all.shuffled(random).take(FANOUT)

    /**
     * Whether at least one more emission fits in the current 60s budget window.
     * NOTE: this is only safe to call from the pump coroutine. External callers
     * should use [submit] which performs its own pre-flight check via queue size.
     */
    private fun budgetAvailable(nowMs: Long): Boolean {
        pumpPruneBudget(nowMs)
        return emissionTimestamps.size < MAX_QUERIES_PER_MINUTE
    }

    companion object {
        const val FANOUT                  = 3
        const val MAX_QUERIES_PER_MINUTE  = 10
        const val BUDGET_WINDOW_MS        = 60_000L
        const val POLL_MS                 = 100L
        val STANDARD_WINDOW_MS            = 0..500
        val MAX_SECURITY_WINDOW_MS        = 1000..3000
    }
}

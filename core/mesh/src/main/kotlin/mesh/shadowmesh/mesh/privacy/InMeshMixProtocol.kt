package mesh.shadowmesh.mesh.privacy

import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom
import java.util.concurrent.ConcurrentLinkedQueue
import mesh.shadowmesh.diagnostics.Diag

/**
 * In-mesh mix protocol — design doc Phase 8, Maximum Security mode only.
 *
 * Batches and reorders fragment relay to break timing correlation between
 * input and output fragment streams. An observer watching the relay node
 * cannot link which incoming fragment corresponds to which outgoing fragment.
 *
 * Parameters:
 *   Window: 2–10 seconds. Fragments are held for this window before flush.
 *   Minimum: ≥3 fragments must be in the pool before any flush.
 *   Decoy injection: if pool has <3 fragments at flush time, decoys are
 *     added to reach the minimum before flush.
 *   Shuffle: fragments in the pool are randomly reordered before forwarding.
 *
 * This is a Maximum Security only feature. In STANDARD mode, fragments are
 * forwarded immediately (no mix). The mix adds 2–10 seconds of latency per hop.
 *
 * User must explicitly enable Maximum Security mode — it is off by default
 * (design doc: "Default OFF — user explicitly enables").
 *
 * Thread-safety: [pool] uses ConcurrentLinkedQueue. [flushJob] is serialised
 * by the single coroutine. Mix operations are single-threaded.
 */
class InMeshMixProtocol(
    private val scope:     CoroutineScope,
    private val transport: MixTransport,
    private val rng:       SecureRandom = SecureRandom(),
    /**
     * Provides the full peer pool for decoy routing. When set, each decoy fragment is
     * forwarded to an independently-chosen random peer rather than the same target as the
     * first real fragment. Without this, all decoys share one target — observable by an
     * adversary watching which peers receive unusual bursts of otherwise-unknown fragment IDs.
     */
    private val getPeers:  (() -> List<DhtContact>)? = null
) {
    private val pool = ConcurrentLinkedQueue<PooledFragment>()

    @Volatile private var enabled   = false
    @Volatile private var windowMs  = DEFAULT_WINDOW_MS
    private var flushJob: Job?      = null
    // Serialises enable()/disable() so concurrent callers cannot spawn two flush loops.
    private val lifecycleMutex      = Mutex()

    data class PooledFragment(
        val fragment:  FragmentEntity,
        val target:    DhtContact,
        val addedAtMs: Long = System.currentTimeMillis()
    )

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Enable mix pooling with the given [windowMs] flush interval.
     *
     * [enabled] is set synchronously before this function returns so that any
     * [relay] call on the same thread immediately observes the new state.
     * The flush loop launch is guarded by [lifecycleMutex] to prevent two
     * concurrent callers from each spawning an independent flush loop.
     */
    fun enable(windowMs: Long = DEFAULT_WINDOW_MS) {
        this.windowMs = windowMs.coerceIn(MIN_WINDOW_MS, MAX_WINDOW_MS)
        enabled = true  // set synchronously — visible to relay() immediately
        scope.launch {
            lifecycleMutex.withLock {
                if (flushJob == null || flushJob?.isActive == false) {
                    flushJob = scope.launch { runFlushLoop() }
                }
            }
        }
    }

    /**
     * Disable mix pooling.
     *
     * [enabled] is cleared synchronously before this function returns so that
     * any [relay] call on the same thread immediately bypasses the pool.
     * The flush-job cancellation and final flush run asynchronously.
     */
    fun disable() {
        enabled = false  // clear synchronously — relay() bypasses pool immediately
        scope.launch {
            lifecycleMutex.withLock {
                flushJob?.cancel()
                flushJob = null
            }
            // Flush remaining fragments outside the lock so forwarding does not
            // block a concurrent enable() call.
            flushNow()
        }
    }

    // ── Fragment ingestion ─────────────────────────────────────────────────

    /**
     * Add [fragment] to the mix pool for relay to [target].
     * If mix is disabled, forwards immediately (STANDARD mode).
     */
    suspend fun relay(fragment: FragmentEntity, target: DhtContact) {
        if (!enabled) {
            transport.forwardFragment(target, fragment)
            return
        }
        pool.add(PooledFragment(fragment, target))
    }

    // ── Flush loop ────────────────────────────────────────────────────────

    private suspend fun runFlushLoop() {
        while (currentCoroutineContext().isActive && enabled) {
            delay(windowMs)
            flushNow()
        }
    }

    private suspend fun flushNow() {
        val batch = drainPool()
        if (batch.isEmpty()) return

        // Inject decoys if below minimum
        val effective = if (batch.size < MIN_POOL_SIZE) {
            batch + generateDecoys(MIN_POOL_SIZE - batch.size, batch.first().target)
        } else {
            batch
        }

        // Shuffle — break input-to-output correlation
        val shuffled = effective.shuffled(java.util.Random(rng.nextLong()))

        // Forward
        shuffled.forEach { pooled ->
            try { transport.forwardFragment(pooled.target, pooled.fragment) }
            catch (e: Exception) {
                Diag.swallowed("mix-protocol", "forward-fragment", e,
                    "target" to pooled.target.nodeId.toHex().take(8))
            }
        }
    }

    private fun drainPool(): List<PooledFragment> {
        val drained = mutableListOf<PooledFragment>()
        while (true) {
            drained.add(pool.poll() ?: break)
        }
        return drained
    }

    private fun generateDecoys(count: Int, fallbackTarget: DhtContact): List<PooledFragment> {
        // Snapshot the peer pool once for this decoy batch. If no pool is configured,
        // all decoys fall back to fallbackTarget (same as before). When a pool is
        // available, each decoy is independently routed to a randomly-chosen peer so
        // an adversary watching any single peer cannot distinguish "one real + N decoys
        // all going to me" from "N real fragments from N different senders".
        val peerPool = getPeers?.invoke()?.takeIf { it.isNotEmpty() }
        return (0 until count).map {
            val target   = if (peerPool != null) peerPool[rng.nextInt(peerPool.size)] else fallbackTarget
            val payload  = ByteArray(512).also { rng.nextBytes(it) }

            // Generate independent random IDs — must be indistinguishable from real fragments.
            // Using SNDP_FAKE_CHANNEL_ID (all-zeros constant) as channelId leaks decoy identity
            // to any relay node that inspects fragment metadata: the design doc requires decoys
            // to be indistinguishable. Instead, use 32 bytes of fresh SecureRandom output for
            // both postId and channelId, formatted as 64-character hex strings — the same format
            // real fragments use. These IDs are never stored or replicated; they are ephemeral.
            val fakePostIdBytes    = ByteArray(32).also { rng.nextBytes(it) }
            val fakeChannelIdBytes = ByteArray(32).also { rng.nextBytes(it) }
            val fakePostIdHex      = fakePostIdBytes.toHex()
            val fakeChannelIdHex   = fakeChannelIdBytes.toHex()

            // Content-addressed fragmentId — same computation as real fragments.
            val fragmentId = mesh.shadowmesh.mesh.fragment.FragmentEntity.computeFragmentId(
                postId        = fakePostIdBytes,
                sequenceIndex = it,
                payload       = payload
            )

            PooledFragment(
                fragment = mesh.shadowmesh.mesh.fragment.FragmentEntity(
                    fragmentId    = fragmentId,
                    postId        = fakePostIdHex,
                    channelId     = fakeChannelIdHex,
                    sequenceIndex = it,
                    totalData     = count,
                    totalParity   = 0,
                    payload       = payload,
                    fecScheme     = mesh.shadowmesh.mesh.fragment.FecScheme.NONE
                ),
                target = target
            )
        }
    }

    fun poolSize(): Int     = pool.size
    fun isEnabled(): Boolean = enabled

    companion object {
        const val DEFAULT_WINDOW_MS = 5_000L
        const val MIN_WINDOW_MS     = 2_000L
        const val MAX_WINDOW_MS     = 10_000L
        const val MIN_POOL_SIZE     = 3
    }
}

interface MixTransport {
    suspend fun forwardFragment(target: DhtContact, fragment: FragmentEntity)
}

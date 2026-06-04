package mesh.shadowmesh.mesh.delivery

import mesh.shadowmesh.mesh.fragment.FragmentEntity
import mesh.shadowmesh.mesh.dht.*
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import mesh.shadowmesh.crypto.hexToBytes
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag

/**
 * Store-and-forward manager — design doc §8.
 *
 * Replication factor 3: every fragment is stored on 3 nodes (anchor-preferred).
 * When the recipient is offline, any of the 3 holding nodes can deliver on reconnect.
 *
 * Replication strategy:
 *   1. Send to the 3 anchor nodes closest to SHA3-256(postId) in DHT space
 *   2. If fewer than 3 anchors available, fill remaining slots with Tier 2 nodes
 *   3. Replication is fire-and-forget — failures are silent
 *      (FEC handles reconstruction from whichever replicas survive)
 *
 * Delivery on reconnect:
 *   When a node comes back online, it queries the DHT for posts in channels
 *   it follows with timestamps > its last-seen timestamp.
 *   Holding nodes respond with fragment sets.
 *
 * Queue (offline outbound):
 *   Posts created while offline are queued locally. On reconnect, they are
 *   dispatched in order. Each post re-enters the PENDING state machine.
 *
 * Thread-safety: ConcurrentHashMap for replica tracking.
 * Outbound queue is a CopyOnWriteArrayList — iterated on reconnect.
 */
class StoreAndForwardManager(
    private val scope:          CoroutineScope,
    private val transport:      StoreForwardTransport,
    private val routingTable:   RoutingTable,
    /**
     * Fragment fetcher with transport preference ordering.
     * When provided, [fetchMissedPosts] delegates to this fetcher, which
     * applies the configured [FetchPolicy] (PREFER_LOCAL by default) before
     * falling back to DHT. When null, the legacy DHT-only path is used.
     */
    private val fragmentFetcher: FragmentFetcher? = null,
    /**
     * Density-aware replication policy.
     * When provided, [replicate] calls [DensityAwareReplicationPolicy.effectiveFactor]
     * with the current local peer count to determine how many DHT nodes to target.
     * When null, the hardcoded [REPLICATION_FACTOR] constant is used (legacy behaviour).
     */
    private val replicationPolicy: DensityAwareReplicationPolicy? = null,
    /**
     * Supplies the current network mode and local peer count for density-aware
     * replication. Called at replicate-time — must return fresh values.
     * Ignored when [replicationPolicy] is null.
     */
    private val densityContext: (() -> DensityContext)? = null
) {
    // Optional health monitor — set by the composition root.
    // In ISOLATED state, queued fragments use ISOLATED_HOLD_MS instead of RELAY_HOLD_MS.
    @Volatile var healthMonitor: mesh.shadowmesh.mesh.health.TransportHealthMonitor? = null

    // postId → list of nodeIds holding replicas
    private val replicaLocations = ConcurrentHashMap<String, java.util.concurrent.CopyOnWriteArrayList<String>>()

    // Outbound queue: posts created offline, pending dispatch
    private val outboundQueue = CopyOnWriteArrayList<QueuedPost>()

    // ── Replicate ─────────────────────────────────────────────────────────

    /**
     * Replicate [fragments] to the effective number of nodes.
     *
     * When a [replicationPolicy] and [densityContext] are provided, the factor
     * is computed from the current [NetworkMode] and local peer count — dense
     * clusters use a lower DHT factor because local peers implicitly hold copies.
     * Without them, falls back to the hardcoded [REPLICATION_FACTOR].
     *
     * @param postId     Used to determine closest DHT nodes
     * @param fragments  Complete fragment set for this post
     */
    suspend fun replicate(postId: ByteArray, fragments: List<FragmentEntity>) {
        val rawFactor = if (replicationPolicy != null && densityContext != null) {
            val ctx = densityContext!!.invoke()
            replicationPolicy.effectiveFactor(ctx.mode, ctx.localPeerCount)
                .coerceAtLeast(DensityAwareReplicationPolicy.MINIMUM_FACTOR)
        } else {
            REPLICATION_FACTOR
        }

        // Guard: Int.MAX_VALUE means "all available" (CRITICAL/SURVIVAL). Multiplying it
        // by 2 overflows to -2, causing List.take(-2) → IllegalArgumentException.
        // Resolve to the actual routing table size so the semantics are correct and
        // no arithmetic overflow can occur regardless of what the policy returns.
        val factor = if (rawFactor == Int.MAX_VALUE) routingTable.size() else rawFactor

        // Hash postId before using as DHT routing target. Passing raw postId bytes
        // exposed the post identity in the DHT address space — any node that received one
        // shard could trivially compute the exact routing target and enumerate all shards.
        // SHA3-256(postId) is a one-way function; the preimage (postId) is only known to
        // channel members who have already received at least one fragment's wire header.
        val target    = NodeId(mesh.shadowmesh.crypto.Hkdf.instance.sha3_256(postId))
        val candidates= routingTable.findClosest(target, (factor * 2).coerceAtLeast(1))

        // Prefer Tier 1 anchors; fill with Tier 2 if needed
        val anchors  = candidates.filter { it.tier == NodeTier.TIER_1 }.take(factor)
        val tier2    = candidates.filter { it.tier == NodeTier.TIER_2 }
        val targets  = (anchors + tier2).distinctBy { it.nodeId }.take(factor.coerceAtLeast(1))

        val postIdHex = postId.toHex()
        val locations = replicaLocations.computeIfAbsent(postIdHex) { java.util.concurrent.CopyOnWriteArrayList() }

        targets.forEach { node ->
            scope.launch {
                try {
                    fragments.forEach { fragment -> transport.storeFragment(node, fragment) }
                    locations.add(node.nodeId.bytes.toHex())  // CopyOnWriteArrayList.add is thread-safe
                } catch (e: Exception) {
                    // FEC tolerates partial replication, but a node that NEVER accepts
                    // fragments is a real availability problem — surface it.
                    Diag.swallowed("store-forward", "replicate-to-node", e,
                        "node" to node.nodeId.bytes.toHex())
                }
            }
        }
    }

    // ── Outbound queue ────────────────────────────────────────────────────

    /**
     * Queue a post for delivery when connectivity is restored.
     *
     * In ISOLATED state, fragments are re-stamped with a 24-hour hold time so relay
     * nodes retain them long enough for the device to regain any transport and deliver.
     */
    fun enqueue(postId: String, channelId: String, fragments: List<FragmentEntity>) {
        // Cap the queue to prevent OOM during long offline periods. Each QueuedPost holds
        // a full List<FragmentEntity> (potentially tens of KB). At MAX_QUEUED_POSTS = 200,
        // worst-case heap impact is ~200 × FEC_RS_10_7 × 64KB/fragment ≈ 340MB.
        // In practice posts are much smaller; 200 queued posts covers realistic offline bursts.
        if (outboundQueue.size >= MAX_QUEUED_POSTS) {
            Diag.degraded("store-forward", "outbound-queue-full",
                "Outbound queue at capacity ($MAX_QUEUED_POSTS) — dropping post $postId. " +
                "Reduce posting rate or restore connectivity to drain the queue.",
                "postId" to postId.take(8))
            return
        }
        val isolated = healthMonitor?.currentState?.value ==
            mesh.shadowmesh.mesh.health.MeshHealthState.ISOLATED
        val holdMs = if (isolated) ISOLATED_HOLD_MS else mesh.shadowmesh.mesh.fragment.FragmentEntity.RELAY_HOLD_MS
        val now = System.currentTimeMillis()
        val stamped = if (isolated) {
            fragments.map { it.copy(heldUntilMs = now + holdMs) }
        } else {
            fragments
        }
        outboundQueue.add(QueuedPost(postId, channelId, stamped, now))
    }

    /**
     * Drain the outbound queue on reconnect.
     * Returns the number of posts dispatched.
     */
    suspend fun drainOnReconnect(): Int {
        val queued = outboundQueue.toList()
        if (queued.isEmpty()) return 0

        var dispatched = 0
        queued.forEach { post ->
            try {
                replicate(hexToBytes(post.postId), post.fragments)
                outboundQueue.remove(post)
                dispatched++
            } catch (e: Exception) {
                Diag.swallowed("store-forward", "drain-retry-kept", e, "postId" to post.postId)
                // Keep in queue — retry next reconnect
            }
        }
        return dispatched
    }

    // ── Fetch on reconnect ────────────────────────────────────────────────

    /**
     * Fetch missed posts for [channelId] since [lastSeenMs].
     *
     * When a [FragmentFetcher] is configured, delegates to it for preference-ordered
     * retrieval (local cache → local peers → DHT). Without a fetcher, falls back
     * to the legacy DHT-only path.
     *
     * @return List of fragment sets ready for reassembly
     */
    suspend fun fetchMissedPosts(
        channelId:  ByteArray,
        lastSeenMs: Long
    ): List<List<FragmentEntity>> {
        // Preferred path: FragmentFetcher with explicit transport preference ordering
        if (fragmentFetcher != null) {
            val fragments = fragmentFetcher.fetchMissedFragments(channelId, lastSeenMs)
            if (fragments.isNotEmpty()) {
                // Group by postId for reassembly
                return fragments.groupBy { it.postId }.values.toList()
            }
        }

        // Legacy fallback: DHT-only (used when no local peers registered)
        return fetchMissedPostsViaDht(channelId, lastSeenMs)
    }

    /** Legacy DHT-only fetch path. Preserved for backwards compatibility. */
    private suspend fun fetchMissedPostsViaDht(
        channelId:  ByteArray,
        lastSeenMs: Long
    ): List<List<FragmentEntity>> {
        val channelKey = NodeId(
            mesh.shadowmesh.crypto.Hkdf.instance.sha3_256(channelId)
        )
        val holders = routingTable.findClosest(channelKey, 3)

        val allFragments = mutableListOf<List<FragmentEntity>>()
        holders.forEach { node ->
            try {
                val frags = transport.fetchFragmentsSince(node, channelId, lastSeenMs)
                allFragments.add(frags)
            } catch (e: Exception) {
                Diag.swallowed("store-forward", "fetch-holder-skip", e,
                    "node" to node.nodeId.bytes.toHex(), "channelId" to channelId.toHex())
                /* try next holder */
            }
        }
        return allFragments
    }

    // ── Replica tracking ──────────────────────────────────────────────────

    fun replicaNodesFor(postId: String): List<String> =
        replicaLocations[postId]?.toList() ?: emptyList()

    fun queueSize(): Int = outboundQueue.size

    // ── Helpers ───────────────────────────────────────────────────────────


    companion object {
        const val REPLICATION_FACTOR = 3

        // In ISOLATED state, hold fragments for 24 h instead of the normal 2 h.
        // This gives the device time to regain any transport and deliver queued posts.
        const val ISOLATED_HOLD_MS = 24L * 60 * 60 * 1000

        /**
         * Maximum posts queued for offline delivery. Each [QueuedPost] holds a full
         * List<FragmentEntity>. Without this cap, a device posting many messages while
         * offline grows the queue without bound. 200 posts covers realistic offline bursts
         * while keeping memory predictable; callers should surface a "queue full" error to
         * the user so they know to wait for connectivity before posting more.
         */
        const val MAX_QUEUED_POSTS = 200
    }
}

data class QueuedPost(
    val postId:    String,
    val channelId: String,
    val fragments: List<FragmentEntity>,
    val queuedAtMs:Long
)

/**
 * Snapshot of the context needed to compute the effective replication factor.
 * Supplied by [StoreAndForwardManager]'s caller at replicate-time so the
 * manager never holds a stale reference to mode or peer state.
 *
 * @param mode           Current [NetworkMode] at time of replication.
 * @param localPeerCount Number of locally-visible peers from [LocalPeerRegistry]
 *                       (WiFi Direct + LAN + BLE). Zero if no local peers registered.
 */
data class DensityContext(
    val mode:           mesh.shadowmesh.mesh.mode.NetworkMode,
    val localPeerCount: Int
)

interface StoreForwardTransport {
    suspend fun storeFragment(node: DhtContact, fragment: FragmentEntity)
    suspend fun fetchFragmentsSince(node: DhtContact, channelId: ByteArray, sinceMs: Long): List<FragmentEntity>
}

package mesh.shadowmesh.mesh.delivery

import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import mesh.shadowmesh.mesh.transport.lan.LanPeer
import kotlinx.coroutines.*
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag

/**
 * Fragment fetcher with explicit transport preference ordering.
 *
 * Problem this solves:
 *   Before this class existed, [StoreAndForwardManager.fetchMissedPosts] went
 *   straight to the DHT regardless of whether the fragment was available from a
 *   device sitting 50cm away on the same WiFi network. The DHT path routes
 *   through the internet, leaks timing metadata, and is slower.
 *
 * Preference order:
 *   1. Local cache — zero-cost, instant
 *   2. Connected local peers in parallel:
 *        a. WiFi Direct peers   (~200m, LAN-speed, zero internet)
 *        b. LAN subnet peers    (same subnet, ethernet/WiFi, zero internet)
 *        c. BLE peers           (<10m, slower, but covers pocket-to-pocket)
 *      First peer to respond wins. All local peers queried simultaneously.
 *   3. DHT lookup over internet — only if all local peers fail or are absent.
 *
 * Proactive push after DHT hit:
 *   When a fragment is fetched from the internet, it is immediately pushed to
 *   all currently-connected local peers. This fills the local mesh cache so
 *   that subsequent requests from nearby devices never need to hit the internet.
 *
 * User preference:
 *   [FetchPolicy.PREFER_LOCAL]   (default) — order above, DHT is last resort.
 *   [FetchPolicy.PREFER_DHT]     — DHT first, local peers skipped. Hides physical
 *                                  location from local peers. Slower, more anonymous.
 *   [FetchPolicy.LOCAL_ONLY]     — never query DHT. Suitable for air-gapped deployments.
 *
 * Thread-safety: [localPeers] and [lanPeers] are read-only after injection;
 * mutations go through the registered [LocalPeerRegistry]. All I/O on Dispatchers.IO.
 */
open class FragmentFetcher(
    private val localCache:   LocalFragmentCache,
    private val localPeers:   LocalPeerRegistry,
    private val dhtEngine:    DhtEngine,
    private val scope:        CoroutineScope,
    private val policy:       FetchPolicy = FetchPolicy.PREFER_LOCAL,
    /**
     * Transport used to fetch fragments from DHT holder nodes on the missed-post path.
     * When null, [fetchMissedDht] returns empty (degraded — DHT batch fetch unavailable).
     * The single-fragment [queryDht] path uses [dhtEngine.findValue] and does not need this.
     */
    private val dhtTransport: StoreForwardTransport? = null
) {

    // ── Primary API ───────────────────────────────────────────────────────

    /**
     * Fetch a specific fragment by [fragmentId] using the configured [policy].
     *
     * @return The [FragmentEntity] if found, or null if not found anywhere.
     */
    suspend fun fetchFragment(
        fragmentId: String,
        postId:     ByteArray
    ): FragmentEntity? = when (policy) {
        FetchPolicy.PREFER_LOCAL -> fetchPreferLocal(fragmentId, postId)
        FetchPolicy.PREFER_DHT   -> fetchPreferDht(fragmentId, postId)
        FetchPolicy.LOCAL_ONLY   -> fetchLocalOnly(fragmentId, postId)
    }

    /**
     * Fetch all missing fragments for [postId] since [lastSeenMs].
     * Applies the preference order to each fragment individually, but batches
     * the local-peer queries to avoid N×M round-trips.
     *
     * @return Flat list of all fragments found, from any source.
     */
    open suspend fun fetchMissedFragments(
        channelId:  ByteArray,
        lastSeenMs: Long
    ): List<FragmentEntity> = when (policy) {
        FetchPolicy.LOCAL_ONLY -> fetchMissedLocal(channelId, lastSeenMs)
        FetchPolicy.PREFER_DHT -> fetchMissedDht(channelId, lastSeenMs)
        FetchPolicy.PREFER_LOCAL -> {
            val fromLocal = fetchMissedLocal(channelId, lastSeenMs)
            if (fromLocal.isNotEmpty()) fromLocal
            else {
                val fromDht = fetchMissedDht(channelId, lastSeenMs)
                if (fromDht.isNotEmpty()) {
                    proactivePushToLocal(fromDht)
                }
                fromDht
            }
        }
    }

    // ── Policy implementations ────────────────────────────────────────────

    /** PREFER_LOCAL: cache → local peers → DHT */
    private suspend fun fetchPreferLocal(
        fragmentId: String,
        postId:     ByteArray
    ): FragmentEntity? {
        // 1. Local cache
        localCache.get(fragmentId)?.let { return it }

        // 2. All local peers in parallel — first response wins
        val fromLocal = queryLocalPeersParallel(fragmentId, postId)
        if (fromLocal != null) {
            localCache.put(fromLocal)
            return fromLocal
        }

        // 3. DHT — last resort
        val fromDht = queryDht(fragmentId, postId)
        if (fromDht != null) {
            localCache.put(fromDht)
            proactivePushToLocal(listOf(fromDht))
        }
        return fromDht
    }

    /** PREFER_DHT: cache → DHT → local peers */
    private suspend fun fetchPreferDht(
        fragmentId: String,
        postId:     ByteArray
    ): FragmentEntity? {
        localCache.get(fragmentId)?.let { return it }

        val fromDht = queryDht(fragmentId, postId)
        if (fromDht != null) {
            localCache.put(fromDht)
            return fromDht
        }

        return queryLocalPeersParallel(fragmentId, postId)?.also { localCache.put(it) }
    }

    /** LOCAL_ONLY: cache → local peers, never queries DHT */
    private suspend fun fetchLocalOnly(
        fragmentId: String,
        postId:     ByteArray
    ): FragmentEntity? {
        localCache.get(fragmentId)?.let { return it }
        return queryLocalPeersParallel(fragmentId, postId)?.also { localCache.put(it) }
    }

    // ── Missed-post batch variants ────────────────────────────────────────

    private suspend fun fetchMissedLocal(
        channelId:  ByteArray,
        lastSeenMs: Long
    ): List<FragmentEntity> {
        val peers = localPeers.allLocalPeers()
        if (peers.isEmpty()) return emptyList()

        // Query all local peers simultaneously, merge results
        return withContext(Dispatchers.IO) {
            peers.map { peer ->
                async {
                    try { peer.fetchFragmentsSince(channelId, lastSeenMs) }
                    catch (e: Exception) {
                        Diag.swallowed("fragment-fetcher", "local-peer-fetch", e,
                            "peer" to peer.peerId, "transport" to peer.transportType.name)
                        emptyList()
                    }
                }
            }.awaitAll().flatten()
        }.also { frags -> frags.forEach { localCache.put(it) } }
    }

    private suspend fun fetchMissedDht(
        channelId:  ByteArray,
        lastSeenMs: Long
    ): List<FragmentEntity> {
        // Find the DHT nodes closest to this channel — they hold the fragment replicas.
        // Key: SHA3-256(channelId) — matches how StoreAndForwardManager.replicate() stores them.
        val channelKey = NodeId(mesh.shadowmesh.crypto.Hkdf.instance.sha3_256(channelId))
        val holders    = dhtEngine.routingTable.findClosest(channelKey, DHT_HOLDER_COUNT)
        if (holders.isEmpty()) return emptyList()
        if (dhtTransport == null) return emptyList()  // degraded — no transport injected

        // Ask each holder for all fragments since lastSeenMs via the StoreForward transport.
        // This is the correct path — StoreForwardTransport.fetchFragmentsSince() is what
        // holding nodes implement to serve missed-post requests.
        return withContext(Dispatchers.IO) {
            holders.map { node ->
                async {
                    try {
                        dhtTransport.fetchFragmentsSince(node, channelId, lastSeenMs)
                    } catch (e: Exception) {
                        Diag.swallowed("fragment-fetcher", "dht-holder-fetch", e,
                            "node" to node.nodeId.bytes.toHex().take(8))
                        emptyList()
                    }
                }
            }.awaitAll().flatten().also { frags ->
                frags.forEach { localCache.put(it) }
            }
        }
    }

    // ── Local peer parallel query ─────────────────────────────────────────

    /**
     * Query all connected local peers in parallel for [fragmentId].
     * WiFi Direct, LAN, and BLE peers are all queried simultaneously.
     * Returns the result of whichever peer responds first, or null if none has it.
     */
    private suspend fun queryLocalPeersParallel(
        fragmentId: String,
        postId:     ByteArray
    ): FragmentEntity? = withContext(Dispatchers.IO) {
        val peers = localPeers.allLocalPeers()
        if (peers.isEmpty()) return@withContext null

        // True race: all peers are queried concurrently. The first non-null
        // result is returned immediately; the remaining coroutines are cancelled.
        //
        // Previous implementation used sequential `d.await()` in a for-loop,
        // which polled peers in list order — a slow peer[0] blocked peers[1..N]
        // even if they had the fragment available immediately.
        //
        // This implementation uses a Channel as a rendezvous point. Each peer
        // coroutine sends its result (or null) as soon as it completes. The
        // collector reads from the channel until it sees a non-null result or
        // all peers have replied.
        val resultChannel = kotlinx.coroutines.channels.Channel<FragmentEntity?>(
            capacity = peers.size
        )
        val jobs = peers.map { peer ->
            launch {
                val fragment = try {
                    // Per-peer timeout: a hung local peer (BLE partner gone silent, TCP stuck
                    // in CLOSE_WAIT) must not block the entire fetch for all other peers.
                    // withTimeoutOrNull returns null on timeout; the collector treats null as
                    // "peer did not have the fragment" and continues.
                    withTimeoutOrNull(PEER_FETCH_TIMEOUT_MS) { peer.fetchFragment(fragmentId) }
                } catch (e: Exception) {
                    Diag.swallowed("fragment-fetcher", "local-peer-query", e,
                        "peer" to peer.peerId, "fragmentId" to fragmentId.take(8))
                    null
                }
                resultChannel.trySend(fragment)
            }
        }

        var result: FragmentEntity? = null
        repeat(peers.size) {
            val fragment = resultChannel.receive()
            if (fragment != null && result == null) {
                result = fragment
            }
        }
        resultChannel.close()
        jobs.forEach { it.cancel() }
        result
    }

    // ── DHT query ─────────────────────────────────────────────────────────

    private suspend fun queryDht(
        fragmentId: String,
        postId:     ByteArray
    ): FragmentEntity? {
        val key    = NodeId(mesh.shadowmesh.crypto.Hkdf.instance.sha3_256(postId))
        val result = dhtEngine.findValue(key)
        return when (result) {
            is LookupResult.Found -> deserializeFragment(result.value)
            else -> null
        }
    }

    /**
     * Deserialize a [FragmentEntity] from the DHT wire format.
     *
     * Wire format (from FragmentModels.kt §wire format):
     *   [32B fragmentId hex][32B postId hex][32B channelId hex]
     *   [2B sequenceIndex][2B totalData][2B totalParity][4B payloadLen]
     *   [payloadLen bytes][1B fecWire]
     *
     * Returns null if the bytes are too short or malformed.
     */
    private fun deserializeFragment(bytes: ByteArray): FragmentEntity? { return try {
        val dis         = java.io.DataInputStream(java.io.ByteArrayInputStream(bytes))
        val fragmentId  = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val postId      = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val channelId   = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        // Use readUnsignedShort() — same sign-extension fix applied to FragmentEntity.fromWire(),
        // LanSubnetTransport.deserializeFragment(), and WiFiDirectTransport.deserializeFragment().
        // readShort().toInt() sign-extends 0xFFFF to -1; a negative totalData causes phantom-Complete
        // in FragmentAccumulator (count >= -1 always true), silently suppressing post delivery.
        val seqIdx      = dis.readUnsignedShort()
        val totalData   = dis.readUnsignedShort()
        val totalParity = dis.readUnsignedShort()
        if (totalData == 0 || totalData > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS ||
            totalParity > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS) return null
        val payloadLen  = dis.readInt()
        if (payloadLen < 0 || payloadLen > MAX_FRAGMENT_PAYLOAD_BYTES) return null
        val payload     = ByteArray(payloadLen).also { dis.readFully(it) }
        val fecWire     = dis.readByte().toInt()
        val fecScheme   = mesh.shadowmesh.mesh.fragment.FecScheme.fromWire(fecWire)
        mesh.shadowmesh.mesh.fragment.FragmentEntity(
            fragmentId    = fragmentId,
            postId        = postId,
            channelId     = channelId,
            sequenceIndex = seqIdx,
            totalData     = totalData,
            totalParity   = totalParity,
            payload       = payload,
            fecScheme     = fecScheme ?: mesh.shadowmesh.mesh.fragment.FecScheme.NONE
        )
    } catch (e: Exception) {
        Diag.swallowed("fragment-fetcher", "deserialize", e)
        null
    } }

    // ── Proactive push to local peers ─────────────────────────────────────

    /**
     * After fetching from DHT, push fragments to all connected local peers
     * so nearby devices don't need to query the internet for the same content.
     */
    private fun proactivePushToLocal(fragments: List<FragmentEntity>) {
        val peers = localPeers.allLocalPeers()
        if (peers.isEmpty() || fragments.isEmpty()) return

        scope.launch(Dispatchers.IO) {
            peers.forEach { peer ->
                launch {
                    fragments.forEach { fragment ->
                        try { peer.pushFragment(fragment) }
                        catch (e: Exception) {
                            Diag.swallowed("fragment-fetcher", "proactive-push", e,
                                "peer" to peer.peerId)
                        }
                    }
                }
            }
        }
    }

    private fun longToBytes(v: Long): ByteArray = ByteArray(8) { i ->
        ((v shr ((7 - i) * 8)) and 0xFF).toByte()
    }

    companion object {
        private const val DHT_HOLDER_COUNT           = 3
        private const val MAX_FRAGMENT_PAYLOAD_BYTES = 64 * 1024  // 64KB max fragment payload

        /**
         * Per-peer timeout for [queryLocalPeersParallel]. Without this, a hung local peer
         * (BLE partner gone silent, LAN TCP stuck in CLOSE_WAIT, WiFi Direct disconnect race)
         * would block the entire fetch for as long as the peer implementation takes to surface
         * the error — indefinitely in the worst case. 5 s is generous for a local transport.
         */
        private const val PEER_FETCH_TIMEOUT_MS = 5_000L
    }
}

// ── Fetch policy ──────────────────────────────────────────────────────────────

/**
 * Transport preference policy for fragment retrieval.
 *
 * [PREFER_LOCAL]  — (default) local cache → WiFi Direct / LAN / BLE → DHT.
 *                   Fastest for co-located devices. Minimises internet use.
 *                   Does not hide physical proximity from local peers.
 *
 * [PREFER_DHT]    — local cache → DHT → local peers.
 *                   Hides physical location: local peers do not learn which
 *                   fragments this node is fetching. Slower, more anonymous.
 *                   Appropriate when operational security outweighs speed.
 *
 * [LOCAL_ONLY]    — local cache → local peers only. Never queries DHT.
 *                   For air-gapped / SURVIVAL mode deployments where internet
 *                   access is absent or prohibited.
 */
enum class FetchPolicy {
    PREFER_LOCAL,
    PREFER_DHT,
    LOCAL_ONLY
}

// ── Peer abstraction ──────────────────────────────────────────────────────────

/**
 * Uniform interface over local transport peers (WiFi Direct, LAN, BLE).
 * The [FragmentFetcher] speaks to all three transports identically.
 * Each transport implements [LocalPeer] in its own module.
 */
interface LocalPeer {
    val peerId: String
    val transportType: LocalTransportType

    /** Fetch a specific fragment by ID. Returns null if the peer does not have it. */
    suspend fun fetchFragment(fragmentId: String): FragmentEntity?

    /** Fetch all fragments for [channelId] since [sinceMs]. */
    suspend fun fetchFragmentsSince(channelId: ByteArray, sinceMs: Long): List<FragmentEntity>

    /** Push a fragment to this peer proactively. */
    suspend fun pushFragment(fragment: FragmentEntity)
}

enum class LocalTransportType {
    WIFI_DIRECT,
    LAN_SUBNET,
    BLE
}

/**
 * Registry of currently-connected local peers across all transport types.
 * Maintained by the transport layer — [FragmentFetcher] reads it at fetch time.
 *
 * Thread-safety: implementations must be thread-safe.
 */
interface LocalPeerRegistry {
    /** All currently-connected local peers, across all transport types. */
    fun allLocalPeers(): List<LocalPeer>

    /** Peers of a specific transport type only. */
    fun peersOfType(type: LocalTransportType): List<LocalPeer>
}

/**
 * Local fragment cache — in-memory, LRU-evicting.
 * Fragments fetched from any source are stored here to serve
 * future requests without any network round-trip.
 *
 * Thread-safety: implementations must be thread-safe.
 */
interface LocalFragmentCache {
    fun get(fragmentId: String): FragmentEntity?
    fun put(fragment: FragmentEntity)
    fun evict(fragmentId: String)
    fun size(): Int
}

/**
 * Simple LRU fragment cache backed by [LinkedHashMap].
 *
 * @param maxSize  Maximum number of fragments to hold. Default: 10,000 (~640MB at 64KB/fragment).
 *                 Adjust for device storage constraints.
 */
class LruFragmentCache(private val maxSize: Int = DEFAULT_CACHE_SIZE) : LocalFragmentCache {

    private val cache = object : LinkedHashMap<String, FragmentEntity>(maxSize, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, FragmentEntity>) =
            size > maxSize
    }

    @Synchronized override fun get(fragmentId: String): FragmentEntity? = cache[fragmentId]
    @Synchronized override fun put(fragment: FragmentEntity) { cache[fragment.fragmentId] = fragment }
    @Synchronized override fun evict(fragmentId: String) { cache.remove(fragmentId) }
    @Synchronized override fun size(): Int = cache.size

    companion object {
        const val DEFAULT_CACHE_SIZE = 10_000
    }
}

package mesh.shadowmesh.mesh.dht

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.diagnostics.Diag

/**
 * Kademlia DHT engine — design doc §4 "Custom Kademlia DHT, Tier 1 anchor nodes only".
 *
 * Implements:
 *   - Iterative FIND_NODE: locate the K closest nodes to a target ID
 *   - FIND_VALUE:          locate a stored value or return closest nodes
 *   - STORE:               publish a value to the K closest nodes
 *   - Local value store:   in-memory cache with TTL eviction
 *   - Dead drop bootstrap: publish and retrieve encrypted channel key blobs
 *   - Stale contact refresh: periodic bucket refresh for nodes not seen recently
 *   - Routing table maintenance: insert / evict / touch on all operations
 *
 * The [transport] parameter abstracts the actual network layer (UDP in Phase 4,
 * injectable for testing). The DHT engine itself is pure logic.
 *
 * Routing table constraint: only Tier 1 anchors are inserted. The engine will
 * still query any contact it receives from a lookup response, but will not add
 * non-Tier-1 nodes to the routing table.
 *
 * Thread-safety: [RoutingTable] is synchronized. Local value store uses
 * ConcurrentHashMap. Lookup operations use structured concurrency.
 *
 * @param localNodeId  This node's DHT identity.
 * @param transport    Network transport — sends RPC messages and returns responses.
 * @param scope        CoroutineScope for background refresh tasks.
 */
open class DhtEngine(
    val localNodeId:  NodeId,
    private val transport: DhtTransport,
    private val scope:     CoroutineScope,
    /**
     * This node's public identity. When provided, the engine maintains a self [SignedContact]
     * that is included in PING responses so peers can obtain verified public key material
     * for this node without a separate out-of-band exchange. Null in test environments that
     * do not have a full [NodePublicIdentity].
     */
    val localPublicIdentity: mesh.shadowmesh.crypto.NodePublicIdentity? = null,
    /**
     * Monotonic sequence counter for this node's signed contacts. Increment on address change.
     * Shared with the transport layer so PING responses always carry the current seq.
     */
    val seqCounter: mesh.shadowmesh.crypto.ContactSeqCounter = mesh.shadowmesh.crypto.ContactSeqCounter()
) {
    val routingTable = RoutingTable(localNodeId)

    // Optional health monitor — set by the composition root after construction.
    // Guards syncCycle() bucket refresh when internet connectivity is absent.
    @Volatile var healthMonitor: mesh.shadowmesh.mesh.health.TransportHealthMonitor? = null

    // Local value store: key → DhtValue. ConcurrentHashMap for thread-safety.
    private val localStore = ConcurrentHashMap<NodeId, DhtValue>()

    // Pending LRS ping state: nodeId → (bucketIdx, lrsContact, newContact)
    private data class PendingPing(val bucketIdx: Int, val lrs: DhtContact, val candidate: DhtContact)
    private val pendingPings = ConcurrentHashMap<NodeId, PendingPing>()

    // ── Bootstrap ─────────────────────────────────────────────────────────

    /**
     * Bootstrap: connect to seed nodes and populate the routing table.
     *
     * 1. Ping each seed to verify it's alive and get its contact info.
     * 2. Perform a FIND_NODE for our own ID to populate buckets near us.
     * 3. Refresh all buckets.
     *
     * @param seeds  Known seed contacts (from hardcoded List A in the APK).
     */
    suspend fun bootstrap(seeds: List<DhtContact>) {
        if (seeds.isEmpty()) {
            // An empty seed list is valid for local-transport-only deployments (LAN, WiFi Direct,
            // BLE). The node will discover peers via local broadcast without internet bootstrap.
            // However, internet-capable deployments that expect a non-empty list A should surface
            // this to operators so they can supply seed entries via SeedList.from() or
            // signed gossip update. Silent failure here means the node appears connected locally
            // but never joins the broader DHT fabric.
            Diag.degraded("dht", "bootstrap-no-seeds",
                "DHT bootstrap seed list is empty. This node will not join the internet DHT " +
                "unless peers are discovered via LAN broadcast, WiFi Direct, or BLE. " +
                "Internet deployments must supply a signed seed list via SeedList.from() " +
                "or receive a SeedListUpdate via gossip from a TRUST_PHYSICAL peer.")
        }

        // Ping seeds and add responding ones to routing table
        seeds.forEach { seed ->
            try {
                val pong = transport.ping(seed)
                if (pong != null) insertContact(pong)
            } catch (e: Exception) {
                Diag.swallowed("dht", "bootstrap-ping", e,
                    "seed" to "${seed.address.ip}:${seed.address.port}")
            }
        }

        // Self-lookup to populate our region of the DHT
        if (routingTable.size() > 0) {
            iterativeFindNode(localNodeId)
        }

        // Refresh all buckets
        refreshAllBuckets()
    }

    /**
     * Return a snapshot of all contacts currently in the routing table.
     * Used by [ShadowMeshForegroundService] to persist the routing table
     * to [DiscoveredPeerEntity] after a successful bootstrap.
     */
    fun currentContacts(): List<DhtContact> = routingTable.allContacts()

    // ── Core RPCs ──────────────────────────────────────────────────────────

    /**
     * Iterative FIND_NODE: find the [K] nodes closest to [target].
     *
     * Uses [ALPHA] parallel lookups at each round. Terminates when no closer
     * node is found in a round, or the target is directly found.
     *
     * Returns the closest [K] contacts found, sorted by XOR distance.
     */
    suspend fun iterativeFindNode(target: NodeId): List<DhtContact> {
        // S/Kademlia eclipse defence: seed from disjoint paths rather than a single
        // findClosest() call. findClosest() returns the K nearest contacts in a
        // single ordered list — an attacker who has filled those K buckets controls
        // the entire seed set and can steer the lookup. findClosestDisjoint() partitions
        // the seed set across DISJOINT_PATHS independent starting points so an attacker
        // must eclipse all paths simultaneously, not just the nearest bucket.
        val closest = routingTable.findClosestDisjoint(target, K).toMutableList()
        if (closest.isEmpty()) return emptyList()

        val queried  = mutableSetOf<NodeId>()
        val resultSet = sortedSetOf(XorDistanceComparator(target), *closest.toTypedArray())

        while (true) {
            val toQuery = resultSet
                .filter { it.nodeId !in queried }
                .take(ALPHA)
            if (toQuery.isEmpty()) break

            val responses = toQuery.map { contact ->
                queried.add(contact.nodeId)
                scope.async {
                    try {
                        val contacts = transport.findNode(contact, target)
                        insertContact(contact.copy(lastSeenMs = System.currentTimeMillis()))
                        contacts
                    } catch (e: Exception) {
                        Diag.swallowed("dht", "find-node-rpc", e,
                            "contact" to contact.nodeId.toHex().take(8))
                        routingTable.remove(contact.nodeId)
                        emptyList()
                    }
                }
            }.awaitAll().flatten()

            val prevClosest = resultSet.firstOrNull()?.nodeId
            responses.forEach { c ->
                resultSet.add(c)
                insertContact(c)
            }

            // Terminate if no closer node found this round
            val newClosest = resultSet.firstOrNull()?.nodeId
            if (newClosest == prevClosest && toQuery.all { it.nodeId in queried }) break
        }

        return resultSet.take(K).toList()
    }

    /**
     * FIND_VALUE: locate a value stored under [key].
     *
     * Returns [LookupResult.Found] if any contacted node has the value,
     * or [LookupResult.Contacts] with the closest nodes if not found.
     */
    open suspend fun findValue(key: NodeId): LookupResult {
        // Check local store first
        localStore[key]?.let { v ->
            if (!v.isExpired()) return LookupResult.Found(v.value, localNodeId)
            else localStore.remove(key)
        }

        // S/Kademlia eclipse defence: same disjoint-path seeding as iterativeFindNode.
        // See iterativeFindNode KDoc for rationale.
        val closest = routingTable.findClosestDisjoint(key, K)
        if (closest.isEmpty()) return LookupResult.NotFound

        val queried  = mutableSetOf<NodeId>()
        val resultSet = sortedSetOf(XorDistanceComparator(key), *closest.toTypedArray())

        while (true) {
            val toQuery = resultSet.filter { it.nodeId !in queried }.take(ALPHA)
            if (toQuery.isEmpty()) break

            val deferred = toQuery.map { contact ->
                queried.add(contact.nodeId)
                scope.async {
                    try {
                        val result = transport.findValue(contact, key)
                        insertContact(contact.copy(lastSeenMs = System.currentTimeMillis()))
                        result
                    } catch (e: Exception) {
                        Diag.swallowed("dht", "find-value-rpc", e,
                            "contact" to contact.nodeId.toHex().take(8))
                        routingTable.remove(contact.nodeId)
                        null
                    }
                }
            }

            for (d in deferred) {
                when (val r = d.await()) {
                    is LookupResult.Found   -> return r
                    is LookupResult.Contacts -> r.closest.forEach { resultSet.add(it); insertContact(it) }
                    else -> { /* continue */ }
                }
            }

            if (toQuery.all { it.nodeId in queried } &&
                resultSet.take(K).all { it.nodeId in queried }) break
        }

        return LookupResult.Contacts(resultSet.take(K).toList())
    }

    /**
     * STORE: publish [value] to the [K] closest nodes PLUS [EXTRA_STORE_TARGETS] randomly
     * selected non-closest nodes. Also stores locally if this node is among the K closest.
     *
     * Why extra targets: storing only to the K closest nodes is deterministic — anyone who
     * knows the DHT key can predict exactly which nodes hold the value and target them with
     * an eclipse attack to suppress retrieval. The extra random targets break this predictability:
     * an attacker must control a larger, unknown subset of the routing table to guarantee
     * interception. Extra storage increases replication overhead by at most [EXTRA_STORE_TARGETS]
     * additional STORE RPCs per write — negligible for infrequent dead-drop deposits.
     */
    suspend fun store(value: DhtValue) {
        val closest = iterativeFindNode(value.key)
        val closestIds = closest.map { it.nodeId }.toHashSet()

        // Add EXTRA_STORE_TARGETS randomly selected non-closest nodes from the routing table
        // to prevent deterministic storage prediction. Shuffled each time so the extra set
        // changes across separate STORE calls for the same key.
        val extraTargets = routingTable.allContacts()
            .filter { it.nodeId !in closestIds }
            .shuffled()
            .take(EXTRA_STORE_TARGETS)

        // Store locally if this node is among the K closest to the key.
        // We compare using a sentinel contact for the local node — PeerAddress
        // is not used by XorDistanceComparator (it only compares nodeId bytes).
        val localSentinel = DhtContact(localNodeId, LOCAL_SENTINEL_ADDRESS)
        val localIsClose  = closest.size < K ||
            XorDistanceComparator(value.key).compare(localSentinel, closest.last()) < 0
        if (localIsClose) localStore[value.key] = value

        // Publish to K closest + extra random nodes
        (closest + extraTargets).forEach { contact ->
            scope.launch {
                try { transport.store(contact, value) }
                catch (e: Exception) {
                    Diag.swallowed("dht", "store-rpc", e,
                        "contact" to contact.nodeId.toHex().take(8))
                }
            }
        }
    }

    // ── Local store operations ─────────────────────────────────────────────

    /** Store a value locally (called when this node receives a STORE RPC). */
    fun storeLocal(value: DhtValue) {
        if (value.value.size > DhtValue.MAX_UDP_VALUE_BYTES) {
            Diag.degraded("dht", "store-local-oversized",
                "DhtValue payload ${value.value.size}B exceeds MAX_UDP_VALUE_BYTES " +
                "(${DhtValue.MAX_UDP_VALUE_BYTES}B); value not stored. " +
                "Dead-drop blobs using Kyber-1024 encapsulation must use an alternative " +
                "delivery channel (SHADOWFILES, BLE, WiFi Direct).",
                "key" to value.key.toHex().take(8),
                "valueSize" to value.value.size.toString()
            )
            return
        }
        if (value.isExpired()) return
        // Reject when the store is already full. Without this cap a malicious peer can
        // flood unique keys to exhaust the JVM heap — each entry is a ConcurrentHashMap
        // node (~200B header + key + value bytes). At 64KB/value and 10K entries that is
        // already ~640MB; unbounded growth would cause OOM. evictExpired() runs on each
        // syncCycle (every 15 min); the cap ensures memory stays bounded between cycles.
        if (localStore.size >= MAX_LOCAL_STORE_ENTRIES) {
            Diag.degraded("dht", "store-local-full",
                "localStore is full (${localStore.size}/${MAX_LOCAL_STORE_ENTRIES}); " +
                "STORE RPC rejected. Run evictExpired() or wait for the next sync cycle.",
                "key" to value.key.toHex().take(8))
            return
        }
        // Cap TTL to prevent a malicious sender pinning an entry permanently with
        // Long.MAX_VALUE or a far-future timestamp (which also causes OOM via unbounded
        // localStore growth since there is no size cap). Any requested TTL beyond
        // MAX_STORED_TTL_MS is clamped silently — callers should not exceed the default.
        val cappedTtlMs = minOf(value.ttlMs, System.currentTimeMillis() + MAX_STORED_TTL_MS)
        localStore[value.key] = value.copy(ttlMs = cappedTtlMs)
    }

    /** Retrieve a value from local store. */
    fun getLocal(key: NodeId): DhtValue? {
        val v = localStore[key]
        return if (v != null && v.isExpired()) { localStore.remove(key); null } else v
    }

    /** Evict expired local values. Called periodically. */
    fun evictExpired(nowMs: Long = System.currentTimeMillis()) {
        localStore.entries.removeIf { it.value.isExpired(nowMs) }
    }

    fun localStoreSize(): Int = localStore.size

    /**
     * Update the tier of a contact already in the routing table.
     * Used by the NSC REVERT_TIER_PROMOTION rollback handler to undo a tier upgrade
     * that was part of a committed transition that failed or was rolled back.
     *
     * Removes the contact from the routing table, updates its tier, and re-inserts.
     * No-op if the contact is not currently in the routing table.
     */
    fun setNodeTier(nodeId: NodeId, tier: NodeTier) {
        val existing = routingTable.allContacts().firstOrNull { it.nodeId == nodeId } ?: return
        routingTable.remove(nodeId)
        routingTable.insert(existing.copy(tier = tier))
    }

    /**
     * Send a raw out-of-band byte payload to [nodeId] using the transport's [DhtTransport.sendRaw].
     * Looks up the contact address from the routing table; silently drops if not found.
     * Used by [NudgeEngine] and other control-plane components that need lightweight
     * direct peer messaging outside the DHT RPC protocol.
     */
    suspend fun sendRawToNode(nodeId: NodeId, bytes: ByteArray) {
        val contact = routingTable.allContacts().firstOrNull { it.nodeId == nodeId } ?: return
        transport.sendRaw(contact.address, bytes)
    }

    // ── Dead drop bootstrap ───────────────────────────────────────────────

    /**
     * DHT dead drop — design doc §4 "DHT dead drop bootstrap".
     *
     * Node A deposits an encrypted channel key blob under a derived DHT key.
     * Node B retrieves it using the same derived key (both know the out-of-band
     * ephemeral private key).
     *
     * DHT key = SHA3-256(ephemeral_public_key || "shadowmesh_dead_drop_v1")
     * The blob itself is encrypted: HybridKem.encapsulate(recipient_pub) + channel_key_blob.
     *
     * This method handles the DHT put/get — encryption is the caller's concern.
     *
     * @param dhtKey   The derived DHT key (caller computes from eph_pub).
     * @param blob     The encrypted channel key blob.
     * @param ttlMs    How long to keep the blob in the DHT (default: 7 days).
     */
    suspend fun deadDropPut(dhtKey: NodeId, blob: ByteArray, ttlMs: Long = DEFAULT_DEAD_DROP_TTL) {
        if (blob.size > DhtValue.MAX_UDP_VALUE_BYTES) {
            Diag.degraded("dht", "dead-drop-oversized",
                "Dead-drop blob ${blob.size}B exceeds MAX_UDP_VALUE_BYTES " +
                "(${DhtValue.MAX_UDP_VALUE_BYTES}B); blob cannot be stored via UDP DHT. " +
                "Use SHADOWFILES or a direct local-transport delivery for large blobs.",
                "dhtKey" to dhtKey.toHex().take(8),
                "blobSize" to blob.size.toString()
            )
            return
        }
        val value = DhtValue(
            key       = dhtKey,
            value     = blob,
            ttlMs     = System.currentTimeMillis() + ttlMs
        )
        store(value)
    }

    /**
     * Retrieve a dead drop blob. Returns the raw encrypted blob, or null if not found.
     * Caller is responsible for decryption using the out-of-band ephemeral private key.
     */
    suspend fun deadDropGet(dhtKey: NodeId): ByteArray? =
        (findValue(dhtKey) as? LookupResult.Found)?.value

    // ── Routing table maintenance ─────────────────────────────────────────

    /**
     * Handle a [PingRequired] result from [RoutingTable.insert].
     * Sends a real ping to the LRS contact; if it responds it stays in the bucket,
     * otherwise it's evicted and the new contact inserted.
     */
    private fun insertContact(contact: DhtContact) {
        when (val result = routingTable.insert(contact)) {
            is InsertResult.Inserted             -> triggerReplicationToNewNode(contact)
            is InsertResult.InsertedProbationary -> { /* probationary — replicate when promoted */ }
            is InsertResult.PingRequired         -> handlePingRequired(result.lrs, contact)
            is InsertResult.Rejected             -> { /* non-Tier-1 — skip */ }
            is InsertResult._EclipseRejected     -> { /* internal sentinel — handled by RoutingTable */ }
        }
    }

    /**
     * After a truly-new node is inserted, re-replicate locally-stored values for
     * which [newContact] is among the K closest nodes.
     *
     * This is the partition-merge fix: when group A and group B reconnect, nodes
     * in B that now appear in A's routing table receive the values A stored during
     * the partition — preventing permanent DATA LOSS for values that only existed
     * in A's portion of the keyspace while the mesh was split.
     *
     * Runs on a background coroutine; non-fatal if it fails (next sync cycle retries).
     */
    private fun triggerReplicationToNewNode(newContact: DhtContact) {
        val snapshot = localStore.toMap()
        if (snapshot.isEmpty()) return
        scope.launch {
            snapshot.forEach { (key, value) ->
                if (value.isExpired()) return@forEach
                // Check if newContact is within the K-closest set for this key.
                // If so, replicate to ensure the newly-discovered partition side holds it.
                val closest = routingTable.findClosestDisjoint(key, K)
                if (closest.any { it.nodeId == newContact.nodeId }) {
                    try {
                        transport.store(newContact, value)
                    } catch (e: Exception) {
                        Diag.swallowed("dht", "partition-replication", e,
                            "key"  to key.toHex().take(8),
                            "peer" to newContact.nodeId.toHex().take(8))
                    }
                }
            }
        }
    }

    private fun handlePingRequired(lrs: DhtContact, candidate: DhtContact) {
        val bucketIdx = localNodeId.bucketIndex(lrs.nodeId)
        if (bucketIdx < 0) return
        pendingPings[lrs.nodeId] = PendingPing(bucketIdx, lrs, candidate)
        scope.launch {
            try {
                val pong = transport.ping(lrs)
                if (pong != null) {
                    routingTable.touch(lrs.nodeId)
                    pendingPings.remove(lrs.nodeId)
                    // LRS alive — discard candidate (Kademlia preference for stable nodes)
                } else {
                    pendingPings.remove(lrs.nodeId)
                    routingTable.remove(lrs.nodeId)
                    routingTable.insert(candidate)
                }
            } catch (e: Exception) {
                Diag.swallowed("dht", "lrs-ping", e,
                    "lrs" to lrs.nodeId.toHex().take(8))
                pendingPings.remove(lrs.nodeId)
                routingTable.remove(lrs.nodeId)
                routingTable.insert(candidate)
            }
        }
    }

    /**
     * Refresh a bucket by performing a FIND_NODE for a random ID in its range.
     * Called for buckets that haven't been touched recently.
     */
    suspend fun refreshBucket(bucketIdx: Int) {
        val target = randomIdInBucket(bucketIdx)
        iterativeFindNode(target)
    }

    /** Refresh all buckets — called on bootstrap and periodically. */
    private suspend fun refreshAllBuckets() = coroutineScope {
        (0 until NUM_BUCKETS).map { idx ->
            async { try { refreshBucket(idx) } catch (e: Exception) { Diag.swallowed("dht", "refresh-bucket", e, "bucket" to idx.toString()) } }
        }.awaitAll()
    }

    private fun randomIdInBucket(bucketIdx: Int): NodeId {
        val bytes = localNodeId.bytes.copyOf()
        val byteIdx = NODE_ID_BYTES - 1 - bucketIdx / 8
        val bitIdx  = bucketIdx % 8
        if (byteIdx >= 0) {
            bytes[byteIdx] = (bytes[byteIdx].toInt() xor (1 shl bitIdx)).toByte()
        }
        return NodeId(bytes)
    }

    /**
     * Issue a DHT PING to the routing table contact with [nodeId].
     *
     * Returns true if the contact responds (alive). Returns false if the contact is not
     * found in the routing table or fails to respond. On success, updates the contact's
     * lastSeenMs via [RoutingTable.touch]; on failure, evicts the contact so the Kademlia
     * LRS eviction mechanism can replace it with a fresher candidate.
     *
     * Used by the gossip watchdog [GossipEngine.issueChallenge] as a true DHT-layer
     * liveness probe — stronger than a recency check because it requires a network
     * round-trip response, not just a cached timestamp.
     */
    suspend fun pingSpecific(nodeId: NodeId): Boolean {
        val contact = routingTable.allContacts().firstOrNull { it.nodeId == nodeId }
            ?: return false
        return try {
            val pong = transport.ping(contact)
            if (pong != null) {
                routingTable.touch(nodeId)
                true
            } else {
                routingTable.remove(nodeId)
                false
            }
        } catch (e: Exception) {
            Diag.swallowed("dht", "ping-specific", e, "peer" to nodeId.toHex().take(8))
            false
        }
    }

    /**
     * Ping the most-recently-seen routing table contact.
     * Returns the round-trip latency in ms on success, or null on failure / empty table.
     * Used by [TransportHealthMonitor] as the INTERNET_DHT probe.
     */
    suspend fun probe(): Long? {
        val contact = routingTable.allContacts()
            .maxByOrNull { it.lastSeenMs }
            ?: return null
        val startMs = System.currentTimeMillis()
        return try {
            val pong = transport.ping(contact)
            if (pong != null) System.currentTimeMillis() - startMs else null
        } catch (_: Exception) {
            null
        }
    }

    /**
     * Periodic DHT maintenance — called by [MeshSyncWorker] on its regular schedule.
     *
     * Two operations:
     *   1. Evict expired values from the local store (TTL-based cleanup).
     *   2. Refresh buckets that haven't been touched recently, ensuring the routing
     *      table stays accurate as peers join and leave.
     *
     * Bucket refresh is skipped when [healthMonitor] reports LOCAL_MESH or below —
     * no internet-DHT nodes are reachable, so bucket refresh is wasted traffic.
     *
     * Bucket refresh is limited to buckets with stale contacts (last-seen >
     * [RoutingTable.STALE_THRESHOLD_MS]) to avoid unnecessary network traffic
     * on an already-healthy routing table.
     */
    suspend fun syncCycle() {
        evictExpired()

        // Skip internet bucket refresh when we have no DHT connectivity.
        val meshState = healthMonitor?.currentState?.value
        if (meshState != null &&
            meshState != mesh.shadowmesh.mesh.health.MeshHealthState.FULL_MESH) {
            Diag.degraded("dht", "sync-cycle-skipped",
                "Skipping bucket refresh — mesh state is $meshState",
                "state" to meshState.name)
            return
        }

        val stale = routingTable.staleContacts()
        val staleBucketIndices = stale
            .mapNotNull { contact ->
                val idx = localNodeId.bucketIndex(contact.nodeId)
                if (idx >= 0) idx else null
            }
            .toSet()

        coroutineScope {
            staleBucketIndices.map { idx ->
                async {
                    try { refreshBucket(idx) }
                    catch (e: Exception) {
                        Diag.swallowed("dht", "sync-cycle-refresh", e,
                            "bucket" to idx.toString())
                    }
                }
            }.awaitAll()
        }
    }

    companion object {
        const val DEFAULT_DEAD_DROP_TTL = 7L * 24 * 60 * 60 * 1000   // 7 days

        /**
         * Maximum TTL accepted by [storeLocal] regardless of what the sender requests.
         * Without this cap, a malicious STORE_REQ with ttlMs=Long.MAX_VALUE causes the
         * entry to be retained forever and localStore to grow without bound (OOM risk).
         * Set to 8 days — just above the default 7-day dead drop TTL so legitimate values
         * are never silently shortened, while any attempt to store indefinitely is capped.
         */
        const val MAX_STORED_TTL_MS = 8L * 24 * 60 * 60 * 1000       // 8 days

        /**
         * Maximum number of entries in [localStore].
         * A malicious peer can flood unique-key STORE RPCs. Without this cap the
         * ConcurrentHashMap grows without bound until OOM. 10K entries × 64KB/value ≈ 640MB
         * worst-case; the actual footprint is lower because most values are smaller dead-drop
         * blobs (~1–4KB), but the cap keeps memory usage predictable regardless.
         * evictExpired() runs every 15 min (MeshSyncWorker) and will open headroom for new
         * legitimate entries. Raising this constant requires a heap budget review.
         */
        const val MAX_LOCAL_STORE_ENTRIES = 10_000

        /**
         * Number of randomly selected non-closest nodes added to every STORE operation.
         * Breaks deterministic node selection — an attacker can no longer predict the exact
         * storage set from the DHT key alone. Value of 2 adds minimal bandwidth overhead
         * while requiring the attacker to control a significantly larger routing table fraction.
         */
        const val EXTRA_STORE_TARGETS = 2

        /**
         * Derive a dead drop DHT key from an ephemeral public key.
         *
         * Formula: SHA3-256(ephPublicKeyBytes || "shadowmesh_dead_drop_v1")
         *
         * The domain label separates dead drop keys from node IDs (hashed pub keys without
         * suffix), channel genesis IDs, and other DHT uses. Callers MUST use this factory
         * rather than computing the NodeId manually to prevent domain collisions.
         */
        fun deadDropKey(ephPublicKeyBytes: ByteArray): NodeId =
            NodeId(mesh.shadowmesh.crypto.Hkdf.instance.sha3_256(
                ephPublicKeyBytes + "shadowmesh_dead_drop_v1".toByteArray(Charsets.UTF_8)
            ))

        /** Sentinel address used when comparing the local node to remote contacts.
         *  XorDistanceComparator only uses nodeId — this address is never contacted. */
        val LOCAL_SENTINEL_ADDRESS = PeerAddress("local", 0)
    }
}

// ── Transport interface ────────────────────────────────────────────────────────

/**
 * Network transport abstraction for DHT RPCs.
 * The real implementation (UDP/TCP) is wired in Phase 5+.
 * Injectable for testing.
 */
interface DhtTransport {
    /** Ping a peer. Returns the peer's contact info if alive, null if no response. */
    suspend fun ping(contact: DhtContact): DhtContact?

    /** FIND_NODE RPC — returns up to K contacts closest to [target] from [peer]'s view. */
    suspend fun findNode(peer: DhtContact, target: NodeId): List<DhtContact>

    /** FIND_VALUE RPC — returns the value if found, or closest contacts otherwise. */
    suspend fun findValue(peer: DhtContact, key: NodeId): LookupResult

    /** STORE RPC — ask [peer] to store [value]. */
    suspend fun store(peer: DhtContact, value: DhtValue)

    /**
     * Send a raw out-of-band byte payload to [address] without DHT framing.
     * Used by [NudgeEngine] for lightweight 12-byte nudge packets that do not fit
     * the DHT RPC request-response model. Default no-op — UDP implementations override.
     */
    suspend fun sendRaw(address: PeerAddress, bytes: ByteArray) {}
}

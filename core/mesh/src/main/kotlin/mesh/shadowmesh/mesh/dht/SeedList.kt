package mesh.shadowmesh.mesh.dht

import mesh.shadowmesh.crypto.Hkdf

/**
 * DHT bootstrap seed list — design doc §3.2 "List A".
 *
 * Two DISTINCT lists per the design doc:
 *
 *   List A — DHT Bootstrap (this class):
 *     IP:port of 10–20 volunteer high-uptime seeder nodes compiled into the APK.
 *     Used ONLY to get the first DHT entry point on first launch.
 *     Contains no key material and no channel information.
 *     IPs are rotatable via signed gossip update once the node is inside the mesh.
 *     A new node contacts any one of these to join the DHT routing fabric.
 *     Not a server — no content, no keys, no persistence required.
 *     Tier A and B nodes do NOT need List A — human introduction provides first peer.
 *
 *   List B — Channel public keys (NOT this class):
 *     100 Tier C open channel access keys for channel discovery.
 *     Not used for network entry. Handled separately in channel discovery.
 *
 * Signed update mechanism:
 *   A seed list update is a [SeedListUpdate] signed by a TRUST_PHYSICAL node.
 *   Nodes that receive a valid update via gossip replace stale entries.
 *   The update contains a list of [SeedEntry] items with TTL fields.
 *   Entries past their TTL are not used for bootstrap.
 *
 * Thread-safety: immutable after construction. [withUpdate] returns a new instance.
 */
class SeedList private constructor(
    val entries: List<SeedEntry>,
    // Per-issuer latest accepted issuedAtMs. Prevents replay of old signed updates:
    // an update from the same issuer with an earlier (or equal) issuedAtMs is rejected.
    private val latestIssuedAtMsPerIssuer: Map<String, Long> = emptyMap()
) {
    /**
     * Convert to [DhtContact] list suitable for [DhtEngine.bootstrap].
     * Filters out expired entries. Node IDs are derived from the seed's
     * public key if available, or generated from the IP:port otherwise
     * (consistent across restarts for the same IP:port pair).
     */
    fun toContacts(
        nowMs: Long = System.currentTimeMillis(),
        hkdf:  Hkdf = Hkdf.instance
    ): List<DhtContact> = entries
        .filter { !it.isExpired(nowMs) }
        .map { seed ->
            val nodeIdBytes = seed.publicKeyHex?.let { hex ->
                hkdf.sha3_256(hex.toByteArray())
            } ?: hkdf.sha3_256("${seed.ip}:${seed.port}".toByteArray())

            DhtContact(
                nodeId     = NodeId(nodeIdBytes),
                address    = PeerAddress(seed.ip, seed.port),
                tier       = NodeTier.TIER_1,
                isAnchor   = true,
                lastSeenMs = 0L   // unknown — bootstrap will update on ping
            )
        }

    /**
     * Apply a verified [SeedListUpdate] and return an updated [SeedList].
     *
     * Replay protection: rejects updates whose [SeedListUpdate.issuedAtMs] is not strictly
     * greater than the latest accepted update from the same issuer. An attacker who captures
     * a signed update from months ago cannot replay it because the per-issuer timestamp
     * tracking will reject it as stale.
     *
     * @return the updated list, or `this` unchanged if the update is a replay.
     */
    fun withUpdate(update: SeedListUpdate): SeedList {
        val issuerHex = update.issuerNodeId.joinToString("") { "%02x".format(it) }
        val lastAcceptedMs = latestIssuedAtMsPerIssuer[issuerHex] ?: 0L
        if (update.issuedAtMs <= lastAcceptedMs) {
            // Stale or replayed update — the issuer already published a newer list.
            return this
        }
        val existing = entries.associateBy { "${it.ip}:${it.port}" }.toMutableMap()
        // Remove any entry from this issuer that is no longer in the update
        // (handles IP migration: old address is evicted when the new update omits it).
        //
        // Bug fixed: the previous code matched on `publicKeyHex == update.entries.firstOrNull()?.publicKeyHex`.
        // When the update has zero entries, `firstOrNull()?.publicKeyHex` is null, matching ALL existing
        // seeds with publicKeyHex = null. An issuer sending an empty update would evict unrelated bootstrap
        // seeds that happen to have no publicKeyHex set.
        //
        // Fix: build the issuer-key set from the update's entries only when entries are non-empty.
        // Eviction applies only to entries whose publicKeyHex matches a key explicitly present in
        // the update, which correctly identifies entries belonging to the same issuer.
        if (update.entries.isNotEmpty()) {
            val updateKeyHexes = update.entries.mapNotNull { it.publicKeyHex }.toSet()
            val issuerEntryKeys = if (updateKeyHexes.isNotEmpty()) {
                existing.filterValues { it.publicKeyHex != null && it.publicKeyHex in updateKeyHexes }.keys
            } else {
                emptySet()
            }
            issuerEntryKeys.forEach { existing.remove(it) }
        }
        update.entries.forEach { entry ->
            existing["${entry.ip}:${entry.port}"] = entry
        }
        return SeedList(
            existing.values.toList(),
            latestIssuedAtMsPerIssuer + (issuerHex to update.issuedAtMs)
        )
    }

    /** Number of non-expired entries. */
    fun activeCount(nowMs: Long = System.currentTimeMillis()): Int =
        entries.count { !it.isExpired(nowMs) }

    companion object {
        /**
         * Default seed list for production bootstrap.
         *
         * Returns [bootstrapEmpty] in this open-source build. Production deployments
         * that have a List A should override this by loading a signed `seeds.json`
         * asset file and calling [from]. The function is named `default()` so that
         * call-sites ([ShadowMeshForegroundService]) are stable across build variants.
         *
         * If no seeds are available the node bootstraps from local transport only
         * (LAN broadcast, WiFi Direct, BLE) — correct and safe behaviour.
         */
        fun default(): SeedList = bootstrapEmpty()

        /**
         * Hardcoded List A — returns an EMPTY seed list in this build.
         *
         * WARNING: The previous loopback addresses (127.0.0.x) were removed because
         * they cause DHT bootstrap to silently fail in every non-loopback environment.
         * A deployment that ships loopback seeds will fail to connect to any real
         * node without any diagnostic error.
         *
         * Real deployments must supply seed entries via one of:
         *   [from]           — load signed volunteer node IPs from an assets file
         *   [forTesting]     — explicit IP:port pairs for integration tests
         *   [bootstrapEmpty] — LAN/WiFi Direct-only (no internet bootstrap needed)
         *
         * An empty seed list is safe: the node will simply wait for a peer to connect
         * via local transport (LAN broadcast, WiFi Direct, BLE) before joining the DHT.
         */
        fun hardcoded(): SeedList = SeedList(emptyList())

        /**
         * Empty seed list for LAN/WiFi Direct-only deployments (air-gapped, SURVIVAL mode).
         * The node discovers peers via local broadcast — no internet bootstrap required.
         */
        fun bootstrapEmpty(): SeedList = SeedList(emptyList())

        /**
         * Seed list for integration tests only. Never call from production code.
         *
         * @param ipPort  Vararg of (IP, port) pairs, e.g. "192.168.1.100" to 7400.
         */
        fun forTesting(vararg ipPort: Pair<String, Int>): SeedList = SeedList(
            ipPort.map { (ip, port) -> SeedEntry(ip, port, ttlMs = Long.MAX_VALUE) }
        )

        /** Construct from a list of [SeedEntry] (e.g. loaded from signed gossip update). */
        fun from(entries: List<SeedEntry>): SeedList = SeedList(entries)
    }
}

/**
 * A single DHT bootstrap seed entry.
 *
 * @param ip           IPv4 or IPv6 address string.
 * @param port         UDP port.
 * @param ttlMs        Absolute expiry timestamp. [Long.MAX_VALUE] = never expires.
 * @param publicKeyHex Hex-encoded public key of the seed node, if known.
 *                     Used to derive the nodeId with stronger binding than IP:port.
 */
data class SeedEntry(
    val ip:           String,
    val port:         Int,
    val ttlMs:        Long,
    val publicKeyHex: String? = null
) {
    fun isExpired(nowMs: Long = System.currentTimeMillis()): Boolean =
        nowMs >= ttlMs && ttlMs != Long.MAX_VALUE

    fun toAddress(): PeerAddress = PeerAddress(ip, port)
}

/**
 * A signed seed list update, propagated via gossip.
 * The signature covers [entries] + [issuedAtMs] and is verified by the receiver
 * using the issuer's TrustCredential (must be TRUST_PHYSICAL).
 */
data class SeedListUpdate(
    val entries:        List<SeedEntry>,
    val issuedAtMs:     Long,
    val issuerNodeId:   ByteArray,   // 32 bytes
    val signature:      ByteArray    // HybridSigner signature
) {
    override fun equals(other: Any?) = other is SeedListUpdate &&
        issuerNodeId.contentEquals(other.issuerNodeId) && issuedAtMs == other.issuedAtMs
    override fun hashCode() = 31 * issuerNodeId.contentHashCode() + issuedAtMs.hashCode()
}

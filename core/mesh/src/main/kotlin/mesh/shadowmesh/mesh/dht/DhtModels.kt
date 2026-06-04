package mesh.shadowmesh.mesh.dht

import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.toHex

// ── Constants ─────────────────────────────────────────────────────────────────

/** K-bucket size — Kademlia standard. */
const val K = 20

/** Alpha — parallel lookup concurrency. */
const val ALPHA = 3

/** Node ID length in bytes (SHA3-256 = 32 bytes = 256 bits). */
const val NODE_ID_BYTES = 32

/** Maximum number of buckets (one per bit of the node ID). */
const val NUM_BUCKETS = NODE_ID_BYTES * 8  // 256

// ── Node ID ───────────────────────────────────────────────────────────────────

/**
 * A 256-bit Kademlia node ID. Immutable; equality and hashing are content-based.
 *
 * NOT a value class: @JvmInline value classes wrapping ByteArray inherit
 * ByteArray's reference-based equals/hashCode, which breaks all map lookups
 * and containment checks. This class overrides equals/hashCode explicitly.
 */
class NodeId(val bytes: ByteArray) {
    init { require(bytes.size == NODE_ID_BYTES) { "NodeId must be $NODE_ID_BYTES bytes" } }

    /** XOR distance to [other]. Lower = closer in Kademlia space. */
    fun xorDistance(other: NodeId): ByteArray {
        val result = ByteArray(NODE_ID_BYTES)
        for (i in 0 until NODE_ID_BYTES) result[i] = (bytes[i].toInt() xor other.bytes[i].toInt()).toByte()
        return result
    }

    /**
     * The index of the highest set bit in the XOR distance to [other].
     * Returns values 0–255 (0 = differ only in lowest bit, 255 = differ in highest bit).
     * Returns -1 if the nodes are identical.
     *
     * Inner term: `7 - Integer.numberOfLeadingZeros(b) + 24`
     * For a byte value b (1–255), numberOfLeadingZeros returns 24–31 in the 32-bit
     * representation (since b is already masked unsigned via `and 0xFF`).
     * Subtracting 24 normalises to 0–7, giving the bit position within the byte.
     * The +24 corrects for Int vs byte leading-zero count difference.
     */
    fun bucketIndex(other: NodeId): Int {
        val dist = xorDistance(other)
        for (byteIdx in 0 until NODE_ID_BYTES) {
            val b = dist[byteIdx].toInt() and 0xFF   // unsigned byte: 0–255
            if (b != 0) {
                val bitPos = 7 - Integer.numberOfLeadingZeros(b) + 24
                return (NODE_ID_BYTES - 1 - byteIdx) * 8 + bitPos
            }
        }
        return -1  // identical
    }

    fun toHex(): String = bytes.toHex()

    override fun toString(): String = toHex().take(8) + "…"

    /** Content-based equality — two NodeIds with the same bytes are equal. */
    override fun equals(other: Any?): Boolean =
        other is NodeId && bytes.contentEquals(other.bytes)

    /** Content-based hash code — consistent with equals. */
    override fun hashCode(): Int = bytes.contentHashCode()

    companion object {
        fun fromHex(hex: String): NodeId {
            require(hex.length == NODE_ID_BYTES * 2) { "NodeId hex must be ${NODE_ID_BYTES * 2} chars" }
            return NodeId(hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray())
        }

        /** Derive a NodeId from the hash of a node's public key material. */
        fun fromPublicKeys(kemPubBytes: ByteArray, sigPubBytes: ByteArray): NodeId =
            NodeId(Hkdf.instance.sha3_256(kemPubBytes + sigPubBytes))

        fun random(): NodeId {
            val bytes = ByteArray(NODE_ID_BYTES)
            java.security.SecureRandom().nextBytes(bytes)
            return NodeId(bytes)
        }
    }
}

/** XOR distance comparator — sorts nodes by closeness to a target. */
class XorDistanceComparator(private val target: NodeId) : Comparator<DhtContact> {
    override fun compare(a: DhtContact, b: DhtContact): Int {
        val da = target.xorDistance(a.nodeId)
        val db = target.xorDistance(b.nodeId)
        for (i in 0 until NODE_ID_BYTES) {
            val cmp = (da[i].toInt() and 0xFF) - (db[i].toInt() and 0xFF)
            if (cmp != 0) return cmp
        }
        return 0
    }
}

// ── Contact ───────────────────────────────────────────────────────────────────

/**
 * A peer known to the DHT. Tier 1 anchors only are eligible for routing table
 * slots (design doc §4 — custom Kademlia DHT, Tier 1 anchor nodes only).
 *
 * @param seq            Monotonic counter from the peer's [ContactSeqCounter]. Used for
 *                       replay protection: a contact with a lower seq than one already in
 *                       the routing table for the same nodeId is rejected.
 * @param publicIdentity The peer's public key identity, if verified out-of-band (NFC bootstrap
 *                       or gossip). Null for contacts learned solely from UDP DHT responses
 *                       (unverified tier). The routing table may require non-null publicIdentity
 *                       for Tier 1 admission when operating in strict authenticated mode.
 */
data class DhtContact(
    val nodeId:         NodeId,
    val address:        PeerAddress,
    val lastSeenMs:     Long = System.currentTimeMillis(),
    val tier:           NodeTier = NodeTier.TIER_2,
    val isAnchor:       Boolean = false,
    val seq:            Long = 0L,
    val publicIdentity: mesh.shadowmesh.crypto.NodePublicIdentity? = null
) {
    fun isTier1Anchor(): Boolean = tier == NodeTier.TIER_1 && isAnchor
}

enum class NodeTier { TIER_1, TIER_2, TIER_3 }

/** Network address for a peer. UDP preferred; TCP fallback. */
data class PeerAddress(
    val ip:       String,
    val port:     Int,
    val protocol: TransportProtocol = TransportProtocol.UDP
) {
    /**
     * Deterministic wire encoding for use in cryptographic payloads (e.g. SignedContact).
     *
     * Format: [1B IP version: 4=IPv4, 6=IPv6][IP bytes: 4 or 16][2B port big-endian]
     * Protocol is not encoded — it is not part of the authenticated address binding.
     * Only IPv4 is supported in this implementation; IPv6 returns empty on the receiver.
     */
    fun toWireBytes(): ByteArray {
        val ipBytes = ipToBytes(ip) ?: return ByteArray(0)
        val version = if (ipBytes.size == 4) 4.toByte() else 6.toByte()
        return byteArrayOf(version) + ipBytes +
               byteArrayOf(((port shr 8) and 0xFF).toByte(), (port and 0xFF).toByte())
    }

    companion object {
        fun fromWireBytes(bytes: ByteArray): PeerAddress? {
            if (bytes.size < 3) return null
            return when (bytes[0].toInt()) {
                4 -> {
                    if (bytes.size < 7) return null
                    val ip   = "${bytes[1].toInt() and 0xFF}.${bytes[2].toInt() and 0xFF}" +
                               ".${bytes[3].toInt() and 0xFF}.${bytes[4].toInt() and 0xFF}"
                    val port = ((bytes[5].toInt() and 0xFF) shl 8) or (bytes[6].toInt() and 0xFF)
                    PeerAddress(ip, port)
                }
                // IPv6: 16 address bytes + 2 port bytes = 19 total after version byte
                6 -> {
                    if (bytes.size < 19) return null
                    val sb = StringBuilder()
                    for (i in 1..16 step 2) {
                        if (i > 1) sb.append(':')
                        sb.append("%02x%02x".format(bytes[i].toInt() and 0xFF, bytes[i+1].toInt() and 0xFF))
                    }
                    val port = ((bytes[17].toInt() and 0xFF) shl 8) or (bytes[18].toInt() and 0xFF)
                    PeerAddress(sb.toString(), port)
                }
                else -> null
            }
        }

        private fun ipToBytes(ip: String): ByteArray? {
            val parts = ip.split(".")
            if (parts.size == 4) {
                val bytes = ByteArray(4)
                for (i in 0..3) {
                    val v = parts[i].toIntOrNull() ?: return null
                    if (v !in 0..255) return null
                    bytes[i] = v.toByte()
                }
                return bytes
            }
            // IPv6: use InetAddress for parsing (only on JVM — acceptable since mesh layer is Android)
            return try {
                java.net.InetAddress.getByName(ip).address.takeIf { it.size == 16 }
            } catch (e: Exception) { null }
        }
    }
}

enum class TransportProtocol { UDP, TCP, WIFI_DIRECT, BLE }

// ── K-Bucket ──────────────────────────────────────────────────────────────────

/**
 * A single Kademlia k-bucket. Holds up to [K] contacts sorted by last-seen time
 * (tail = most recently seen). When full, the least-recently-seen contact is
 * pinged; if it responds it stays and the new contact is discarded; if it doesn't
 * respond it's replaced.
 *
 * Thread-safety: not thread-safe. The routing table synchronizes access.
 */
class KBucket {
    private val contacts = ArrayDeque<DhtContact>(K)

    fun size(): Int = contacts.size
    fun isFull(): Boolean = contacts.size >= K
    fun getAll(): List<DhtContact> = contacts.toList()

    /** Returns the least-recently-seen contact (head) without modifying the bucket, or null if empty. */
    fun lrsContact(): DhtContact? = contacts.firstOrNull()

    /** Returns the contact with [nodeId], or null if not present. */
    fun find(nodeId: NodeId): DhtContact? = contacts.firstOrNull { it.nodeId == nodeId }

    /**
     * Insert or update a contact.
     * - If already present: move to tail (most recently seen).
     * - If bucket not full: add to tail.
     * - If full: return the least-recently-seen contact (head) for ping check.
     *   Caller pings it; if dead, call [evictAndInsert].
     */
    fun insertOrUpdate(contact: DhtContact): DhtContact? {
        val existing = contacts.indexOfFirst { it.nodeId == contact.nodeId }
        if (existing >= 0) {
            contacts.removeAt(existing)
            contacts.addLast(contact)
            return null  // updated — no ping needed
        }
        return if (!isFull()) {
            contacts.addLast(contact)
            null  // inserted — no ping needed
        } else {
            contacts.first()  // full — return LRS for ping
        }
    }

    /** Remove the least-recently-seen contact and insert [newContact]. */
    fun evictAndInsert(newContact: DhtContact) {
        if (contacts.isNotEmpty()) contacts.removeFirst()
        contacts.addLast(newContact)
    }

    /** Remove a contact by nodeId. Used when a node is confirmed dead. */
    fun remove(nodeId: NodeId): Boolean {
        val idx = contacts.indexOfFirst { it.nodeId == nodeId }
        return if (idx >= 0) { contacts.removeAt(idx); true } else false
    }

    fun contains(nodeId: NodeId): Boolean = contacts.any { it.nodeId == nodeId }

    fun touch(nodeId: NodeId, nowMs: Long = System.currentTimeMillis()) {
        val idx = contacts.indexOfFirst { it.nodeId == nodeId }
        if (idx >= 0) {
            val updated = contacts[idx].copy(lastSeenMs = nowMs)
            contacts.removeAt(idx)
            contacts.addLast(updated)
        }
    }
}

// ── DHT value types ───────────────────────────────────────────────────────────

/**
 * A value stored in the DHT. Fragment location metadata, dead drop blobs,
 * or ratchet checkpoints all use this type.
 *
 * [key]   = SHA3-256 of the logical key (fragment hash, channel ID, etc.)
 * [value] = opaque encrypted bytes
 * [ttlMs] = absolute expiry; nodes purge after this time
 */
data class DhtValue(
    val key:       NodeId,    // DHT key (determines which nodes store it)
    val value:     ByteArray, // encrypted payload
    val ttlMs:     Long,
    val publishedAtMs: Long = System.currentTimeMillis()
) {
    fun isExpired(nowMs: Long = System.currentTimeMillis()) = nowMs >= ttlMs

    override fun equals(other: Any?) = other is DhtValue && key == other.key
    override fun hashCode() = key.hashCode()

    companion object {
        /**
         * Maximum value payload size for UDP DHT transport.
         *
         * Derived from: 1400B MTU - 43B DHT header - 1B found-byte - 44B value header = 1312B.
         * Values exceeding this limit cannot be delivered via a single UDP datagram and will
         * be rejected by [DhtEngine.storeLocal] with a [Diag.degraded] event.
         *
         * Dead-drop blobs using Kyber-1024 encapsulation (ciphertext ~1568B) exceed this limit
         * and must use an alternative delivery channel (SHADOWFILES, BLE, WiFi Direct) or be
         * split by the application layer before storage.
         */
        const val MAX_UDP_VALUE_BYTES = 1312
    }
}

// ── Lookup results ────────────────────────────────────────────────────────────

sealed class LookupResult {
    data class Found(val value: ByteArray, val from: NodeId)     : LookupResult()
    data class Contacts(val closest: List<DhtContact>)           : LookupResult()
    object NotFound                                               : LookupResult()
    data class Error(val reason: String)                         : LookupResult()
}

// ── VRF election types ────────────────────────────────────────────────────────

/**
 * VRF commit-reveal anchor election — design doc §4.
 *
 * Phase 1 COMMIT: each candidate gossips SHA3-256(nonce)
 * Phase 2 REVEAL: candidates reveal nonce; non-revealers excluded
 * Winner: lowest VRF_sk(nonce || round_id)
 * Tie-break on partition heal: lowest node ID wins
 */
data class VrfCommit(
    val candidateNodeId: NodeId,
    val commitHash:      ByteArray,  // SHA3-256(nonce)
    val roundId:         String,     // last_post_hash + election_seq
    val timestampMs:     Long = System.currentTimeMillis()
)

data class VrfReveal(
    val candidateNodeId: NodeId,
    val nonce:           ByteArray,  // 32 bytes — the preimage of commitHash
    val roundId:         String,
    val vrfOutput:       ByteArray   // HKDF(node_signing_key, nonce || roundId)
)

data class ElectionResult(
    val winner:   NodeId,
    val roundId:  String,
    val allVotes: List<VrfReveal>
)

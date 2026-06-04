package mesh.shadowmesh.mesh.fragment

import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.hexToBytes
import mesh.shadowmesh.crypto.toHex

/**
 * Fragment model — Phase 5 full implementation.
 * Replaces the compilation stub in StorageModels.kt.
 *
 * A post is split into N data fragments. Reed-Solomon adds P parity fragments.
 * Any K of the N+P total fragments suffice to reconstruct the post.
 *
 * fragmentId = SHA3-256(postId || sequenceIndex_bytes || payload)
 * Content-addressed: any tampered fragment produces a different fragmentId
 * and fails Merkle verification.
 *
 * Merkle tree:
 *   Leaves = SHA3-256(payload) for each fragment in order.
 *   Root   = computed bottom-up, stored in the post.
 *   Verification: any fragment + its sibling path proves membership without
 *   revealing other fragments.
 *
 * Wire format (see [FragmentEntity.toWire] / [FragmentEntity.fromWire]):
 *   [64B fragmentId hex][64B postId hex][64B OBFUSCATED channelId hex]
 *   [2B sequenceIndex][2B totalData][2B totalParity][4B payloadLen][payload bytes][1B fecScheme]
 *
 * channelId on the wire is SHA3-256(realChannelId || domain) — prevents passive observers
 * from correlating fragments to known channels. See [FragmentEntity.Companion.obfuscateChannelId].
 */
data class FragmentEntity(
    val fragmentId:     String,      // hex SHA3-256
    val postId:         String,      // hex postId
    val channelId:      String,      // hex channelId
    val sequenceIndex:  Int,         // 0-based position in fragment set
    val totalData:      Int,         // N data fragments
    val totalParity:    Int,         // P parity fragments (RS overhead)
    val payload:        ByteArray,   // encrypted fragment bytes
    val fecScheme:      FecScheme,   // which RS parameters were used
    val createdAtMs:    Long = System.currentTimeMillis(),
    val heldUntilMs:    Long = createdAtMs + RELAY_HOLD_MS  // relay retention window
) {
    val totalFragments: Int get() = totalData + totalParity
    val isDataFragment: Boolean get() = sequenceIndex < totalData
    val isParityFragment: Boolean get() = sequenceIndex >= totalData

    /** Minimum fragments needed to reconstruct (= totalData). */
    val reconstructionThreshold: Int get() = totalData

    /**
     * Serialize to the DHT wire format with channelId obfuscation.
     *
     * Wire: [64B fragmentId hex][64B postId hex][64B OBFUSCATED channelId hex]
     *       [2B seqIdx][2B totalData][2B totalParity][4B payloadLen][payload][1B fecScheme]
     *
     * The channelId is obfuscated via [Companion.obfuscateChannelId] before transmission.
     * Receivers hold the obfuscated ID in their FragmentEntity.channelId field after
     * calling [fromWire]; they verify channel membership by comparing:
     *   Companion.obfuscateChannelId(knownChannelIdBytes) == fragment.channelId
     */
    fun toWire(): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(out)
        val fidBytes = fragmentId.toByteArray(Charsets.US_ASCII)
        require(fidBytes.size == 64) { "fragmentId must be 64 hex chars, got ${fidBytes.size}" }
        dos.write(fidBytes)
        val pidBytes = postId.toByteArray(Charsets.US_ASCII)
        require(pidBytes.size == 64) { "postId must be 64 hex chars, got ${pidBytes.size}" }
        dos.write(pidBytes)
        val wireChannelIdHex = obfuscateChannelId(hexToBytes(channelId))
        dos.write(wireChannelIdHex.toByteArray(Charsets.US_ASCII))   // 64 bytes
        dos.writeShort(sequenceIndex)
        dos.writeShort(totalData)
        dos.writeShort(totalParity)
        dos.writeInt(payload.size)
        dos.write(payload)
        dos.writeByte(fecScheme.wire)
        dos.flush()
        return out.toByteArray()
    }

    override fun equals(other: Any?) = other is FragmentEntity &&
        fragmentId == other.fragmentId
    override fun hashCode() = fragmentId.hashCode()

    companion object {
        /** How long relay nodes retain fragments for retransmission. */
        const val RELAY_HOLD_MS = 2L * 60 * 60 * 1000  // 2 hours

        /** Maximum payload size accepted by [fromWire]. Prevents OOM on crafted messages. */
        const val MAX_FRAGMENT_PAYLOAD_BYTES = 64 * 1024  // 64 KB

        /**
         * Maximum shard count accepted for totalData or totalParity in [fromWire].
         * ShadowMesh's largest RS scheme is RS_10_10 (20 shards total). 256 is generous
         * headroom for future schemes while preventing absurd values from misconfiguring
         * accumulators or causing RS arithmetic anomalies.
         */
        const val MAX_SHARDS = 256

        /**
         * Derive the obfuscated wire channel ID from a raw 32-byte channelId.
         *
         * Wire channel ID = SHA3-256(channelId_bytes || "shadowmesh_wire_chan_v1")
         *
         * The obfuscated ID is written to the wire instead of the real channelId,
         * preventing passive observers from correlating fragments to known channels.
         * The domain suffix separates this derivation from other HKDF uses.
         *
         * Subscribers filter fragments by computing:
         *   obfuscateChannelId(theirKnownChannelIdBytes) == wireChannelId
         *
         * @param channelIdBytes  Raw 32-byte channel identifier (decoded from hex).
         * @return 64-character lowercase hex string of the obfuscated wire ID.
         */
        fun obfuscateChannelId(channelIdBytes: ByteArray): String =
            Hkdf.instance.sha3_256(
                channelIdBytes + "shadowmesh_wire_chan_v1".toByteArray(Charsets.UTF_8)
            ).toHex()

        /**
         * Deserialize from the DHT wire format used by [AckRouter] and [GossipTransport].
         *
         * NOTE: the channelId field in the returned [FragmentEntity] holds the OBFUSCATED
         * wire channel ID (from [obfuscateChannelId]), not the real channel identifier.
         * Subscribers must compare it against their own obfuscated IDs for filtering.
         *
         * Wire: [64B fragmentId hex][64B postId hex][64B channelId hex (obfuscated)]
         *       [2B seqIdx][2B totalData][2B totalParity][4B payloadLen][payload][1B fecScheme]
         */
        fun fromWire(bytes: ByteArray): FragmentEntity? = try {
            val dis = java.io.DataInputStream(java.io.ByteArrayInputStream(bytes))
            val fragmentId  = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
            val postId      = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
            val channelId   = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
            // Use readUnsignedShort() (0..65535) instead of readShort().toInt() (-32768..32767).
            // readShort() sign-extends: a wire value of 0xFFFF decodes to -1. A negative
            // totalData causes FragmentAccumulator.currentStatus() to return Complete immediately
            // for any single fragment (`count >= -1` is always true) — a phantom-Complete attack
            // that suppresses real post delivery. readUnsignedShort() prevents sign extension.
            val seqIdx      = dis.readUnsignedShort()
            val totalData   = dis.readUnsignedShort()
            val totalParity = dis.readUnsignedShort()
            // Bounds: totalData must be positive; combined shard count must be sane.
            // ShadowMesh's largest RS scheme is RS_10_10 (20 shards). Capping at 256 is generous
            // while preventing an absurd totalData that makes accumulators behave strangely.
            if (totalData == 0 || totalData > MAX_SHARDS || totalParity > MAX_SHARDS)
                throw IllegalArgumentException("Invalid shard counts: totalData=$totalData totalParity=$totalParity")
            val payloadLen  = dis.readInt()
            // Guard both negative and oversized values before allocation: a crafted wire
            // message with payloadLen = Integer.MAX_VALUE would allocate a 2 GB ByteArray and
            // crash the process with OutOfMemoryError before any trust gate runs.
            if (payloadLen < 0 || payloadLen > MAX_FRAGMENT_PAYLOAD_BYTES)
                throw IllegalArgumentException("Invalid payload length: $payloadLen")
            val payload     = ByteArray(payloadLen).also { dis.readFully(it) }
            val fecWire     = dis.readByte().toInt()
            FragmentEntity(fragmentId, postId, channelId, seqIdx, totalData, totalParity,
                payload, FecScheme.fromWire(fecWire) ?: FecScheme.NONE)
        } catch (_: Exception) { null }

        fun computeFragmentId(
            postId:        ByteArray,
            sequenceIndex: Int,
            payload:       ByteArray,
            hkdf:          Hkdf = Hkdf.instance
        ): String {
            val seqBytes = byteArrayOf(
                (sequenceIndex shr 8).toByte(),
                sequenceIndex.toByte()
            )
            return hkdf.sha3_256(postId + seqBytes + payload).toHex()
        }
    }
}

/**
 * Reed-Solomon FEC scheme — adaptive based on link quality (design doc §7).
 *
 * @param dataShards    N — number of data shards
 * @param parityShards  P — number of parity shards
 * @param minLinkPct    Minimum link quality % for this scheme to apply
 */
enum class FecScheme(
    val dataShards:   Int,
    val parityShards: Int,
    val minLinkPct:   Int,
    val wire:         Int   // Int avoids Byte literal coercion compile error
) {
    RS_10_7  (10,  7, 90, 1),
    RS_10_8  (10,  8, 75, 2),
    RS_10_9  (10,  9, 60, 3),
    RS_10_10 (10, 10,  0, 4),
    NONE     ( 1,  0,  0, 0);

    val overheadPct: Int get() =
        if (dataShards == 0) 0
        else (parityShards * 100) / dataShards

    val lossTolerance: Float get() =
        if (dataShards + parityShards == 0) 0f
        else parityShards.toFloat() / (dataShards + parityShards)

    companion object {
        /**
         * Select the appropriate FEC scheme given measured link quality.
         * Design doc §7: overhead decreases as conditions worsen.
         */
        fun selectForLinkQuality(linkQualityPct: Int, offline: Boolean = false): FecScheme {
            if (offline) return NONE
            return when {
                linkQualityPct >= 90 -> RS_10_7
                linkQualityPct >= 75 -> RS_10_8
                linkQualityPct >= 60 -> RS_10_9
                else                 -> RS_10_10
            }
        }

        fun fromWire(b: Int) = values().firstOrNull { it.wire == b }

        /**
         * Recover the [FecScheme] from the stored [dataShards] and [parityShards] counts.
         *
         * Used when restoring fragments from the storage layer, which does not persist
         * the [FecScheme] enum directly (it stores [total] and [totalData] instead).
         * Deriving the scheme here avoids a schema migration and keeps the recovery
         * path correct for all present and future FEC configurations.
         *
         * Falls back to [NONE] if no scheme matches — callers must handle this
         * gracefully (e.g. by falling back to direct-copy reassembly).
         */
        fun fromShards(dataShards: Int, parityShards: Int): FecScheme =
            values().firstOrNull {
                it.dataShards == dataShards && it.parityShards == parityShards
            } ?: NONE
    }
}

/**
 * Merkle tree for a set of fragments.
 *
 * ## Domain separation (RFC 6962 / CVE-2012-2459 mitigation)
 *
 * Leaf nodes:     SHA3-256(0x00 || position_2B_BE || payload)
 * Internal nodes: SHA3-256(0x01 || left || right)
 *
 * The 0x00/0x01 prefix prevents second-preimage attacks where a crafted internal-
 * node hash is presented as a leaf, enabling forged tree roots. Without domain
 * separation, an attacker who can make a 32-byte internal hash appear as a leaf
 * can construct fraudulent Merkle proofs.
 *
 * The 2-byte big-endian position in the leaf hash commits each leaf to its position,
 * preventing position-swap attacks where two payloads are swapped but the root is
 * unchanged (without position, `sha3_256(payload_A)` at position 0 is the same hash
 * as `sha3_256(payload_A)` if it were at position 1).
 *
 * ## Odd-leaf handling
 *
 * When the number of nodes at a level is odd, the last node is promoted to the next
 * level unchanged (not duplicated). Duplication creates root collisions between an
 * N-leaf tree and an (N+1)-leaf tree where the extra leaf equals the duplicate hash.
 */
data class FragmentMerkleTree(
    val root:   ByteArray,           // 32 bytes — the Merkle root
    val leaves: List<ByteArray>      // domain-separated leaf hashes in order
) {
    /**
     * Sibling path for leaf at [index] — used for single-fragment Merkle membership proofs.
     *
     * Verification: to re-derive the root from a leaf at position [index]:
     *   var current = SHA3-256(0x00 || index.to2BytesBE() || leafPayload)   // leaf domain
     *   for (step in path):
     *     current = if (step.isRight) SHA3-256(0x01 || current + step.sibling)  // internal
     *               else              SHA3-256(0x01 || step.sibling + current)
     *   assert(current == root)
     */
    fun siblingPath(index: Int): List<MerkleProofStep> {
        val path  = mutableListOf<MerkleProofStep>()
        var nodes = leaves.toMutableList<ByteArray>()
        var idx   = index
        while (nodes.size > 1) {
            if (nodes.size % 2 != 0) {
                // Promote last node rather than duplicate — avoids root collisions
                // between N-leaf and (N+1)-leaf trees with identical trailing payload.
                val promoted = nodes.removeLast()
                val parent   = (nodes.indices step 2).map { i -> merkleNode(nodes[i], nodes[i+1]) }
                nodes = (parent + listOf(promoted)).toMutableList()
                // Adjust idx if we are on the right side of the promoted range
                if (idx >= parent.size * 2) idx = parent.size  // promoted node becomes last parent
                else idx /= 2
                continue
            }
            val siblingIdx     = if (idx % 2 == 0) idx + 1 else idx - 1
            val siblingIsRight = (idx % 2 == 0)
            path.add(MerkleProofStep(sibling = nodes[siblingIdx], siblingIsRight = siblingIsRight))
            val parent = mutableListOf<ByteArray>()
            for (i in nodes.indices step 2) parent.add(merkleNode(nodes[i], nodes[i + 1]))
            nodes = parent
            idx /= 2
        }
        return path
    }

    companion object {
        /**
         * Build a Merkle tree from [payloads] (in sequenceIndex order, data shards only).
         *
         * Each leaf is: SHA3-256(0x00 || position_2B_BE || payload)
         * where position is the list index (0 = first data shard's sequenceIndex).
         */
        fun build(payloads: List<ByteArray>, hkdf: Hkdf = Hkdf.instance): FragmentMerkleTree {
            require(payloads.isNotEmpty()) { "Cannot build Merkle tree from empty payload list" }
            val leaves = payloads.mapIndexed { idx, payload ->
                // Leaf domain: 0x00 prefix + 2-byte big-endian position + payload
                hkdf.sha3_256(byteArrayOf(0x00) +
                              byteArrayOf((idx shr 8).toByte(), idx.toByte()) +
                              payload)
            }
            val root = computeRoot(leaves.toMutableList(), hkdf)
            return FragmentMerkleTree(root, leaves)
        }

        private fun computeRoot(nodes: MutableList<ByteArray>, hkdf: Hkdf): ByteArray {
            if (nodes.size == 1) return nodes[0]
            return if (nodes.size % 2 == 0) {
                val parent = (nodes.indices step 2).map { i -> merkleNode(nodes[i], nodes[i+1]) }
                computeRoot(parent.toMutableList(), hkdf)
            } else {
                // Promote last node — avoids duplicate-leaf root collision
                val promoted = nodes.removeLast()
                val parent   = (nodes.indices step 2).map { i -> merkleNode(nodes[i], nodes[i+1]) }
                computeRoot((parent + listOf(promoted)).toMutableList(), hkdf)
            }
        }

        // Internal node: 0x01 prefix prevents leaf/node domain confusion (RFC 6962)
        private fun merkleNode(left: ByteArray, right: ByteArray): ByteArray =
            Hkdf.instance.sha3_256(byteArrayOf(0x01) + left + right)
    }

    override fun equals(other: Any?) = other is FragmentMerkleTree &&
        root.contentEquals(other.root)
    override fun hashCode() = root.contentHashCode()
}

/**
 * One step in a Merkle membership proof.
 *
 * @param sibling      The sibling node hash at this level.
 * @param siblingIsRight  True if the sibling is to the RIGHT of the current node
 *                        (i.e., current node is the left child). The verifier must
 *                        combine as SHA3-256(current || sibling) when true, or
 *                        SHA3-256(sibling || current) when false.
 */
data class MerkleProofStep(
    val sibling:       ByteArray,
    val siblingIsRight:Boolean
) {
    override fun equals(other: Any?) = other is MerkleProofStep &&
        sibling.contentEquals(other.sibling) && siblingIsRight == other.siblingIsRight
    override fun hashCode() = 31 * sibling.contentHashCode() + siblingIsRight.hashCode()
}

package mesh.shadowmesh.mesh.fragment

import com.backblaze.erasure.ReedSolomon
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.SymmetricCipher
import mesh.shadowmesh.crypto.hexToBytes
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag

/**
 * Fragmentation engine — design doc §7, §8.
 *
 * Splits an encrypted post into N data shards + P parity shards using
 * Reed-Solomon erasure coding. Any N of the N+P shards suffice to
 * reconstruct the original payload.
 *
 * Shard size is fixed per fragmentation run — all shards (data + parity)
 * are padded to the same size. The last data shard is padded with zeros;
 * the receiver trims to [originalLength] on reassembly.
 *
 * Fragment IDs are content-addressed:
 *   fragmentId = SHA3-256(postId || sequenceIndex_bytes || payload)
 *
 * Merkle tree built over all data + parity shard payloads in order.
 * The root is stored in the post record and included in ACK packets.
 *
 * Thread-safety: stateless — thread-safe by construction.
 */
class FragmentationEngine(
    private val hkdf:   Hkdf          = Hkdf.instance
) {

    /**
     * Fragment an encrypted post payload into a [FragmentSet].
     *
     * @param postId         32-byte post identifier
     * @param channelId      32-byte channel identifier
     * @param encryptedPost  Full encrypted post bytes
     * @param scheme         RS parameters — selected by [FecScheme.selectForLinkQuality]
     */
    fun fragment(
        postId:        ByteArray,
        channelId:     ByteArray,
        encryptedPost: ByteArray,
        scheme:        FecScheme
    ): FragmentSet {
        if (scheme == FecScheme.NONE) return fragmentAsBlob(postId, channelId, encryptedPost)

        val n          = scheme.dataShards
        val p          = scheme.parityShards
        val shardSize  = computeShardSize(encryptedPost.size, n)
        val padded     = encryptedPost.copyOf(shardSize * n)  // zero-pad to shard boundary

        // Split into data shards
        val shards: Array<ByteArray?> = Array(n + p) { i ->
            if (i < n) padded.copyOfRange(i * shardSize, (i + 1) * shardSize)
            else ByteArray(shardSize)
        }

        // Compute parity shards
        ReedSolomon.create(n, p).encodeParity(shards, 0, shardSize)

        val postIdHex    = postId.toHex()
        val channelIdHex = channelId.toHex()
        val originalLen  = encryptedPost.size

        val fragments = shards.mapIndexed { idx, shard ->
            val payload    = shard!!
            val fragmentId = FragmentEntity.computeFragmentId(postId, idx, payload, hkdf)
            FragmentEntity(
                fragmentId    = fragmentId,
                postId        = postIdHex,
                channelId     = channelIdHex,
                sequenceIndex = idx,
                totalData     = n,
                totalParity   = p,
                payload       = payload,
                fecScheme     = scheme
            )
        }

        // Build the Merkle tree from DATA shards only (indices 0..n-1), sorted by sequenceIndex.
        // Parity shards are excluded so the sender's root matches the receiver's root computed
        // in FragmentIngestor, which also filters to data-only shards before tree construction.
        // Using all n+p shards here produced a root that never matched the receiver's root on
        // parity-assisted reconstruction, silently invalidating every Merkle ACK.
        val merkleTree = FragmentMerkleTree.build(
            fragments.filter { it.isDataFragment }.sortedBy { it.sequenceIndex }.map { it.payload },
            hkdf
        )

        return FragmentSet(
            postId       = postIdHex,
            channelId    = channelIdHex,
            fragments    = fragments,
            merkleRoot   = merkleTree.root,
            originalLength = originalLen,
            scheme       = scheme
        )
    }

    /**
     * Reassemble a post from a subset of fragments.
     * Requires at least [scheme.dataShards] fragments (data or parity).
     * Returns null if reconstruction fails.
     */
    fun reassemble(
        fragments:     List<FragmentEntity>,
        originalLength:Int,
        scheme:        FecScheme
    ): ByteArray? {
        if (scheme == FecScheme.NONE) {
            return fragments.firstOrNull()?.payload
        }

        val n = scheme.dataShards
        val p = scheme.parityShards
        if (fragments.isEmpty()) return null

        // Bound originalLength before any allocation.
        // This value comes from inbound wire data — an attacker can set it to Int.MAX_VALUE.
        // assembled.copyOf(originalLength) at line 152 would attempt a 2 GB allocation and OOM.
        // MAX_ASSEMBLED_BYTES caps at 10 MB — well above any legitimate ShadowMesh post.
        if (originalLength < 0 || originalLength > MAX_ASSEMBLED_BYTES) {
            Diag.degraded("fragmentation", "reassemble-oversized",
                "Rejecting reassemble: originalLength=$originalLength exceeds MAX_ASSEMBLED_BYTES",
                "scheme" to scheme.name)
            return null
        }

        val shardSize  = fragments.first().payload.size
        // Also verify the declared length could have come from the declared shard configuration.
        if (originalLength > n * shardSize) {
            Diag.degraded("fragmentation", "reassemble-length-impossible",
                "Rejecting reassemble: originalLength=$originalLength > n*shardSize=${n * shardSize}",
                "scheme" to scheme.name)
            return null
        }
        val shards:     Array<ByteArray?> = arrayOfNulls(n + p)
        val shardPresent = BooleanArray(n + p)

        fragments.forEach { f ->
            val idx = f.sequenceIndex
            if (idx in 0 until (n + p)) {
                shards[idx]       = f.payload.copyOf()
                shardPresent[idx] = true
            }
        }

        val presentCount = shardPresent.count { it }
        // The check is: at least n total shards (data OR parity) must be present to
        // reconstruct n data shards. This is correct for Reed-Solomon: any n of the
        // n+p total shards suffice. The backblaze ReedSolomon.decodeMissing() fills in
        // missing shards in-place — both data and parity gaps are reconstructed from
        // the available n shards.
        if (presentCount < n) return null  // not enough shards to reconstruct

        // Fill missing shards with zeros for RS decoder
        for (i in shards.indices) {
            if (shards[i] == null) shards[i] = ByteArray(shardSize)
        }

        return try {
            ReedSolomon.create(n, p).decodeMissing(shards, shardPresent, 0, shardSize)
            // Concatenate data shards, trim to original length
            val assembled = ByteArray(n * shardSize)
            for (i in 0 until n) {
                System.arraycopy(shards[i]!!, 0, assembled, i * shardSize, shardSize)
            }
            assembled.copyOf(originalLength)
        } catch (e: Exception) {
            Diag.swallowed("fragmentation", "reassemble-rs", e,
                "scheme" to scheme.name, "presentCount" to presentCount.toString())
            null
        }
    }

    /**
     * Verify a single fragment's integrity by recomputing its content-addressed ID.
     * fragmentId = SHA3-256(postId || sequenceIndex_bytes || payload)
     * This is self-contained — requires no other fragments and no Merkle tree.
     */
    fun verifyFragment(fragment: FragmentEntity): Boolean {
        val postIdBytes = hexToBytes(fragment.postId)
        val expected    = FragmentEntity.computeFragmentId(
            postId        = postIdBytes,
            sequenceIndex = fragment.sequenceIndex,
            payload       = fragment.payload,
            hkdf          = hkdf
        )
        return expected == fragment.fragmentId
    }

    // ── No-FEC (single blob) mode ─────────────────────────────────────────

    private fun fragmentAsBlob(
        postId:    ByteArray,
        channelId: ByteArray,
        payload:   ByteArray
    ): FragmentSet {
        val fragmentId = FragmentEntity.computeFragmentId(postId, 0, payload, hkdf)
        val fragment = FragmentEntity(
            fragmentId    = fragmentId,
            postId        = postId.toHex(),
            channelId     = channelId.toHex(),
            sequenceIndex = 0,
            totalData     = 1,
            totalParity   = 0,
            payload       = payload,
            fecScheme     = FecScheme.NONE
        )
        val merkleRoot = hkdf.sha3_256(payload)
        return FragmentSet(
            postId        = postId.toHex(),
            channelId     = channelId.toHex(),
            fragments     = listOf(fragment),
            merkleRoot    = merkleRoot,
            originalLength = payload.size,
            scheme        = FecScheme.NONE
        )
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun computeShardSize(dataLen: Int, n: Int): Int {
        val base = (dataLen + n - 1) / n
        return maxOf(base, MIN_SHARD_SIZE)
    }


    companion object {
        const val MIN_SHARD_SIZE = 64

        /**
         * Maximum assembled post size accepted by [reassemble].
         * The `originalLength` field in fragment wire data is attacker-controlled —
         * a crafted fragment with originalLength=Int.MAX_VALUE would cause `assembled.copyOf(originalLength)`
         * to attempt a 2 GB allocation and OOM the process before any trust gate runs.
         * 10 MB is well above any legitimate ShadowMesh post (designed for short-form content).
         */
        const val MAX_ASSEMBLED_BYTES = 10 * 1024 * 1024  // 10 MB
    }
}

/**
 * The complete output of a fragmentation operation.
 */
data class FragmentSet(
    val postId:        String,
    val channelId:     String,
    val fragments:     List<FragmentEntity>,
    val merkleRoot:    ByteArray,
    val originalLength:Int,
    val scheme:        FecScheme
) {
    val dataFragments:   List<FragmentEntity> get() = fragments.filter { it.isDataFragment }
    val parityFragments: List<FragmentEntity> get() = fragments.filter { it.isParityFragment }

    override fun equals(other: Any?) = other is FragmentSet && postId == other.postId
    override fun hashCode() = postId.hashCode()
}

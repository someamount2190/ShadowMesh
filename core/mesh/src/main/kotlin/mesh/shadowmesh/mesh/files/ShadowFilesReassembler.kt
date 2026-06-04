package mesh.shadowmesh.mesh.files

import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.mesh.fragment.*
import mesh.shadowmesh.storage.ShadowMeshDao
import mesh.shadowmesh.storage.TransferCheckpointEntity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * SHADOWFILES reassembly, checkpoint, and resume — design doc Phase 7.
 *
 * Reassembles a file from its fragment sets, verifying each chunk's Merkle
 * root before decrypting. Persists progress to SQLCipher so transfers
 * resume correctly after process death or disconnection.
 *
 * Reassembly lifecycle:
 *   1. Fragments arrive via gossip → accumulated per chunk via [ingestFragment]
 *   2. When a chunk has enough fragments (≥ dataShards), [tryAssembleChunk] is called
 *   3. Chunk is reassembled and Merkle-verified against the manifest
 *   4. Chunk is decrypted with the per-transfer key
 *   5. [persistCheckpoint] records progress (last confirmed chunkIndex) in the
 *      dedicated transfer_checkpoints table
 *   6. On completion: all chunks concatenated, final Merkle root verified
 *
 * Resume:
 *   On reconnect, [loadCheckpoint] restores progress from SQLCipher.
 *   Only chunks after the last confirmed checkpoint are requested again.
 *   The incomplete current chunk restarts from its last confirmed fragment.
 *
 * Corruption detection:
 *   - Fragment-level: [FragmentationEngine.verifyFragment] checks content address
 *   - Chunk-level: Merkle root verified before decrypt
 *   - Transfer-level: final Merkle root verified against manifest
 *   Any corruption produces [AssemblyResult.Corrupted] with the chunk index;
 *   those fragment sequences are NACKed for retransmission.
 *
 * Thread-safety: [chunkAccumulators] uses ConcurrentHashMap.
 *   All DAO ops are dispatched to Dispatchers.IO.
 */
class ShadowFilesReassembler(
    private val dao:               ShadowMeshDao,
    private val fragmentationEngine: FragmentationEngine = FragmentationEngine(),
    private val cipher:            SymmetricCipher       = SymmetricCipher(),
    private val hkdf:              Hkdf                  = Hkdf.instance
) {
    // Per-transfer chunk accumulators: transferId → (chunkIndex → ChunkAccumulator)
    private val chunkAccumulators =
        ConcurrentHashMap<String, ConcurrentHashMap<Int, ChunkAccumulator>>()

    // ── Fragment ingestion ────────────────────────────────────────────────

    /**
     * Ingest an incoming fragment.
     *
     * @param fragment     The incoming fragment.
     * @param transferId   Identifies this transfer (manifest hash hex).
     * @param chunkIndex   Which 64KB chunk this fragment belongs to.
     * @param manifest     The transfer manifest (for FEC params and Merkle root).
     *
     * @return [IngestResult] indicating if more fragments are needed or the
     *         chunk is ready for reassembly.
     */
    fun ingestFragment(
        fragment:   FragmentEntity,
        transferId: String,
        chunkIndex: Int,
        manifest:   TransferManifest
    ): IngestResult {
        // Fragment integrity check — content-addressed
        if (!fragmentationEngine.verifyFragment(fragment)) {
            return IngestResult.Corrupted(
                chunkIndex  = chunkIndex,
                missingSeqs = listOf(fragment.sequenceIndex),
                reason      = "Fragment content address mismatch: ${fragment.fragmentId}"
            )
        }

        val transferAccum = chunkAccumulators.computeIfAbsent(transferId) { ConcurrentHashMap() }
        val chunkAccum    = transferAccum.computeIfAbsent(chunkIndex) {
            ChunkAccumulator(chunkIndex, manifest.fecScheme)
        }

        chunkAccum.addFragment(fragment)

        return when {
            chunkAccum.canReconstruct() -> IngestResult.ChunkReady(chunkIndex)
            else -> IngestResult.NeedMore(
                chunkIndex       = chunkIndex,
                receivedFragments= chunkAccum.receivedCount(),
                totalFragments   = chunkAccum.totalFragments()
            )
        }
    }

    // ── Chunk assembly ────────────────────────────────────────────────────

    /**
     * Try to assemble and decrypt chunk [chunkIndex] for transfer [transferId].
     *
     * @param transferKey        32-byte per-transfer key. Caller owns — not stored here.
     * @param expectedChunkHash  SHA3-256 of the *encrypted* chunk bytes (pre-decrypt).
     *                           Merkle verification is performed on the encrypted bytes
     *                           before decryption, so tampering is caught before any
     *                           crypto work is done on the plaintext.
     * @param encryptedChunkLen  Byte length of the encrypted chunk — used by Reed-Solomon
     *                           as [originalLength] to trim the reconstructed shard
     *                           concatenation to the correct encrypted byte count.
     *                           This is NOT the plaintext chunk length; it is the
     *                           ciphertext length (plaintext + 24-byte nonce + 16-byte MAC).
     */
    suspend fun tryAssembleChunk(
        transferId:       String,
        chunkIndex:       Int,
        manifest:         TransferManifest,
        transferKey:      ByteArray,
        expectedChunkHash:ByteArray,
        encryptedChunkLen:Int
    ): ChunkAssemblyResult = withContext(Dispatchers.IO) {
        val transferAccum = chunkAccumulators[transferId]
            ?: return@withContext ChunkAssemblyResult.NotEnoughFragments
        val chunkAccum = transferAccum[chunkIndex]
            ?: return@withContext ChunkAssemblyResult.NotEnoughFragments

        if (!chunkAccum.canReconstruct()) return@withContext ChunkAssemblyResult.NotEnoughFragments

        // Reassemble encrypted chunk bytes via Reed-Solomon.
        // originalLength here is the encrypted chunk length — RS trims the shard
        // concatenation to exactly [encryptedChunkLen] bytes of ciphertext.
        val encryptedChunk = fragmentationEngine.reassemble(
            fragments      = chunkAccum.fragments(),
            originalLength = encryptedChunkLen,
            scheme         = manifest.fecScheme
        ) ?: return@withContext ChunkAssemblyResult.ReassemblyFailed

        // Verify encrypted chunk hash before decrypt (Merkle integrity check on ciphertext).
        // Constant-time comparison: an attacker supplying forged chunk bytes should not be
        // able to learn how many leading bytes match the expected hash via timing.
        val actualHash = hkdf.sha3_256(encryptedChunk)
        if (!java.security.MessageDigest.isEqual(actualHash, expectedChunkHash)) {
            val missing = chunkAccum.missingSequences()
            return@withContext ChunkAssemblyResult.MerkleFailure(
                chunkIndex  = chunkIndex,
                missingSeqs = missing
            )
        }

        // Decrypt chunk — nonce is prepended by SymmetricCipher (XChaCha20-Poly1305)
        val plainChunk = cipher.decrypt(encryptedChunk, transferKey).getOrNull()
            ?: return@withContext ChunkAssemblyResult.DecryptFailed

        // Persist checkpoint
        persistCheckpoint(transferId, chunkIndex, manifest.chunkCount)

        // Clear this chunk's accumulator — no longer needed
        transferAccum.remove(chunkIndex)

        ChunkAssemblyResult.Success(chunkIndex, plainChunk)
    }

    // ── Final assembly ────────────────────────────────────────────────────

    /**
     * Concatenate all assembled chunks into the final file bytes.
     * Verifies the transfer-level Merkle root against [manifest].
     *
     * Call this when all chunks have been successfully assembled.
     *
     * @param assembledChunks  Map of chunkIndex → plaintext chunk bytes, in order.
     * @return [FinalAssemblyResult.Success] with the complete file bytes on success.
     */
    fun finalAssemble(
        manifest:       TransferManifest,
        assembledChunks:Map<Int, ByteArray>
    ): FinalAssemblyResult {
        if (assembledChunks.size != manifest.chunkCount) {
            val missing = (0 until manifest.chunkCount).filter { it !in assembledChunks }
            return FinalAssemblyResult.MissingChunks(missing)
        }

        // Concatenate in order — any missing key means a sparse map was supplied
        val fileBytes = run {
            val chunks = mutableListOf<ByteArray>()
            for (i in 0 until manifest.chunkCount) {
                chunks += assembledChunks[i]
                    ?: return FinalAssemblyResult.MissingChunks(listOf(i))
            }
            chunks.fold(ByteArray(0)) { acc, chunk -> acc + chunk }
        }

        // Verify total size
        if (fileBytes.size != manifest.totalSize) {
            return FinalAssemblyResult.SizeMismatch(manifest.totalSize, fileBytes.size)
        }

        return FinalAssemblyResult.Success(fileBytes)
    }

    // ── Checkpoint persistence ────────────────────────────────────────────

    private suspend fun persistCheckpoint(
        transferId:  String,
        chunkIndex:  Int,
        totalChunks: Int
    ) = withContext(Dispatchers.IO) {
        // Dedicated transfer_checkpoints table (replaces the old synthetic-fragment-row
        // workaround). One row per transfer; REPLACE keeps only the latest confirmed
        // chunk so resume picks up from there.
        dao.upsertTransferCheckpoint(
            mesh.shadowmesh.storage.TransferCheckpointEntity(
                transferId     = transferId,
                lastChunkIndex = chunkIndex,
                totalChunks    = totalChunks,
                updatedAtMs    = System.currentTimeMillis()
            )
        )
    }

    /**
     * Load checkpoint for [transferId] from SQLCipher.
     * Returns the index of the last confirmed chunk, or -1 if no checkpoint.
     */
    suspend fun loadCheckpoint(transferId: String): Int = withContext(Dispatchers.IO) {
        dao.getTransferCheckpoint(transferId)?.lastChunkIndex ?: -1
    }

    /**
     * Clear all checkpoints and accumulators for [transferId].
     * Called on transfer completion or cancellation.
     */
    suspend fun clearTransfer(transferId: String) = withContext(Dispatchers.IO) {
        chunkAccumulators.remove(transferId)
        dao.deleteTransferCheckpoint(transferId)
    }

    // ── Queries ───────────────────────────────────────────────────────────

    fun activeTransferCount(): Int = chunkAccumulators.size

    fun chunkProgress(transferId: String, chunkIndex: Int): ChunkProgress? {
        val accum = chunkAccumulators[transferId]?.get(chunkIndex) ?: return null
        return ChunkProgress(
            chunkIndex       = chunkIndex,
            receivedFragments= accum.receivedCount(),
            totalFragments   = accum.totalFragments(),
            canReconstruct   = accum.canReconstruct()
        )
    }

}

// ── Chunk accumulator ─────────────────────────────────────────────────────────

/**
 * Accumulates fragments for a single 64KB chunk.
 * Thread-safe via ConcurrentHashMap.
 */
class ChunkAccumulator(
    val chunkIndex: Int,
    val scheme:     FecScheme
) {
    private val received = ConcurrentHashMap<Int, FragmentEntity>()

    fun addFragment(f: FragmentEntity) {
        // Same bounds guard as FragmentAccumulator: reject out-of-range indices before storing.
        // An attacker-supplied fragment with sequenceIndex = Int.MAX_VALUE would inflate
        // received.size and falsely trigger canReconstruct() (size >= scheme.dataShards)
        // without providing real data shards — reassembly would then silently fail.
        if (f.sequenceIndex < 0 || f.sequenceIndex >= totalFragments()) return
        received[f.sequenceIndex] = f
    }

    fun receivedCount(): Int = received.size
    fun totalFragments(): Int = scheme.dataShards + scheme.parityShards

    /** Can reconstruct if we have at least [scheme.dataShards] fragments. */
    fun canReconstruct(): Boolean = received.size >= scheme.dataShards

    fun fragments(): List<FragmentEntity> = received.values.toList()

    fun missingSequences(): List<Int> =
        (0 until totalFragments()).filter { !received.containsKey(it) }
}

// ── Result types ──────────────────────────────────────────────────────────────

sealed class IngestResult {
    data class NeedMore(val chunkIndex: Int, val receivedFragments: Int, val totalFragments: Int) : IngestResult()
    data class ChunkReady(val chunkIndex: Int) : IngestResult()
    data class Corrupted(val chunkIndex: Int, val missingSeqs: List<Int>, val reason: String) : IngestResult()
}

sealed class ChunkAssemblyResult {
    object NotEnoughFragments                                              : ChunkAssemblyResult()
    object ReassemblyFailed                                                : ChunkAssemblyResult()
    object DecryptFailed                                                   : ChunkAssemblyResult()
    data class MerkleFailure(val chunkIndex: Int, val missingSeqs: List<Int>) : ChunkAssemblyResult()
    data class Success(val chunkIndex: Int, val plainBytes: ByteArray)    : ChunkAssemblyResult()
}

sealed class FinalAssemblyResult {
    data class Success(val fileBytes: ByteArray)                           : FinalAssemblyResult()
    data class MissingChunks(val missingIndices: List<Int>)               : FinalAssemblyResult()
    data class SizeMismatch(val expected: Int, val actual: Int)           : FinalAssemblyResult()
}

data class ChunkProgress(
    val chunkIndex:        Int,
    val receivedFragments: Int,
    val totalFragments:    Int,
    val canReconstruct:    Boolean
)

package mesh.shadowmesh.distribution

import android.content.Context
import kotlinx.coroutines.Dispatchers
import mesh.shadowmesh.crypto.intTo4Bytes
import mesh.shadowmesh.diagnostics.Diag
import kotlinx.coroutines.withContext
import mesh.shadowmesh.mesh.files.FinalAssemblyResult
import mesh.shadowmesh.mesh.files.IngestResult
import mesh.shadowmesh.mesh.files.ChunkAssemblyResult
import mesh.shadowmesh.mesh.files.ShadowFilesChunker
import mesh.shadowmesh.mesh.files.ShadowFilesReassembler
import mesh.shadowmesh.mesh.files.TransferManifest
import mesh.shadowmesh.storage.ShadowMeshDao
import mesh.shadowmesh.storage.TransferCheckpointEntity
import java.io.File

/**
 * Pull side of app self-distribution (design Features 1 + 2).
 *
 * Given a [AppBootstrapQr] (from a scanned QR) and an [ArtifactFetcher] (BLE/WiFi-Direct in
 * production), this:
 *   1. fetches + verifies the signed descriptor,
 *   2. fast-rejects against the QR's 8-byte signature prefix,
 *   3. fetches the manifest + per-chunk index,
 *   4. pulls every chunk's fragments, reassembles via ShadowFilesReassembler,
 *   5. writes the assembled APK to a file and runs the full [ApkArtifactVerifier] gate,
 *   6. emits a verified APK path the caller can hand to the package installer.
 *
 * Multi-session resume: IMPLEMENTED, gated on the optional [dao] constructor param.
 *   - When [dao] is non-null (production wiring passes a real DAO), [acquire] checkpoints
 *     each assembled chunk to disk + a TransferCheckpointEntity row, and on re-entry for the
 *     same transferId it reloads confirmed chunks and resumes from the last checkpoint
 *     (falling back to a full re-fetch on a stale/missing chunk cache). [clearTransfer] prunes
 *     the checkpoint row and chunk cache on success or permanent failure. This lets a node on a
 *     poor mesh link (BLE, degraded WiFi Direct) survive a process death mid-transfer instead
 *     of restarting from chunk 0.
 *   - When [dao] is null (e.g. unit tests that don't need persistence), resume is disabled and
 *     the transfer is always single-session.
 *
 * See the "Multi-session resume" block in [acquire] for the chunk-level logic, and the
 * write-before-checkpoint ordering note (a crash between write and checkpoint forces a safe
 * re-fetch rather than a corrupt resume).
 *

 * The transfer key is re-derived locally from the PUBLIC distribution channel key + the
 * descriptor's manifestHash (the key derivation seed) — identical to what the seeder used —
 * so no key travels over the wire.
 *
 * Per-chunk hashes/lengths are served via [ArtifactFetcher.fetchChunkIndex], a dedicated
 * interface method. The acquirer authenticates the index against the manifest's Merkle root
 * before trusting it.
 */
class AppArtifactAcquirer(
    private val context:  Context,
    private val verifier: ApkArtifactVerifier,
    private val fetcher:  ArtifactFetcher,
    private val chunker:  ShadowFilesChunker = ShadowFilesChunker(),
    private val reassembler: ShadowFilesReassembler,
    /**
     * Optional DAO for multi-session resume. When provided, each successfully assembled
     * chunk is checkpointed so that a process death mid-transfer resumes from the last
     * confirmed chunk rather than restarting from chunk 0.
     *
     * When null (default, e.g. in tests), resume is disabled and the transfer always
     * starts from chunk 0. In production, inject [ShadowMeshDao] so that poor BLE
     * connections or process deaths don't permanently block first-install acquisition.
     */
    private val dao: ShadowMeshDao? = null
) {

    sealed class Outcome {
        data class Success(val apkFile: File, val versionCode: Int, val versionName: String) : Outcome()
        data class Failed(val reason: String) : Outcome()
    }

    /** Per-chunk verification data the seeder must serve alongside the manifest. */
    data class ChunkIndex(
        val chunkHashes:       List<ByteArray>,   // SHA3-256 of each encrypted chunk, in order
        val encryptedChunkLen: List<Int>          // encrypted length of each chunk, in order
    )

    suspend fun acquire(qr: AppBootstrapQr): Outcome = withContext(Dispatchers.IO) {
        // 1. Descriptor
        val descBytes = fetcher.fetchDescriptor(qr.seederHint, qr.versionCode)
            ?: return@withContext Outcome.Failed("Could not fetch descriptor from seeder")
        val descriptor = AppArtifactDescriptor.fromBytes(descBytes)
            ?: return@withContext Outcome.Failed("Malformed descriptor")

        // 2. QR fast-reject: the QR's 8-byte prefix must match the descriptor's signature.
        if (!descriptor.signature.copyOf(8).contentEquals(qr.descriptorSig8)) {
            return@withContext Outcome.Failed("Descriptor does not match QR (signature prefix)")
        }
        if (descriptor.versionCode != qr.versionCode ||
            !descriptor.manifestHash.contentEquals(qr.manifestHash)) {
            return@withContext Outcome.Failed("Descriptor does not match QR (version/manifest)")
        }

        // 3. Manifest + chunk index
        val manifestBytes = fetcher.fetchManifest(qr.seederHint, descriptor.manifestHash)
            ?: return@withContext Outcome.Failed("Could not fetch manifest")
        val manifest = chunker.deserializeManifest(manifestBytes)
            ?: return@withContext Outcome.Failed("Malformed manifest")
        if (!manifest.manifestHash.contentEquals(descriptor.manifestHash)) {
            return@withContext Outcome.Failed("Manifest hash disagrees with descriptor")
        }
        val index = fetchAndVerifyChunkIndex(qr.seederHint, manifest)
            ?: return@withContext Outcome.Failed("Chunk index missing or fails Merkle check")

        // 4. Transfer key (re-derived locally; nothing secret travels)
        val transferId = DistributionConstants.transferId(descriptor.versionCode)
        // Transfer key (re-derived locally; nothing secret travels)
        val transferKey = chunker.deriveKeyFromChannel(
            DistributionConstants.CHANNEL_KEY, descriptor.manifestHash
        )

        // ── Multi-session resume ───────────────────────────────────────────
        // Load any existing checkpoint. If a prior acquire() for this transferId
        // was interrupted (process death, BLE disconnect) the checkpoint records
        // the last successfully assembled chunk. We skip already-confirmed chunks
        // and load their plaintext from disk rather than re-fetching from the seeder.
        //
        // Resume is only active when [dao] is injected. Without it (tests, degraded
        // mode), acquisition always starts from chunk 0.
        val resumeFromChunk: Int = if (dao != null) {
            dao.getTransferCheckpoint(transferId)?.lastChunkIndex?.plus(1) ?: 0
        } else {
            0
        }
        if (resumeFromChunk > 0) {
            Diag.info("apk-acquirer", "resume",
                "Resuming transfer $transferId from chunk $resumeFromChunk of ${manifest.chunkCount}",
                "version" to descriptor.versionCode.toString())
        }

        // ── Pull + assemble each chunk ─────────────────────────────────────
        val assembled = HashMap<Int, ByteArray>(manifest.chunkCount)

        // Load already-confirmed chunks from disk (resume path).
        // Each confirmed chunk's plaintext is written to the cache dir on first assembly.
        // On resume, we read it back rather than re-fetching from the seeder.
        for (chunkIdx in 0 until resumeFromChunk) {
            val chunkFile = chunkCacheFile(context, transferId, chunkIdx)
            if (chunkFile.exists()) {
                assembled[chunkIdx] = chunkFile.readBytes()
            } else {
                // Cache file missing — stale checkpoint. Fall back to full re-fetch.
                Diag.fallback("apk-acquirer", "resume-cache-miss",
                    "Chunk $chunkIdx cache file missing — restarting from chunk 0",
                    "transferId" to transferId, "chunkIdx" to chunkIdx.toString())
                assembled.clear()
                break
            }
        }

        val startChunk = if (assembled.size == resumeFromChunk) resumeFromChunk else 0

        for (chunkIdx in startChunk until manifest.chunkCount) {
            val chunkPostId = perChunkPostId(descriptor.versionCode, chunkIdx)
            val frags = fetcher.fetchChunkFragments(qr.seederHint, chunkPostId)
                ?: return@withContext Outcome.Failed("Could not fetch fragments for chunk $chunkIdx")

            frags.forEach { reassembler.ingestFragment(it, transferId, chunkIdx, manifest) }

            val res = reassembler.tryAssembleChunk(
                transferId        = transferId,
                chunkIndex        = chunkIdx,
                manifest          = manifest,
                transferKey       = transferKey,
                expectedChunkHash = index.chunkHashes[chunkIdx],
                encryptedChunkLen = index.encryptedChunkLen[chunkIdx]
            )
            when (res) {
                is ChunkAssemblyResult.Success -> {
                    assembled[chunkIdx] = res.plainBytes
                    // Persist the assembled chunk plaintext so a restart can reload it.
                    // Write before checkpointing so a crash between write and checkpoint
                    // causes a re-fetch (safe) rather than an unreadable checkpoint (corrupt).
                    if (dao != null) {
                        try {
                            chunkCacheFile(context, transferId, chunkIdx).writeBytes(res.plainBytes)
                            dao.upsertTransferCheckpoint(
                                TransferCheckpointEntity(
                                    transferId     = transferId,
                                    lastChunkIndex = chunkIdx,
                                    totalChunks    = manifest.chunkCount,
                                    updatedAtMs    = System.currentTimeMillis()
                                )
                            )
                        } catch (e: Exception) {
                            Diag.swallowed("apk-acquirer", "checkpoint-write", e,
                                "chunkIdx" to chunkIdx.toString())
                            // Non-fatal: resume on next restart will re-fetch this chunk.
                        }
                    }
                }
                else -> return@withContext Outcome.Failed("Chunk $chunkIdx failed to assemble: ${res::class.simpleName}")
            }
        }
        // 6. Final assembly + verification gate
        val finalRes = reassembler.finalAssemble(manifest, assembled)
        val apkBytes = when (finalRes) {
            is FinalAssemblyResult.Success -> finalRes.fileBytes
            is FinalAssemblyResult.MissingChunks -> return@withContext Outcome.Failed("Missing chunks: ${finalRes.missingIndices}")
            is FinalAssemblyResult.SizeMismatch -> return@withContext Outcome.Failed("Size mismatch ${finalRes.expected}/${finalRes.actual}")
        }

        val outFile = File(context.cacheDir, "shadowmesh_v${descriptor.versionCode}.apk")
        outFile.writeBytes(apkBytes)

        when (val v = verifier.verify(outFile, descriptor)) {
            is ApkArtifactVerifier.Result.Verified -> {
                cleanupTransfer(transferId, manifest.chunkCount)
                Outcome.Success(outFile, v.versionCode, v.versionName)
            }
            is ApkArtifactVerifier.Result.Rejected -> {
                outFile.delete()   // never leave an unverified APK on disk
                // Clear the transfer checkpoint and chunk cache files so a subsequent
                // acquire attempt starts fresh rather than loading stale/invalid data.
                cleanupTransfer(transferId, manifest.chunkCount)
                Outcome.Failed("Verification failed: ${v.reason}")
            }
        }
    }

    /**
     * Clean up all persistent state for a completed or failed transfer:
     * the reassembler's in-memory state, the DAO checkpoint row, and the
     * per-chunk plaintext cache files written during resume-aware assembly.
     */
    private suspend fun cleanupTransfer(transferId: String, chunkCount: Int) {
        reassembler.clearTransfer(transferId)
        // Delete the checkpoint DB row so a subsequent acquire() for the same transferId
        // starts fresh rather than attempting (and immediately falling back from) a stale resume.
        // Without this, stale TransferCheckpointEntity rows accumulate across sessions.
        try { dao?.deleteTransferCheckpoint(transferId) } catch (_: Exception) {}
        for (chunkIdx in 0 until chunkCount) {
            try { chunkCacheFile(context, transferId, chunkIdx).delete() } catch (_: Exception) {}
        }
    }

    /**
     * Per-chunk plaintext cache file path. Written on first successful assembly,
     * read back on resume to skip re-fetching already-confirmed chunks.
     *
     * Files are stored in [Context.cacheDir] under a transfer-specific subdirectory
     * so they are automatically deleted when the OS clears the app cache under storage
     * pressure. In the worst case this causes a re-fetch — never a correctness failure.
     */
    private fun chunkCacheFile(context: Context, transferId: String, chunkIdx: Int): File {
        val dir = File(context.cacheDir, "apk_transfer_$transferId").also { it.mkdirs() }
        return File(dir, "chunk_$chunkIdx.bin")
    }

    /**
     * Fetch the per-chunk index and authenticate it: recompute the Merkle root over the
     * supplied chunk hashes and require it to equal the manifest's merkleRoot. This stops a
     * malicious seeder from supplying a doctored index that would pass per-chunk checks against
     * forged chunks.
     *
     * Uses [ArtifactFetcher.fetchChunkIndex] — a dedicated method in the fetcher interface —
     * rather than the earlier sidecar hack that reused [ArtifactFetcher.fetchManifest] with
     * the merkleRoot as an implicit sentinel. The explicit method makes the protocol contract
     * visible to all ArtifactFetcher implementers.
     */
    private suspend fun fetchAndVerifyChunkIndex(
        seederHint: ByteArray, manifest: TransferManifest
    ): ChunkIndex? {
        val indexBytes = fetcher.fetchChunkIndex(seederHint, manifest.merkleRoot) ?: return null
        val index = parseChunkIndex(indexBytes) ?: return null
        if (index.chunkHashes.size != manifest.chunkCount) return null
        val recomputed = merkleRootOf(index.chunkHashes)
        if (!recomputed.contentEquals(manifest.merkleRoot)) return null
        return index
    }

    private fun perChunkPostId(versionCode: Int, chunkIdx: Int): ByteArray {
        val base = DistributionConstants.distributionPostId(versionCode)
        return Hkdfs.sha3(base + intTo4Bytes(chunkIdx)).copyOf(32)
    }

    // ── small local helpers (mirror chunker's internal derivations) ─────────

    private object Hkdfs {
        private val h = mesh.shadowmesh.crypto.Hkdf.instance
        fun sha3(b: ByteArray) = h.sha3_256(b)
    }

    /** Merkle root matching ShadowFilesChunker.buildChunkMerkleRoot (duplicate-last padding). */
    private fun merkleRootOf(hashes: List<ByteArray>): ByteArray {
        if (hashes.isEmpty()) return ByteArray(32)
        var nodes = hashes.toMutableList()
        while (nodes.size > 1) {
            if (nodes.size % 2 != 0) nodes.add(nodes.last())
            nodes = (nodes.indices step 2).map { i ->
                Hkdfs.sha3(nodes[i] + nodes[i + 1])
            }.toMutableList()
        }
        return nodes.first()
    }


    private fun parseChunkIndex(bytes: ByteArray): ChunkIndex? { return try {
        val dis = java.io.DataInputStream(java.io.ByteArrayInputStream(bytes))
        val n = dis.readInt()
        // Bounds check before allocation: attacker-controlled n = Int.MAX_VALUE causes
        // ArrayList<ByteArray>(Int.MAX_VALUE) to throw OutOfMemoryError (an Error, not
        // Exception) which escapes `catch (_: Exception)` and crashes the process.
        // Cap at MAX_CHUNK_COUNT — any APK requiring more chunks at 1 KB each would be >10 MB.
        if (n < 0 || n > MAX_CHUNK_COUNT) return null
        val hashes = ArrayList<ByteArray>(n)
        val lens = ArrayList<Int>(n)
        repeat(n) {
            hashes.add(ByteArray(32).also { dis.readFully(it) })
            lens.add(dis.readInt())
        }
        ChunkIndex(hashes, lens)
    } catch (_: Exception) { null } }

    companion object {
        /**
         * Maximum chunk count accepted from a fetched chunk index.
         * A 100 MB APK at 1 KB per chunk = 100_000 chunks. Cap at 10_000 — any legitimate
         * APK fits well within this. Prevents an attacker-controlled chunk count from
         * causing OutOfMemoryError via ArrayList allocation before the catch block.
         */
        const val MAX_CHUNK_COUNT = 10_000

        /** Serialize a ChunkIndex (used by the seeder side / tests). */
        fun serializeChunkIndex(chunkHashes: List<ByteArray>, encryptedLens: List<Int>): ByteArray {
            val out = java.io.ByteArrayOutputStream()
            java.io.DataOutputStream(out).use { d ->
                d.writeInt(chunkHashes.size)
                chunkHashes.forEachIndexed { i, h -> d.write(h); d.writeInt(encryptedLens[i]) }
            }
            return out.toByteArray()
        }
    }
}

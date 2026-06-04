package mesh.shadowmesh.mesh.files

import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.mesh.fragment.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mesh.shadowmesh.diagnostics.Diag

/**
 * SHADOWFILES blob chunker and manifest — design doc Phase 7.
 *
 * Splits a binary file into 64KB chunks. Each chunk is then fragmented
 * via the standard [FragmentationEngine] (RS FEC). All fragments are
 * encrypted with a per-transfer key before any leave the device.
 *
 * Per-transfer key derivation (two methods):
 *   QR exchange:    Key is encoded in a QR code shown to the recipient.
 *                   Key = HKDF(ephemeral_secret, salt=manifest_hash, info="shadowfiles_v1")
 *   Channel-derived: Key = HKDF(channel_key, salt=manifest_hash, info="shadowfiles_v1")
 *                   No separate out-of-band step if both parties share a channel.
 *
 * Transfer manifest (gossiped separately from fragments):
 *   - filename (optional — omitted for sensitive transfers)
 *   - total size in bytes
 *   - chunk count
 *   - root Merkle hash (SHA3-256 of all chunk hashes)
 *   - per-transfer key reference (QR token hex or channel DHT key hex)
 *   - TTL (default 7 days)
 *   - FEC scheme
 *
 * Wire format (manifest):
 *   [1B version][8B ttlMs][4B totalSizeBytes][4B chunkCount][32B merkleRoot]
 *   [1B filenameLen][filenameLen bytes][32B keyRef][1B fecWire]
 *   total: 83 + filenameLen bytes
 *
 * A 100 MB file produces ~1,600 chunks × 17 fragments each = ~27,200 fragments.
 * Fragment IDs are content-addressed — deduplicated by gossip bloom filter.
 *
 * Thread-safety: stateless — thread-safe by construction.
 */
class ShadowFilesChunker(
    private val hkdf:              Hkdf              = Hkdf.instance,
    private val cipher:            SymmetricCipher   = SymmetricCipher(),
    private val fragmentationEngine: FragmentationEngine = FragmentationEngine()
) {

    // ── Key derivation ─────────────────────────────────────────────────────

    /**
     * Derive a per-transfer key from an ephemeral secret (QR exchange path).
     *
     * @param ephemeralSecret  32-byte secret shared out-of-band (encoded in QR).
     * @param manifestHash     SHA3-256 of the manifest content — binds key to transfer.
     */
    fun deriveKeyFromEphemeral(ephemeralSecret: ByteArray, manifestHash: ByteArray): ByteArray {
        require(ephemeralSecret.size == 32) { "Ephemeral secret must be 32 bytes" }
        return hkdf.derive(
            ikm       = ephemeralSecret,
            salt      = manifestHash,
            info      = KEY_INFO,
            outputLen = 32
        )
    }

    /**
     * Derive a per-transfer key from an existing channel key.
     * No QR exchange needed — both parties share the channel key.
     *
     * @param channelKey    32-byte channel key from [KeyOrchestrator].
     * @param manifestHash  SHA3-256 of the manifest content.
     */
    fun deriveKeyFromChannel(channelKey: ByteArray, manifestHash: ByteArray): ByteArray {
        require(channelKey.size == 32) { "Channel key must be 32 bytes" }
        return hkdf.derive(
            ikm       = channelKey,
            salt      = manifestHash,
            info      = KEY_INFO,
            outputLen = 32
        )
    }

    // ── Chunking and fragmentation ─────────────────────────────────────────

    /**
     * Chunk a file, encrypt each chunk, and produce the [TransferManifest].
     *
     * All chunks are encrypted with [transferKey] before fragmentation.
     * The key is then wiped from the returned result — caller must pass it
     * separately to fragment delivery.
     *
     * @param fileBytes     Complete file contents (in-memory; caller loads from storage).
     * @param transferKey   32-byte per-transfer key.
     *                      This method uses [transferKey] across multiple [cipher.encrypt]
     *                      calls for the duration of the suspend call. The caller MUST NOT
     *                      wipe [transferKey] until this method returns. After it returns,
     *                      the caller SHOULD wipe [transferKey] with fill(0) immediately —
     *                      this class makes no internal copy and does not wipe it.
     * @param postId        32-byte post ID — used as fragment postId for DHT routing.
     * @param channelId     32-byte channel ID.
     * @param filename      Optional display name (omit for sensitive transfers).
     * @param scheme        FEC scheme (default: RS_10_7 for good link quality).
     * @param ttlMs         Transfer TTL in milliseconds from now (default 7 days).
     */
    suspend fun chunk(
        fileBytes:   ByteArray,
        transferKey: ByteArray,
        postId:      ByteArray,
        channelId:   ByteArray,
        filename:    String? = null,
        scheme:      FecScheme = FecScheme.RS_10_7,
        ttlMs:       Long = System.currentTimeMillis() + DEFAULT_TTL_MS
    ): ChunkResult = withContext(Dispatchers.IO) {
        require(transferKey.size == 32) { "Transfer key must be 32 bytes" }

        val chunks  = splitIntoChunks(fileBytes)
        val allSets = mutableListOf<FragmentSet>()
        val chunkHashes = mutableListOf<ByteArray>()

        chunks.forEachIndexed { chunkIdx, chunk ->
            // Encrypt this chunk with the transfer key
            val encryptedChunk = cipher.encrypt(chunk, transferKey).getOrThrow()
            chunkHashes.add(hkdf.sha3_256(encryptedChunk))

            // Derive a per-chunk postId so DHT can route each chunk independently
            val chunkPostId = hkdf.sha3_256(postId + intTo4Bytes(chunkIdx)).copyOf(32)

            val fragmentSet = fragmentationEngine.fragment(chunkPostId, channelId, encryptedChunk, scheme)
            allSets.add(fragmentSet)
        }

        // Build transfer Merkle root from all chunk hashes
        val merkleRoot = buildChunkMerkleRoot(chunkHashes)

        // Build manifest hash — used to bind the per-transfer key
        val manifestHash = buildManifestHash(
            totalSize  = fileBytes.size,
            chunkCount = chunks.size,
            merkleRoot = merkleRoot,
            filename   = filename
        )

        val manifest = TransferManifest(
            version    = MANIFEST_VERSION,
            totalSize  = fileBytes.size,
            chunkCount = chunks.size,
            merkleRoot = merkleRoot,
            manifestHash = manifestHash,
            filename   = filename,
            ttlMs      = ttlMs,
            fecScheme  = scheme
        )

        ChunkResult(
            manifest     = manifest,
            fragmentSets = allSets,
            manifestHash = manifestHash,
            chunkHashes  = chunkHashes.toList()
        )
    }

    // ── QR code generation ─────────────────────────────────────────────────

    /**
     * Build a compact QR payload for the transfer key exchange.
     * The QR payload is the ephemeral secret XOR'd with the manifest hash —
     * the recipient recovers the ephemeral secret and derives the transfer key.
     *
     * QR payload (65 bytes):
     *   [1B version][32B ephemeral_secret XOR manifest_hash][32B manifest_hash]
     *
     * The manifest hash is included so the recipient can verify the file identity.
     */
    fun buildQrPayload(ephemeralSecret: ByteArray, manifestHash: ByteArray): ByteArray {
        require(ephemeralSecret.size == 32) { "Ephemeral secret must be 32 bytes" }
        require(manifestHash.size == 32)    { "Manifest hash must be 32 bytes" }
        val xored = ByteArray(32) { i -> (ephemeralSecret[i].toInt() xor manifestHash[i].toInt()).toByte() }
        return byteArrayOf(QR_VERSION) + xored + manifestHash
    }

    fun parseQrPayload(qrBytes: ByteArray): QrPayload? {
        if (qrBytes.size != 65) return null
        if (qrBytes[0] != QR_VERSION) return null
        val xored        = qrBytes.copyOfRange(1, 33)
        val manifestHash = qrBytes.copyOfRange(33, 65)
        val ephemeral    = ByteArray(32) { i -> (xored[i].toInt() xor manifestHash[i].toInt()).toByte() }
        return QrPayload(ephemeralSecret = ephemeral, manifestHash = manifestHash)
    }

    // ── Manifest serialization ────────────────────────────────────────────

    fun serializeManifest(manifest: TransferManifest): ByteArray {
        val filenameBytes = manifest.filename?.toByteArray() ?: ByteArray(0)
        val out = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(out)
        dos.writeByte(manifest.version.toInt())
        dos.writeLong(manifest.ttlMs)
        dos.writeInt(manifest.totalSize)
        dos.writeInt(manifest.chunkCount)
        dos.write(manifest.merkleRoot)
        dos.writeByte(filenameBytes.size)
        if (filenameBytes.isNotEmpty()) dos.write(filenameBytes)
        dos.write(manifest.manifestHash)
        dos.writeByte(manifest.fecScheme.wire)
        dos.flush()
        return out.toByteArray()
    }

    fun deserializeManifest(bytes: ByteArray): TransferManifest? { return try {
        val dis         = java.io.DataInputStream(java.io.ByteArrayInputStream(bytes))
        val version     = dis.readByte()
        val ttlMs       = dis.readLong()
        val totalSize   = dis.readInt()
        val chunkCount  = dis.readInt()
        // Reject implausible values before they reach finalAssemble()'s `0 until chunkCount`
        // loop. chunkCount = Int.MAX_VALUE would iterate ~2 billion times, freezing the process.
        // MAX_CHUNKS = 2048 covers files up to 128 GB at 64 KB/chunk — far beyond realistic use.
        if (chunkCount <= 0 || chunkCount > MAX_CHUNKS) {
            Diag.degraded("shadowfiles", "manifest-chunk-count-invalid",
                "chunkCount=$chunkCount out of valid range [1, $MAX_CHUNKS] — rejecting manifest")
            return null
        }
        if (totalSize <= 0 || totalSize.toLong() > chunkCount.toLong() * CHUNK_SIZE_BYTES) {
            Diag.degraded("shadowfiles", "manifest-total-size-invalid",
                "totalSize=$totalSize inconsistent with chunkCount=$chunkCount — rejecting manifest")
            return null
        }
        val merkleRoot  = ByteArray(32).also { dis.readFully(it) }
        val filenameLen = dis.readByte().toInt() and 0xFF
        val filename    = if (filenameLen > 0) ByteArray(filenameLen).also { dis.readFully(it) }
                              .decodeToString() else null
        val manifestHash = ByteArray(32).also { dis.readFully(it) }
        val fecWire     = dis.readByte().toInt()
        val fecScheme   = FecScheme.fromWire(fecWire)
        TransferManifest(version, totalSize, chunkCount, merkleRoot, manifestHash, filename, ttlMs, fecScheme ?: FecScheme.NONE)
    } catch (e: Exception) {
        Diag.swallowed("shadowfiles", "deserialize-manifest", e)
        null
    } }

    // ── Internal helpers ──────────────────────────────────────────────────

    private fun splitIntoChunks(bytes: ByteArray): List<ByteArray> {
        val chunks = mutableListOf<ByteArray>()
        var offset = 0
        while (offset < bytes.size) {
            val end = minOf(offset + CHUNK_SIZE_BYTES, bytes.size)
            chunks.add(bytes.copyOfRange(offset, end))
            offset = end
        }
        return chunks
    }

    private fun buildChunkMerkleRoot(chunkHashes: List<ByteArray>): ByteArray {
        var nodes = chunkHashes.toMutableList()
        while (nodes.size > 1) {
            if (nodes.size % 2 != 0) nodes.add(nodes.last())
            nodes = (nodes.indices step 2).map { i ->
                hkdf.sha3_256(nodes[i] + nodes[i + 1])
            }.toMutableList()
        }
        return nodes.firstOrNull() ?: ByteArray(32)
    }

    private fun buildManifestHash(
        totalSize:  Int,
        chunkCount: Int,
        merkleRoot: ByteArray,
        filename:   String?
    ): ByteArray {
        val nameBytes = filename?.toByteArray() ?: ByteArray(0)
        return hkdf.sha3_256(
            intTo4Bytes(totalSize) + intTo4Bytes(chunkCount) + merkleRoot + nameBytes
        )
    }


    companion object {
        const val CHUNK_SIZE_BYTES  = 64 * 1024          // 64 KB
        const val DEFAULT_TTL_MS    = 7L * 24 * 60 * 60 * 1000
        const val MANIFEST_VERSION  : Byte = 1
        const val QR_VERSION        : Byte = 1
        val KEY_INFO = "shadowfiles_v1".toByteArray()

        /**
         * Maximum chunk count accepted from a deserialized manifest.
         * 2048 chunks × 64 KB = 128 GB — far beyond any realistic SHADOWFILES transfer.
         * Without this cap, a crafted manifest with chunkCount = Int.MAX_VALUE causes
         * [finalAssemble]'s `0 until chunkCount` loop to run ~2 billion iterations (DoS).
         */
        const val MAX_CHUNKS = 2048
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

data class TransferManifest(
    val version:      Byte,
    val totalSize:    Int,
    val chunkCount:   Int,
    val merkleRoot:   ByteArray,    // Merkle root of all chunk hashes
    val manifestHash: ByteArray,    // SHA3-256 of manifest content (key binding)
    val filename:     String?,      // null for sensitive transfers
    val ttlMs:        Long,
    val fecScheme:    FecScheme
) {
    override fun equals(other: Any?) = other is TransferManifest &&
        manifestHash.contentEquals(other.manifestHash)
    override fun hashCode() = manifestHash.contentHashCode()
}

data class ChunkResult(
    val manifest:     TransferManifest,
    val fragmentSets: List<FragmentSet>,   // one FragmentSet per 64KB chunk
    val manifestHash: ByteArray,
    /** SHA3-256 of each encrypted chunk, in order. Use these as [expectedChunkHash]
     *  in [ShadowFilesReassembler.tryAssembleChunk] — do NOT re-derive by re-encrypting,
     *  since SymmetricCipher uses a random nonce and re-encryption produces a different hash. */
    val chunkHashes:  List<ByteArray>
)

data class QrPayload(
    val ephemeralSecret: ByteArray,   // 32 bytes — used to derive transfer key
    val manifestHash:    ByteArray    // 32 bytes — identifies the transfer
)

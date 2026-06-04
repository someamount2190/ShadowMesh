package mesh.shadowmesh.distribution.visual
import mesh.shadowmesh.diagnostics.Diag

import mesh.shadowmesh.distribution.AppArtifactDescriptor
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.security.MessageDigest
import java.util.zip.CRC32

/**
 * Visual app distribution — the QR frames ARE the data channel (design: Visual Distribution).
 *
 * A seeder displays a looping animation of QR frames on its screen; an acquirer films the screen
 * with its camera and reconstructs the APK. No radio, no internet, no pairing — only the camera
 * lens. This is the txqr / libcimbar approach, built on the [LtFountain] code above and the
 * existing [AppArtifactDescriptor] / ApkArtifactVerifier for the trust gate.
 *
 * Each frame payload is built to survive being shown out-of-order and partially missed:
 *
 *   STREAM HEADER frame (frameType=0, emitted periodically so a late joiner can sync):
 *     magic[4]="SMVS" | type:byte=0 | totalLen:int | blockSize:int | sourceBlockCount:int
 *     | seed:long | descriptorLen:short | descriptorBytes | crc32:int
 *
 *   DATA frame (frameType=1):
 *     magic[4]="SMVS" | type:byte=1 | seqNo:long | blockSize:int | encodedBlock | crc32:int
 *
 * The QR codec (turning these byte payloads into displayable / scannable QR images) lives in the
 * app/UI layer using a QR library; this class is the transport-agnostic byte protocol, fully
 * unit-testable without a screen or camera.
 */
object VisualFrameProtocol {
    const val MAGIC = "SMVS"            // SHADOWMESH Visual Stream
    const val TYPE_HEADER: Byte = 0
    const val TYPE_DATA:   Byte = 1

    /**
     * Maximum APK file size accepted in a visual stream header.
     * ShadowMesh APKs are small (<50 MB). Rejecting oversized values prevents a
     * crafted header from triggering a multi-GB [assembleFile] allocation.
     */
    const val MAX_FILE_BYTES     = 100 * 1024 * 1024   // 100 MB
    /**
     * Maximum block size per encoded chunk. 64 KB is generous for QR-based delivery.
     * Larger values cause per-block allocations that exceed practical QR payload limits.
     */
    const val MAX_BLOCK_SIZE     = 64 * 1024            // 64 KB
    /**
     * Maximum source block count for the LT fountain decoder.
     * LtFountain.buildRobustSolitonCdf() allocates DoubleArray(sourceBlockCount).
     * At MAX_FILE_BYTES / MIN_BLOCK_SIZE = 100 MB / 1 B = 100M blocks (pathological).
     * Capping at 100 000 covers any realistic APK at any practical block size while
     * keeping the CDF array ≤ 800 KB.
     */
    const val MAX_SOURCE_BLOCKS  = 100_000

    // ── Encode side (seeder) ─────────────────────────────────────────────────

    /** Immutable plan the seeder loops over to emit frames. */
    class StreamEncoder(
        private val fileBytes:  ByteArray,
        val descriptor:         AppArtifactDescriptor,
        val blockSize:          Int = 1024,
        seed:                   Long = System.nanoTime()
    ) {
        val sourceBlockCount: Int = (fileBytes.size + blockSize - 1) / blockSize
        private val fountain = LtFountain(sourceBlockCount, blockSize, seed)
        private val sourceBlocks: List<ByteArray> = buildSourceBlocks(fileBytes, blockSize, sourceBlockCount)
        val seed: Long = seed

        /** The header frame; emit this every [headerEvery] frames so late joiners can sync. */
        fun headerFrame(): ByteArray {
            val descBytes = descriptor.toBytes()
            val body = ByteArrayOutputStream()
            DataOutputStream(body).use { d ->
                d.writeBytes(MAGIC); d.writeByte(TYPE_HEADER.toInt())
                d.writeInt(fileBytes.size); d.writeInt(blockSize)
                d.writeInt(sourceBlockCount); d.writeLong(seed)
                d.writeShort(descBytes.size); d.write(descBytes)
            }
            return withCrc(body.toByteArray())
        }

        /** Data frame for the unbounded output index [seqNo]. */
        fun dataFrame(seqNo: Long): ByteArray {
            val encoded = fountain.encodeBlock(sourceBlocks, seqNo)
            val body = ByteArrayOutputStream()
            DataOutputStream(body).use { d ->
                d.writeBytes(MAGIC); d.writeByte(TYPE_DATA.toInt())
                d.writeLong(seqNo); d.writeInt(blockSize); d.write(encoded)
            }
            return withCrc(body.toByteArray())
        }

        /**
         * Convenience: produce the full frame sequence for one loop iteration —
         * the header followed by [count] data frames. The seeder shows these in a loop;
         * because the code is rateless, looping with fresh seqNos keeps helping the receiver.
         */
        fun frameLoop(startSeq: Long, count: Int, headerEvery: Int = 16): List<ByteArray> {
            val frames = ArrayList<ByteArray>(count + count / headerEvery + 1)
            for (i in 0 until count) {
                if (i % headerEvery == 0) frames.add(headerFrame())
                frames.add(dataFrame(startSeq + i))
            }
            return frames
        }
    }

    // ── Decode side (acquirer) ───────────────────────────────────────────────

    sealed class Frame {
        data class Header(
            val totalLen: Int, val blockSize: Int, val sourceBlockCount: Int,
            val seed: Long, val descriptor: AppArtifactDescriptor
        ) : Frame()
        data class Data(val seqNo: Long, val encoded: ByteArray) : Frame()
        object Invalid : Frame()
    }

    /** Parse a captured frame payload (CRC-checked). Returns [Frame.Invalid] on any error. */
    fun parseFrame(bytes: ByteArray): Frame {
        val body = stripCrc(bytes) ?: return Frame.Invalid
        return try {
            val dis = DataInputStream(ByteArrayInputStream(body))
            val magic = ByteArray(4).also { dis.readFully(it) }
            if (String(magic) != MAGIC) return Frame.Invalid
            when (dis.readByte()) {
                TYPE_HEADER -> {
                    val totalLen = dis.readInt(); val blockSize = dis.readInt()
                    val k = dis.readInt(); val seed = dis.readLong()
                    // Bounds check before constructing LtFountain: a crafted frame with
                    // sourceBlockCount=Int.MAX_VALUE causes LtFountain.buildRobustSolitonCdf()
                    // to allocate DoubleArray(Int.MAX_VALUE) ≈ 8 GB → OOM crash.
                    // Similarly, an oversized blockSize or negative totalLen must be rejected.
                    if (totalLen <= 0 || totalLen > MAX_FILE_BYTES)       return Frame.Invalid
                    if (blockSize <= 0 || blockSize > MAX_BLOCK_SIZE)     return Frame.Invalid
                    if (k <= 0 || k > MAX_SOURCE_BLOCKS)                  return Frame.Invalid
                    val dLen = dis.readUnsignedShort()
                    val descBytes = ByteArray(dLen).also { dis.readFully(it) }
                    val desc = AppArtifactDescriptor.fromBytes(descBytes) ?: return Frame.Invalid
                    Frame.Header(totalLen, blockSize, k, seed, desc)
                }
                TYPE_DATA -> {
                    val seqNo = dis.readLong(); val blockSize = dis.readInt()
                    if (blockSize <= 0 || blockSize > MAX_BLOCK_SIZE) return Frame.Invalid
                    val encoded = ByteArray(blockSize).also { dis.readFully(it) }
                    Frame.Data(seqNo, encoded)
                }
                else -> Frame.Invalid
            }
        } catch (_: Exception) { Frame.Invalid }
    }

    /**
     * Stateful receiver. Feed it parsed frames (from the camera/QR decoder) until [isComplete].
     * The first valid header initialises the fountain decoder; data frames are then peeled.
     */
    class StreamReceiver {
        private var decoder: LtFountain.Decoder? = null
        private var header: Frame.Header? = null

        val isComplete: Boolean get() = decoder?.isComplete == true
        val descriptor: AppArtifactDescriptor? get() = header?.descriptor
        val sourceBlockCount: Int get() = header?.sourceBlockCount ?: 0
        val progress: Int get() = decoder?.progress ?: 0

        /** Returns true once the file is fully recovered. */
        fun offer(frame: Frame): Boolean {
            when (frame) {
                is Frame.Header -> if (decoder == null) {
                    header = frame
                    decoder = LtFountain.Decoder(LtFountain(frame.sourceBlockCount, frame.blockSize, frame.seed))
                }
                is Frame.Data -> decoder?.offer(frame.seqNo, frame.encoded)
                Frame.Invalid -> {}
            }
            return isComplete
        }

        /** Reconstructed file bytes, trimmed to the true length. Null until complete. */
        fun assembleFile(): ByteArray? {
            val h = header ?: return null
            val raw = decoder?.assemble() ?: return null
            return raw.copyOf(h.totalLen)
        }
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private fun buildSourceBlocks(bytes: ByteArray, blockSize: Int, k: Int): List<ByteArray> =
        (0 until k).map { i ->
            val start = i * blockSize
            val end = minOf(start + blockSize, bytes.size)
            ByteArray(blockSize).also { if (start < bytes.size) System.arraycopy(bytes, start, it, 0, end - start) }
        }

    private fun withCrc(body: ByteArray): ByteArray {
        val crc = CRC32().apply { update(body) }.value.toInt()
        return body + byteArrayOf((crc ushr 24).toByte(), (crc ushr 16).toByte(), (crc ushr 8).toByte(), crc.toByte())
    }

    private fun stripCrc(frame: ByteArray): ByteArray? {
        if (frame.size < 5) return null
        val body = frame.copyOf(frame.size - 4)
        val want = ((frame[frame.size - 4].toInt() and 0xFF) shl 24) or
                   ((frame[frame.size - 3].toInt() and 0xFF) shl 16) or
                   ((frame[frame.size - 2].toInt() and 0xFF) shl 8) or
                   (frame[frame.size - 1].toInt() and 0xFF)
        val have = CRC32().apply { update(body) }.value.toInt()
        return if (have == want) body else null
    }
}

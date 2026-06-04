package mesh.shadowmesh.mesh.privacy

import java.security.SecureRandom

/**
 * Packet size normalization — design doc Phase 8.
 *
 * All outbound packets are padded to one of four size buckets to prevent
 * DPI (Deep Packet Inspection) from inferring message content or type
 * from packet size distributions. The normalized profile resembles CDN
 * traffic — uniform bucket distribution, no size correlation to content.
 *
 * Buckets: 128 / 512 / 1024 / 4096 bytes.
 *
 * Padding scheme:
 *   - Random bytes appended to reach the next bucket boundary.
 *   - Header size is determined by the bucket, not the payload size:
 *       Buckets 128/512/1024 → 1-byte header (max payload 127/511/1023)
 *       Bucket 4096          → 2-byte header (max payload 4094)
 *   - This makes header selection deterministic from the bucket alone, so
 *     [denormalize] can recover it from packet.size without any ambiguity.
 *   - Normalization is applied AFTER onion encryption — the circuit layer
 *     sees normalized sizes, not the raw post sizes.
 *
 * Overhead: ≤ 5% of total bytes on average across all bucket sizes.
 *
 * Wire format:
 *   Buckets 128/512/1024: [1B real_len][payload][padding to bucket]
 *   Bucket 4096:          [2B real_len BE][payload][padding to bucket]
 *
 * Thread-safety: stateless — thread-safe by construction.
 */
object PacketNormalizer {

    private val BUCKETS     = intArrayOf(128, 512, 1024, 4096)
    private val BUCKET_SET  = BUCKETS.toHashSet()   // O(1) membership check in denormalize()
    private val rng         = SecureRandom()

    /**
     * Returns true if [bucket] uses a 2-byte length header.
     * Only the 4096-byte bucket requires 2 bytes (max payload = 4094 bytes > 255).
     * All smaller buckets use a 1-byte header.
     */
    private fun uses2ByteHeader(bucket: Int): Boolean = bucket == 4096

    /**
     * Normalize [payload] to the smallest bucket that fits it (plus overhead).
     * Returns null if the payload exceeds the largest bucket capacity.
     *
     * Header size is bucket-driven (not payload-size-driven) so that
     * [denormalize] can unambiguously determine the header format from the
     * packet size alone.
     */
    fun normalize(payload: ByteArray): ByteArray? {
        // Find the smallest bucket that can hold the payload + its header.
        // 1-byte header supports payloads up to (bucket - 1) bytes.
        // 2-byte header (4096 only) supports payloads up to (bucket - 2) = 4094 bytes.
        val bucket = BUCKETS.firstOrNull { b ->
            val headerSize = if (uses2ByteHeader(b)) 2 else 1
            payload.size <= b - headerSize
        } ?: return null  // payload too large for any bucket

        val headerSize = if (uses2ByteHeader(bucket)) 2 else 1
        val padSize    = bucket - headerSize - payload.size
        val padding    = ByteArray(padSize).also { rng.nextBytes(it) }

        return if (headerSize == 1) {
            byteArrayOf(payload.size.toByte()) + payload + padding
        } else {
            byteArrayOf((payload.size shr 8).toByte(), payload.size.toByte()) + payload + padding
        }
    }

    /**
     * Extract the real payload from a normalized packet.
     * Header format is determined solely by packet size — only exact bucket
     * sizes {128, 512, 1024, 4096} are valid. Any other size returns null.
     * Returns null if the packet is malformed or not a recognized bucket size.
     */
    fun denormalize(packet: ByteArray): ByteArray? {
        if (packet.isEmpty()) return null
        // Reject any packet that is not exactly one of the four bucket sizes.
        // Without this, a 200-byte packet would enter the 1-byte path and return
        // a partial result rather than null.
        if (packet.size !in BUCKET_SET) return null

        return if (!uses2ByteHeader(packet.size)) {
            // 1-byte header (128 / 512 / 1024 buckets)
            val len = packet[0].toInt() and 0xFF
            if (packet.size < 1 + len) null else packet.copyOfRange(1, 1 + len)
        } else {
            // 2-byte header (4096 bucket)
            if (packet.size < 2) return null
            val len = ((packet[0].toInt() and 0xFF) shl 8) or (packet[1].toInt() and 0xFF)
            if (packet.size < 2 + len) null else packet.copyOfRange(2, 2 + len)
        }
    }

    /**
     * Which bucket a payload of [payloadSize] bytes will be normalized into.
     * Returns -1 if the payload is too large for any bucket.
     */
    fun bucketFor(payloadSize: Int): Int {
        return BUCKETS.firstOrNull { b ->
            val headerSize = if (uses2ByteHeader(b)) 2 else 1
            payloadSize <= b - headerSize
        } ?: -1
    }

    fun maxPayloadForBucket(bucket: Int): Int = when (bucket) {
        128  -> 127   // 128 - 1B header
        512  -> 511   // 512 - 1B header
        1024 -> 1023  // 1024 - 1B header
        4096 -> 4094  // 4096 - 2B header
        else -> -1
    }

    val buckets: IntArray get() = BUCKETS.copyOf()
}

package mesh.shadowmesh.storage

import java.util.concurrent.atomic.AtomicLong
import kotlin.math.ceil
import kotlin.math.ln
import kotlin.math.pow

/**
 * Bloom filter for gossip fragment deduplication — design doc Phase 3.
 *
 * Prevents relay amplification: a fragment that has already been forwarded
 * is rejected before relay. The false positive rate is <0.1% at the
 * configured capacity, meaning <0.1% of new fragments are incorrectly
 * dropped — acceptable for a gossip mesh.
 *
 * Reset policy: the filter resets when [insertCount] reaches [capacity].
 * After reset, all fragments are treated as new for one cycle. This is
 * correct — a briefly re-seen fragment is a minor inefficiency, not a
 * correctness failure.
 *
 * Thread-safety: all public operations are @Synchronized.
 * The filter is in-memory only — it does not need to survive process death
 * (fragment deduplication is best-effort).
 *
 * Implementation: pure Kotlin — no external dependencies.
 *   k hash functions are simulated via double-hashing:
 *     h_i(x) = (h1(x) + i * h2(x)) mod m
 *   where h1 and h2 are the upper/lower 32 bits of MurmurHash3-128.
 *   This is the standard technique used by Guava's BloomFilter internally.
 *   Bit array size m and hash count k are derived from [capacity] and [fpp]:
 *     m = -n * ln(p) / (ln 2)²
 *     k = (m / n) * ln 2
 *
 * @param capacity    Expected number of fragments before reset. Default 50,000.
 * @param fpp         Target false positive probability. Default 0.001 (0.1%).
 */
class GossipBloomFilter(
    private val capacity: Int    = DEFAULT_CAPACITY,
    private val fpp:      Double = DEFAULT_FPP
) {
    // Bit array size and hash count derived from capacity and fpp.
    private val m: Int = optimalBitArraySize(capacity, fpp)
    private val k: Int = optimalHashFunctions(m, capacity)

    // Single pre-allocated bit array, reused across resets to avoid GC pressure.
    // At DEFAULT_CAPACITY=50_000 and DEFAULT_FPP=0.001, m ≈ 718,416 bits ≈ 88KB.
    // Allocating a new LongArray on every reset (every 50k inserts) would generate
    // ~88KB of garbage each cycle. fill(0) resets in-place: same O(m/64) cost,
    // zero allocation.
    private val bits: LongArray = LongArray((m + 63) / 64)
    private val insertCount = AtomicLong(0)

    @Synchronized
    fun testAndAdd(fragmentId: ByteArray): Boolean {
        val (h1, h2) = murmur3Hash128(fragmentId)
        var isNew = false
        for (i in 0 until k) {
            val bit = ((h1 + i.toLong() * h2) and Long.MAX_VALUE) % m
            val word = (bit / 64).toInt()
            val mask = 1L shl (bit % 64).toInt()
            if (bits[word] and mask == 0L) {
                isNew = true
                bits[word] = bits[word] or mask
            }
        }
        if (isNew && insertCount.incrementAndGet() >= capacity) {
            bits.fill(0)
            insertCount.set(0)
        }
        return isNew
    }

    @Synchronized
    fun reset() {
        bits.fill(0)
        insertCount.set(0)
    }

    fun currentSize(): Long = insertCount.get()

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun optimalBitArraySize(n: Int, p: Double): Int =
        ceil(-n * ln(p) / (ln(2.0).pow(2))).toInt().coerceAtLeast(64)

    private fun optimalHashFunctions(m: Int, n: Int): Int =
        ceil((m.toDouble() / n) * ln(2.0)).toInt().coerceAtLeast(1)

    /**
     * MurmurHash3 128-bit (x64 variant), adapted for byte arrays.
     * Returns (h1, h2) — upper and lower 64-bit halves of the hash.
     * Used as the double-hashing base; this is the same hash Guava uses internally.
     */
    private fun murmur3Hash128(data: ByteArray): Pair<Long, Long> {
        val seed = 0x9368L
        var h1 = seed
        var h2 = seed
        val c1 = -0x783c846eeebdac2bL  // 0x87c37b91114253d5
        val c2 = 0x4cf5ad432745937fL

        val nblocks = data.size / 16
        for (i in 0 until nblocks) {
            var k1 = getLong(data, i * 16)
            var k2 = getLong(data, i * 16 + 8)
            k1 *= c1; k1 = java.lang.Long.rotateLeft(k1, 31); k1 *= c2; h1 = h1 xor k1
            h1 = java.lang.Long.rotateLeft(h1, 27); h1 += h2; h1 = h1 * 5 + 0x52dce729L
            k2 *= c2; k2 = java.lang.Long.rotateLeft(k2, 33); k2 *= c1; h2 = h2 xor k2
            h2 = java.lang.Long.rotateLeft(h2, 31); h2 += h1; h2 = h2 * 5 + 0x38495ab5L
        }

        val tail = data.size - nblocks * 16
        var k1 = 0L; var k2 = 0L
        val offset = nblocks * 16
        if (tail >= 15) k2 = k2 xor (data[offset + 14].toLong() and 0xFF shl 48)
        if (tail >= 14) k2 = k2 xor (data[offset + 13].toLong() and 0xFF shl 40)
        if (tail >= 13) k2 = k2 xor (data[offset + 12].toLong() and 0xFF shl 32)
        if (tail >= 12) k2 = k2 xor (data[offset + 11].toLong() and 0xFF shl 24)
        if (tail >= 11) k2 = k2 xor (data[offset + 10].toLong() and 0xFF shl 16)
        if (tail >= 10) k2 = k2 xor (data[offset +  9].toLong() and 0xFF shl  8)
        if (tail >=  9) k2 = k2 xor (data[offset +  8].toLong() and 0xFF)
        k2 *= c2; k2 = java.lang.Long.rotateLeft(k2, 33); k2 *= c1; h2 = h2 xor k2
        if (tail >= 8) k1 = k1 xor (data[offset + 7].toLong() and 0xFF shl 56)
        if (tail >= 7) k1 = k1 xor (data[offset + 6].toLong() and 0xFF shl 48)
        if (tail >= 6) k1 = k1 xor (data[offset + 5].toLong() and 0xFF shl 40)
        if (tail >= 5) k1 = k1 xor (data[offset + 4].toLong() and 0xFF shl 32)
        if (tail >= 4) k1 = k1 xor (data[offset + 3].toLong() and 0xFF shl 24)
        if (tail >= 3) k1 = k1 xor (data[offset + 2].toLong() and 0xFF shl 16)
        if (tail >= 2) k1 = k1 xor (data[offset + 1].toLong() and 0xFF shl  8)
        if (tail >= 1) k1 = k1 xor (data[offset    ].toLong() and 0xFF)
        k1 *= c1; k1 = java.lang.Long.rotateLeft(k1, 31); k1 *= c2; h1 = h1 xor k1

        h1 = h1 xor data.size.toLong(); h2 = h2 xor data.size.toLong()
        h1 += h2; h2 += h1
        h1 = fmix(h1); h2 = fmix(h2)
        h1 += h2; h2 += h1
        return h1 to h2
    }

    private fun fmix(k: Long): Long {
        var h = k
        h = h xor (h ushr 33); h *= -49064778989728563L   // bit pattern: 0xff51afd7ed558ccd
        h = h xor (h ushr 33); h *= -4265267296055464877L  // bit pattern: 0xc4ceb9fe1a85ec53
        h = h xor (h ushr 33)
        return h
    }

    private fun getLong(data: ByteArray, offset: Int): Long {
        var v = 0L
        for (i in 7 downTo 0) v = (v shl 8) or (data[offset + i].toLong() and 0xFF)
        return v
    }

    companion object {
        const val DEFAULT_CAPACITY = 50_000
        const val DEFAULT_FPP      = 0.001
    }
}

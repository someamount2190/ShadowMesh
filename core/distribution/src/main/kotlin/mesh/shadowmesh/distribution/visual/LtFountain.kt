package mesh.shadowmesh.distribution.visual

import kotlin.random.Random

/**
 * Luby Transform (LT) fountain code — the rateless erasure code used for unidirectional
 * screen→camera app transfer (design: Visual Distribution).
 *
 * Why a fountain code at all: a camera filming a looping animated barcode misses frames
 * (motion blur, refresh/shutter beat, focus hunts). With a fixed sequence you'd have to keep
 * looping until the receiver happens to catch every index. An LT code instead lets the seeder
 * emit an UNBOUNDED stream of encoded blocks, each an XOR of a pseudo-random subset of the K
 * source blocks; the receiver collects ANY ~K·(1+ε) distinct blocks, in any order, and
 * reconstructs. Missed frames cost nothing — just wait for more. This matches the txqr /
 * libcimbar designs (both moved from "repeat the sequence" to fountain codes for exactly this).
 *
 * Layering vs the existing Reed-Solomon FEC: RS in FragmentationEngine corrects *bit errors
 * within one captured frame*. The LT code here handles *whole missing frames across the stream*.
 * They are complementary — RS makes each frame's bytes trustworthy, LT makes the set of frames
 * reconstructable despite gaps.
 *
 * Determinism: the degree/neighbour selection for block `seqNo` is seeded purely by
 * (`seed`, `seqNo`), so the decoder reconstructs each block's neighbour set from its header
 * without the encoder transmitting the membership. Encoder and decoder share [seed] (carried in
 * the stream header).
 *
 * This is a clean, dependency-free LT implementation (robust soliton degree distribution).
 * The ~2× overhead versus optimal Raptor codes is acceptable for the emergency-last-resort
 * visual channel. If overhead becomes a constraint, the algorithm can be improved by
 * reimplementing a more efficient fountain code internally — not by adding an external
 * library dependency, which would contradict the project's no-external-trust-surface posture.
 * The frame protocol ([VisualFrameProtocol]) is independent of this class, so an algorithmic
 * upgrade is a drop-in replacement with no wire format change.
 */
class LtFountain(
    /** Number of source blocks K. */
    val sourceBlockCount: Int,
    /** Fixed byte size of every block (last source block is zero-padded to this). */
    val blockSize: Int,
    /** Shared PRNG seed; encoder and decoder must agree (carried in the stream header). */
    val seed: Long,
    private val c:     Double = 0.03,
    private val delta: Double = 0.05
) {
    init {
        require(sourceBlockCount > 0) { "K must be > 0" }
        require(blockSize > 0)        { "blockSize must be > 0" }
    }

    /** Precomputed robust-soliton CDF for degree sampling. */
    private val cdf: DoubleArray = buildRobustSolitonCdf()

    // ── Encoder ─────────────────────────────────────────────────────────────

    /**
     * Produce the encoded block for output index [seqNo] by XOR-ing the source blocks selected
     * for that index. [source] must be exactly [sourceBlockCount] blocks of [blockSize] bytes.
     */
    fun encodeBlock(source: List<ByteArray>, seqNo: Long): ByteArray {
        require(source.size == sourceBlockCount) { "source must have K blocks" }
        val out = ByteArray(blockSize)
        for (idx in neighbours(seqNo)) {
            val src = source[idx]
            for (i in 0 until blockSize) out[i] = (out[i].toInt() xor src[i].toInt()).toByte()
        }
        return out
    }

    // ── Decoder (peeling / belief-propagation) ───────────────────────────────

    class Decoder(private val fountain: LtFountain) {
        private val k = fountain.sourceBlockCount
        private val recovered = arrayOfNulls<ByteArray>(k)
        private var recoveredCount = 0
        // Pending encoded blocks not yet reducible to a single unknown.
        private data class Pending(var data: ByteArray, val neighbours: MutableSet<Int>)
        private val pending = mutableListOf<Pending>()
        private val seenSeq = HashSet<Long>()

        val isComplete: Boolean get() = recoveredCount == k
        val progress: Int get() = recoveredCount

        /** Ingest one received encoded block. Returns true once the whole file is recovered. */
        fun offer(seqNo: Long, encoded: ByteArray): Boolean {
            if (isComplete) return true
            // Cap seenSeq to prevent OOM from a crafted stream with unique seqNos.
            // A legitimate fountain stream needs at most ~K*1.5 distinct blocks to decode;
            // any session emitting more than MAX_SEEN_SEQ unique IDs is pathological.
            if (seenSeq.size >= MAX_SEEN_SEQ) return false
            if (!seenSeq.add(seqNo)) return isComplete   // duplicate frame — ignore
            var data = encoded.copyOf()
            val nb = fountain.neighbours(seqNo).toMutableSet()
            // Reduce against already-recovered sources.
            val it = nb.iterator()
            while (it.hasNext()) {
                val idx = it.next()
                val r = recovered[idx]
                if (r != null) { xorInto(data, r); it.remove() }
            }
            when (nb.size) {
                0 -> {} // fully redundant — drop
                1 -> cascadeRecover(nb.first(), data)
                else -> pending.add(Pending(data, nb))
            }
            return isComplete
        }

        /** A source block became known — substitute it into all pending blocks (peeling). */
        private fun cascadeRecover(index: Int, value: ByteArray) {
            if (recovered[index] != null) return
            recovered[index] = value
            recoveredCount++
            var progressed = true
            while (progressed) {
                progressed = false
                val readyToFix = mutableListOf<Pair<Int, ByteArray>>()
                for (p in pending) {
                    if (index in p.neighbours) {
                        xorInto(p.data, value); p.neighbours.remove(index)
                    }
                    if (p.neighbours.size == 1) {
                        val only = p.neighbours.first()
                        if (recovered[only] == null) readyToFix.add(only to p.data.copyOf())
                    }
                }
                pending.removeAll { it.neighbours.size <= 1 }
                for ((idx, v) in readyToFix) {
                    // recovered[idx] == null guard handles duplicate idx entries:
                    // two pending blocks that both reduced to the same unknown will both
                    // appear in readyToFix. The first one stores the value; the second
                    // hits the null check and is skipped. Both should produce identical
                    // v (they XOR the same neighbours) so the skip is always correct.
                    if (recovered[idx] == null) { recovered[idx] = v; recoveredCount++; progressed = true }
                }
            }
        }

        /** Concatenate recovered source blocks (caller trims to the true file length). */
        fun assemble(): ByteArray? {
            if (!isComplete) return null
            val out = ByteArray(k * fountain.blockSize)
            for (i in 0 until k) System.arraycopy(recovered[i]!!, 0, out, i * fountain.blockSize, fountain.blockSize)
            return out
        }

        private fun xorInto(dst: ByteArray, src: ByteArray) {
            for (i in dst.indices) dst[i] = (dst[i].toInt() xor src[i].toInt()).toByte()
        }
    }

    // ── Degree / neighbour selection (deterministic per seqNo) ───────────────

    /** Source-block indices that the encoded block [seqNo] is the XOR of. */
    fun neighbours(seqNo: Long): IntArray {
        val rng = Random(seed xor (seqNo * -0x61c8864680b583ebL))   // splitmix-ish per-seq seed
        val degree = sampleDegree(rng)
        if (degree >= sourceBlockCount) return IntArray(sourceBlockCount) { it }
        val picked = LinkedHashSet<Int>()
        while (picked.size < degree) picked.add(rng.nextInt(sourceBlockCount))
        return picked.toIntArray()
    }

    private fun sampleDegree(rng: Random): Int {
        val u = rng.nextDouble()
        var d = 1
        while (d < cdf.size && u > cdf[d - 1]) d++
        return d.coerceIn(1, sourceBlockCount)
    }

    /** Robust soliton distribution CDF over degrees 1..K. */
    private fun buildRobustSolitonCdf(): DoubleArray {
        val k = sourceBlockCount
        val rho = DoubleArray(k + 1)
        rho[1] = 1.0 / k
        for (d in 2..k) rho[d] = 1.0 / (d.toDouble() * (d - 1))
        // tau spike
        val r = c * Math.log(k / delta) * Math.sqrt(k.toDouble())
        val kr = Math.max(1, (k / r).toInt())
        val tau = DoubleArray(k + 1)
        for (d in 1 until kr) tau[d] = r / (d.toDouble() * k)
        if (kr in 1..k) tau[kr] = r * Math.log(r / delta) / k
        val beta = (1..k).sumOf { rho[it] + tau[it] }
        val mu = DoubleArray(k) // index 0..k-1 == degree 1..k
        for (d in 1..k) mu[d - 1] = (rho[d] + tau[d]) / beta
        val cdf = DoubleArray(k)
        var acc = 0.0
        for (i in 0 until k) { acc += mu[i]; cdf[i] = acc }
        return cdf
    }

    companion object {
        /** Recommended number of encoded blocks to emit before the receiver is very likely done. */
        fun recommendedOverhead(k: Int): Int = (k * 1.10).toInt() + 8

        /**
         * Maximum unique sequence numbers a [Decoder] will accept in one session.
         * A legitimate fountain session for K source blocks needs at most ~K*2 distinct
         * blocks (generous overhead). Capping at 65536 covers any realistic K while
         * bounding the seenSeq HashSet to ~512 KB.
         */
        const val MAX_SEEN_SEQ = 65_536
    }
}

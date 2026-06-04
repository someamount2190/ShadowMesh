package mesh.shadowmesh.debug

import android.content.Context
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.HybridSigner
import mesh.shadowmesh.crypto.PostRatchet
import mesh.shadowmesh.distribution.visual.LtFountain
import mesh.shadowmesh.storage.GossipBloomFilter
import mesh.shadowmesh.storage.RateLimiter
import kotlin.random.Random

// ─── Hybrid signer: both schemes must pass; a tampered message must be rejected ──
object SignerRoundTripProbe : Probe {
    override val id = "signer_roundtrip"
    override val title = "Hybrid signature round-trip + tamper reject"
    override val category = ProbeCategory.CRYPTO
    override val description = "Signs and verifies, then confirms a flipped byte fails verification (both Dilithium and Ed25519)."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult = try {
        val signer = HybridSigner()
        val kp = signer.generateSigningKeyPair().getOrThrow()
        val msg = "shadowmesh-diagnostic".encodeToByteArray()
        val sig = signer.sign(msg, kp.privateKey).getOrThrow()
        val good = signer.verify(msg, sig, kp.publicKey).getOrThrow()
        val tampered = msg.copyOf().also { it[0] = (it[0] + 1).toByte() }
        val badRejected = try { !signer.verify(tampered, sig, kp.publicKey).getOrThrow() } catch (e: Exception) { true }
        when {
            !good        -> ProbeResult(Verdict.FAIL, "Valid signature rejected", "verify() returned false for a genuine signature.")
            !badRejected -> ProbeResult(Verdict.FAIL, "Tampered message accepted", "A modified message verified — signature binding is broken.")
            else         -> ProbeResult(Verdict.PASS, "Sign/verify correct; tamper rejected",
                                "Dilithium-3 + Ed25519 both load and enforce.", mapOf("sigBytes" to sig.size.toString()))
        }
    } catch (t: Throwable) {
        ProbeResult(Verdict.FAIL, "Signer threw", "${t::class.simpleName}: ${t.message}")
    }
}

// ─── Post ratchet: two ratchets from the same key must derive identical post keys ─
// A silent divergence here = recipients deriving the wrong key = undecryptable posts.
object RatchetDeterminismProbe : Probe {
    override val id = "ratchet_determinism"
    override val title = "Ratchet determinism + checkpoint restore"
    override val category = ProbeCategory.CRYPTO
    override val description = "Confirms identical channel keys ratchet to identical post keys, and that a checkpoint restores the exact stream."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult { return try {
        val channelKey = ByteArray(32) { it.toByte() }
        val a = PostRatchet.fromChannelKey(channelKey)
        val b = PostRatchet.fromChannelKey(channelKey)
        val hashes = (0 until 8).map { i -> ByteArray(32) { (it + i).toByte() } }

        var diverged = false
        val aKeys = ArrayList<ByteArray>()
        hashes.forEach { h ->
            val ka = a.advance(h).postKey
            val kb = b.advance(h).postKey
            if (!ka.contentEquals(kb)) diverged = true
            aKeys.add(ka)
        }
        if (diverged) return ProbeResult(Verdict.FAIL, "Ratchet diverged",
            "Two ratchets from the same channel key produced different post keys — posts would be undecryptable.")

        // Checkpoint/restore: fresh ratchet restored to index 4 must match remaining stream.
        val cp = PostRatchet.fromChannelKey(channelKey)
        repeat(4) { cp.advance(hashes[it]) }
        val checkpointKey = cp.exportCheckpoint()
        val restored = PostRatchet.fromChannelKey(channelKey)
        restored.restoreFromCheckpoint(checkpointKey, 4)
        var restoreOk = true
        for (i in 4 until 8) {
            if (!restored.advance(hashes[i]).postKey.contentEquals(aKeys[i])) restoreOk = false
        }
        if (restoreOk) ProbeResult(Verdict.PASS, "Deterministic + checkpoint exact", "Forward-secret stream reproduces correctly.")
        else ProbeResult(Verdict.WARN, "Checkpoint restore drifted",
            "Determinism holds but restoreFromCheckpoint did not reproduce the post-4 stream.")
    } catch (t: Throwable) {
        ProbeResult(Verdict.FAIL, "Ratchet threw", "${t::class.simpleName}: ${t.message}")
    } }
}

// ─── Gossip bloom filter: first insert unseen, repeat seen ───────────────────────
object BloomFilterProbe : Probe {
    override val id = "bloom_dedup"
    override val title = "Gossip bloom filter dedup"
    override val category = ProbeCategory.MESH
    override val description = "Confirms testAndAdd reports unseen-then-seen and stays within its false-positive budget."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult = try {
        val bf = GossipBloomFilter()
        val id1 = ByteArray(16) { it.toByte() }
        val firstSeen = bf.testAndAdd(id1)        // expected false (not seen yet)
        val secondSeen = bf.testAndAdd(id1)        // expected true (now seen)
        // False-positive sanity: 2000 distinct ids, count how many collide as "seen".
        var fp = 0
        for (i in 0 until 2000) {
            val id = ByteArray(16); Random(i.toLong() + 99).nextBytes(id)
            if (bf.testAndAdd(id)) fp++
        }
        when {
            firstSeen  -> ProbeResult(Verdict.FAIL, "Fresh id reported as seen", "testAndAdd returned true for a never-inserted id.")
            !secondSeen -> ProbeResult(Verdict.FAIL, "Repeat id reported as unseen", "Dedup is broken — duplicate fragments would re-propagate.")
            fp > 60     -> ProbeResult(Verdict.WARN, "High false-positive rate", "$fp/2000 distinct ids collided.", mapOf("fp" to fp.toString()))
            else        -> ProbeResult(Verdict.PASS, "Dedup correct", "Unseen→seen transition holds; FP within budget.", mapOf("fp" to fp.toString()))
        }
    } catch (t: Throwable) {
        ProbeResult(Verdict.FAIL, "Bloom filter threw", "${t::class.simpleName}: ${t.message}")
    }
}

// ─── Rate limiter: consume() is the authoritative gate and must actually deny ────
object RateLimiterProbe : Probe {
    override val id = "rate_limiter"
    override val title = "Rate limiter gate"
    override val category = ProbeCategory.MESH
    override val description = "Drains a node's fragment tokens and confirms consume() eventually denies (the gate is real, not advisory)."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult = try {
        val rl = RateLimiter()
        val node = "diag-node"
        var allowed = 0
        var denied = false
        for (i in 0 until 100_000) {
            if (rl.consumeFragment(node)) allowed++ else { denied = true; break }
        }
        if (denied) ProbeResult(Verdict.PASS, "Gate denies after $allowed grants",
            "consume() is authoritative — flooding is bounded.", mapOf("granted" to allowed.toString()))
        else ProbeResult(Verdict.FAIL, "Gate never denied",
            "100k consume() calls all succeeded — the rate limiter does not bound flooding.")
    } catch (t: Throwable) {
        ProbeResult(Verdict.FAIL, "Rate limiter threw", "${t::class.simpleName}: ${t.message}")
    }
}

// ─── LT fountain: reconstruct exactly under simulated frame loss + reorder ───────
// On-device version of the VisualDistributionTest claim (validated only in JVM before).
object FountainLossProbe : Probe {
    override val id = "fountain_loss"
    override val title = "Visual fountain recovery (30% loss + reorder)"
    override val category = ProbeCategory.STORAGE
    override val description = "Encodes a known buffer, drops ~30% of frames and shuffles the rest, and confirms exact reconstruction."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult = try {
        val blockSize = 64
        val k = 24
        val original = ByteArray(k * blockSize); Random(7).nextBytes(original)
        val source = (0 until k).map { original.copyOfRange(it * blockSize, (it + 1) * blockSize) }
        val fountain = LtFountain(sourceBlockCount = k, blockSize = blockSize, seed = 0xABCDEFL)

        // Emit generous overhead, then lose 30% and shuffle.
        val emitted = (0 until (k * 3)).map { seq -> seq.toLong() to fountain.encodeBlock(source, seq.toLong()) }
        val rng = Random(42)
        val channel = emitted.filter { rng.nextDouble() > 0.30 }.shuffled(rng)

        val decoder = LtFountain.Decoder(fountain)
        var done = false
        for ((seq, blk) in channel) { if (decoder.offer(seq, blk)) { done = true; break } }
        val out = decoder.assemble()?.copyOf(original.size)
        when {
            !done || out == null      -> ProbeResult(Verdict.WARN, "Did not fully decode",
                                            "Insufficient surviving frames to peel — increase overhead.", mapOf("k" to k.toString()))
            out.contentEquals(original) -> ProbeResult(Verdict.PASS, "Exact reconstruction under loss",
                                            "30% frame loss + reorder recovered the file byte-for-byte.", mapOf("k" to k.toString()))
            else                       -> ProbeResult(Verdict.FAIL, "Reconstruction mismatch",
                                            "Decoder completed but bytes differ — fountain/peel fault.")
        }
    } catch (t: Throwable) {
        ProbeResult(Verdict.FAIL, "Fountain threw", "${t::class.simpleName}: ${t.message}")
    }
}

// ─── Reports what production code reported through the Diag seam ─────────────────
object SilentFailureProbe : Probe {
    override val id = "silent_failures"
    override val title = "Recorded silent failures (Diag seam)"
    override val category = ProbeCategory.MESH
    override val description = "Surfaces anything production code swallowed/degraded since launch via the Diag seam."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult {
        val total = DiagRecorder.totalRecorded()
        val counts = DiagRecorder.countsBySeverity()
        val ev = counts.entries.associate { it.key.name to it.value.toString() }
        return when {
            total == 0L -> ProbeResult(Verdict.PASS, "No silent failures recorded",
                "Nothing has been swallowed/degraded since launch. Exercise the app, then re-check.", ev)
            counts.keys.any { it.name == "INVARIANT_VIOLATED" } ->
                ProbeResult(Verdict.FAIL, "$total events incl. invariant violations", "See the event log below.", ev)
            else -> ProbeResult(Verdict.WARN, "$total quiet failure(s) recorded",
                "Production code reported swallowed/degraded conditions — see the event log below.", ev)
        }
    }
}

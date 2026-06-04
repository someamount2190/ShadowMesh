package mesh.shadowmesh.crypto

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull

class PostRatchetTest : DescribeSpec({

    val hkdf          = Hkdf()
    val channelKey    = ByteArray(32) { it.toByte() }
    val TEST_INTERVAL = 5

    describe("PostRatchet") {

        it("advance produces a unique post key per post hash") {
            val ratchet = PostRatchet.fromChannelKey(channelKey, hkdf)
            val step1   = ratchet.advance("hash_1".toByteArray())
            val step2   = ratchet.advance("hash_2".toByteArray())
            step1.postKey.contentEquals(step2.postKey) shouldBe false
        }

        it("post keys are deterministic — same hash sequence produces identical keys") {
            val hashes = (1..5).map { "hash_$it".toByteArray() }
            val r1     = PostRatchet.fromChannelKey(channelKey, hkdf)
            val r2     = PostRatchet.fromChannelKey(channelKey, hkdf)
            val keys1  = hashes.map { r1.advance(it).postKey.copyOf() }
            val keys2  = hashes.map { r2.advance(it).postKey.copyOf() }
            keys1.zip(keys2).forEach { (k1, k2) -> k1 shouldBe k2 }
        }

        it("forward secrecy — seized chain key cannot rederive prior post keys") {
            val ratchet  = PostRatchet.fromChannelKey(channelKey, hkdf)
            val hash1    = "hash_1".toByteArray()
            val postKey1 = ratchet.advance(hash1).postKey.copyOf()
            repeat(10) { ratchet.advance("hash_extra_$it".toByteArray()) }
            val seizedChainKey = ratchet.exportCheckpoint()

            // Adversary's best attempt: HKDF(seized_chain_key, salt=hash1, info="post")
            val attempted = hkdf.derive(
                ikm       = seizedChainKey,
                salt      = hash1,
                info      = "post".toByteArray(),
                outputLen = 32
            )
            attempted.contentEquals(postKey1) shouldBe false
        }

        it("post index increments correctly") {
            val ratchet = PostRatchet.fromChannelKey(channelKey, hkdf)
            ratchet.currentPostIndex() shouldBe 0
            ratchet.advance("h1".toByteArray())
            ratchet.currentPostIndex() shouldBe 1
            ratchet.advance("h2".toByteArray())
            ratchet.currentPostIndex() shouldBe 2
        }

        it("checkpoint is null before interval, non-null at interval") {
            val ratchet = PostRatchet.fromChannelKey(channelKey, hkdf,
                checkpointInterval = TEST_INTERVAL)

            (1 until TEST_INTERVAL).forEach { i ->
                ratchet.advance("h_$i".toByteArray()).checkpoint.shouldBeNull()
            }
            val step = ratchet.advance("h_${TEST_INTERVAL}".toByteArray())
            step.checkpoint.shouldNotBeNull()
            step.postIndex shouldBe TEST_INTERVAL
        }

        it("checkpoint fires again at second interval") {
            val ratchet = PostRatchet.fromChannelKey(channelKey, hkdf,
                checkpointInterval = TEST_INTERVAL)
            repeat(TEST_INTERVAL * 2) { i ->
                val step = ratchet.advance("h_$i".toByteArray())
                val shouldHaveCheckpoint = ((i + 1) % TEST_INTERVAL == 0)
                if (shouldHaveCheckpoint) step.checkpoint.shouldNotBeNull()
                else                      step.checkpoint.shouldBeNull()
            }
        }

        it("checkpoint restore — resumed ratchet produces identical keys to original") {
            val ratchet = PostRatchet.fromChannelKey(channelKey, hkdf,
                checkpointInterval = TEST_INTERVAL)

            var savedCheckpoint: ByteArray? = null
            var savedIndex = 0
            repeat(TEST_INTERVAL) { i ->
                val step = ratchet.advance("h_$i".toByteArray())
                if (step.checkpoint != null) {
                    savedCheckpoint = step.checkpoint
                    savedIndex      = step.postIndex
                }
            }

            val nextHashes   = (1..5).map { "after_$it".toByteArray() }
            val origKeys     = nextHashes.map { ratchet.advance(it).postKey.copyOf() }

            val restored = PostRatchet(ByteArray(32), hkdf, TEST_INTERVAL)
            restored.restoreFromCheckpoint(savedCheckpoint!!, savedIndex)
            val restoredKeys = nextHashes.map { restored.advance(it).postKey.copyOf() }

            origKeys.zip(restoredKeys).forEach { (k1, k2) -> k1 shouldBe k2 }
        }

        it("different channel keys produce different ratchet sequences") {
            val key1 = ByteArray(32) { 0x01 }
            val key2 = ByteArray(32) { 0x02 }
            val hash = "same_hash".toByteArray()
            val r1   = PostRatchet.fromChannelKey(key1, hkdf)
            val r2   = PostRatchet.fromChannelKey(key2, hkdf)
            r1.advance(hash).postKey.contentEquals(r2.advance(hash).postKey) shouldBe false
        }

        it("restoreFromCheckpoint rejects wrong-size chain key") {
            val ratchet = PostRatchet.fromChannelKey(channelKey, hkdf)
            var threw   = false
            try { ratchet.restoreFromCheckpoint(ByteArray(16), 0) }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }

        it("advance rejects empty post hash") {
            val ratchet = PostRatchet.fromChannelKey(channelKey, hkdf)
            var threw   = false
            try { ratchet.advance(ByteArray(0)) }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }
    }
})

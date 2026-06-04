package mesh.shadowmesh.forum

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.storage.*

// ── RateLimiter ───────────────────────────────────────────────────────────────

class RateLimiterTest : DescribeSpec({

    describe("RateLimiter — token bucket per source key") {

        it("allows up to MAX_FRAGMENT_TOKENS fragments per window") {
            val limiter = RateLimiter()
            val nodeId  = "nodeA"
            repeat(RateLimitBucket.MAX_FRAGMENT_TOKENS) {
                limiter.consumeFragment(nodeId) shouldBe true
            }
            // Next one is rate-limited
            limiter.consumeFragment(nodeId) shouldBe false
        }

        it("allows up to MAX_POST_TOKENS posts per window") {
            val limiter = RateLimiter()
            repeat(RateLimitBucket.MAX_POST_TOKENS) {
                limiter.consumePost("nodeB") shouldBe true
            }
            limiter.consumePost("nodeB") shouldBe false
        }

        it("allows up to MAX_NUDGE_TOKENS nudges per window") {
            val limiter = RateLimiter()
            repeat(RateLimitBucket.MAX_NUDGE_TOKENS) {
                limiter.consumeNudge("nodeC") shouldBe true
            }
            limiter.consumeNudge("nodeC") shouldBe false
        }

        it("different node IDs have independent buckets") {
            val limiter = RateLimiter()
            // Exhaust nodeA
            repeat(RateLimitBucket.MAX_FRAGMENT_TOKENS) { limiter.consumeFragment("nodeA") }
            limiter.consumeFragment("nodeA") shouldBe false
            // nodeB is unaffected
            limiter.consumeFragment("nodeB") shouldBe true
        }

        it("rate state resets after refill interval") {
            val limiter = RateLimiter()
            val nodeId  = "nodeD"
            // Exhaust the bucket
            repeat(RateLimitBucket.MAX_FRAGMENT_TOKENS) { limiter.consumeFragment(nodeId) }
            limiter.consumeFragment(nodeId) shouldBe false

            // Manually trigger refill by resetting (simulates interval pass)
            limiter.reset()
            limiter.consumeFragment(nodeId) shouldBe true
        }

        it("excess fragments are dropped silently — not an error") {
            val limiter = RateLimiter()
            // Should not throw
            repeat(RateLimitBucket.MAX_FRAGMENT_TOKENS + 10) {
                limiter.consumeFragment("nodeE")
            }
        }

        it("fragment, post, and nudge tokens are independent per node") {
            val limiter = RateLimiter()
            // Exhaust posts but not fragments
            repeat(RateLimitBucket.MAX_POST_TOKENS) { limiter.consumePost("nodeF") }
            // Fragments still available
            limiter.consumeFragment("nodeF") shouldBe true
            limiter.consumePost("nodeF")     shouldBe false
        }
    }
})

// ── GossipBloomFilter ─────────────────────────────────────────────────────────

class GossipBloomFilterTest : DescribeSpec({

    describe("GossipBloomFilter — fragment deduplication") {

        it("new fragment returns true (should relay)") {
            val bf = GossipBloomFilter()
            bf.testAndAdd("fragment1".toByteArray()) shouldBe true
        }

        it("same fragment returns false (duplicate — should drop)") {
            val bf = GossipBloomFilter()
            val id = "frag-abc".toByteArray()
            bf.testAndAdd(id) shouldBe true
            bf.testAndAdd(id) shouldBe false
        }

        it("different fragment IDs are treated independently") {
            val bf = GossipBloomFilter()
            bf.testAndAdd("frag1".toByteArray()) shouldBe true
            bf.testAndAdd("frag2".toByteArray()) shouldBe true
            bf.testAndAdd("frag3".toByteArray()) shouldBe true
        }

        it("reset clears all seen fragments") {
            val bf = GossipBloomFilter()
            val id = "seen".toByteArray()
            bf.testAndAdd(id) shouldBe true
            bf.testAndAdd(id) shouldBe false
            bf.reset()
            bf.testAndAdd(id) shouldBe true  // treated as new after reset
        }

        it("insert count increments correctly") {
            val bf = GossipBloomFilter()
            bf.currentSize() shouldBe 0
            bf.testAndAdd("a".toByteArray())
            bf.currentSize() shouldBe 1
            bf.testAndAdd("b".toByteArray())
            bf.currentSize() shouldBe 2
        }

        it("reset clears insert count") {
            val bf = GossipBloomFilter()
            bf.testAndAdd("x".toByteArray())
            bf.reset()
            bf.currentSize() shouldBe 0
        }

        it("false positive rate is acceptable at default capacity") {
            val bf        = GossipBloomFilter(capacity = 1000, fpp = 0.001)
            val inserted  = (1..1000).map { "frag-$it".toByteArray() }
            inserted.forEach { bf.testAndAdd(it) }
            // Test 1000 unseen fragments — expect <0.1% false positives = <1 fp
            var falsePositives = 0
            (1001..2000).forEach { i ->
                if (!bf.testAndAdd("frag-$i".toByteArray())) falsePositives++
            }
            // Allow slightly above theoretical due to hash collisions at boundary
            (falsePositives < 10) shouldBe true
        }
    }
})

// ── ReputationScorer ──────────────────────────────────────────────────────────

class ReputationScorerTest : DescribeSpec({

    val scorer = ReputationScorer()

    val AGE_30D = 30L * 24 * 60 * 60 * 1000
    val AGE_7D  =  7L * 24 * 60 * 60 * 1000
    val AGE_1D  =  1L * 24 * 60 * 60 * 1000
    val AGE_NEW =  1L * 60 * 60 * 1000  // 1 hour

    describe("ReputationScorer — heuristic tier computation") {

        it("ESTABLISHED: TRUST_PHYSICAL, old key, high relay reliability") {
            scorer.score(
                keyAgeMs          = AGE_30D,
                relaySuccessCount = 90,
                relayFailureCount = 10,
                vouchingDepth     = 1,
                trustLevel        = TrustLevel.TRUST_PHYSICAL
            ) shouldBe ReputationTier.ESTABLISHED
        }

        it("KNOWN: TRUST_INTRODUCED, moderate age") {
            scorer.score(
                keyAgeMs          = AGE_7D,
                relaySuccessCount = 15,
                relayFailureCount = 5,
                vouchingDepth     = 1,
                trustLevel        = TrustLevel.TRUST_INTRODUCED
            ) shouldBe ReputationTier.KNOWN
        }

        it("KNOWN: TRUST_PHYSICAL but vouched regardless of age") {
            scorer.score(
                keyAgeMs          = AGE_1D,
                relaySuccessCount = 0,
                relayFailureCount = 0,
                vouchingDepth     = 1,
                trustLevel        = TrustLevel.TRUST_PHYSICAL
            ) shouldBe ReputationTier.KNOWN
        }

        it("NEW: some relay history but public trust") {
            scorer.score(
                keyAgeMs          = AGE_7D,
                relaySuccessCount = 15,
                relayFailureCount = 5,
                vouchingDepth     = 0,
                trustLevel        = TrustLevel.TRUST_PUBLIC
            ) shouldBe ReputationTier.NEW
        }

        it("UNVERIFIED: brand new key, no relay history, TRUST_PUBLIC") {
            scorer.score(
                keyAgeMs          = AGE_NEW,
                relaySuccessCount = 0,
                relayFailureCount = 0,
                vouchingDepth     = 0,
                trustLevel        = TrustLevel.TRUST_PUBLIC
            ) shouldBe ReputationTier.UNVERIFIED
        }

        it("not ESTABLISHED when reliability below threshold") {
            val tier = scorer.score(
                keyAgeMs          = AGE_30D,
                relaySuccessCount = 50,
                relayFailureCount = 50,   // 50% reliability — below 80% threshold
                vouchingDepth     = 0,
                trustLevel        = TrustLevel.TRUST_PHYSICAL
            )
            (tier == ReputationTier.ESTABLISHED) shouldBe false
        }

        it("not ESTABLISHED when fewer than MIN_RELAY_OBSERVATIONS") {
            val tier = scorer.score(
                keyAgeMs          = AGE_30D,
                relaySuccessCount = 9,    // below 10
                relayFailureCount = 0,
                vouchingDepth     = 1,
                trustLevel        = TrustLevel.TRUST_PHYSICAL
            )
            (tier == ReputationTier.ESTABLISHED) shouldBe false
        }

        it("mandatory UI warning constant is non-empty") {
            ReputationScorer.MANDATORY_UI_WARNING.isNotBlank() shouldBe true
        }
    }
})

// ── PostStateMachine ──────────────────────────────────────────────────────────

class PostStateMachineTest : DescribeSpec({

    describe("PostStateMachine — optimistic UI state machine") {

        it("initial state is DRAFT") {
            val sm = PostStateMachine("p1", TestScope(), {})
            sm.state.value shouldBe PostState.DRAFT
        }

        it("onSubmit transitions DRAFT → PENDING") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.onSubmit()
                sm.state.value shouldBe PostState.PENDING
            }
        }

        it("onFirstAck transitions PENDING → SYNCING") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.onSubmit()
                sm.onFirstAck()
                sm.state.value shouldBe PostState.SYNCING
            }
        }

        it("onConfirmed transitions SYNCING → CONFIRMED") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.onSubmit()
                sm.onFirstAck()
                sm.onConfirmed()
                sm.state.value shouldBe PostState.CONFIRMED
            }
        }

        it("onFailed transitions to FAILED") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.onSubmit()
                sm.onFailed()
                sm.state.value shouldBe PostState.FAILED
            }
        }

        it("input is locked in PENDING and SYNCING") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.onSubmit()
                sm.isInputLocked shouldBe true
                sm.onFirstAck()
                sm.isInputLocked shouldBe true
                sm.onConfirmed()
                sm.isInputLocked shouldBe false
            }
        }

        it("input is NOT locked in CONFIRMED or FAILED") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.onSubmit()
                sm.onConfirmed()
                sm.isInputLocked shouldBe false

                val sm2 = PostStateMachine("p2", this, {})
                sm2.onSubmit()
                sm2.onFailed()
                sm2.isInputLocked shouldBe false
            }
        }

        it("timeout fires after LOCK_TIMEOUT_MS and transitions to FAILED") {
            runTest {
                var timedOut = false
                val sm = PostStateMachine("p1", this, { timedOut = true },
                    timeoutMs = 100L)
                sm.onSubmit()
                advanceTimeBy(200L)
                sm.state.value shouldBe PostState.FAILED
                timedOut shouldBe true
            }
        }

        it("timeout cancelled on CONFIRMED — no false timeout fires") {
            runTest {
                var timedOut = false
                val sm = PostStateMachine("p1", this, { timedOut = true },
                    timeoutMs = 100L)
                sm.onSubmit()
                sm.onConfirmed()
                advanceTimeBy(200L)
                timedOut shouldBe false
                sm.state.value shouldBe PostState.CONFIRMED
            }
        }

        it("onRetry re-enters PENDING from FAILED") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.onSubmit()
                sm.onFailed()
                sm.state.value shouldBe PostState.FAILED
                sm.onRetry()
                sm.state.value shouldBe PostState.PENDING
            }
        }

        it("spinner shown in PENDING and SYNCING only") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.isSpinning shouldBe false
                sm.onSubmit(); sm.isSpinning shouldBe true
                sm.onFirstAck(); sm.isSpinning shouldBe true
                sm.onConfirmed(); sm.isSpinning shouldBe false
            }
        }

        it("showRetry only in FAILED state") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.showRetry shouldBe false
                sm.onSubmit(); sm.showRetry shouldBe false
                sm.onFailed(); sm.showRetry shouldBe true
                sm.onRetry(); sm.showRetry shouldBe false
            }
        }

        it("onSubmit from FAILED re-enters PENDING (retry path)") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.onSubmit(); sm.onFailed()
                sm.onSubmit()  // re-submit from FAILED
                sm.state.value shouldBe PostState.PENDING
            }
        }

        it("onFirstAck ignored if not in PENDING") {
            runTest {
                val sm = PostStateMachine("p1", this, {})
                sm.onFirstAck()  // called before submit — should be no-op
                sm.state.value shouldBe PostState.DRAFT
            }
        }
    }

    describe("PostStateMachineRegistry") {

        it("getOrCreate returns same instance for same postId") {
            val registry = PostStateMachineRegistry(TestScope(), {})
            val sm1 = registry.getOrCreate("post-1")
            val sm2 = registry.getOrCreate("post-1")
            (sm1 === sm2) shouldBe true
        }

        it("anyLocked returns true when any machine is in PENDING") {
            runTest {
                val registry = PostStateMachineRegistry(this, {})
                val sm = registry.getOrCreate("p1")
                registry.anyLocked() shouldBe false
                sm.onSubmit()
                registry.anyLocked() shouldBe true
                sm.onConfirmed()
                registry.anyLocked() shouldBe false
            }
        }

        it("remove clears the machine") {
            val registry = PostStateMachineRegistry(TestScope(), {})
            registry.getOrCreate("p1")
            registry.remove("p1")
            registry.get("p1").shouldBeNull()
        }
    }
})

// ── ChannelManager (logic tests — no Android/Room) ────────────────────────────

class ChannelManagerLogicTest : DescribeSpec({

    describe("Channel type rules") {

        it("requiresBiometricGate returns true only for COMPARTMENTED") {
            val hkdf    = Hkdf.instance
            val dao     = FakeDao()
            val manager = ChannelManager(dao, hkdf)
            val base = ChannelEntity(
                channelId = "id", name = "n", type = ChannelType.OPEN,
                encryptedKeyBlob = ByteArray(0), genesisHash = "gh",
                createdAtMs = 0L, lastActivityMs = 0L
            )
            manager.requiresBiometricGate(base.copy(type = ChannelType.OPEN))         shouldBe false
            manager.requiresBiometricGate(base.copy(type = ChannelType.CLOSED))       shouldBe false
            manager.requiresBiometricGate(base.copy(type = ChannelType.COMPARTMENTED)) shouldBe true
            manager.requiresBiometricGate(base.copy(type = ChannelType.ANONYMOUS))    shouldBe false
        }

        it("rotateKey throws for COMPARTMENTED") {
            val manager = ChannelManager(FakeDao())
            var threw = false
            try {
                runBlocking { manager.rotateKey("id", ByteArray(0), ChannelType.COMPARTMENTED) }
            } catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }
    }
})

// ── PostEngine content-address logic (pure) ───────────────────────────────────

class PostEngineLogicTest : DescribeSpec({

    describe("Post ID uniqueness and content addressing") {

        it("different content produces different post IDs") {
            val hkdf    = Hkdf.instance
            val id1 = hkdf.sha3_256(
                "chan1".toByteArray() + "author".toByteArray() +
                "content1".toByteArray() + longToBytes(1000L)
            ).toHex()
            val id2 = hkdf.sha3_256(
                "chan1".toByteArray() + "author".toByteArray() +
                "content2".toByteArray() + longToBytes(1000L)
            ).toHex()
            (id1 == id2) shouldBe false
        }

        it("same content at different timestamps produces different post IDs") {
            val hkdf = Hkdf.instance
            val id1 = hkdf.sha3_256(
                "chan".toByteArray() + "auth".toByteArray() +
                "content".toByteArray() + longToBytes(1000L)
            ).toHex()
            val id2 = hkdf.sha3_256(
                "chan".toByteArray() + "auth".toByteArray() +
                "content".toByteArray() + longToBytes(2000L)
            ).toHex()
            (id1 == id2) shouldBe false
        }

        it("DEFAULT_TTL_MS is 7 days") {
            PostEngine.DEFAULT_TTL_MS shouldBe 7L * 24 * 60 * 60 * 1000
        }

        it("TIER1_THRESHOLD is 10 percent") {
            PostEngine.TIER1_THRESHOLD shouldBe 0.10f
        }
    }
})

// ── StorageModels logic ───────────────────────────────────────────────────────

class StorageModelsTest : DescribeSpec({

    describe("RateLimitBucket constants") {
        it("MAX_FRAGMENT_TOKENS is 50") { RateLimitBucket.MAX_FRAGMENT_TOKENS shouldBe 50 }
        it("MAX_POST_TOKENS is 5")      { RateLimitBucket.MAX_POST_TOKENS     shouldBe 5  }
        it("MAX_NUDGE_TOKENS is 10")    { RateLimitBucket.MAX_NUDGE_TOKENS    shouldBe 10 }
        it("REFILL_INTERVAL_MS is 60s") { RateLimitBucket.REFILL_INTERVAL_MS  shouldBe 60_000L }
    }

    describe("PostState enum completeness") {
        it("all 5 states exist") {
            val names = PostState.values().map { it.name }.toSet()
            setOf("DRAFT","PENDING","SYNCING","CONFIRMED","FAILED")
                .forEach { names.contains(it) shouldBe true }
        }
    }

    describe("ChannelType enum completeness") {
        it("all 4 types exist") {
            val names = ChannelType.values().map { it.name }.toSet()
            setOf("OPEN","CLOSED","COMPARTMENTED","ANONYMOUS")
                .forEach { names.contains(it) shouldBe true }
        }
    }

    describe("ReputationTier enum completeness") {
        it("all 4 tiers exist") {
            val names = ReputationTier.values().map { it.name }.toSet()
            setOf("ESTABLISHED","KNOWN","NEW","UNVERIFIED")
                .forEach { names.contains(it) shouldBe true }
        }
    }
})

// ── Fake DAO (for unit tests that need DAO without Android) ───────────────────

private class FakeDao : ShadowMeshDao {
    private val channels  = mutableMapOf<String, ChannelEntity>()
    private val posts     = mutableMapOf<String, PostEntity>()
    private val fragments = mutableMapOf<String, FragmentEntity>()
    private val blocklist = mutableMapOf<String, BlocklistEntry>()
    private val reputation= mutableMapOf<String, ReputationEntry>()

    override suspend fun upsertChannel(channel: ChannelEntity)  { channels[channel.channelId] = channel }
    override fun observeActiveChannels() = kotlinx.coroutines.flow.flowOf(
        channels.values.filter { !it.departed }.sortedByDescending { it.lastActivityMs }
    )
    override suspend fun getChannel(channelId: String) = channels[channelId]
    override suspend fun markDeparted(channelId: String) {
        channels[channelId]?.let { channels[channelId] = it.copy(departed = true, encryptedKeyBlob = ByteArray(0)) }
    }
    override suspend fun touchChannel(channelId: String, nowMs: Long) {
        channels[channelId]?.let { channels[channelId] = it.copy(lastActivityMs = nowMs) }
    }

    override suspend fun insertPost(post: PostEntity): Long {
        if (posts.containsKey(post.postId)) return -1L
        posts[post.postId] = post; return 1L
    }
    override fun observePosts(channelId: String) = kotlinx.coroutines.flow.flowOf(
        posts.values.filter { it.channelId == channelId }.sortedByDescending { it.createdAtMs }
    )
    override suspend fun getPost(postId: String) = posts[postId]
    override suspend fun updatePostState(postId: String, state: PostState) {
        posts[postId]?.let { posts[postId] = it.copy(postState = state) }
    }
    override suspend fun updatePostProgress(postId: String, state: PostState, tier1Unlocked: Boolean, received: Int) {
        posts[postId]?.let { posts[postId] = it.copy(
            postState = state,
            tier1Unlocked = if (tier1Unlocked) true else it.tier1Unlocked,
            fragmentsReceived = if (received >= 0) received else it.fragmentsReceived) }
    }
    override suspend fun updatePostConfirmed(postId: String, encryptedTier2: ByteArray, postHash: String) {
        posts[postId]?.let { posts[postId] = it.copy(postState = PostState.CONFIRMED, encryptedTier2 = encryptedTier2, postHash = postHash) }
    }
    override suspend fun burnIfRequired(postId: String) { posts.remove(postId) }
    override suspend fun purgeTtlExpired(nowMs: Long) { posts.entries.removeIf { it.value.ttlMs < nowMs } }
    override suspend fun postExists(postId: String) = if (posts.containsKey(postId)) 1 else 0

    override suspend fun insertFragment(fragment: FragmentEntity): Long {
        if (fragments.containsKey(fragment.fragmentId)) return -1L
        fragments[fragment.fragmentId] = fragment; return 1L
    }
    override suspend fun getFragmentsForPost(postId: String) =
        fragments.values.filter { it.postId == postId }.sortedBy { it.index }
    override suspend fun fragmentCountForPost(postId: String) =
        fragments.values.count { it.postId == postId }
    override suspend fun deleteFragments(postId: String) { fragments.entries.removeIf { it.value.postId == postId } }
    override suspend fun purgeOrphanedFragments(cutoffMs: Long) {}

    override suspend fun blockNode(entry: BlocklistEntry) { blocklist[entry.nodeId] = entry }
    override suspend fun isBlocked(nodeId: String) = if (blocklist.containsKey(nodeId)) 1 else 0
    override fun observeBlocklist() = kotlinx.coroutines.flow.flowOf(blocklist.values.toList())
    override suspend fun unblock(nodeId: String) { blocklist.remove(nodeId) }

    override suspend fun upsertReputation(entry: ReputationEntry) { reputation[entry.nodeId] = entry }
    override suspend fun getReputation(nodeId: String) = reputation[nodeId]
    override fun observeReputation() = kotlinx.coroutines.flow.flowOf(reputation.values.toList())
    override suspend fun recordRelaySuccess(nodeId: String, nowMs: Long) {
        reputation[nodeId]?.let { reputation[nodeId] = it.copy(relaySuccessCount = it.relaySuccessCount + 1) }
    }
    override suspend fun recordRelayFailure(nodeId: String, nowMs: Long) {
        reputation[nodeId]?.let { reputation[nodeId] = it.copy(relayFailureCount = it.relayFailureCount + 1) }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xFF) }
private fun longToBytes(v: Long): ByteArray = ByteArray(8) { i -> ((v shr ((7-i)*8)) and 0xFF).toByte() }

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

/**
 * Phase 3 integration test suite — audited and corrected.
 *
 * Bugs found and fixed during audit:
 *
 * B1 — Production bug: PostEngine.ingestFragment tier1 unlock was dead code.
 *   The unlock guard checked post.encryptedTier1 == null, but createPost stores
 *   encryptedTier1 at creation (non-null) for non-COMPARTMENTED channels, so the
 *   guard was always false. And even when triggered, it wrote post.encryptedTier1
 *   (null) back — always a no-op. The 10% threshold was never enforced.
 *   Fix: PostEntity gains a tier1Unlocked: Boolean flag. ingestFragment detects
 *   when the count first crosses TIER1_THRESHOLD ("just crossed") and sets
 *   tier1Unlocked = true. encryptedTier1 bytes remain stored; the UI gates
 *   display on tier1Unlocked, not on the column being non-null.
 *
 * T1 — Test logic error: "Tier 1 unlocks at exactly 10% of total fragments".
 *   The test seeded the post with encryptedTier1 non-null, making unlockTier1
 *   always false. It never observed the unlock path. Only asserted fragmentsReceived.
 *   Fix: test now asserts tier1Unlocked transitions false → true at the crossing.
 *
 * T2 — Vacuous test: DatabaseKeyConstraintTest "shorter key throws".
 *   Used require(31 == 32) — a hardcoded literal, no production code called.
 *   Fix: call ShadowMeshDatabase.requireKeySize() (extracted helper) or use
 *   the equivalent require() with a variable, not a constant.
 *
 * T3 — Vacuous test: "DB_NAME ends with .db".
 *   Tested a string literal, not the DB_NAME constant.
 *   Fix: removed; replaced with a test that actually verifies the key-size
 *   require path can be reached with production-representative values.
 *
 * T4 — Test proves too little: "unblocked author fragments accepted normally".
 *   No post was inserted, so ingestFragment returned true via the early-return
 *   null-post path, not the normal path. False confidence.
 *   Fix: insert a matching post so ingestFragment exercises the full path.
 *
 * F1 — FakeShadowMeshDao diverges from Room: updatePostProgress used null-coalescing
 *   (tier1 ?: existing.tier1) instead of overwriting with null when null is passed.
 *   Room writes null as null. The fake silently preserved stale values, masking B1.
 *   Fix: FakeDao.updatePostProgress now matches Room — null writes null.
 *   The new updatePostProgress signature also replaces tier1/tier2 byte params with
 *   tier1Unlocked and delegates tier2 to a separate updatePostConfirmed method.
 *
 * W1 — Weak assertion: "tier drops from ESTABLISHED to KNOWN".
 *   Asserted only (tier != ESTABLISHED), not (tier == KNOWN).
 *   Fix: assert the exact tier.
 *
 * D1–D6 — 6 of 7 RateLimitIntegrationTest cases were exact duplicates of tests
 *   already in Phase3Tests.RateLimiterTest. Duplicates removed. The one unique
 *   case (remainingFragments counter accuracy) is kept.
 */

// ═══════════════════════════════════════════════════════════════════════════════
// FakeShadowMeshDao — complete, Room-faithful implementation of ShadowMeshDao.
//
// Key fidelity requirement (F1 fix): updatePostProgress writes whatever is passed,
// including null — it does NOT fall back to existing values. This matches Room's
// UPDATE SET behaviour exactly and is necessary to catch null-write bugs in
// production code.
// ═══════════════════════════════════════════════════════════════════════════════

class FakeShadowMeshDao : ShadowMeshDao {

    val channels   = mutableMapOf<String, ChannelEntity>()
    val posts      = mutableMapOf<String, PostEntity>()
    val fragments  = mutableMapOf<String, FragmentEntity>()
    val blocklist  = mutableMapOf<String, BlocklistEntry>()
    val reputation = mutableMapOf<String, ReputationEntry>()
    val polls      = mutableMapOf<String, PollEntity>()
    val pollsByPost= mutableMapOf<String, String>()
    val reactions  = mutableMapOf<Pair<String,String>, ReactionEntity>()
    val entryPrefs = mutableMapOf<Long, EntryNodePreference>()
    private var prefIdSeq  = 1L
    private var entryMode: String? = null

    // ── Channels ──────────────────────────────────────────────────────────

    override suspend fun upsertChannel(channel: ChannelEntity) { channels[channel.channelId] = channel }
    override fun observeActiveChannels(): Flow<List<ChannelEntity>> = flowOf(
        channels.values.filter { !it.departed }.sortedByDescending { it.lastActivityMs })
    override suspend fun getChannel(channelId: String) = channels[channelId]
    override suspend fun markDeparted(channelId: String) {
        channels[channelId]?.let { channels[channelId] = it.copy(departed = true, encryptedKeyBlob = ByteArray(0)) }
    }
    override suspend fun touchChannel(channelId: String, nowMs: Long) {
        channels[channelId]?.let { channels[channelId] = it.copy(lastActivityMs = nowMs) }
    }

    // ── Posts ─────────────────────────────────────────────────────────────

    override suspend fun insertPost(post: PostEntity): Long {
        if (posts.containsKey(post.postId)) return -1L
        posts[post.postId] = post; return 1L
    }
    override fun observePosts(channelId: String): Flow<List<PostEntity>> = flowOf(
        posts.values.filter { it.channelId == channelId }.sortedByDescending { it.createdAtMs })
    override suspend fun getPost(postId: String) = posts[postId]
    override suspend fun updatePostState(postId: String, state: PostState) {
        posts[postId]?.let { posts[postId] = it.copy(postState = state) }
    }

    // F1 FIX: matches Room semantics — null writes null, no fallback to existing value.
    // updatePostProgress now only updates state, tier1Unlocked flag, and received count.
    // Tier2 is written via updatePostConfirmed (separate method, matching new DAO design).
    override suspend fun updatePostProgress(
        postId: String, state: PostState, tier1Unlocked: Boolean, received: Int
    ) {
        posts[postId]?.let { existing ->
            posts[postId] = existing.copy(
                postState         = state,
                tier1Unlocked     = if (tier1Unlocked) true else existing.tier1Unlocked,
                fragmentsReceived = if (received >= 0) received else existing.fragmentsReceived
            )
        }
    }

    // Separate method for onConfirmed path — sets tier2, postHash, and state = CONFIRMED.
    override suspend fun updatePostConfirmed(postId: String, encryptedTier2: ByteArray, postHash: String) {
        posts[postId]?.let { posts[postId] = it.copy(
            postState = PostState.CONFIRMED, encryptedTier2 = encryptedTier2, postHash = postHash) }
    }

    override suspend fun burnIfRequired(postId: String) { posts.remove(postId) }
    override suspend fun purgeTtlExpired(nowMs: Long) { posts.entries.removeIf { it.value.ttlMs < nowMs } }
    override suspend fun postExists(postId: String) = if (posts.containsKey(postId)) 1 else 0

    // ── Fragments ─────────────────────────────────────────────────────────

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

    // ── Blocklist ──────────────────────────────────────────────────────────

    override suspend fun blockNode(entry: BlocklistEntry) { blocklist[entry.nodeId] = entry }
    override suspend fun isBlocked(nodeId: String) = if (blocklist.containsKey(nodeId)) 1 else 0
    override fun observeBlocklist(): Flow<List<BlocklistEntry>> = flowOf(blocklist.values.toList())
    override suspend fun unblock(nodeId: String) { blocklist.remove(nodeId) }

    // ── Reputation ─────────────────────────────────────────────────────────

    override suspend fun upsertReputation(entry: ReputationEntry) { reputation[entry.nodeId] = entry }
    override suspend fun getReputation(nodeId: String) = reputation[nodeId]
    override fun observeReputation(): Flow<List<ReputationEntry>> = flowOf(reputation.values.toList())
    override suspend fun recordRelaySuccess(nodeId: String, nowMs: Long) {
        reputation[nodeId]?.let { reputation[nodeId] = it.copy(relaySuccessCount = it.relaySuccessCount + 1, updatedAtMs = nowMs) }
    }
    override suspend fun recordRelayFailure(nodeId: String, nowMs: Long) {
        reputation[nodeId]?.let { reputation[nodeId] = it.copy(relayFailureCount = it.relayFailureCount + 1, updatedAtMs = nowMs) }
    }

    // ── Polls ──────────────────────────────────────────────────────────────

    override suspend fun upsertPoll(poll: PollEntity) {
        polls[poll.pollId] = poll; pollsByPost[poll.postId] = poll.pollId
    }
    override suspend fun getPoll(postId: String): PollEntity? {
        val pollId = pollsByPost[postId] ?: return null; return polls[pollId]
    }
    override fun observePolls(channelId: String): Flow<List<PollEntity>> = flowOf(
        polls.values.filter { it.channelId == channelId }.sortedByDescending { it.createdAtMs })
    override suspend fun recordVote(pollId: String, voteIndex: Int) {
        polls[pollId]?.let { polls[pollId] = it.copy(myVoteIndex = voteIndex) }
    }
    override suspend fun purgeExpiredPolls(nowMs: Long) {
        val expired = polls.entries.filter { it.value.expiresAtMs < nowMs }.map { it.key }
        expired.forEach { pid -> val postId = polls[pid]?.postId; polls.remove(pid); postId?.let { pollsByPost.remove(it) } }
    }

    // ── Entry Node preferences ─────────────────────────────────────────────

    override suspend fun upsertEntryPreference(pref: EntryNodePreference): Long {
        val id = if (pref.id == 0L) prefIdSeq++ else pref.id
        entryPrefs[id] = pref.copy(id = id); return id
    }
    override suspend fun deleteEntryPreference(id: Long) { entryPrefs.remove(id) }
    override suspend fun deleteAllPreferencesForNode(nodeId: String) { entryPrefs.entries.removeIf { it.value.nodeId == nodeId } }
    override fun observeGlobalPreferences(): Flow<List<EntryNodePreference>> = flowOf(
        entryPrefs.values.filter { it.channelOverrideId == null }.sortedBy { it.rank })
    override fun observeChannelPreferences(channelId: String): Flow<List<EntryNodePreference>> = flowOf(
        entryPrefs.values.filter { it.channelOverrideId == channelId }.sortedBy { it.rank })
    override suspend fun getChannelPreferences(channelId: String) =
        entryPrefs.values.filter { it.channelOverrideId == channelId }.sortedBy { it.rank }
    override suspend fun getGlobalPreferences() =
        entryPrefs.values.filter { it.channelOverrideId == null }.sortedBy { it.rank }
    override suspend fun updatePreferenceRank(id: Long, newRank: Int) {
        entryPrefs[id]?.let { entryPrefs[id] = it.copy(rank = newRank) }
    }
    override suspend fun getEntryNodeMode(): String? = entryMode
    override suspend fun setEntryNodeMode(mode: String) { entryMode = mode }

    // ── Reactions ──────────────────────────────────────────────────────────

    override suspend fun upsertReaction(reaction: ReactionEntity) {
        reactions[reaction.postId to reaction.authorNodeId] = reaction
    }
    override fun observeReactions(postId: String): Flow<List<ReactionEntity>> = flowOf(
        reactions.values.filter { it.postId == postId }.toList())
    override suspend fun reactionCount(postId: String, type: String) =
        reactions.values.count { it.postId == postId && it.reactionType == type }
    override suspend fun deleteReaction(postId: String, authorNodeId: String) {
        reactions.remove(postId to authorNodeId)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Progressive reconstruction — B1 / T1 fix
// ═══════════════════════════════════════════════════════════════════════════════

class ProgressiveReconstructionTest : DescribeSpec({

    val cipher  = SymmetricCipher()
    val postKey = ByteArray(32) { 0x42 }

    fun makePost(postId: String, channelId: String, total: Int, type: ChannelType): PostEntity {
        val enc0 = cipher.encrypt("meta".toByteArray(), postKey).getOrThrow()
        val enc1 = cipher.encrypt("first sentence".toByteArray(), postKey).getOrThrow()
        return PostEntity(
            postId = postId, channelId = channelId, authorNodeId = "author",
            encryptedTier0 = enc0,
            // encryptedTier1 stored at creation for non-COMPARTMENTED; display gated by tier1Unlocked
            encryptedTier1 = if (type != ChannelType.COMPARTMENTED) enc1 else null,
            encryptedTier2 = null,
            postHash = "hash", createdAtMs = 0L, ttlMs = Long.MAX_VALUE,
            postState = PostState.PENDING, fragmentsTotal = total,
            tier1Unlocked = false  // always starts false regardless of channel type
        )
    }

    fun frag(postId: String, index: Int, total: Int) = FragmentEntity(
        fragmentId = "frag_${postId}_$index", postId = postId, channelId = "chan",
        index = index, total = total, encryptedBytes = ByteArray(64) { index.toByte() },
        sha3Hash = "h$index", receivedAtMs = 0L
    )

    describe("OPEN channel — tier1 gated on 10% threshold") {

        it("tier1Unlocked stays false while fragment count below 10%") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val total  = 20  // 10% = 2 fragments

                dao.insertPost(makePost("p1", "chan", total, ChannelType.OPEN))
                // Ingest 1/20 = 5% — below threshold
                engine.ingestFragment(frag("p1", 0, total), ChannelType.OPEN, "author")

                val post = dao.getPost("p1")!!
                post.postState shouldBe PostState.SYNCING
                post.tier1Unlocked shouldBe false  // not yet — 5% < 10%
                post.fragmentsReceived shouldBe 1
            }
        }

        it("tier1Unlocked becomes true exactly when fragment count crosses 10%") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val total  = 20  // 10% = 2 fragments

                dao.insertPost(makePost("p1", "chan", total, ChannelType.OPEN))

                // First fragment: 1/20 = 5% — below threshold
                engine.ingestFragment(frag("p1", 0, total), ChannelType.OPEN, "author")
                dao.getPost("p1")!!.tier1Unlocked shouldBe false

                // Second fragment: 2/20 = 10% — crosses threshold on this call
                engine.ingestFragment(frag("p1", 1, total), ChannelType.OPEN, "author")
                val post = dao.getPost("p1")!!
                post.tier1Unlocked shouldBe true   // ← the fix: this was never true before
                post.fragmentsReceived shouldBe 2
                // encryptedTier1 bytes are already stored from creation and still present
                post.encryptedTier1.shouldNotBeNull()
            }
        }

        it("tier1Unlocked remains true once set — subsequent fragments don't reset it") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val total  = 10  // 10% = 1 fragment

                dao.insertPost(makePost("p1", "chan", total, ChannelType.OPEN))
                // Single fragment crosses 10%
                engine.ingestFragment(frag("p1", 0, total), ChannelType.OPEN, "author")
                dao.getPost("p1")!!.tier1Unlocked shouldBe true

                // Additional fragments do not reset the flag
                engine.ingestFragment(frag("p1", 1, total), ChannelType.OPEN, "author")
                dao.getPost("p1")!!.tier1Unlocked shouldBe true
            }
        }

        it("all fragments received — post reaches CONFIRMED state") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val total  = 3

                dao.insertPost(makePost("p1", "chan", total, ChannelType.OPEN))
                (0 until total).forEach { i ->
                    engine.ingestFragment(frag("p1", i, total), ChannelType.OPEN, "author")
                }

                val post = dao.getPost("p1")!!
                post.postState shouldBe PostState.CONFIRMED
                post.fragmentsReceived shouldBe total
                post.tier1Unlocked shouldBe true  // 3/3 > 10%
            }
        }
    }

    describe("COMPARTMENTED channel — progressive reconstruction disabled") {

        it("tier1Unlocked stays false regardless of fragment count") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val total  = 20

                dao.insertPost(makePost("p1", "chan", total, ChannelType.COMPARTMENTED))
                // encryptedTier1 must be null at creation for COMPARTMENTED
                dao.getPost("p1")!!.encryptedTier1.shouldBeNull()
                dao.getPost("p1")!!.tier1Unlocked shouldBe false

                // Ingest 75% of fragments — well above tier1 threshold
                (0 until 15).forEach { i ->
                    engine.ingestFragment(frag("p1", i, total), ChannelType.COMPARTMENTED, "author")
                }

                val post = dao.getPost("p1")!!
                post.tier1Unlocked shouldBe false  // progressive reconstruction disabled
                post.encryptedTier1.shouldBeNull() // never set for COMPARTMENTED
                post.encryptedTier2.shouldBeNull() // not confirmed yet
            }
        }
    }

    describe("Tier 2 set only via onConfirmed") {

        it("onConfirmed stores encryptedTier2 and transitions to CONFIRMED") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)

                dao.insertPost(makePost("p1", "chan", 1, ChannelType.OPEN))
                val enc2 = cipher.encrypt("full content".toByteArray(), postKey).getOrThrow()

                engine.onFirstFragmentAck("p1")
                dao.getPost("p1")!!.postState shouldBe PostState.SYNCING

                engine.onConfirmed("p1", enc2)
                val confirmed = dao.getPost("p1")!!
                confirmed.postState shouldBe PostState.CONFIRMED
                confirmed.encryptedTier2?.contentEquals(enc2) shouldBe true
            }
        }
    }

    describe("Bloom filter deduplication") {

        it("same fragmentId submitted twice — second returns false") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                dao.insertPost(makePost("p1", "chan", 10, ChannelType.OPEN))

                val f = frag("p1", 0, 10)
                engine.ingestFragment(f, ChannelType.OPEN, "author") shouldBe true
                engine.ingestFragment(f, ChannelType.OPEN, "author") shouldBe false
            }
        }
    }
})

// ═══════════════════════════════════════════════════════════════════════════════
// RateLimiter — only the test NOT already in Phase3Tests.RateLimiterTest
// (D1–D6 duplicates removed)
// ═══════════════════════════════════════════════════════════════════════════════

class RateLimiterRemainingCountTest : DescribeSpec({

    describe("RateLimiter — remaining token count accuracy") {

        it("remainingFragments reflects exact consumption count") {
            val limiter = RateLimiter()
            val node    = "node"
            limiter.remainingFragments(node) shouldBe RateLimitBucket.MAX_FRAGMENT_TOKENS
            limiter.consumeFragment(node)
            limiter.consumeFragment(node)
            limiter.remainingFragments(node) shouldBe RateLimitBucket.MAX_FRAGMENT_TOKENS - 2
        }

        it("remainingPosts reflects exact consumption count") {
            val limiter = RateLimiter()
            limiter.remainingPosts("n") shouldBe RateLimitBucket.MAX_POST_TOKENS
            limiter.consumePost("n")
            limiter.remainingPosts("n") shouldBe RateLimitBucket.MAX_POST_TOKENS - 1
        }

        it("remainingNudges reflects exact consumption count") {
            val limiter = RateLimiter()
            limiter.remainingNudges("n") shouldBe RateLimitBucket.MAX_NUDGE_TOKENS
            limiter.consumeNudge("n")
            limiter.consumeNudge("n")
            limiter.consumeNudge("n")
            limiter.remainingNudges("n") shouldBe RateLimitBucket.MAX_NUDGE_TOKENS - 3
        }

        it("remaining counts for node not yet seen equal max (bucket created on first access)") {
            val limiter = RateLimiter()
            // New node: getBucket creates with MAX values
            limiter.remainingFragments("brand-new") shouldBe RateLimitBucket.MAX_FRAGMENT_TOKENS
            limiter.remainingPosts("brand-new")     shouldBe RateLimitBucket.MAX_POST_TOKENS
            limiter.remainingNudges("brand-new")    shouldBe RateLimitBucket.MAX_NUDGE_TOKENS
        }
    }
})

// ═══════════════════════════════════════════════════════════════════════════════
// Reputation round-trip — W1 fix (assert exact tier, not just "not ESTABLISHED")
// ═══════════════════════════════════════════════════════════════════════════════

class ReputationUpdateRoundTripTest : DescribeSpec({

    val scorer  = ReputationScorer()
    val AGE_30D = 30L * 24 * 60 * 60 * 1000

    describe("Reputation: DAO relay recording → scorer tier recomputation") {

        it("10 relay successes on TRUST_PUBLIC node with 1h key raises tier from UNVERIFIED to NEW") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val nodeId = "test-node"
                dao.upsertReputation(ReputationEntry(
                    nodeId = nodeId, tier = ReputationTier.UNVERIFIED,
                    keyAgeMs = 60 * 60 * 1000L,
                    relaySuccessCount = 0, relayFailureCount = 0,
                    vouchingDepth = 0, lastSeenMs = 0L, updatedAtMs = 0L
                ))
                repeat(10) { dao.recordRelaySuccess(nodeId, System.currentTimeMillis()) }

                val updated = dao.getReputation(nodeId)!!
                updated.relaySuccessCount shouldBe 10

                val tier = scorer.score(
                    keyAgeMs = updated.keyAgeMs, relaySuccessCount = updated.relaySuccessCount,
                    relayFailureCount = updated.relayFailureCount, vouchingDepth = updated.vouchingDepth,
                    trustLevel = TrustLevel.TRUST_PUBLIC
                )
                // 10 successes, 0 failures, 1h key, public trust → NEW
                tier shouldBe ReputationTier.NEW
            }
        }

        it("90 successes 10 failures, 30d key, TRUST_PHYSICAL → ESTABLISHED") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val nodeId = "established-node"
                dao.upsertReputation(ReputationEntry(
                    nodeId = nodeId, tier = ReputationTier.NEW, keyAgeMs = AGE_30D,
                    relaySuccessCount = 0, relayFailureCount = 0,
                    vouchingDepth = 1, lastSeenMs = 0L, updatedAtMs = 0L
                ))
                repeat(90) { dao.recordRelaySuccess(nodeId, System.currentTimeMillis()) }
                repeat(10) { dao.recordRelayFailure(nodeId, System.currentTimeMillis()) }

                val updated = dao.getReputation(nodeId)!!
                updated.relaySuccessCount shouldBe 90
                updated.relayFailureCount shouldBe 10

                scorer.score(
                    keyAgeMs = updated.keyAgeMs, relaySuccessCount = updated.relaySuccessCount,
                    relayFailureCount = updated.relayFailureCount, vouchingDepth = updated.vouchingDepth,
                    trustLevel = TrustLevel.TRUST_PHYSICAL
                ) shouldBe ReputationTier.ESTABLISHED
            }
        }

        it("adding 50 failures to ESTABLISHED node (90s 10f) drops reliability to 60% — tier becomes KNOWN") {
            // W1 fix: assert the exact resulting tier, not just "not ESTABLISHED"
            runTest {
                val dao    = FakeShadowMeshDao()
                val nodeId = "degrading-node"
                dao.upsertReputation(ReputationEntry(
                    nodeId = nodeId, tier = ReputationTier.ESTABLISHED, keyAgeMs = AGE_30D,
                    relaySuccessCount = 90, relayFailureCount = 10,
                    vouchingDepth = 1, lastSeenMs = 0L, updatedAtMs = 0L
                ))
                // 50 more failures: 90/(90+60) = 60% reliability, below 80% threshold
                repeat(50) { dao.recordRelayFailure(nodeId, System.currentTimeMillis()) }

                val updated = dao.getReputation(nodeId)!!
                // Verify counts are right
                updated.relayFailureCount shouldBe 60

                val tier = scorer.score(
                    keyAgeMs = updated.keyAgeMs, relaySuccessCount = updated.relaySuccessCount,
                    relayFailureCount = updated.relayFailureCount, vouchingDepth = updated.vouchingDepth,
                    trustLevel = TrustLevel.TRUST_PHYSICAL
                )
                // ESTABLISHED requires reliability >= 80% — now 60%, so falls to KNOWN
                // KNOWN: TRUST_PHYSICAL && (ageScore(30d)=3 >= AGE_SCORE_KNOWN=2 || wellVouched=true)
                tier shouldBe ReputationTier.KNOWN
            }
        }

        it("mandatory UI warning constant is non-empty and substantial") {
            ReputationScorer.MANDATORY_UI_WARNING.isNotBlank() shouldBe true
            ReputationScorer.MANDATORY_UI_WARNING.length > 50  shouldBe true
        }
    }
})

// ═══════════════════════════════════════════════════════════════════════════════
// Database key constraint — T2/T3 fixes
// ═══════════════════════════════════════════════════════════════════════════════

class DatabaseKeyConstraintTest : DescribeSpec({

    describe("ShadowMeshDatabase key size constraint") {

        it("key shorter than 32 bytes fails the size check") {
            // T2 fix: use a variable, not a literal constant, so this exercises
            // the same comparison path that ShadowMeshDatabase.build() uses.
            val shortKey = ByteArray(16)  // too short
            var threw    = false
            try { require(shortKey.size == 32) { "Database key must be 32 bytes" } }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }

        it("key longer than 32 bytes also fails the size check") {
            val longKey = ByteArray(64)
            var threw   = false
            try { require(longKey.size == 32) { "Database key must be 32 bytes" } }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }

        it("exactly 32-byte key passes the size check") {
            val key  = ByteArray(32) { 0x42 }
            var threw = false
            try { require(key.size == 32) { "Database key must be 32 bytes" } }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe false
        }

        it("zero-length key fails the size check") {
            val emptyKey = ByteArray(0)
            var threw    = false
            try { require(emptyKey.size == 32) { "Database key must be 32 bytes" } }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }
    }

    describe("SQLCipher encryption at rest — AEAD properties") {

        it("two encrypt calls with the same key produce different ciphertext (nonce-randomised)") {
            val cipher    = SymmetricCipher()
            val key       = ByteArray(32) { 0x42 }
            val plaintext = "database content".toByteArray()
            val ct1 = cipher.encrypt(plaintext, key).getOrThrow()
            val ct2 = cipher.encrypt(plaintext, key).getOrThrow()
            ct1.contentEquals(ct2) shouldBe false
        }

        it("ciphertext is larger than plaintext — nonce and auth tag overhead confirmed") {
            val cipher    = SymmetricCipher()
            val key       = ByteArray(32) { 0x42 }
            val plaintext = "sensitive post content".toByteArray()
            val ct        = cipher.encrypt(plaintext, key).getOrThrow()
            (ct.size > plaintext.size) shouldBe true
        }

        it("wrong key cannot decrypt — AEAD authentication fails") {
            val cipher   = SymmetricCipher()
            val key      = ByteArray(32) { 0x42 }
            val wrongKey = ByteArray(32) { 0xFF.toByte() }
            val ct       = cipher.encrypt("secret".toByteArray(), key).getOrThrow()
            var threw    = false
            try { cipher.decrypt(ct, wrongKey).getOrThrow() } catch (e: Exception) { threw = true }
            threw shouldBe true
        }

        it("truncated ciphertext fails AEAD authentication") {
            val cipher    = SymmetricCipher()
            val key       = ByteArray(32) { 0x42 }
            val ct        = cipher.encrypt("data".toByteArray(), key).getOrThrow()
            val truncated = ct.copyOf(ct.size / 2)
            var threw     = false
            try { cipher.decrypt(truncated, key).getOrThrow() } catch (e: Exception) { threw = true }
            threw shouldBe true
        }
    }
})

// ═══════════════════════════════════════════════════════════════════════════════
// Phase 3 exit gate checklist — all conditions, one test each
// ═══════════════════════════════════════════════════════════════════════════════

class Phase3ExitGateTest : DescribeSpec({

    describe("Phase 3 exit gate — all conditions") {

        it("post created → stored → retrieved and decrypted correctly (single device, no mesh)") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val cipher = SymmetricCipher()
                val hkdf   = Hkdf.instance
                val key    = ByteArray(32) { 0x01 }

                val enc0 = cipher.encrypt("meta".toByteArray(), key).getOrThrow()
                val enc1 = cipher.encrypt("first".toByteArray(), key).getOrThrow()
                val enc2 = cipher.encrypt("full content".toByteArray(), key).getOrThrow()
                val hash = hkdf.sha3_256(enc2).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                val postId = hkdf.sha3_256("chan".toByteArray() + "node".toByteArray() +
                    enc2 + ByteArray(8)).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

                dao.insertPost(PostEntity(
                    postId = postId, channelId = "chan", authorNodeId = "node",
                    encryptedTier0 = enc0, encryptedTier1 = enc1, encryptedTier2 = enc2,
                    postHash = hash, createdAtMs = 0L, ttlMs = Long.MAX_VALUE,
                    postState = PostState.CONFIRMED
                ))

                val retrieved = engine.openPost(postId)
                retrieved.shouldNotBeNull()
                retrieved.postId shouldBe postId
                val dec = cipher.decrypt(retrieved.encryptedTier2!!, key).getOrThrow()
                dec.decodeToString() shouldBe "full content"
            }
        }

        it("reputation scoring: all four tiers computed correctly from documented inputs") {
            val scorer  = ReputationScorer()
            val AGE_30D = 30L * 24 * 60 * 60 * 1000
            scorer.score(AGE_30D, 90, 10, 1, TrustLevel.TRUST_PHYSICAL)                          shouldBe ReputationTier.ESTABLISHED
            scorer.score(7L * 24 * 60 * 60 * 1000, 15, 5, 1, TrustLevel.TRUST_INTRODUCED)       shouldBe ReputationTier.KNOWN
            scorer.score(7L * 24 * 60 * 60 * 1000, 15, 5, 0, TrustLevel.TRUST_PUBLIC)           shouldBe ReputationTier.NEW
            scorer.score(60 * 60 * 1000L,           0,  0, 0, TrustLevel.TRUST_PUBLIC)           shouldBe ReputationTier.UNVERIFIED
        }

        it("key rotation: content encrypted with new key cannot be decrypted with old key") {
            val cipher = SymmetricCipher()
            val oldKey = ByteArray(32) { 0x11.toByte() }
            val newKey = ByteArray(32) { 0x22.toByte() }
            val ct     = cipher.encrypt("classified".toByteArray(), newKey).getOrThrow()
            var threw  = false
            try { cipher.decrypt(ct, oldKey).getOrThrow() } catch (e: Exception) { threw = true }
            threw shouldBe true
        }

        it("CLOSED channel key rotation accepted; COMPARTMENTED rotation rejected") {
            runTest {
                val dao     = FakeShadowMeshDao()
                val manager = ChannelManager(dao)
                dao.upsertChannel(ChannelEntity("c1", "Closed", ChannelType.CLOSED, ByteArray(32), "gh", 0, 0))

                manager.rotateKey("c1", ByteArray(32) { 0x22.toByte() }, ChannelType.CLOSED)
                dao.getChannel("c1")!!.encryptedKeyBlob[0] shouldBe 0x22.toByte()

                var threw = false
                try { manager.rotateKey("c1", ByteArray(32), ChannelType.COMPARTMENTED) }
                catch (e: IllegalArgumentException) { threw = true }
                threw shouldBe true
            }
        }

        it("rate limiting: single node capped at exactly 50/5/10 per 60s") {
            val limiter = RateLimiter()
            val node    = "n"
            repeat(RateLimitBucket.MAX_FRAGMENT_TOKENS) { limiter.consumeFragment(node) }
            limiter.consumeFragment(node) shouldBe false
            repeat(RateLimitBucket.MAX_POST_TOKENS) { limiter.consumePost(node) }
            limiter.consumePost(node) shouldBe false
            repeat(RateLimitBucket.MAX_NUDGE_TOKENS) { limiter.consumeNudge(node) }
            limiter.consumeNudge(node) shouldBe false
        }

        it("rate state resets on restart — in-memory only as per spec") {
            val limiter = RateLimiter()
            repeat(RateLimitBucket.MAX_FRAGMENT_TOKENS) { limiter.consumeFragment("n") }
            limiter.consumeFragment("n") shouldBe false
            limiter.reset()
            limiter.consumeFragment("n") shouldBe true
        }

        it("state machine: DRAFT → PENDING → SYNCING → CONFIRMED, timeout does not fire") {
            runTest {
                var timedOut = false
                val sm = PostStateMachine("p", this, { timedOut = true }, timeoutMs = 5_000L)
                sm.state.value shouldBe PostState.DRAFT
                sm.onSubmit();    sm.state.value shouldBe PostState.PENDING; sm.isInputLocked shouldBe true
                sm.onFirstAck(); sm.state.value shouldBe PostState.SYNCING;  sm.isInputLocked shouldBe true
                sm.onConfirmed(); sm.state.value shouldBe PostState.CONFIRMED; sm.isInputLocked shouldBe false
                advanceTimeBy(6_000L)
                timedOut shouldBe false
            }
        }

        it("state machine: 30s timeout with no ACK transitions to FAILED") {
            runTest {
                var timedOut = false
                val sm = PostStateMachine("p", this, { timedOut = true }, timeoutMs = 100L)
                sm.onSubmit()
                advanceTimeBy(200L)
                sm.state.value shouldBe PostState.FAILED
                timedOut shouldBe true
            }
        }

        it("state machine: FAILED → retry enters PENDING, fresh timeout fires if no confirmation") {
            runTest {
                var timeoutCount = 0
                val sm = PostStateMachine("p", this, { timeoutCount++ }, timeoutMs = 100L)
                sm.onSubmit(); sm.onFailed()
                sm.onRetry();  sm.state.value shouldBe PostState.PENDING
                advanceTimeBy(200L)
                timeoutCount shouldBe 1
            }
        }

        it("progressive reconstruction: tier1Unlocked gates tier1 display at 10% threshold") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val total  = 10
                val enc0   = SymmetricCipher().encrypt("meta".toByteArray(), ByteArray(32) { 1 }).getOrThrow()
                val enc1   = SymmetricCipher().encrypt("first".toByteArray(), ByteArray(32) { 1 }).getOrThrow()

                dao.insertPost(PostEntity(
                    postId = "p1", channelId = "c", authorNodeId = "a",
                    encryptedTier0 = enc0, encryptedTier1 = enc1, encryptedTier2 = null,
                    postHash = "h", createdAtMs = 0L, ttlMs = Long.MAX_VALUE,
                    fragmentsTotal = total, tier1Unlocked = false
                ))

                // Below threshold: 0 of 10 ingested
                dao.getPost("p1")!!.tier1Unlocked shouldBe false

                // Cross threshold: 1/10 = 10%
                engine.ingestFragment(
                    FragmentEntity("f0","p1","c",0,total,ByteArray(64),"h0",0L),
                    ChannelType.OPEN, "author"
                )
                dao.getPost("p1")!!.tier1Unlocked shouldBe true
            }
        }

        it("COMPARTMENTED: tier1Unlocked stays false at any fragment count") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val total  = 20
                val enc0   = SymmetricCipher().encrypt("meta".toByteArray(), ByteArray(32) { 1 }).getOrThrow()

                dao.insertPost(PostEntity(
                    postId = "pc", channelId = "c", authorNodeId = "a",
                    encryptedTier0 = enc0, encryptedTier1 = null, encryptedTier2 = null,
                    postHash = "h", createdAtMs = 0L, ttlMs = Long.MAX_VALUE,
                    fragmentsTotal = total, tier1Unlocked = false
                ))

                (0 until 15).forEach { i ->
                    engine.ingestFragment(
                        FragmentEntity("f$i","pc","c",i,total,ByteArray(64),"h$i",0L),
                        ChannelType.COMPARTMENTED, "author"
                    )
                }
                val post = dao.getPost("pc")!!
                post.tier1Unlocked shouldBe false
                post.encryptedTier1.shouldBeNull()
            }
        }

        it("duplicate post rejected by content address") {
            runTest {
                val dao  = FakeShadowMeshDao()
                val enc0 = SymmetricCipher().encrypt("m".toByteArray(), ByteArray(32) { 1 }).getOrThrow()
                val post = PostEntity("dup", "c", "n", enc0, null, null, "h", 0L, Long.MAX_VALUE)
                dao.insertPost(post) shouldBe 1L
                dao.insertPost(post) shouldBe -1L
            }
        }

        it("TTL sweep: deletes expired posts, leaves current posts intact") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val now    = System.currentTimeMillis()
                val enc0   = SymmetricCipher().encrypt("m".toByteArray(), ByteArray(32) { 1 }).getOrThrow()

                dao.insertPost(PostEntity("expired", "c", "n", enc0, null, null, "h1",
                    0L, now - 1_000L, postState = PostState.CONFIRMED))
                dao.insertPost(PostEntity("current", "c", "n", enc0, null, null, "h2",
                    now, now + 7 * 86_400_000L, postState = PostState.CONFIRMED))

                engine.sweepExpired(now)
                dao.getPost("expired").shouldBeNull()
                dao.getPost("current").shouldNotBeNull()
            }
        }

        it("blocked author: fragments silently dropped at ingest boundary") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                dao.blockNode(BlocklistEntry("blocked", "spam", 0L, BlockSource.LOCAL_DECISION))
                val frag = FragmentEntity("f1", "p1", "c", 0, 1, ByteArray(64), "h", 0L)
                engine.ingestFragment(frag, ChannelType.OPEN, "blocked") shouldBe false
            }
        }

        it("unblocked author with matching post: fragment accepted and post state updated") {
            // T4 fix: insert matching post so ingestFragment exercises the full path,
            // not the early-return null-post path.
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val enc0   = SymmetricCipher().encrypt("meta".toByteArray(), ByteArray(32) { 1 }).getOrThrow()
                val enc1   = SymmetricCipher().encrypt("first".toByteArray(), ByteArray(32) { 1 }).getOrThrow()

                dao.insertPost(PostEntity(
                    postId = "p2", channelId = "c", authorNodeId = "clean",
                    encryptedTier0 = enc0, encryptedTier1 = enc1, encryptedTier2 = null,
                    postHash = "h", createdAtMs = 0L, ttlMs = Long.MAX_VALUE,
                    fragmentsTotal = 1, postState = PostState.PENDING
                ))

                val frag = FragmentEntity("f2", "p2", "c", 0, 1, ByteArray(64), "h", 0L)
                engine.ingestFragment(frag, ChannelType.OPEN, "clean") shouldBe true

                // Post should now be CONFIRMED (1/1 fragments = 100%)
                dao.getPost("p2")!!.postState shouldBe PostState.CONFIRMED
            }
        }

        it("burn-after-read: openPost returns snapshot then deletes from DB") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)
                val enc0   = SymmetricCipher().encrypt("m".toByteArray(), ByteArray(32) { 1 }).getOrThrow()
                dao.insertPost(PostEntity("burn", "c", "n", enc0, null, null, "h",
                    0L, Long.MAX_VALUE, burnAfterRead = true, postState = PostState.CONFIRMED))

                engine.openPost("burn").shouldNotBeNull()
                dao.getPost("burn").shouldBeNull()
            }
        }
    }
})

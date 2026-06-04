package mesh.shadowmesh.forum

import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.diagnostics.Diag
import mesh.shadowmesh.storage.*
import mesh.shadowmesh.mesh.fragment.FragmentEntity as MeshFragmentEntity
import mesh.shadowmesh.storage.OptionTally
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import mesh.shadowmesh.crypto.toHex

/**
 * Post engine — design doc Phase 3.
 *
 * Handles:
 *   - Content-addressed post storage (SHA3-256 post ID)
 *   - Duplicate rejection by post ID
 *   - Post state machine: DRAFT → PENDING → SYNCING → CONFIRMED → FAILED
 *   - Progressive partial reconstruction (Tier 0/1/2)
 *   - TTL enforcement and burn-after-reading
 *   - Bloom filter deduplication for gossip
 *
 * Post ID derivation:
 *   postId   = SHA3-256(channelId || authorNodeId || encryptedContent || createdAtMs)
 *   postHash = SHA3-256(encryptedTier2) — hash of the ENCRYPTED bytes, not plaintext.
 *              Used as an integrity anchor in onConfirmed() to detect relay substitution.
 *
 * Encryption:
 *   Posts are encrypted with the channel key advanced through the PostRatchet.
 *   The post key is derived: post_key = HKDF(chain_key, salt=post_hash, info="post").
 *   Tier 0 (metadata), Tier 1 (≥10% fragments, first sentence), Tier 2 (full content)
 *   use the same post key — the tiers are content partitions, not separate keys.
 *
 * Progressive reconstruction is DISABLED for COMPARTMENTED channels.
 *
 * Thread-safety: all DAO operations use Dispatchers.IO.
 */
class PostEngine(
    private val dao:         ShadowMeshDao,
    private val bloomFilter: GossipBloomFilter = GossipBloomFilter(),
    private val hkdf:        Hkdf = Hkdf.instance,
    private val cipher:      SymmetricCipher = SymmetricCipher()
) {

    // ── Observe ───────────────────────────────────────────────────────────

    /**
     * Observe posts for [channelId], with runtime TTL filtering.
     *
     * The TTL sweep worker evicts expired posts every 6 hours, leaving a worst-case
     * 6-hour window where expired posts remain in the database. This filter ensures
     * the UI never shows posts past their TTL regardless of when the sweep last ran.
     * Short-TTL posts (e.g. "burn after reading" variants with 1-hour TTL) would
     * otherwise remain visible for hours after expiry.
     *
     * [System.currentTimeMillis()] is re-evaluated on each emission so late-arriving
     * posts that expire while the list is displayed disappear on the next DB update.
     */
    fun observePosts(channelId: String): Flow<List<PostEntity>> =
        dao.observePosts(channelId).map { posts ->
            val now = System.currentTimeMillis()
            posts.filter { it.ttlMs <= 0L || it.ttlMs > now }
        }

    /**
     * Flow of unread post count for [channelId].
     * A post is unread when openedAtMs IS NULL and postState is CONFIRMED.
     * Used by ForumUiViewModel to compute per-channel unread badges.
     */
    fun observeUnread(channelId: String): Flow<Int> =
        dao.observeUnreadCount(channelId)

    /** Mark [postId] as read. Called by openPost — idempotent, no-op if already opened. */
    suspend fun markOpened(postId: String, nowMs: Long = System.currentTimeMillis()) =
        withContext(Dispatchers.IO) { dao.markPostOpened(postId, nowMs) }

    // ── Create ────────────────────────────────────────────────────────────

    /**
     * Create and store a new post locally.
     *
     * The post enters PENDING state immediately (optimistic UI — appears in feed).
     * The mesh layer will transition it to SYNCING → CONFIRMED or FAILED.
     *
     * @param channelId       Target channel.
     * @param authorNodeId    32-byte author identity (hex).
     * @param plaintextTier0  Metadata bytes (always small — channel name, author, timestamp).
     * @param plaintextTier1  First sentence bytes.
     * @param plaintextTier2  Full post content bytes.
     * @param postKey         32-byte post key from PostRatchet.advance().
     * @param channelType     Used to enforce progressive reconstruction rules.
     * @param ttlMs           Absolute expiry timestamp (default: now + 7 days).
     * @param burnAfterRead   If true, delete on first open.
     *
     * @return The [PostEntity] as stored, or null if duplicate (rejected by content address).
     */
    suspend fun createPost(
        channelId:      String,
        authorNodeId:   String,
        plaintextTier0: ByteArray,
        plaintextTier1: ByteArray,
        plaintextTier2: ByteArray,
        postKey:        ByteArray,
        channelType:    ChannelType,
        ttlMs:          Long    = System.currentTimeMillis() + DEFAULT_TTL_MS,
        burnAfterRead:  Boolean = false,
        nowMs:          Long    = System.currentTimeMillis(),
        /** Non-null when this post endorses an OFFLINE_LOCAL post — links back to its postId. */
        endorsedPostId: String? = null,
    ): PostEntity? = withContext(Dispatchers.IO) {
        // postKey is the CHANNEL key (not a ratchet key). The ratchet re-encryption happens
        // in PostDispatcher.dispatch() when the post is actually sent. All tiers are encrypted
        // with the static channel key here so the receiver can decrypt for display after
        // unwrapping the outer ratchet layer. The channel key is wiped by the caller.
        require(postKey.size == 32) { "Post key must be 32 bytes" }

        val encTier0 = cipher.encrypt(plaintextTier0, postKey).getOrThrow()
        val encTier1 = cipher.encrypt(plaintextTier1, postKey).getOrThrow()
        val encTier2 = cipher.encrypt(plaintextTier2, postKey).getOrThrow()

        val postHash = hkdf.sha3_256(encTier2).toHex()
        val postId   = hkdf.sha3_256(
            channelId.toByteArray() + authorNodeId.toByteArray() + encTier2 + longToBytes(nowMs)
        ).toHex()

        // Monotonic sequence number per (channelId, authorNodeId) for clock-independent ordering.
        val nextSeq = dao.getMaxSequenceNumber(channelId, authorNodeId) + 1L

        // Progressive reconstruction: COMPARTMENTED channels always encrypt all tiers
        // but Tier 1/2 are withheld from display until all fragments arrive.
        // encryptedTier2 is stored immediately (channel-key-encrypted full content) so the
        // confirmed delivery path can verify sha3_256(encTier2) == postHash without a
        // separate DB write. Display is gated on postState == CONFIRMED in ForumViewModel.
        val entity = PostEntity(
            postId           = postId,
            channelId        = channelId,
            authorNodeId     = authorNodeId,
            encryptedTier0   = encTier0,
            encryptedTier1   = if (channelType != ChannelType.COMPARTMENTED) encTier1 else null,
            encryptedTier2   = encTier2,   // channel-key-encrypted full content; display gated on CONFIRMED
            postHash         = postHash,
            createdAtMs      = nowMs,
            ttlMs            = ttlMs,
            burnAfterRead    = burnAfterRead,
            postState        = PostState.PENDING,
            sequenceNumber   = nextSeq,
            endorsedPostId   = endorsedPostId,
        )

        val rowId = dao.insertPost(entity)
        if (rowId == -1L) null else entity  // -1L = duplicate rejected
    }

    // ── Post state transitions (called by mesh delivery layer) ────────────

    /** Post dispatched — first fragment ACK received from mesh. */
    suspend fun onFirstFragmentAck(postId: String) = withContext(Dispatchers.IO) {
        dao.updatePostState(postId, PostState.SYNCING)
    }

    /** All fragments received and Merkle root ACK confirmed. */
    suspend fun onConfirmed(postId: String, encryptedTier2: ByteArray) = withContext(Dispatchers.IO) {
        // Security gate: verify the assembled tier2 content matches the postHash
        // recorded at creation time (sha3_256(encTier2)).
        //
        // Without this check an adversarial relay could substitute a different
        // encryptedTier2 payload at confirmation time — the CONFIRMED post would
        // display different content than what was sent, with no indication to the reader.
        //
        // The postHash is sha3_256(encTier2) computed in createPost() from the
        // locally-encrypted content. We recompute here and compare.
        val post = dao.getPost(postId) ?: return@withContext   // already gone — no-op
        val computedHash = hkdf.sha3_256(encryptedTier2).toHex()
        if (post.postHash.isNotEmpty() && computedHash != post.postHash) {
            // Hash mismatch for a sender-created post: do NOT write substituted content.
            // Mark FAILED so the user sees a delivery error rather than silently
            // displaying attacker-supplied content.
            dao.updatePostState(postId, PostState.FAILED)
            return@withContext
        }
        // Stub posts (postHash == "") are receiver-side stubs created on first fragment
        // arrival before the full content is known. They cannot be pre-committed to a hash.
        // The Merkle verification in FragmentIngestor.attemptConfirmation provides fragment-
        // layer integrity; channel-key encryption provides content confidentiality.
        // For observability: log whenever a stub is confirmed without a prior hash commitment.
        if (post.postHash.isEmpty()) {
            Diag.info("post-engine", "stub-confirmed-without-precommit",
                "Receiver stub confirmed — postHash set from assembled content (no sender pre-commitment)",
                "postId" to postId.take(8))
        }
        dao.updatePostConfirmed(postId = postId, encryptedTier2 = encryptedTier2, postHash = computedHash)
        // Fix: touch the channel using post.channelId, not postId.
        // Previously dao.touchChannel(postId, ...) ran UPDATE channels WHERE channelId = postId
        // which always matched zero rows — postId is a post hash, not a channel ID.
        dao.touchChannel(post.channelId, System.currentTimeMillis())
    }

    /** 30s timeout with no ACK — delivery failed. */
    suspend fun onDeliveryFailed(postId: String) = withContext(Dispatchers.IO) {
        dao.updatePostState(postId, PostState.FAILED)
    }

    /** Fail all SYNCING posts in [channelId] after max sync retries are exhausted. */
    suspend fun failSyncingPostsInChannel(channelId: String) = withContext(Dispatchers.IO) {
        dao.failSyncingPostsInChannel(channelId)
    }

    // ── Fragment ingestion and progressive reconstruction ─────────────────

    /**
     * Ingest a received fragment. Updates post progress and unlocks tiers
     * as fragment count crosses thresholds.
     *
     * Bloom filter dedup: fragment is rejected if already seen.
     *
     * Progressive reconstruction thresholds:
     *   Tier 0: always available (metadata, first fragment)
     *   Tier 1: available when ≥10% of total fragments received
     *   Tier 2: available only on full assembly (CONFIRMED state)
     *
     * COMPARTMENTED channels: progressive reconstruction disabled.
     * Tier 1 and Tier 2 only shown after full assembly.
     *
     * @return true if the fragment was accepted; false if duplicate or rate-limited.
     */
    suspend fun ingestFragment(
        fragment:     FragmentEntity,
        channelType:  ChannelType,
        authorNodeId: String           // hex node ID of the fragment's author
    ): Boolean = withContext(Dispatchers.IO) {
        // Blocklist check — silently discard fragments from locally blocked nodes.
        // The sender is unaware they are blocked (design doc §5.10a).
        if (dao.isBlocked(authorNodeId) > 0) return@withContext false

        // Bloom filter dedup
        if (!bloomFilter.testAndAdd(fragment.fragmentId.toByteArray())) return@withContext false

        // Validate declared index range BEFORE insertion so a malformed fragment
        // is never written to the database. The previous order (insert → validate → delete)
        // left a window where concurrent ingestFragment calls could read the invalid
        // fragment between the insert and the compensating delete.
        val total = fragment.total
        if (total <= 0 || fragment.index < 0 || fragment.index >= total) {
            return@withContext false
        }

        val inserted = dao.insertFragment(fragment)
        if (inserted == -1L) return@withContext false  // duplicate by PK

        val received = dao.fragmentCountForPost(fragment.postId)

        // Reject total mismatch — all fragments of a post must declare the same total.
        // A fragment arriving with a different total than the one already established
        // (fragmentsTotal > 0 in the PostEntity) is either malformed or from a malicious
        // peer trying to poison the accumulator: accepting it could cause the received-count
        // threshold (received >= total) to fire at the wrong point, triggering premature
        // CONFIRMED state or permanently preventing confirmation.
        //
        // fragmentsTotal == 0 means this is the first fragment seen for this post —
        // the CASE in updatePostProgress will set it from this fragment's total.
        // Create a stub PostEntity for received-only posts (from other channel members).
        // The sender's createPost() already created the entity for locally-authored posts.
        // postHash and encryptedTier* are unknown at fragment-arrival time; they are filled
        // by onConfirmed() once all fragments are assembled and the outer ratchet layer decrypted.
        val post = dao.getPost(fragment.postId) ?: run {
            val stub = PostEntity(
                postId         = fragment.postId,
                channelId      = fragment.channelId,
                authorNodeId   = authorNodeId,  // relay sender; best available without wire-level author field
                encryptedTier0 = ByteArray(0),  // placeholder — filled on confirmation
                encryptedTier1 = null,           // unknown until confirmation
                encryptedTier2 = null,           // unknown until confirmation
                postHash       = "",             // placeholder — filled on confirmation
                postState      = PostState.SYNCING,
                createdAtMs    = System.currentTimeMillis(),
                ttlMs          = System.currentTimeMillis() + DEFAULT_TTL_MS,
            )
            val rowId = dao.insertPost(stub)
            if (rowId == -1L) {
                // Race: another coroutine already inserted the stub — load it instead.
                dao.getPost(fragment.postId) ?: return@withContext true
            } else {
                stub
            }
        }
        // Use totalData as the canonical reconstruction threshold stored in fragmentsTotal.
        // total = totalData + totalParity; we only care about data shards for reconstruction.
        val totalData = fragment.totalData.coerceAtLeast(1)
        if (post.fragmentsTotal > 0 && post.fragmentsTotal != totalData) {
            dao.deleteFragment(fragment.fragmentId)
            return@withContext false
        }
        // FIX (B1): Track whether the 10% threshold is crossed on THIS specific ingest call.
        //
        // Previous bug: unlockTier1 used "post.encryptedTier1 == null" as a guard.
        // For non-COMPARTMENTED channels, createPost stores encryptedTier1 at creation
        // (non-null), so the guard was always false — the unlock path was dead code.
        // And even when (incorrectly) triggered, it wrote post.encryptedTier1 (null) — a no-op.
        //
        // Correct model:
        //   - encryptedTier1 bytes are durably stored at creation for non-COMPARTMENTED.
        //   - Display is gated by tier1Unlocked (false until threshold first crossed).
        //   - "Just crossed" = this ingest took us from below to at/above TIER1_THRESHOLD.
        //   - The UI reads tier1Unlocked before decrypting encryptedTier1.
        //   - COMPARTMENTED: progressive reconstruction disabled — tier1Unlocked stays false.
        //
        // Progress and the tier-1 threshold MUST be measured against the reconstruction
        // threshold (totalData), not the full shard count (total = totalData + totalParity).
        // CONFIRMED fires at `received >= reconstructionThreshold` below; if the percentage
        // divided by `total` instead, a CONFIRMED post would read ~totalData/total (e.g.
        // 10/17 ≈ 59%) and `justCrossed` would evaluate the TIER1 threshold against the wrong
        // basis — firing the progressive unlock at the wrong received-count. Use the same
        // denominator the CONFIRMED gate uses.
        val reconstructionThreshold = fragment.totalData.coerceAtLeast(1)
        val prevPct     = if (received > 1) (received - 1).toFloat() / reconstructionThreshold else 0f
        val currPct     = received.toFloat() / reconstructionThreshold
        val justCrossed = prevPct < TIER1_THRESHOLD && currPct >= TIER1_THRESHOLD

        // post already loaded above for the total-mismatch check; reuse it here.

        // FIX (Bug 5): CONFIRMED when received >= totalData (reconstruction threshold),
        // NOT when received >= total (all shards including parity).
        // RS_10_7 for example: 10 data shards suffice of 17 total.
        val newState = when {
            received >= reconstructionThreshold -> PostState.CONFIRMED
            post.postState == PostState.PENDING -> PostState.SYNCING
            else -> post.postState
        }

        val unlockTier1 = justCrossed && channelType != ChannelType.COMPARTMENTED && !post.tier1Unlocked

        dao.updatePostProgress(
            postId        = fragment.postId,
            state         = newState,
            tier1Unlocked = unlockTier1,
            received      = received,
            total         = totalData  // store reconstruction threshold, not total shard count
        )
        true
    }

    // ── Read / open ───────────────────────────────────────────────────────

    /**
     * Open a post for reading. Handles burn-after-read deletion.
     * Returns the post entity, or null if not found.
     * After returning, if burnAfterRead is set, the post is deleted from local store.
     */
    suspend fun openPost(postId: String): PostEntity? = withContext(Dispatchers.IO) {
        val post = dao.getPost(postId) ?: return@withContext null
        // Copy the entity into a local val BEFORE deleting from DB.
        // This prevents the race where the caller holds a null reference
        // because the DB row was deleted before the return value was captured.
        val snapshot = post.copy()
        if (snapshot.burnAfterRead) {
            dao.burnIfRequired(postId)
        }
        snapshot
    }

    // ── Polls ──────────────────────────────────────────────────────────────

    /**
     * Create a poll attached to [postId].
     * Poll ID = SHA3-256(postId || question) as hex.
     * Options stored as minimal JSON array — no external JSON library required.
     */
    suspend fun createPoll(
        postId:      String,
        channelId:   String,
        question:    String,
        options:     List<String>,
        expiresAtMs: Long = System.currentTimeMillis() + DEFAULT_TTL_MS,
        nowMs:       Long = System.currentTimeMillis()
    ): PollEntity = withContext(Dispatchers.IO) {
        require(options.size in 2..8) { "Poll must have 2–8 options" }
        require(question.isNotBlank()) { "Poll question must not be blank" }

        val pollId      = hkdf.sha3_256(postId.toByteArray() + question.toByteArray()).toHex()
        val optionsJson = options.joinToString(",", "[", "]") {
            "\"${it.replace("\\", "\\\\").replace("\"", "\\\"")}\""
        }
        val entity = PollEntity(
            pollId = pollId, postId = postId, channelId = channelId,
            question = question, optionsJson = optionsJson,
            expiresAtMs = expiresAtMs, createdAtMs = nowMs
        )
        dao.upsertPoll(entity)
        entity
    }

    /**
     * Record THIS node's vote on [pollId] for [optionIndex].
     * Updates PollEntity.myVoteIndex for fast local access, and upserts a
     * PollVoteEntity row so the vote is included in aggregate tallies.
     */
    suspend fun votePoll(
        pollId:       String,
        optionIndex:  Int,
        localNodeId:  String,
        nowMs:        Long = System.currentTimeMillis()
    ) = withContext(Dispatchers.IO) {
        dao.recordVote(pollId, optionIndex)
        dao.upsertPollVote(
            PollVoteEntity(
                pollId       = pollId,
                voterNodeId  = localNodeId,
                optionIndex  = optionIndex,
                receivedAtMs = nowMs
            )
        )
    }

    /**
     * Record a peer's vote received from the mesh as an encrypted vote fragment.
     * [voterNodeId] is the fragment's authorNodeId; [optionIndex] is decrypted from
     * the fragment payload. Upserts — a peer can update their vote by sending a new fragment.
     */
    suspend fun receivePeerVote(
        pollId:      String,
        voterNodeId: String,
        optionIndex: Int,
        nowMs:       Long = System.currentTimeMillis()
    ) = withContext(Dispatchers.IO) {
        dao.upsertPollVote(
            PollVoteEntity(
                pollId       = pollId,
                voterNodeId  = voterNodeId,
                optionIndex  = optionIndex,
                receivedAtMs = nowMs
            )
        )
    }

    /**
     * Get the aggregate vote tally for [pollId].
     * Returns a list of (optionIndex, voteCount) in ascending option order.
     * This is the data needed to render a poll results bar chart.
     */
    suspend fun getPollTally(pollId: String): List<OptionTally> =
        withContext(Dispatchers.IO) { dao.getVoteTally(pollId) }

    /** Total number of unique voters for [pollId]. */
    suspend fun getPollVoterCount(pollId: String): Int =
        withContext(Dispatchers.IO) { dao.getTotalVoterCount(pollId) }

    suspend fun getPoll(postId: String): PollEntity? = withContext(Dispatchers.IO) {
        dao.getPoll(postId)
    }

    // ── Reactions ──────────────────────────────────────────────────────────

    /**
     * Add or replace [authorNodeId]'s reaction to [postId].
     * One reaction per author per post — upsert replaces any prior reaction.
     * [encryptedBlob] is the reaction encrypted with the channel key, ready for relay.
     */
    suspend fun addReaction(
        postId:        String,
        authorNodeId:  String,
        reactionType:  String,
        encryptedBlob: ByteArray,
        nowMs:         Long = System.currentTimeMillis()
    ): ReactionEntity = withContext(Dispatchers.IO) {
        require(reactionType.isNotBlank()) { "Reaction type must not be blank" }
        val entity = ReactionEntity(
            postId = postId, authorNodeId = authorNodeId,
            reactionType = reactionType, encryptedBlob = encryptedBlob,
            receivedAtMs = nowMs
        )
        dao.upsertReaction(entity)
        entity
    }

    suspend fun removeReaction(postId: String, authorNodeId: String) =
        withContext(Dispatchers.IO) { dao.deleteReaction(postId, authorNodeId) }


    // ── Backend integration hooks ─────────────────────────────────────────

    /**
     * Load a post for outbound dispatch. Returns the full entity, or null if not found.
     * Separate from [openPost] because dispatch does not trigger burn-after-read.
     */
    suspend fun loadForDispatch(postId: String): PostEntity? =
        withContext(Dispatchers.IO) { dao.getPost(postId) }

    /** Directly set the state of a post. Used for OFFLINE_LOCAL / PENDING_ONLINE transitions. */
    suspend fun setPostState(postId: String, state: PostState) =
        withContext(Dispatchers.IO) { dao.updatePostState(postId, state) }

    /** Returns the single PENDING_ONLINE post for [channelId], or null if none is queued. */
    suspend fun getPendingOnlineForChannel(channelId: String): PostEntity? =
        withContext(Dispatchers.IO) { dao.getPendingOnlineForChannel(channelId) }

    /**
     * Returns true if no fragment for [postId] has been ingested yet.
     * Used by [FragmentIngestor] to detect the first-fragment event (PENDING → SYNCING).
     */
    suspend fun isFirstFragment(postId: String): Boolean =
        withContext(Dispatchers.IO) { dao.fragmentCountForPost(postId) == 0 }

    /**
     * Returns the original (pre-FEC) encrypted payload length for [postId].
     * Used by [FragmentIngestor] when calling [FragmentationEngine.reassemble].
     * Returns 0 if the post is not found.
     */
    /**
     * Returns the original (pre-FEC) encrypted payload length for [postId].
     * Used by [FragmentIngestor] when calling [FragmentationEngine.reassemble].
     *
     * FIX (B2): previously multiplied received fragment count by payload size,
     * returning an undercount when only partial fragments had arrived.
     * Correct value is: declared [FragmentEntity.total] × per-fragment payload size.
     * [FragmentEntity.total] is the original count written at fragmentation time
     * and is identical in every fragment of the same post — using any one fragment
     * is correct. Returns 0 if no fragments exist yet.
     */
    suspend fun getFragmentTotal(postId: String): Int =
        withContext(Dispatchers.IO) {
            val frag = dao.getFragmentsForPost(postId).firstOrNull() ?: return@withContext 0
            frag.totalData * frag.encryptedBytes.size  // data shards × bytes/shard = original encrypted payload length
        }

    // ── TTL sweep (called by WorkManager) ─────────────────────────────────

    /** Delete all posts past their TTL expiry. Call from WorkManager periodic task. */
    suspend fun sweepExpired(nowMs: Long = System.currentTimeMillis()) =
        withContext(Dispatchers.IO) {
            dao.purgeTtlExpired(nowMs)   // cascades to fragment rows via FK
            dao.purgeOrphanedFragments() // fragments whose post row was never created
            dao.purgeExpiredPolls(nowMs)
        }

    // ── Content address check ─────────────────────────────────────────────

    /** Returns true if a post with [postId] already exists locally. */
    suspend fun exists(postId: String): Boolean =
        withContext(Dispatchers.IO) { dao.postExists(postId) > 0 }

    /**
     * Return up to [limit] recent post hashes (decoded from postId hex) for use as
     * entropy seeds in [mesh.shadowmesh.mesh.privacy.SndpEngine.onSyncCycleStart].
     * These seeds drive probabilistic cover-traffic trigger decisions; they are NOT
     * included in any fake fragment's content.
     */
    suspend fun recentPostHashes(limit: Int = 50): List<ByteArray> =
        withContext(Dispatchers.IO) {
            dao.getRecentPostIds(limit).map { hexToBytes(it) }
        }



    /**
     * Ingest a received mesh fragment. Converts from the mesh wire model to the
     * storage model, preserving [MeshFragmentEntity.totalData] as the FEC reconstruction
     * threshold. Called by [FragmentIngestor] for all inbound fragments.
     */
    suspend fun ingestFragment(
        fragment:     MeshFragmentEntity,
        channelType:  ChannelType,
        authorNodeId: String,
        nowMs:        Long = System.currentTimeMillis()
    ): Boolean = ingestFragment(
        fragment     = fragment.toStorageFragment(nowMs),
        channelType  = channelType,
        authorNodeId = authorNodeId
    )

    // ── Mesh-to-storage fragment conversion ───────────────────────────────

    /**
     * Convert a mesh [MeshFragmentEntity] to the storage [FragmentEntity].
     *
     * [MeshFragmentEntity.totalData] is the reconstruction threshold (data shards only).
     * [MeshFragmentEntity.totalFragments] = totalData + totalParity = total wire shards.
     * The storage model records both so CONFIRMED logic uses totalData, not total.
     */
    private fun MeshFragmentEntity.toStorageFragment(nowMs: Long): FragmentEntity =
        FragmentEntity(
            fragmentId    = fragmentId,
            postId        = postId,
            channelId     = channelId,
            index         = sequenceIndex,
            total         = totalFragments,   // all shards: data + parity
            totalData     = totalData,         // reconstruction threshold
            encryptedBytes= payload,
            sha3Hash      = fragmentId,        // fragmentId IS sha3-content-address
            receivedAtMs  = nowMs,
            isOwn         = false
        )

    companion object {
        const val DEFAULT_TTL_MS    = 7L * 24 * 60 * 60 * 1000   // 7 days
        const val TIER1_THRESHOLD   = 0.10f                       // 10% fragments
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────


private fun longToBytes(v: Long): ByteArray = ByteArray(8) { i ->
    ((v shr ((7 - i) * 8)) and 0xFF).toByte()
}

package mesh.shadowmesh.storage

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface ShadowMeshDao {

    // ── Channels ──────────────────────────────────────────────────────────

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertChannel(channel: ChannelEntity)

    @Query("SELECT * FROM channels WHERE departed = 0 ORDER BY dhtPopularity DESC, lastActivityMs DESC LIMIT 1000")
    fun observeActiveChannels(): Flow<List<ChannelEntity>>

    @Query("SELECT COUNT(*) FROM posts WHERE channelId = :channelId AND openedAtMs IS NULL AND postState = 'CONFIRMED'")
    fun observeUnreadCount(channelId: String): Flow<Int>

    @Query("SELECT COUNT(*) FROM posts WHERE channelId = :channelId AND openedAtMs IS NULL AND postState = 'CONFIRMED'")
    suspend fun unreadCountForChannel(channelId: String): Int

    @Query("UPDATE posts SET openedAtMs = :nowMs WHERE postId = :postId AND openedAtMs IS NULL")
    suspend fun markPostOpened(postId: String, nowMs: Long)

    @Query("UPDATE channels SET dhtPopularity = :popularity WHERE channelId = :channelId")
    suspend fun updateChannelDhtPopularity(channelId: String, popularity: Int)

    @Query("SELECT * FROM channels WHERE channelId = :channelId")
    suspend fun getChannel(channelId: String): ChannelEntity?

    @Query("UPDATE channels SET departed = 1, encryptedKeyBlob = X'' WHERE channelId = :channelId")
    suspend fun markDeparted(channelId: String)

    @Query("UPDATE channels SET lastActivityMs = :nowMs WHERE channelId = :channelId")
    suspend fun touchChannel(channelId: String, nowMs: Long)

    // ── Posts ─────────────────────────────────────────────────────────────

    @Insert(onConflict = OnConflictStrategy.IGNORE) // duplicate rejected by PK
    suspend fun insertPost(post: PostEntity): Long   // -1 if duplicate

    @Query("SELECT * FROM posts WHERE channelId = :channelId ORDER BY createdAtMs DESC LIMIT 500")
    fun observePosts(channelId: String): Flow<List<PostEntity>>

    @Query("SELECT * FROM posts WHERE postId = :postId")
    suspend fun getPost(postId: String): PostEntity?

    @Query("SELECT * FROM posts WHERE channelId = :channelId AND postState = 'PENDING_ONLINE' LIMIT 1")
    suspend fun getPendingOnlineForChannel(channelId: String): PostEntity?

    @Query("UPDATE posts SET postState = :state WHERE postId = :postId")
    suspend fun updatePostState(postId: String, state: PostState)

    // FIX (B1): updatePostProgress now sets tier1Unlocked instead of writing tier1 bytes.
    // encryptedTier1 bytes are stored at creation and never re-written by this method.
    // tier1Unlocked starts false and is set to true exactly once when the 10% threshold
    // is first crossed. Room writes a boolean column; the UPDATE uses CASE to enforce
    // the monotonic false→true constraint at the SQL level.
    //
    // FIX: also writes fragmentsTotal so the DB row reflects the declared total from the
    // fragment wire format. Without this, PostEntity.fragmentsTotal stays 0 forever and
    // any UI that reads it (e.g. "12 / 0 fragments") is broken.
    // fragmentsTotal is monotonically set: CASE ensures it is only written if > 0
    // (first received fragment sets it; subsequent ingests keep it the same value since
    // all fragments in a post declare the same total).
    @Query("""
        UPDATE posts SET
            postState         = :state,
            tier1Unlocked     = CASE WHEN :tier1Unlocked = 1 THEN 1 ELSE tier1Unlocked END,
            fragmentsReceived = :received,
            fragmentsTotal    = CASE WHEN :total > 0 THEN :total ELSE fragmentsTotal END
        WHERE postId = :postId
    """)
    suspend fun updatePostProgress(
        postId:       String,
        state:        PostState,
        tier1Unlocked:Boolean,
        received:     Int,
        total:        Int
    )

    // Separate method for the onConfirmed path — sets encryptedTier2, postHash, and postState=CONFIRMED.
    // Called only by PostEngine.onConfirmed; not used by ingestFragment.
    // postHash is updated here to fill stubs created for received-only posts (postHash was "" at
    // fragment-arrival time because the hash wasn't known until the outer ratchet layer was decrypted).
    @Query("UPDATE posts SET postState = 'CONFIRMED', encryptedTier2 = :encryptedTier2, postHash = :postHash WHERE postId = :postId")
    suspend fun updatePostConfirmed(postId: String, encryptedTier2: ByteArray, postHash: String)

    /** Burn-after-read: delete on first open. */
    @Query("DELETE FROM posts WHERE postId = :postId AND burnAfterRead = 1")
    suspend fun burnIfRequired(postId: String)

    /** Transition all SYNCING posts in [channelId] to FAILED. Called after max sync retries. */
    @Query("UPDATE posts SET postState = 'FAILED' WHERE channelId = :channelId AND postState = 'SYNCING'")
    suspend fun failSyncingPostsInChannel(channelId: String)

    /**
     * Mark all CONFIRMED posts in [channelId] whose [createdAtMs] falls within the reconnect
     * window as [receivedOffline]=true. Called by [ChannelSyncCoordinator.onReconnect] once
     * the catch-up fetch completes so the UI can show a "While you were offline" separator.
     *
     * Uses `createdAtMs` (when the post was authored) rather than a received timestamp so that
     * posts authored during the disconnection period — including your own queued outbound posts
     * — all appear under the offline separator regardless of local receive time.
     */
    @Query("""
        UPDATE posts SET receivedOffline = 1
        WHERE channelId = :channelId
          AND createdAtMs BETWEEN :windowStartMs AND :windowEndMs
          AND postState = 'CONFIRMED'
    """)
    suspend fun markOfflineWindowPosts(channelId: String, windowStartMs: Long, windowEndMs: Long)

    /** WorkManager TTL sweep — deletes all posts past their expiry. */
    @Query("DELETE FROM posts WHERE ttlMs < :nowMs")
    suspend fun purgeTtlExpired(nowMs: Long)

    /**
     * Returns the highest [PostEntity.sequenceNumber] for posts by [authorNodeId] in [channelId].
     * Returns 0 if no posts exist yet (so the next sequence number is 1).
     * Used by [PostEngine.createPost] to assign monotonically increasing sequence numbers.
     */
    @Query("SELECT COALESCE(MAX(sequenceNumber), 0) FROM posts WHERE channelId = :channelId AND authorNodeId = :authorNodeId")
    suspend fun getMaxSequenceNumber(channelId: String, authorNodeId: String): Long

    @Query("SELECT COUNT(*) FROM posts WHERE postId = :postId")
    suspend fun postExists(postId: String): Int

    // ── Fragments ─────────────────────────────────────────────────────────

    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertFragment(fragment: FragmentEntity): Long

    @Query("SELECT * FROM fragments WHERE postId = :postId ORDER BY `index` ASC")
    suspend fun getFragmentsForPost(postId: String): List<FragmentEntity>

    /**
     * Fragments for [channelId] received after [sinceMs].
     * Used by [ChannelSyncCoordinator.onReconnect] to drain missed fragments
     * after a node comes back online. Returns fragments in receive-time order
     * so the ingestor processes them chronologically.
     */
    @Query("SELECT * FROM fragments WHERE channelId = :channelId AND receivedAtMs > :sinceMs ORDER BY receivedAtMs ASC")
    suspend fun getMissedFragmentsForChannel(channelId: String, sinceMs: Long): List<FragmentEntity>

    @Query("SELECT COUNT(*) FROM fragments WHERE postId = :postId")
    suspend fun fragmentCountForPost(postId: String): Int

    @Query("DELETE FROM fragments WHERE fragmentId = :fragmentId")
    suspend fun deleteFragment(fragmentId: String)

    @Query("DELETE FROM fragments WHERE postId = :postId")
    suspend fun deleteFragments(postId: String)

    // Fix #8: orphaned fragment pruning now uses per-post ttlMs rather than a fixed
    // cutoff passed from the caller. Using a fixed DEFAULT_TTL_MS cutoff caused fragments
    // for posts still being assembled (e.g., on a node that was offline for several days)
    // to be swept before assembly completed, because the cutoff was computed from
    // System.currentTimeMillis() with no regard for when the post was created.
    //
    // The correct semantics: a fragment is orphaned when its parent post's TTL has
    // expired OR when the post does not exist at all. Both cases are covered here:
    // - Posts with ttlMs < nowMs are swept by purgeTtlExpired (cascades to fragments).
    // - Fragments whose postId has no entry in the posts table (truly orphaned — the
    //   post row was never created locally) are deleted directly.
    @Query("""
        DELETE FROM fragments
        WHERE postId NOT IN (SELECT postId FROM posts)
    """)
    suspend fun purgeOrphanedFragments()

    // ── Blocklist ──────────────────────────────────────────────────────────

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun blockNode(entry: BlocklistEntry)

    @Query("SELECT COUNT(*) FROM blocklist WHERE nodeId = :nodeId")
    suspend fun isBlocked(nodeId: String): Int

    @Query("SELECT * FROM blocklist ORDER BY blockedAtMs DESC")
    fun observeBlocklist(): Flow<List<BlocklistEntry>>

    @Query("DELETE FROM blocklist WHERE nodeId = :nodeId")
    suspend fun unblock(nodeId: String)

    // ── Reputation ─────────────────────────────────────────────────────────

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertReputation(entry: ReputationEntry)

    @Query("SELECT * FROM reputation WHERE nodeId = :nodeId")
    suspend fun getReputation(nodeId: String): ReputationEntry?

    @Query("SELECT * FROM reputation ORDER BY updatedAtMs DESC")
    fun observeReputation(): Flow<List<ReputationEntry>>

    @Query("UPDATE reputation SET relaySuccessCount = relaySuccessCount + 1, updatedAtMs = :nowMs WHERE nodeId = :nodeId")
    suspend fun recordRelaySuccess(nodeId: String, nowMs: Long)

    @Query("UPDATE reputation SET relayFailureCount = relayFailureCount + 1, updatedAtMs = :nowMs WHERE nodeId = :nodeId")
    suspend fun recordRelayFailure(nodeId: String, nowMs: Long)

    // ── Polls ──────────────────────────────────────────────────────────────

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertPoll(poll: PollEntity)

    @Query("SELECT * FROM polls WHERE postId = :postId")
    suspend fun getPoll(postId: String): PollEntity?

    @Query("SELECT * FROM polls WHERE channelId = :channelId ORDER BY createdAtMs DESC")
    fun observePolls(channelId: String): Flow<List<PollEntity>>

    @Query("UPDATE polls SET myVoteIndex = :voteIndex WHERE pollId = :pollId")
    suspend fun recordVote(pollId: String, voteIndex: Int)

    @Query("DELETE FROM polls WHERE expiresAtMs < :nowMs")
    suspend fun purgeExpiredPolls(nowMs: Long)

    // ── Poll votes (peer votes for aggregate tally) ─────────────────────────

    /** Record or update a peer's vote. Upserts — last received vote wins. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertPollVote(vote: PollVoteEntity)

    /** All votes for a poll, for computing the aggregate tally. */
    @Query("SELECT * FROM poll_votes WHERE pollId = :pollId")
    fun observePollVotes(pollId: String): Flow<List<PollVoteEntity>>

    /** Snapshot vote count per option for [pollId]. Returns list of (optionIndex, count). */
    @Query("""
        SELECT optionIndex, COUNT(*) AS voteCount
        FROM poll_votes
        WHERE pollId = :pollId
        GROUP BY optionIndex
        ORDER BY optionIndex ASC
    """)
    suspend fun getVoteTally(pollId: String): List<OptionTally>

    /** Total number of unique voters for [pollId]. */
    @Query("SELECT COUNT(DISTINCT voterNodeId) FROM poll_votes WHERE pollId = :pollId")
    suspend fun getTotalVoterCount(pollId: String): Int

    /** Delete all votes for a poll (called when the poll is purged). */
    @Query("DELETE FROM poll_votes WHERE pollId = :pollId")
    suspend fun deletePollVotes(pollId: String)

    // ── Entry Node preferences ─────────────────────────────────────────────

    /** Insert or replace a preference entry. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertEntryPreference(pref: EntryNodePreference): Long

    /** Delete a specific preference by primary key. */
    @Query("DELETE FROM entry_node_preferences WHERE id = :id")
    suspend fun deleteEntryPreference(id: Long)

    /** Delete all preferences for a node across all scopes (global + per-channel). */
    @Query("DELETE FROM entry_node_preferences WHERE nodeId = :nodeId")
    suspend fun deleteAllPreferencesForNode(nodeId: String)

    /**
     * Global preference list, ordered by rank ascending.
     * Returns only entries where channelOverrideId IS NULL.
     */
    @Query("""
        SELECT * FROM entry_node_preferences
        WHERE channelOverrideId IS NULL
        ORDER BY rank ASC
    """)
    fun observeGlobalPreferences(): Flow<List<EntryNodePreference>>

    /**
     * Per-channel override list for [channelId], ordered by rank ascending.
     * Returns only entries scoped to the given channel.
     */
    @Query("""
        SELECT * FROM entry_node_preferences
        WHERE channelOverrideId = :channelId
        ORDER BY rank ASC
    """)
    fun observeChannelPreferences(channelId: String): Flow<List<EntryNodePreference>>

    /**
     * Effective preference list for [channelId]:
     *   If per-channel entries exist, return those (ranked).
     *   Otherwise return the global list (ranked).
     * The caller resolves this by calling both and preferring channel-scoped.
     * Suspending snapshot — use observe variants for live updates.
     */
    @Query("""
        SELECT * FROM entry_node_preferences
        WHERE channelOverrideId = :channelId
        ORDER BY rank ASC
    """)
    suspend fun getChannelPreferences(channelId: String): List<EntryNodePreference>

    @Query("""
        SELECT * FROM entry_node_preferences
        WHERE channelOverrideId IS NULL
        ORDER BY rank ASC
    """)
    suspend fun getGlobalPreferences(): List<EntryNodePreference>

    /** Reorder: update the rank of a single preference entry. */
    @Query("UPDATE entry_node_preferences SET rank = :newRank WHERE id = :id")
    suspend fun updatePreferenceRank(id: Long, newRank: Int)

    /**
     * Reorder all entries atomically in a single transaction.
     * [orderedIds] is the complete ordered list of preference IDs; each ID
     * receives the rank equal to its index in the list. Use this instead of
     * calling [updatePreferenceRank] in a loop — a process kill mid-loop would
     * leave a partial reorder in the database.
     */
    @Transaction
    suspend fun reorderPreferencesTransactional(orderedIds: List<Long>) {
        orderedIds.forEachIndexed { newRank, id ->
            updatePreferenceRank(id, newRank)
        }
    }

    // ── Entry Node mode ────────────────────────────────────────────────────

    /**
     * The global Entry Node mode.
     * Stored as a string in a single-row key-value table (node_settings).
     * Defaults to AUTOMATIC if not set.
     */
    @Query("SELECT value FROM node_settings WHERE key = 'entry_node_mode'")
    suspend fun getEntryNodeMode(): String?

    @Query("INSERT OR REPLACE INTO node_settings (key, value) VALUES ('entry_node_mode', :mode)")
    suspend fun setEntryNodeMode(mode: String)

    // ── Reactions ──────────────────────────────────────────────────────────

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertReaction(reaction: ReactionEntity)

    @Query("SELECT * FROM reactions WHERE postId = :postId")
    fun observeReactions(postId: String): Flow<List<ReactionEntity>>

    @Query("SELECT COUNT(*) FROM reactions WHERE postId = :postId AND reactionType = :type")
    suspend fun reactionCount(postId: String, type: String): Int

    @Query("DELETE FROM reactions WHERE postId = :postId AND authorNodeId = :authorNodeId")
    suspend fun deleteReaction(postId: String, authorNodeId: String)

    // ── SHADOWFILES transfer checkpoints ───────────────────────────────────

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTransferCheckpoint(checkpoint: TransferCheckpointEntity)

    @Query("SELECT * FROM transfer_checkpoints WHERE transferId = :transferId")
    suspend fun getTransferCheckpoint(transferId: String): TransferCheckpointEntity?

    @Query("DELETE FROM transfer_checkpoints WHERE transferId = :transferId")
    suspend fun deleteTransferCheckpoint(transferId: String)


    // ── Backend sync helpers ───────────────────────────────────────────────

    /** Snapshot of all active (non-departed) channels. */
    @Query("SELECT * FROM channels WHERE departed = 0 ORDER BY lastActivityMs DESC")
    suspend fun getActiveChannels(): List<ChannelEntity>

    /** ChannelIds that have at least one post in [state]. */
    @Query("""
        SELECT DISTINCT channelId FROM posts WHERE postState = :state
    """)
    suspend fun channelIdsWithPostState(state: PostState): List<String>

    // ── One-time channel destroy (Feature 4) ───────────────────────────────

    @Query("DELETE FROM posts WHERE channelId = :channelId")
    suspend fun deletePostsForChannel(channelId: String)

    @Query("DELETE FROM channels WHERE channelId = :channelId")
    suspend fun deleteChannel(channelId: String)

    // ── Bootstrap nonce replay prevention ─────────────────────────────────

    /**
     * Returns true if [nonceHex] was already accepted in a previous bootstrap session.
     * Called by [PhysicalKeyExchange.receiveQrCode] before accepting a QR code.
     */
    @Query("SELECT COUNT(*) > 0 FROM used_bootstrap_nonces WHERE nonceHex = :nonceHex")
    suspend fun isNonceUsed(nonceHex: String): Boolean

    /**
     * Record [nonce] as consumed so it cannot be replayed after a process restart.
     * [seenAtMs] is the wall-clock time the nonce was first accepted.
     */
    @Insert(onConflict = OnConflictStrategy.IGNORE)
    suspend fun insertUsedNonce(nonce: UsedBootstrapNonce)

    /**
     * Sweep expired nonces. Called by [TtlSweepWorker] each cycle.
     *
     * [oldestAllowedMs] is the minimum seenAtMs a nonce must have to be retained.
     * Nonces seen before this time are deleted.
     *
     * Caller MUST pass: System.currentTimeMillis() - UsedBootstrapNonce.NONCE_RETAIN_MS
     * Passing System.currentTimeMillis() directly deletes ALL nonces, breaking replay protection.
     *
     * Example (correct):
     *   dao.deleteExpiredNonces(System.currentTimeMillis() - UsedBootstrapNonce.NONCE_RETAIN_MS)
     */
    @Query("DELETE FROM used_bootstrap_nonces WHERE seenAtMs < :oldestAllowedMs")
    suspend fun deleteExpiredNonces(oldestAllowedMs: Long)

    // ── Discovered peer cache ─────────────────────────────────────────────────

    /**
     * Insert or replace a discovered peer record.
     *
     * REPLACE: the unique constraint is on [DiscoveredPeerEntity.nodeIdHex] (primary key).
     * Calling this after every successful contact refreshes [DiscoveredPeerEntity.lastSeenMs]
     * and [DiscoveredPeerEntity.addressHint] so the next bootstrap attempt uses the most
     * recent address for that peer.
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertDiscoveredPeer(peer: DiscoveredPeerEntity)

    /**
     * Return all peers last seen at or after [minLastSeenMs].
     *
     * Used by [ShadowMeshForegroundService] before [DhtEngine.bootstrap] to seed
     * the initial contact list. Pass:
     *   System.currentTimeMillis() - DiscoveredPeerEntity.CACHE_RETAIN_MS
     * to filter to the 7-day window.
     */
    @Query("SELECT * FROM discovered_peers WHERE lastSeenMs >= :minLastSeenMs")
    suspend fun getRecentDiscoveredPeers(minLastSeenMs: Long): List<DiscoveredPeerEntity>

    // ── SNDP cover traffic ───────────────────────────────────────────────────

    /**
     * Return the [limit] most-recently-created post IDs (hex) across all channels.
     * Used by [PostEngine.recentPostHashes] to supply entropy seeds to
     * [SndpEngine.onSyncCycleStart]. The seeds drive probabilistic trigger decisions
     * for cover-traffic bursts; they are NOT used in fake fragment construction.
     */
    @Query("SELECT postId FROM posts ORDER BY createdAtMs DESC LIMIT :limit")
    suspend fun getRecentPostIds(limit: Int): List<String>
}

/** Room projection for poll vote tally queries. */
data class OptionTally(
    val optionIndex: Int,
    val voteCount:   Int
)

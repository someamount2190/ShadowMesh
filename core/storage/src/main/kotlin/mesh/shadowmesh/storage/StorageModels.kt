package mesh.shadowmesh.storage

import androidx.room.*

// ── Channel types ─────────────────────────────────────────────────────────────

enum class ChannelType { OPEN, CLOSED, COMPARTMENTED, ANONYMOUS, GLOBAL }

// ── Post state machine ────────────────────────────────────────────────────────

enum class PostState {
    DRAFT,
    PENDING,
    SYNCING,
    CONFIRMED,
    FAILED,
    /** Created while isolated — shared within the local offline partition only. Never auto-transmitted online. */
    OFFLINE_LOCAL,
    /** User selected this OFFLINE_LOCAL post for manual online submission. At most one per channel. */
    PENDING_ONLINE,
}

// ── Trust / reputation ────────────────────────────────────────────────────────

enum class ReputationTier { ESTABLISHED, KNOWN, NEW, UNVERIFIED }

// ── Channel entity ────────────────────────────────────────────────────────────

/**
 * A SHADOWMESH channel. Key material stored encrypted; the actual key bytes
 * are wrapped by BiometricKeyManager before storage (COMPARTMENTED) or
 * wrapped by the device secret (OPEN/CLOSED).
 *
 * channelId = SHA3-256(genesis_post_hash || channel_type || created_at_ms)
 * Stored as hex string.
 */
@Entity(tableName = "channels")
data class ChannelEntity(
    @PrimaryKey val channelId:       String,
    val name:                        String,
    val type:                        ChannelType,
    val encryptedKeyBlob:            ByteArray,
    val genesisHash:                 String,
    val createdAtMs:                 Long,
    val lastActivityMs:              Long,
    val departed:                    Boolean = false,
    /**
     * DHT replication density for this channel: 0–100.
     * Derived by DensityAwareReplicationPolicy from the number of anchor nodes
     * holding confirmed fragments for this channel relative to the replication
     * target. Updated on each sync cycle. Used by the UI to sort channels within
     * each tier — higher density = more resilient = ranked higher.
     */
    val dhtPopularity:               Int = 0,
    /**
     * Monotonically increasing counter incremented on every key rotation.
     * Receivers compare this against their local value to detect missed rotations —
     * a gap means the device was offline when the key changed and must re-fetch the key.
     */
    val keyVersionNumber:            Int  = 1,
    /** Wall-clock time (ms) when [keyVersionNumber] last changed. */
    val keyVersionTimestampMs:       Long = createdAtMs
) {
    override fun equals(other: Any?) = other is ChannelEntity && channelId == other.channelId
    override fun hashCode() = channelId.hashCode()
}

// ── Post entity ───────────────────────────────────────────────────────────────

/**
 * A post in a channel.
 *
 * postId = SHA3-256(channelId || authorNodeId || content || timestamp)
 * Stored as hex. Duplicate posts are rejected by primary key constraint.
 *
 * Content is stored encrypted with the channel key + post ratchet key.
 * Tier 0 (metadata), Tier 1 (first sentence), Tier 2 (full content) are
 * progressive decryption stages — stored separately so partial reconstruction
 * can render incrementally.
 *
 * ttlMs: absolute expiry timestamp. WorkManager sweeps posts past this time.
 * burnAfterRead: if true, deleted from local store on first open.
 */
@Entity(
    tableName = "posts",
    foreignKeys = [ForeignKey(
        entity = ChannelEntity::class,
        parentColumns = ["channelId"],
        childColumns  = ["channelId"],
        onDelete      = ForeignKey.CASCADE
    )],
    indices = [
        Index("channelId"),
        Index("postState"),
        Index("ttlMs"),
        // Composite index for observeUnreadCount / unreadCountForChannel.
        // The query filters on (channelId, postState = 'CONFIRMED', openedAtMs IS NULL).
        // Without this, SQLite does a full table scan filtered by channelId alone.
        // With this index, the query uses a covering index scan restricted to the
        // relevant (channelId, postState) prefix — O(log n + k) instead of O(n).
        Index(value = ["channelId", "postState", "openedAtMs"])
    ]
)
data class PostEntity(
    @PrimaryKey val postId:          String,   // 64 hex
    val channelId:                   String,
    val authorNodeId:                String,   // 64 hex
    val encryptedTier0:              ByteArray, // metadata fragment (nonce+ct)
    val encryptedTier1:              ByteArray?, // first sentence, null until ≥10% frags
    val encryptedTier2:              ByteArray?, // full content; stored at creation for sender posts, null for received-only stubs until onConfirmed()
    val postHash:                    String,   // 64 hex — SHA3-256 of encryptedTier2 bytes (NOT plaintext)
    val createdAtMs:                 Long,
    val ttlMs:                       Long,
    val burnAfterRead:               Boolean = false,
    val postState:                   PostState = PostState.PENDING,
    val ratchetIndex:                Int = 0,
    /**
     * Monotonically increasing per (channelId, authorNodeId).
     * Used for clock-independent message ordering — the UI sorts by sequenceNumber
     * rather than createdAtMs so clock skew cannot reorder a sender's own messages.
     * 0 = legacy / unknown (pre-v14 posts).
     */
    val sequenceNumber:              Long = 0L,
    val fragmentsReceived:           Int = 0,
    val fragmentsTotal:              Int = 0,
    // FIX (B1): tracks whether the 10% fragment threshold has been crossed.
    // encryptedTier1 bytes are stored at creation (for non-COMPARTMENTED channels)
    // but the UI must not display them until tier1Unlocked = true.
    // Set by PostEngine.ingestFragment when received/total first crosses TIER1_THRESHOLD.
    val tier1Unlocked:               Boolean = false,
    /**
     * Timestamp when this post was first opened for reading on THIS device.
     * Null = unread. Set by PostEngine.openPost() on first access.
     * Used by the UI to compute per-channel unread counts without a separate table.
     * Never transmitted — local read state is per-device.
     */
    val openedAtMs:                  Long? = null,
    /**
     * True when this post arrived during a reconnect sync window — i.e., it was fetched by
     * [ChannelSyncCoordinator.onReconnect] after a period of disconnection rather than
     * received live from the gossip stream.
     *
     * Used by the UI to show a "While you were offline" separator grouping catch-up messages
     * from a partition or network absence period. Never transmitted — local display state only.
     *
     * Default false for posts received in normal online operation and for all pre-v12 rows.
     */
    val receivedOffline:             Boolean = false,
    /**
     * Non-null when this post is an endorsement of an OFFLINE_LOCAL post.
     * Stores the postId of the original offline post so the UI can cross-reference it.
     * Set only on the endorsing author's device; null on all other devices.
     * The endorsed content is embedded verbatim in this post's encrypted tier2.
     */
    val endorsedPostId:              String? = null,
) {
    override fun equals(other: Any?) = other is PostEntity && postId == other.postId
    override fun hashCode() = postId.hashCode()
}

// ── Fragment entity ───────────────────────────────────────────────────────────

/**
 * An individual fragment of a post. Stored locally until the post is complete
 * or TTL expires. Never contains plaintext — always the encrypted wire bytes.
 */
@Entity(
    tableName = "fragments",
    foreignKeys = [ForeignKey(
        entity = PostEntity::class,
        parentColumns = ["postId"],
        childColumns  = ["postId"],
        onDelete      = ForeignKey.CASCADE
    )],
    indices = [Index("postId")]
)
data class FragmentEntity(
    @PrimaryKey val fragmentId:      String,   // 64 hex
    val postId:                      String,
    val channelId:                   String,
    val index:                       Int,
    val total:                       Int,         // totalData + totalParity
    val totalData:                   Int = total, // data shards needed for FEC reconstruction
    val encryptedBytes:              ByteArray, // wire bytes — nonce + ciphertext
    val sha3Hash:                    String,   // 64 hex — SHA3-256 of encryptedBytes
    val receivedAtMs:                Long,
    val isOwn:                       Boolean = false  // sent by this node
) {
    override fun equals(other: Any?) = other is FragmentEntity && fragmentId == other.fragmentId
    override fun hashCode() = fragmentId.hashCode()
}

// ── Blocklist entity ──────────────────────────────────────────────────────────

/**
 * Local-only blocklist. A blocked key's fragments are silently discarded.
 * Never transmitted — each node enforces independently.
 * ~64 bytes per entry as per design doc.
 */
@Entity(tableName = "blocklist")
data class BlocklistEntry(
    @PrimaryKey val nodeId:          String,   // 64 hex
    val reason:                      String,
    val blockedAtMs:                 Long,
    val source:                      BlockSource
)

enum class BlockSource { LOCAL_DECISION, WATCHDOG, HONEY_ANCHOR }

// ── Reputation entity ─────────────────────────────────────────────────────────

/**
 * Local reputation cache — local heuristic only.
 * Key age, relay reliability, vouching depth → ReputationTier.
 * Never transmitted. Mandatory UI warning shown when displayed.
 * ~128 bytes per peer as per design doc.
 */
@Entity(tableName = "reputation")
data class ReputationEntry(
    @PrimaryKey val nodeId:          String,   // 64 hex
    val tier:                        ReputationTier,
    val keyAgeMs:                    Long,     // age of node's identity key
    val relaySuccessCount:           Int = 0,
    val relayFailureCount:           Int = 0,
    val vouchingDepth:               Int = 0,  // 0=none, 1=TRUST_PHYSICAL vouched, etc.
    val lastSeenMs:                  Long,
    val updatedAtMs:                 Long
)

// ── Poll entity ───────────────────────────────────────────────────────────────

/**
 * A poll attached to a post. Options stored as a JSON array of strings.
 * Votes are per-node — each node records its own vote locally.
 * Results are encrypted with the channel key and relayed as normal post fragments.
 * Polls expire with their parent post (ttlMs mirrors PostEntity.ttlMs).
 */
@Entity(
    tableName = "polls",
    foreignKeys = [ForeignKey(
        entity        = PostEntity::class,
        parentColumns = ["postId"],
        childColumns  = ["postId"],
        onDelete      = ForeignKey.CASCADE
    )],
    indices = [Index("postId")]
)
data class PollEntity(
    @PrimaryKey val pollId:      String,   // SHA3-256(postId || question)
    val postId:                  String,
    val channelId:               String,
    val question:                String,
    val optionsJson:             String,   // JSON array: ["Option A","Option B",...]
    val myVoteIndex:             Int = -1, // -1 = not voted
    val expiresAtMs:             Long,
    val createdAtMs:             Long
) {
    override fun equals(other: Any?) = other is PollEntity && pollId == other.pollId
    override fun hashCode() = pollId.hashCode()
}

// ── Poll vote entity ──────────────────────────────────────────────────────────

/**
 * A single vote cast by a peer node on a poll.
 *
 * Each peer's vote is relayed as an encrypted post fragment and stored here
 * after decryption. The vote tally (how many peers chose each option) is
 * derived by querying this table, not from PollEntity.myVoteIndex.
 *
 * myVoteIndex on PollEntity records only THIS device's vote for fast local
 * access. PollVoteEntity stores all received peer votes for aggregate display.
 *
 * Primary key: (pollId, voterNodeId) — one vote per voter per poll.
 * A voter who changes their vote sends a new encrypted vote fragment; the
 * DAO upserts (REPLACE) so the latest vote wins.
 *
 * Not persisted beyond TTL — purged with the parent poll.
 */
@Entity(
    tableName = "poll_votes",
    foreignKeys = [ForeignKey(
        entity        = PollEntity::class,
        parentColumns = ["pollId"],
        childColumns  = ["pollId"],
        onDelete      = ForeignKey.CASCADE
    )],
    indices = [Index("pollId"), Index("voterNodeId")],
    primaryKeys = ["pollId", "voterNodeId"]
)
data class PollVoteEntity(
    val pollId:       String,
    val voterNodeId:  String,   // hex node ID of the voter
    val optionIndex:  Int,      // which option they voted for (0-based)
    val receivedAtMs: Long      // when this vote fragment was received
) {
    override fun equals(other: Any?) = other is PollVoteEntity &&
        pollId == other.pollId && voterNodeId == other.voterNodeId
    override fun hashCode() = 31 * pollId.hashCode() + voterNodeId.hashCode()
}

/**
 * A per-post, per-author reaction (emoji/thumbs). One reaction per author per post.
 * Reactions are encrypted with the channel key — the reactionType is never in plaintext.
 * Stored locally as decrypted after successful channel key access.
 */
@Entity(
    tableName = "reactions",
    foreignKeys = [ForeignKey(
        entity        = PostEntity::class,
        parentColumns = ["postId"],
        childColumns  = ["postId"],
        onDelete      = ForeignKey.CASCADE
    )],
    indices = [Index("postId"), Index("authorNodeId")],
    primaryKeys = ["postId", "authorNodeId"]
)
data class ReactionEntity(
    val postId:        String,
    val authorNodeId:  String,   // hex node ID
    val reactionType:  String,   // emoji string, e.g. "👍", "❤️", "🔥"
    val encryptedBlob: ByteArray,// wire-format encrypted reaction for relay
    val receivedAtMs:  Long
) {
    override fun equals(other: Any?) = other is ReactionEntity &&
        postId == other.postId && authorNodeId == other.authorNodeId
    override fun hashCode() = 31 * postId.hashCode() + authorNodeId.hashCode()
}

// ── Entry Node preference ─────────────────────────────────────────────────────

/**
 * How the app selects the Entry Node for a given scope (global or per-channel).
 *
 *   AUTOMATIC  — use the global ranked preference list; fall back through the
 *                chain automatically if preferred nodes are offline.
 *   ASK_EACH_TIME — prompt the user before sending in any circuit-active channel.
 *                   The UI presents the available TRUST_PHYSICAL contacts and
 *                   the user picks before the post is dispatched. Suitable for
 *                   COMPARTMENTED channels where the user wants explicit control.
 */
enum class EntryNodeMode { AUTOMATIC, ASK_EACH_TIME }

/**
 * A single entry in the user's ranked Entry Node preference list.
 *
 * [rank] is 0-based — lower rank = higher preference. The app walks the list
 * in ascending rank order and uses the first available (online, not blocked) node.
 *
 * [channelOverrideId] is null for the global default list. When non-null, this
 * entry applies only to the specified channel (per-channel override). Per-channel
 * entries take precedence over global entries when a channel match exists.
 *
 * [displayName] is a local-only nickname the user assigned at bootstrap time.
 * Never transmitted. Shown in the Entry Node picker UI.
 *
 * The underlying nodeId is the 64-hex identity of the TRUST_PHYSICAL contact.
 * Only TRUST_PHYSICAL contacts are eligible — enforced at insert time by
 * [EntryNodeStore].
 */
@Entity(
    tableName = "entry_node_preferences",
    indices   = [
        Index("rank"),
        Index("channelOverrideId"),
        Index(value = ["nodeId", "channelOverrideId"], unique = true)
    ]
)
data class EntryNodePreference(
    @PrimaryKey(autoGenerate = true)
    val id:                 Long = 0,
    val nodeId:             String,   // 64 hex — TRUST_PHYSICAL contact
    val displayName:        String,   // local nickname — never transmitted
    val rank:               Int,      // 0 = highest preference
    val channelOverrideId:  String?,  // null = global; non-null = per-channel override
    val addedAtMs:          Long = System.currentTimeMillis()
) {
    override fun equals(other: Any?) = other is EntryNodePreference && id == other.id
    override fun hashCode() = id.hashCode()
}

// ── Key-value settings store ──────────────────────────────────────────────────

/**
 * Generic key-value settings table. Persists simple scalar settings such as the
 * Entry Node mode. Each key maps to exactly one string value; INSERT OR REPLACE
 * in the DAO ensures upsert semantics without a separate UPDATE query.
 */
@Entity(tableName = "node_settings")
data class NodeSettingEntity(
    @PrimaryKey val key:   String,
    val value:             String
)

// ── Rate limit state ──────────────────────────────────────────────────────────
// RateLimitBucket is defined in RateLimiter.kt (same package).
// Moved there so the bucket class and the limiter that owns it are co-located.
// This stub comment replaces the duplicate data class that was here — having two
// classes named RateLimitBucket in the same package is a compile error.

// ── Fragment entity ────────────────────────────────────────────────────────────
// Full implementation: core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/fragment/FragmentModels.kt
// FecScheme, FragmentEntity, FragmentMerkleTree, FragmentSet are defined there.
// The Phase 4 compilation stub has been removed now that Phase 5 is complete.

// ── SHADOWFILES transfer checkpoint entity ──────────────────────────────────────

/**
 * Resume checkpoint for a SHADOWFILES chunked transfer (design doc Phase 7).
 *
 * Replaces the earlier workaround that stored checkpoints as synthetic rows in the
 * `fragments` table — that overloaded the fragment schema and (after the fragment
 * entity diverged) no longer matched its columns. This is a dedicated table keyed by
 * transferId, recording the highest confirmed chunk so a reconnect resumes from there
 * instead of restarting at chunk 0.
 */
@Entity(tableName = "transfer_checkpoints")
data class TransferCheckpointEntity(
    @PrimaryKey val transferId: String,
    val lastChunkIndex:         Int,
    val totalChunks:            Int,
    val updatedAtMs:            Long
)

// ── Bootstrap nonce store ────────────────────────────────────────────────────

/**
 * Persisted record of a consumed QR/NFC bootstrap nonce.
 *
 * PhysicalKeyExchange.receiveQrCode and receivePayload both carry a short-lived
 * nonce (8 bytes for QR, derived from timestamp+nodeId). Without persistence, a
 * process restart clears the in-memory set and an attacker can replay a captured
 * QR code that was accepted moments before the crash — the timestamp freshness
 * check still passes if the replay occurs within the 5-minute validity window.
 *
 * Nonces are stored for [NONCE_RETAIN_MS] (10 minutes — 2× the payload validity
 * window) and then swept by [TtlSweepWorker]. The table is tiny: at most a few
 * rows per bootstrap session.
 *
 * @param nonceHex   Hex-encoded nonce bytes (primary key).
 * @param seenAtMs   Wall-clock time when this nonce was first accepted.
 */
@Entity(tableName = "used_bootstrap_nonces")
data class UsedBootstrapNonce(
    @PrimaryKey val nonceHex: String,
    val seenAtMs:             Long
) {
    companion object {
        /** Retain nonces for 2× the payload validity window (10 minutes). */
        const val NONCE_RETAIN_MS = 10L * 60 * 1000
    }
}

// ── Discovered peer cache ─────────────────────────────────────────────────────

/**
 * Persists DHT/local-transport peers seen during active sessions so that
 * [DhtEngine.bootstrap] can warm-start from known contacts rather than
 * re-discovering from scratch after a process restart.
 *
 * Entries older than [CACHE_RETAIN_MS] (7 days) are excluded from seeding by
 * the query in [ShadowMeshDao.getRecentDiscoveredPeers].  The table is never
 * deleted proactively — stale rows are simply not returned by the query, and the
 * next successful contact updates the timestamp via upsert.
 *
 * @param nodeIdHex   64-char hex node ID (primary key).
 * @param lastSeenMs  Wall-clock time of the last confirmed successful contact.
 * @param transport   Which transport yielded this peer ("DHT", "BLE", "LAN", "WIFI_DIRECT").
 * @param addressHint Best-known network address ("ip:port") for DHT/LAN peers; null for BLE.
 * @param trustLevel  Effective trust level at last contact ([TrustLevel.name]).
 */
@Entity(tableName = "discovered_peers")
data class DiscoveredPeerEntity(
    @PrimaryKey val nodeIdHex: String,   // 64-char hex
    val lastSeenMs:            Long,
    val transport:             String,   // "DHT", "BLE", "LAN", "WIFI_DIRECT"
    val addressHint:           String?,  // "ip:port" for network peers; null for BLE
    val trustLevel:            String    // TrustLevel.name()
) {
    companion object {
        /** Only seed bootstrap from peers seen within this window. */
        const val CACHE_RETAIN_MS = 7L * 24 * 60 * 60 * 1000  // 7 days
    }
}

// ── Member removal entry ──────────────────────────────────────────────────────

/**
 * Records an explicit channel membership removal event.
 *
 * Written when this device receives a [MemberRemovalFrame] from the gossip layer.
 * Used by [FragmentIngestor] to stop relaying fragments from removed members, and
 * by [ChannelManager] to show removal state in the UI.
 *
 * The table is keyed (channelId, removedNodeId) so a node that is removed and
 * re-added (new introduction) simply upserts over the old row.
 */
@Entity(
    tableName = "member_removals",
    primaryKeys = ["channelId", "removedNodeId"]
)
data class MemberRemovalEntry(
    val channelId:       String,
    val removedNodeId:   String,   // 64-char hex nodeId of the removed member
    val removedAtMs:     Long,
    val initiatorNodeId: String,   // 64-char hex nodeId of who performed the removal
    val receivedAtMs:    Long = System.currentTimeMillis()
)

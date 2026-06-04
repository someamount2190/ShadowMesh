package mesh.shadowmesh.storage

import androidx.room.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.PostRatchet
import mesh.shadowmesh.crypto.SymmetricCipher

/**
 * Ratchet state persistence — Phase 3 gap.
 *
 * PostRatchet is stateful: chain_key advances with every post. If the process
 * dies mid-session, the chain_key must be restored exactly — otherwise the
 * node cannot derive the correct post keys and cannot decrypt incoming posts.
 *
 * Storage model:
 *   The chain_key (32 bytes) is NEVER written to disk in plaintext.
 *   It is encrypted with the channel key before storage, using a per-checkpoint
 *   nonce. The channel key itself is already wrapped in the database; the
 *   chain_key is wrapped inside it — layered encryption.
 *
 * Persistence granularity:
 *   The ratchet writes a checkpoint every [PostRatchet.DEFAULT_CHECKPOINT_INTERVAL]
 *   posts (default 1000). Between checkpoints, the chain_key lives only in memory.
 *   On process death between checkpoints, the node restores from the last checkpoint
 *   and re-advances using the known post hashes from the post history.
 *
 *   This is the same recovery path as design doc §12.1 "Ratchet checkpoint".
 *
 * Thread-safety: all DAO operations use Dispatchers.IO.
 */

// ── Room entity ───────────────────────────────────────────────────────────────

/**
 * Per-SENDER ratchet checkpoint. The primary key is (channelId, senderNodeId).
 *
 * With shared-ratchet there was one row per channel. With per-sender ratchets there is
 * one row per (channel, sender) pair. The sender is the node whose chain this checkpoint
 * belongs to — your own node ID for your outbound chain, the remote node ID for each
 * inbound chain you are tracking.
 *
 * This schema replaces the previous single-column PK on channelId (database v11 → v12).
 */
@Entity(
    tableName = "ratchet_checkpoints",
    primaryKeys = ["channelId", "senderNodeId"]
)
data class RatchetCheckpointEntity(
    val channelId:           String,
    /** 64-char hex node ID of the sender whose chain this checkpoint belongs to. */
    val senderNodeId:        String,
    val encryptedChainKey:   ByteArray,   // XChaCha20-Poly1305(chain_key, channel_key)
    val postIndex:           Int,
    val updatedAtMs:         Long
) {
    override fun equals(other: Any?) = other is RatchetCheckpointEntity &&
        channelId == other.channelId && senderNodeId == other.senderNodeId
    override fun hashCode() = 31 * channelId.hashCode() + senderNodeId.hashCode()
}

// ── DAO ───────────────────────────────────────────────────────────────────────

@Dao
interface RatchetDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertCheckpoint(checkpoint: RatchetCheckpointEntity)

    @Query("SELECT * FROM ratchet_checkpoints WHERE channelId = :channelId AND senderNodeId = :senderNodeId")
    suspend fun getCheckpoint(channelId: String, senderNodeId: String): RatchetCheckpointEntity?

    @Query("DELETE FROM ratchet_checkpoints WHERE channelId = :channelId AND senderNodeId = :senderNodeId")
    suspend fun deleteCheckpoint(channelId: String, senderNodeId: String)

    /** Delete ALL sender checkpoints for a channel (called on channel departure / key rotation). */
    @Query("DELETE FROM ratchet_checkpoints WHERE channelId = :channelId")
    suspend fun deleteAllCheckpoints(channelId: String)

    /** Count all stored checkpoints. Used by PerProcessIntegrityChecker to verify DB accessibility. */
    @Query("SELECT COUNT(*) FROM ratchet_checkpoints")
    suspend fun countAll(): Int
}

// ── Store ─────────────────────────────────────────────────────────────────────

/**
 * Saves and restores ratchet state across process death.
 *
 * Usage:
 *   // On each ratchet checkpoint (every 1000 posts):
 *   store.save(channelId, ratchet.exportCheckpoint(), ratchet.currentPostIndex(), channelKey)
 *
 *   // On process restart, before processing any posts:
 *   val (chainKey, postIndex) = store.restore(channelId, channelKey) ?: <init from scratch>
 *   ratchet.restoreFromCheckpoint(chainKey, postIndex)
 *   chainKey.fill(0)  // wipe after restoring
 */
class RatchetStateStore(
    private val dao:    RatchetDao,
    private val cipher: SymmetricCipher = SymmetricCipher()
) {
    /**
     * Persist a per-sender ratchet checkpoint.
     *
     * @param channelId    The channel this ratchet belongs to.
     * @param senderNodeId 64-char hex node ID of the ratchet owner (your local ID for
     *                     your outbound chain; remote node ID for inbound chains).
     * @param chainKey     32-byte chain key from [PostRatchet.exportCheckpoint].
     * @param postIndex    Current post index from [PostRatchet.currentPostIndex].
     * @param channelKey   32-byte channel key — wraps chainKey for storage.
     */
    suspend fun save(
        channelId:    String,
        senderNodeId: String,
        chainKey:     ByteArray,
        postIndex:    Int,
        channelKey:   ByteArray
    ) = withContext(Dispatchers.IO) {
        require(chainKey.size == 32)   { "chainKey must be 32 bytes" }
        require(channelKey.size == 32) { "channelKey must be 32 bytes" }

        val encryptedChainKey = cipher.encrypt(chainKey, channelKey).getOrThrow()
        dao.upsertCheckpoint(RatchetCheckpointEntity(
            channelId         = channelId,
            senderNodeId      = senderNodeId,
            encryptedChainKey = encryptedChainKey,
            postIndex         = postIndex,
            updatedAtMs       = System.currentTimeMillis()
        ))
    }

    /**
     * Restore a per-sender ratchet checkpoint.
     *
     * @param senderNodeId 64-char hex node ID of the ratchet owner.
     * @param channelKey   32-byte channel key — decrypts the stored chain key.
     * @return [RestoredRatchet] or null if no checkpoint exists for this (channel, sender) pair.
     *
     * The caller MUST wipe [RestoredRatchet.chainKey] with fill(0) after use.
     */
    suspend fun restore(
        channelId:    String,
        senderNodeId: String,
        channelKey:   ByteArray
    ): RestoredRatchet? = withContext(Dispatchers.IO) {
        require(channelKey.size == 32) { "channelKey must be 32 bytes" }
        val entity = dao.getCheckpoint(channelId, senderNodeId) ?: return@withContext null
        val chainKey = cipher.decrypt(entity.encryptedChainKey, channelKey).getOrThrow()
        RestoredRatchet(chainKey = chainKey, postIndex = entity.postIndex)
    }

    /**
     * Delete a specific sender's ratchet checkpoint.
     * Called when a specific sender's chain is evicted (e.g., sender departed channel).
     */
    suspend fun delete(channelId: String, senderNodeId: String) = withContext(Dispatchers.IO) {
        dao.deleteCheckpoint(channelId, senderNodeId)
    }

    /**
     * Delete ALL sender checkpoints for a channel.
     * Called on channel departure or key rotation — all per-sender chains are invalidated
     * because the channel key (which seeds every sender's chain) has changed.
     */
    suspend fun deleteAll(channelId: String) = withContext(Dispatchers.IO) {
        dao.deleteAllCheckpoints(channelId)
    }

    /**
     * Returns true if the ratchet checkpoint table is accessible without error.
     * Used by [PerProcessIntegrityChecker] to verify the SQLCipher database is still
     * decryptable with the current device secret. A query exception indicates that the
     * database key has changed, the DB file is corrupted, or the DB has been deleted.
     */
    suspend fun checkAccessible(): Boolean = withContext(Dispatchers.IO) {
        runCatching { dao.countAll() >= 0 }.getOrDefault(false)
    }
}

data class RestoredRatchet(
    val chainKey:  ByteArray,  // 32 bytes — MUST be wiped after use
    val postIndex: Int
) {
    override fun equals(other: Any?) = other is RestoredRatchet &&
        chainKey.contentEquals(other.chainKey) && postIndex == other.postIndex
    override fun hashCode() = 31 * chainKey.contentHashCode() + postIndex
}

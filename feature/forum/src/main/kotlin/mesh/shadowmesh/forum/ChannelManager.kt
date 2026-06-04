package mesh.shadowmesh.forum

import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.storage.*
import mesh.shadowmesh.storage.PostState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import mesh.shadowmesh.crypto.toHex

/**
 * Channel management — design doc Phase 3.
 *
 * Handles:
 *   - Channel creation with type enforcement and key assignment
 *   - Biometric gate for COMPARTMENTED channel access
 *   - Voluntary departure — local key deletion
 *   - Key rotation for spam expulsion (CLOSED channels)
 *   - Channel list persistence across restart
 *
 * Channel types:
 *   OPEN        — public read; posts encrypted with a shared gossip key
 *   CLOSED      — membership key; key rotation expels members
 *   COMPARTMENTED — biometric-gated; physical re-exchange required for rotation
 *   ANONYMOUS   — no author attribution in post metadata
 *
 * Key management:
 *   OPEN/CLOSED keys: derived via IntegrityBoundedKeyDerivation and stored
 *   wrapped in the database (BiometricKeyManager not required).
 *   COMPARTMENTED keys: wrapped by BiometricKeyManager with 30s auth window.
 *   On departure: encryptedKeyBlob is wiped to X'' in the database.
 *
 * Thread-safety: all DAO operations use Dispatchers.IO.
 */
class ChannelManager(
    private val dao:    ShadowMeshDao,
    private val hkdf:   Hkdf = Hkdf.instance,
    private val cipher: SymmetricCipher = SymmetricCipher()
) {

    // ── Observe ───────────────────────────────────────────────────────────

    /** Live list of active (non-departed) channels, ordered by last activity. */
    fun observeActiveChannels(): Flow<List<ChannelEntity>> = dao.observeActiveChannels()

    // ── Create ────────────────────────────────────────────────────────────

    /**
     * Create a new channel.
     *
     * @param name            Display name.
     * @param type            Channel type — enforces access and key rules.
     * @param genesisNodeId   The creating node's ID (32 bytes, used in channelId derivation).
     * @param wrappedKey      Pre-wrapped channel key bytes. The caller is responsible
     *                        for wrapping via BiometricKeyManager (COMPARTMENTED) or
     *                        IntegrityBoundedKeyDerivation (others) before calling here.
     *                        This class does not touch unwrapped key material.
     */
    suspend fun createChannel(
        name:          String,
        type:          ChannelType,
        genesisNodeId: ByteArray,
        wrappedKey:    ByteArray,
        nowMs:         Long = System.currentTimeMillis()
    ): ChannelEntity = withContext(Dispatchers.IO) {
        require(name.isNotBlank())    { "Channel name must not be blank" }
        require(genesisNodeId.size == 32) { "genesisNodeId must be 32 bytes" }

        val genesisHash = hkdf.sha3_256(genesisNodeId + name.toByteArray() + longToBytes(nowMs))
        val channelId   = hkdf.sha3_256(genesisHash + type.name.toByteArray()).toHex()

        val entity = ChannelEntity(
            channelId       = channelId,
            name            = name,
            type            = type,
            encryptedKeyBlob = wrappedKey,
            genesisHash     = genesisHash.toHex(),
            createdAtMs     = nowMs,
            lastActivityMs  = nowMs
        )
        dao.upsertChannel(entity)
        entity
    }

    // ── Access ────────────────────────────────────────────────────────────

    /**
     * Retrieve a channel. Returns null if not found or if the node has departed.
     * Callers must check [ChannelEntity.departed] before accessing key material.
     */
    suspend fun getChannel(channelId: String): ChannelEntity? =
        withContext(Dispatchers.IO) { dao.getChannel(channelId) }

    /**
     * Check that COMPARTMENTED channel access is gated — the caller must have
     * already authenticated via BiometricPrompt within the 30s window.
     * Returns true if access should proceed; false if biometric gate not satisfied.
     *
     * This is an assertion point — actual biometric auth happens in the UI layer
     * via BiometricKeyManager. This method validates the type constraint only.
     */
    fun requiresBiometricGate(channel: ChannelEntity): Boolean =
        channel.type == ChannelType.COMPARTMENTED

    // ── Departure ─────────────────────────────────────────────────────────

    /**
     * Voluntary departure from a channel.
     *
     * Wipes the encrypted key blob from the database. After departure:
     *   - The node cannot decrypt new posts (key gone).
     *   - The node cannot post (no key for fragment auth).
     *   - Local cache remains until manually cleared or TTL expires.
     *   - Rejoin requires out-of-band key distribution.
     *
     * The global channel ([GlobalChannel.ID]) cannot be departed — [ensureGlobalChannel]
     * will restore it on the next launch regardless. This call is a no-op for that ID.
     */
    suspend fun departChannel(channelId: String) = withContext(Dispatchers.IO) {
        if (channelId == GlobalChannel.ID) return@withContext
        dao.markDeparted(channelId)
    }

    /**
     * Ensure the global public channel exists in the database.
     *
     * Idempotent — safe to call on every app launch. Upserts the channel so it is
     * restored even if the user previously departed it (departure is blocked by
     * [departChannel], but a wiped DB or re-install scenario also needs recovery).
     *
     * [wrappedKey] is the raw global channel key wrapped by KeyOrchestrator using
     * the device-local HKDF+device-secret mechanism (same as OPEN channels).
     */
    suspend fun ensureGlobalChannel(wrappedKey: ByteArray) = withContext(Dispatchers.IO) {
        val entity = ChannelEntity(
            channelId        = GlobalChannel.ID,
            name             = GlobalChannel.NAME,
            type             = ChannelType.GLOBAL,
            encryptedKeyBlob = wrappedKey,
            genesisHash      = GlobalChannel.GENESIS_HASH,
            createdAtMs      = GlobalChannel.CREATED_AT_MS,
            lastActivityMs   = GlobalChannel.CREATED_AT_MS,
            departed         = false,
        )
        dao.upsertChannel(entity)
    }

    // ── Key rotation (CLOSED channels) ────────────────────────────────────

    /**
     * Rotate the channel key to expel a member — CLOSED channels only.
     *
     * The caller must:
     *   1. Generate a new channel key.
     *   2. Distribute it out-of-band to all retained members
     *      (Tier B invite token, Signal, printed QR — same as initial join).
     *   3. Call this method with the new wrapped key.
     *   4. Post the first message with the new key to signal rotation is live.
     *
     * The expelled node retains the old key and can read old posts up to the
     * rotation point, but cannot read any post after rotation.
     *
     * COMPARTMENTED channels: physical re-exchange required. Digital distribution
     * is prohibited — a mechanism that could rotate digitally would be a mechanism
     * an adversary could trigger.
     *
     * @param channelId     The channel to rotate.
     * @param newWrappedKey New wrapped key bytes from the caller.
     * @param channelType   Must be CLOSED. COMPARTMENTED caller must use physical exchange.
     */
    suspend fun rotateKey(
        channelId:    String,
        newWrappedKey:ByteArray,
        channelType:  ChannelType
    ) = withContext(Dispatchers.IO) {
        require(channelType == ChannelType.CLOSED) {
            "Key rotation via this method is only valid for CLOSED channels. " +
            "COMPARTMENTED channels require physical re-exchange."
        }
        val existing = dao.getChannel(channelId)
            ?: throw IllegalStateException("Channel $channelId not found")
        dao.upsertChannel(existing.copy(
            encryptedKeyBlob      = newWrappedKey,
            keyVersionNumber      = existing.keyVersionNumber + 1,
            keyVersionTimestampMs = System.currentTimeMillis()
        ))
    }


    // ── Backend integration hooks ─────────────────────────────────────────

    /**
     * Snapshot of all active (non-departed) channels at this instant.
     * Used by [ChannelSyncCoordinator.onReconnect] to iterate channels for sync.
     * Unlike [observeActiveChannels], this is a one-shot suspend call, not a Flow.
     */
    suspend fun activeChannelSnapshot(): List<ChannelEntity> =
        withContext(Dispatchers.IO) { dao.getActiveChannels() }

    /**
     * Returns the channelIds of channels that have at least one post in [state].
     * Used by [ChannelSyncCoordinator.syncCycle] to find channels with SYNCING posts.
     */
    suspend fun channelsWithState(state: PostState): List<String> =
        withContext(Dispatchers.IO) { dao.channelIdsWithPostState(state) }

    // ── Touch ─────────────────────────────────────────────────────────────

    suspend fun touchActivity(channelId: String, nowMs: Long = System.currentTimeMillis()) =
        withContext(Dispatchers.IO) { dao.touchChannel(channelId, nowMs) }
}

// ── Helpers ───────────────────────────────────────────────────────────────────


private fun longToBytes(v: Long): ByteArray = ByteArray(8) { i ->
    ((v shr ((7 - i) * 8)) and 0xFF).toByte()
}

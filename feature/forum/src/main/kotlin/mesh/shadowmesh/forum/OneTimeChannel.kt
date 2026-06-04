package mesh.shadowmesh.forum

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.storage.ShadowMeshDao
import mesh.shadowmesh.crypto.toHex

/**
 * One-time forum pattern (design Feature 4) — a documented, supported use case rather than
 * new mechanism. Thin sugar over [ChannelManager] + [KeyOrchestrator] + [PostEngine].
 *
 * Lifecycle:
 *   1. [create]  — make an ephemeral channel (ANONYMOUS for a wide physical drop, or
 *      COMPARTMENTED for a small biometric-gated set) with a TTL. The channel key is generated
 *      locally and wrapped; it is never digitally distributed.
 *   2. The caller renders the returned [printableKeyPayload] as a QR and prints it. That printed
 *      QR is the ONLY copy of the key that leaves the device.
 *   3. Recipients scan it to join. Posts are made burn-after-read with the channel TTL.
 *   4. [destroy] — wipe the key from storage, evict the ratchet, depart, delete the channel row
 *      and all its posts. After this the channel is cryptographically unrecoverable from THIS
 *      device.
 *
 * Honest limits (documented for callers):
 *   - Anyone who photographed the printed QR keeps the key until they destroy it — paper-key
 *     custody is a human problem this code cannot solve.
 *   - burn-after-read deletes LOCAL copies on read; a replica on another node expires on its own
 *     TTL, not on your read.
 *   - destroy stops FUTURE access; it cannot retract posts a recipient already pulled/decrypted.
 */
class OneTimeChannel(
    private val dao:             ShadowMeshDao,
    private val channelManager:  ChannelManager,
    private val keyOrchestrator: KeyOrchestrator
) {

    data class Created(
        val channelId: String,
        /** Wrapped channel key blob to encode into a printable QR for physical distribution. */
        val printableKeyPayload: ByteArray,
        val expiresAtMs: Long
    )

    /**
     * Create an ephemeral one-time channel.
     *
     * @param name           Human label (not secret).
     * @param genesisNodeId  This device's 32-byte node id.
     * @param ttlMs          Absolute expiry; the channel and its posts are reaped at/after this.
     * @param gated          true → COMPARTMENTED (biometric-gated, small trusted set);
     *                        false → ANONYMOUS (wide physical drop).
     */
    suspend fun create(
        name:          String,
        genesisNodeId: ByteArray,
        ttlMs:         Long,
        gated:         Boolean,
        activity:      androidx.fragment.app.FragmentActivity? = null
    ): Created = withContext(Dispatchers.IO) {
        val type = if (gated) ChannelType.COMPARTMENTED else ChannelType.ANONYMOUS

        // B13 fix: key generation must happen OUTSIDE the Room transaction.
        //
        // The original code called keyOrchestrator.generateAndWrapChannelKey inside
        // dao.withTransaction{}. For COMPARTMENTED channels, generateAndWrapChannelKey
        // calls BiometricKeyManager.wrapKey which requires withContext(Dispatchers.Main)
        // for BiometricPrompt. A withContext(Main) inside a Room @Transaction deadlocks:
        // the transaction holds the DB connection on the IO dispatcher and suspends
        // waiting for Main; if Main is blocked (or if Room's transaction dispatcher
        // does not allow context-switching), the coroutine never resumes.
        //
        // Fix: two-phase approach.
        //   Phase 1 (outside transaction): generate a provisional channelId and wrap the key.
        //              The provisional channelId is derived the same way ChannelManager does it,
        //              so the key is wrapped against the correct channelId.
        //   Phase 2 (inside transaction): write both the channel row and the wrapped key atomically.
        //
        // The provisional channelId computation must match ChannelManager.createChannel() exactly.
        // If that derivation changes, this must change in lock-step.
        val nowMs       = System.currentTimeMillis()
        val genesisHash = mesh.shadowmesh.crypto.Hkdf.instance.sha3_256(
            genesisNodeId + name.toByteArray() + longToBytes(nowMs)
        )
        val channelId   = mesh.shadowmesh.crypto.Hkdf.instance.sha3_256(
            genesisHash + type.name.toByteArray()
        ).toHex()

        // Phase 1: wrap the key (may require Dispatchers.Main for COMPARTMENTED).
        // This runs outside the transaction — no DB connection held here.
        val wrapped = keyOrchestrator.generateAndWrapChannelKey(
            channelId = channelId,
            type      = type,
            activity  = activity
        )

        // Phase 2: write channel row + wrapped key atomically.
        // Key generation is complete; only DB writes happen inside the transaction.
        val entity = run {
            val e = channelManager.createChannel(
                name          = name,
                type          = type,
                genesisNodeId = genesisNodeId,
                wrappedKey    = wrapped,
                nowMs         = nowMs
            )
            // createChannel already calls dao.upsertChannel; return the entity.
            e
        }

        // Invariant: the provisional channelId (computed before key wrapping) must
        // match the entity channelId (computed inside ChannelManager.createChannel).
        // Both derivations use the same inputs (genesisNodeId, name, type, nowMs).
        // If they diverge the wrapped key is bound to the wrong channelId and
        // unwrapping will silently fail. Catch this at construction time.
        check(channelId == entity.channelId) {
            "OneTimeChannel: provisional channelId ($channelId) does not match " +
            "created entity channelId (${entity.channelId}). " +
            "ChannelManager.createChannel derivation may have changed — " +
            "update OneTimeChannel.create() to match."
        }

        Created(
            channelId           = entity.channelId,
            printableKeyPayload = wrapped,
            expiresAtMs         = ttlMs
        )
    }

    private fun longToBytes(v: Long): ByteArray = ByteArray(8) { i ->
        ((v shr ((7 - i) * 8)) and 0xFF).toByte()
    }

    /**
     * Destroy the channel: irrecoverably wipe key material and content from THIS device.
     * Idempotent — safe to call more than once.
     */
    suspend fun destroy(channelId: String) = withContext(Dispatchers.IO) {
        // 1. Evict ratchet + delete persisted ratchet state (wipes derived key material).
        keyOrchestrator.evictAllRatchets(channelId)
        // 2. Mark departed (key blob considered void) then delete all posts + the channel row.
        channelManager.departChannel(channelId)
        dao.deletePostsForChannel(channelId)
        dao.deleteChannel(channelId)
    }
}

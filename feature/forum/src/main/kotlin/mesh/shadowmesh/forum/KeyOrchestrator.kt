package mesh.shadowmesh.forum

import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.security.BiometricKeyManager
import mesh.shadowmesh.security.BiometricKeyManager.ChannelSensitivity
import mesh.shadowmesh.storage.*
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import mesh.shadowmesh.crypto.hexToBytes
import java.util.concurrent.ConcurrentHashMap

/**
 * Emitted by [KeyOrchestrator.reportRatchetGap] when ratchet decryption fails for a post,
 * indicating the receiver's ratchet is out of sync (missed intermediate posts).
 *
 * [ChannelSyncCoordinator] subscribes to [KeyOrchestrator.ratchetGapEvents] and triggers
 * a full channel re-fetch when this event fires. The re-fetch attempts to recover the
 * intermediate postIds, advancing the ratchet back into sync.
 *
 * @param channelId  Hex channelId where the gap was detected.
 * @param gapPostId  PostId of the post that could not be decrypted (the gap post).
 */
data class RatchetGapEvent(
    val channelId: String,
    val gapPostId: String
)

/**
 * Key orchestrator — Phase 3 gap.
 *
 * The single place that knows the full key lifecycle for a channel:
 *
 *   1. GENERATION — produce a random 32-byte channel key
 *   2. WRAPPING    — encrypt it for storage:
 *                      COMPARTMENTED: BiometricKeyManager (Keystore + biometric)
 *                      OPEN/CLOSED/ANONYMOUS: HKDF(device_secret || apk_hash, channelId)
 *   3. STORAGE     — write wrapped key into ChannelEntity.encryptedKeyBlob via ChannelManager
 *   4. RETRIEVAL   — unwrap and return the 32-byte channel key for encrypt/decrypt
 *   5. WIPE        — on departure or key rotation, wipe the stored key blob
 *
 * The channel key never exists in plaintext on disk. It lives in memory only
 * for the duration of a single encrypt/decrypt operation and is wiped immediately
 * after use by the caller.
 *
 * Ratchet integration:
 *   KeyOrchestrator also owns the per-channel PostRatchet lifecycle:
 *   - Creates a fresh ratchet from the channel key on channel join
 *   - Restores from RatchetStateStore on process restart
 *   - Saves checkpoints when the ratchet signals one
 *   - Wipes the ratchet on departure
 *
 * Thread-safety: all operations dispatched to Dispatchers.IO except biometric
 * operations (which must be called from Main dispatcher via BiometricKeyManager).
 *
 * @param deviceSecret       32-byte hardware-backed secret from Android Keystore.
 *                           Used for OPEN/CLOSED/ANONYMOUS key wrapping.
 * @param apkBindingHash     32-byte APK binding hash from ApkIntegrityVerifier.
 *                           Combined with device secret for key derivation.
 * @param biometric          BiometricKeyManager instance. May be null in tests
 *                           where COMPARTMENTED channels are not exercised.
 * @param channelManager     For storing/retrieving channel entities.
 * @param ratchetStateStore  For persisting ratchet checkpoints.
 */
class KeyOrchestrator(
    private val deviceSecret:      ByteArray,
    private val apkBindingHash:    ByteArray,
    private val biometric:         BiometricKeyManager?,
    private val channelManager:    ChannelManager,
    private val ratchetStateStore: RatchetStateStore,
    private val hkdf:              Hkdf = Hkdf.instance,
    private val cipher:            SymmetricCipher = SymmetricCipher(),
    private val ibd:               IntegrityBoundedKeyDerivation = IntegrityBoundedKeyDerivation()
) {

    // B11 fix: ConcurrentHashMap replaces mutableMapOf.
    // getOrRestoreRatchet dispatches to Dispatchers.IO where multiple coroutines
    // can race on the cache miss path. Two concurrent callers both seeing a cache
    // miss would each restore a ratchet and one would silently overwrite the other,
    // losing that ratchet's advance history. computeIfAbsent is atomic — only one
    // caller wins and initialises; the other receives the winner's result.
    // Note: computeIfAbsent lambda must not suspend; async restoration is handled
    // by the suspend wrapper getOrRestoreRatchet below.
    private val ratchets = ConcurrentHashMap<String, PostRatchet>()

    // Per-channel Mutex that serialises advanceRatchet calls.
    //
    // PostRatchet is explicitly NOT thread-safe (see its KDoc). Two concurrent
    // advanceRatchet calls for the same channel on the same cached PostRatchet
    // instance would both read the same chainKey, derive the same postKey, and
    // both overwrite chainKey with the same next value — producing duplicate
    // message keys for two different posts. That is a catastrophic forward-secrecy
    // failure: two posts share a key, an observer who obtains either key can read
    // both, and the ratchet has effectively not advanced.
    //
    // The fix: every advanceRatchet call acquires the channel's Mutex before
    // touching the ratchet. Restoration (getOrRestoreRatchet) is also serialised
    // via the same Mutex on the slow path to prevent two concurrent restorations
    // from each creating a ratchet and advancing independently before putIfAbsent.
    //
    // computeIfAbsent (not getOrPut) is required here. Kotlin's getOrPut extension
    // on MutableMap calls get() then put() as two separate operations — not atomic.
    // Two concurrent cold-miss callers both see absent, both create a Mutex, and
    // both call put(): the second overwrites the first. Each caller then holds its
    // own Mutex instance, neither blocks the other, and both enter the critical
    // section simultaneously. computeIfAbsent holds the ConcurrentHashMap bucket
    // lock for the entire creation, guaranteeing all callers receive the same instance.
    private val ratchetMutexes = ConcurrentHashMap<String, Mutex>()

    // ── Ratchet gap resolution ─────────────────────────────────────────────

    /**
     * Emits [RatchetGapEvent] when ratchet decryption fails for a received post.
     * Bounded at 100 entries with DROP_OLDEST overflow so an attacker flooding
     * out-of-order posts cannot grow this queue without bound. Legitimate gap
     * bursts are rare and channel re-sync handles re-detection on the next cycle.
     * [ChannelSyncCoordinator] consumes events via [startGapResolution][].
     */
    val ratchetGapEvents: Channel<RatchetGapEvent> = Channel(
        capacity       = 100,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )

    /**
     * Report a ratchet desynchronisation for [channelId] at [gapPostId].
     *
     * Called by [FragmentIngestor] when ratchet-layer decryption fails for a post,
     * indicating the receiver's ratchet may have missed intermediate posts.
     * Non-suspending — uses [Channel.trySend] (never blocks with UNLIMITED capacity).
     */
    fun reportRatchetGap(channelId: String, gapPostId: String) {
        ratchetGapEvents.trySend(RatchetGapEvent(channelId, gapPostId))
    }

    // ── Channel key generation and storage ───────────────────────────────

    /**
     * Generate a fresh channel key, wrap it, and return the wrapped bytes
     * ready for [ChannelManager.createChannel].
     *
     * For COMPARTMENTED channels: requires [activity] for BiometricPrompt.
     * For other types: wraps using HKDF(device_secret || apk_hash, channelId).
     *
     * @param channelId  The channel ID (used as salt for OPEN/CLOSED wrapping).
     * @param type       Channel type — determines wrapping method.
     * @param activity   Required for COMPARTMENTED only. Null for others.
     */
    suspend fun generateAndWrapChannelKey(
        channelId: String,
        type:      ChannelType,
        activity:  FragmentActivity? = null
    ): ByteArray {
        val rawKey = cipher.generateKey()  // 32-byte random key
        return try {
            wrapKey(channelId, type, rawKey, activity)
        } finally {
            rawKey.fill(0)
        }
    }

    /**
     * Wrap a caller-supplied [rawKey] for [channelId].
     * Used by [ShadowMeshApplication] to wrap the well-known global channel key.
     * The caller MUST fill [rawKey] with zeros after this returns.
     */
    suspend fun wrapChannelKey(
        channelId: String,
        type:      ChannelType,
        rawKey:    ByteArray
    ): ByteArray = wrapKey(channelId, type, rawKey, activity = null)

    /**
     * Retrieve the plaintext channel key for [channelId].
     * The returned key is for immediate use — caller MUST wipe with fill(0) after use.
     *
     * For COMPARTMENTED: requires [activity] for BiometricPrompt (30s window).
     * For others: unwraps using HKDF derivation (no UI interaction).
     *
     * Returns null if the channel has been departed (key wiped).
     */
    suspend fun retrieveChannelKey(
        channelId: String,
        type:      ChannelType,
        activity:  FragmentActivity? = null
    ): ByteArray? = withContext(Dispatchers.IO) {
        val channel = channelManager.getChannel(channelId) ?: return@withContext null
        if (channel.departed) return@withContext null
        if (channel.encryptedKeyBlob.isEmpty()) return@withContext null

        unwrapKey(channelId, type, channel.encryptedKeyBlob, activity)
    }

    // ── Ratchet lifecycle ─────────────────────────────────────────────────

    // ── Per-sender ratchet key ────────────────────────────────────────────
    //
    // Ratchets are keyed by "$channelId:$senderNodeId" (hex senderNodeId).
    // Each sender in a channel has an independent ratchet chain seeded from
    // HKDF(channelKey, salt=senderNodeId, info="shadowmesh_sender_ratchet_v1").
    //
    // This eliminates ratchet divergence under network partition: isolated clusters
    // each advance only their own members' chains, which are disjoint. On merge,
    // receivers catch up each sender's chain independently by replaying that
    // sender's posts in arrival order — no global ordering required.

    private fun ratchetKey(channelId: String, senderNodeId: String) = "$channelId:$senderNodeId"

    /**
     * Get or restore the per-sender PostRatchet for [channelId] / [senderNodeId].
     *
     * @param channelKey   32-byte channel key (unwrapped). Wiped internally after use.
     * @param senderNodeId 64-char hex node ID of the ratchet owner.
     */
    suspend fun getOrRestoreRatchet(
        channelId:    String,
        senderNodeId: String,
        channelKey:   ByteArray
    ): PostRatchet = withContext(Dispatchers.IO) {
        val key = ratchetKey(channelId, senderNodeId)
        // Fast path: already cached
        ratchets[key]?.let { return@withContext it }

        // Slow path: restore from checkpoint or derive fresh from (channelKey, senderNodeId)
        val restored = ratchetStateStore.restore(channelId, senderNodeId, channelKey)
        val senderIdBytes = hexToBytes(senderNodeId)
        val candidate = if (restored != null) {
            val r = PostRatchet.fromCheckpoint(restored.chainKey, restored.postIndex, hkdf)
            restored.chainKey.fill(0)
            r
        } else {
            PostRatchet.fromChannelKeyAndSender(channelKey, senderIdBytes, hkdf)
        }

        val winner = ratchets.putIfAbsent(key, candidate)
        if (winner != null && winner !== candidate) {
            // This thread lost the putIfAbsent race: another concurrent call already inserted
            // a ratchet for this key. The losing `candidate` is permanently abandoned.
            // Without this wipe, the candidate's 32-byte chainKey ByteArray sits in heap
            // memory until GC collects it — recoverable by a memory scan between creation
            // and collection. Wipe immediately to close the window.
            candidate.zeroChainKey()
            return@withContext winner
        }
        candidate
    }

    /**
     * Advance the per-sender ratchet for [channelId] / [senderNodeId] by one post.
     *
     * Pass [senderNodeId] = your own node ID (hex) when dispatching outbound posts.
     * Pass [senderNodeId] = the author's node ID (hex) when processing inbound posts.
     *
     * @param senderNodeId 64-char hex node ID of the ratchet owner.
     * @param postHash     SHA3-256 hash of the post content.
     * @param type         Channel type — determines key unwrapping method.
     * @param activity     Required for COMPARTMENTED channels only.
     */
    suspend fun advanceRatchet(
        channelId:    String,
        senderNodeId: String,
        postHash:     ByteArray,
        type:         ChannelType,
        activity:     androidx.fragment.app.FragmentActivity? = null
    ): RatchetStep = withContext(Dispatchers.IO) {
        val key   = ratchetKey(channelId, senderNodeId)
        val mutex = ratchetMutexes.computeIfAbsent(key) { Mutex() }
        mutex.withLock {
            val ratchet = ratchets[key] ?: run {
                val channelKey = retrieveChannelKey(channelId, type, activity)
                    ?: throw IllegalStateException(
                        "Cannot advance ratchet for $channelId/$senderNodeId — channel key unavailable"
                    )
                try {
                    getOrRestoreRatchet(channelId, senderNodeId, channelKey)
                } finally {
                    channelKey.fill(0)
                }
            }

            val step = ratchet.advance(postHash)

            val stepCheckpoint = step.checkpoint
            if (stepCheckpoint != null) {
                val channelKey = retrieveChannelKey(channelId, type, activity)
                    ?: throw IllegalStateException(
                        "Cannot retrieve channel key for checkpoint — $channelId/$senderNodeId departed?"
                    )
                try {
                    ratchetStateStore.save(channelId, senderNodeId, stepCheckpoint, step.postIndex, channelKey)
                } finally {
                    channelKey.fill(0)
                }
            }

            step
        }
    }

    /**
     * Evict a specific sender's ratchet for [channelId] and delete its persisted checkpoint.
     * Called when a sender departs the channel or their chain needs to be reset.
     */
    suspend fun evictRatchet(channelId: String, senderNodeId: String) = withContext(Dispatchers.IO) {
        val key = ratchetKey(channelId, senderNodeId)
        ratchets.remove(key)?.zeroChainKey()
        ratchetMutexes.remove(key)
        ratchetStateStore.delete(channelId, senderNodeId)
    }

    /**
     * Evict ALL per-sender ratchets for [channelId] and delete all persisted checkpoints.
     * Called on channel departure or key rotation — all chains are invalidated together
     * because the channel key (which seeds every sender's chain) has changed.
     */
    suspend fun evictAllRatchets(channelId: String) = withContext(Dispatchers.IO) {
        val prefix = "$channelId:"
        val toEvict = ratchets.keys().toList().filter { it.startsWith(prefix) }
        toEvict.forEach { key ->
            ratchets.remove(key)?.zeroChainKey()
            ratchetMutexes.remove(key)
        }
        ratchetStateStore.deleteAll(channelId)
    }

    /**
     * Panic wipe — step 7.
     *
     * Immediately clears all in-memory chain keys from every active ratchet.
     * Each chain key is zeroed via [PostRatchet.zeroChainKey] before the ratchet
     * is removed from the map, minimising the window during which a memory-dump
     * attacker could recover key material.
     *
     * This does NOT delete persisted checkpoints — the DB is already unreadable
     * after step 1 (SQLCipher key eviction) and deleted in step 2. Calling
     * [evictRatchet] per channel during a panic would race with ongoing DB deletion.
     *
     * Safe to call from any thread — [ratchets] is a [ConcurrentHashMap].
     */
    fun wipeAllRatchets() {
        val keys = ratchets.keys().toList()
        keys.forEach { channelId ->
            ratchets.remove(channelId)?.zeroChainKey()
        }
        ratchetMutexes.clear()
    }

    // ── Key wrapping internals ────────────────────────────────────────────

    private suspend fun wrapKey(
        channelId: String,
        type:      ChannelType,
        rawKey:    ByteArray,
        activity:  FragmentActivity?
    ): ByteArray = when (type) {
        ChannelType.COMPARTMENTED -> {
            requireNotNull(activity) { "FragmentActivity required for COMPARTMENTED channel key wrapping" }
            requireNotNull(biometric) { "BiometricKeyManager required for COMPARTMENTED channels" }
            val wrapped = biometric.wrapKey(
                activity    = activity,
                keyAlias    = BiometricKeyManager.channelKeyAlias(channelId),
                keyBytes    = rawKey,
                sensitivity = ChannelSensitivity.COMPARTMENTED
            )
            wrapped.toBytes()
        }
        else -> {
            // Derive a wrapping key from device_secret + apk_hash + channelId
            val wrappingKey = deriveWrappingKey(channelId)
            try {
                cipher.encrypt(rawKey, wrappingKey).getOrThrow()
            } finally {
                wrappingKey.fill(0)
            }
        }
    }

    private suspend fun unwrapKey(
        channelId:   String,
        type:        ChannelType,
        wrappedBlob: ByteArray,
        activity:    FragmentActivity?
    ): ByteArray = when (type) {
        ChannelType.COMPARTMENTED -> {
            requireNotNull(activity) { "FragmentActivity required for COMPARTMENTED channel key unwrapping" }
            requireNotNull(biometric) { "BiometricKeyManager required for COMPARTMENTED channels" }
            val wrapped = mesh.shadowmesh.security.WrappedKey.fromBytes(wrappedBlob)
            biometric.unwrapKey(
                activity    = activity,
                keyAlias    = BiometricKeyManager.channelKeyAlias(channelId),
                wrapped     = wrapped,
                sensitivity = ChannelSensitivity.COMPARTMENTED
            )
        }
        else -> {
            val wrappingKey = deriveWrappingKey(channelId)
            try {
                cipher.decrypt(wrappedBlob, wrappingKey).getOrThrow()
            } finally {
                wrappingKey.fill(0)
            }
        }
    }

    private fun deriveWrappingKey(channelId: String): ByteArray =
        ibd.derive(
            deviceSecret       = deviceSecret,
            apkBindingHash     = apkBindingHash,
            channelGenesisHash = hkdf.sha3_256(channelId.toByteArray()).copyOf(32),
            purpose            = IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL
        )
}

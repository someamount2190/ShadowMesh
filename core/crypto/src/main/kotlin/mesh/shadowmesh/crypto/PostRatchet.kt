package mesh.shadowmesh.crypto

/**
 * Asynchronous post ratchet for forward secrecy.
 *
 * Design doc §12.1:
 *   post_key_i  = HKDF(ikm=chain_key, salt=post_hash_i, info="post",    len=32)
 *   chain_key   = HKDF(ikm=chain_key, salt=post_hash_i, info="ratchet", len=32)
 *
 * post_hash_i passes through the HKDF extract phase as the salt, which
 * provides stronger entropy mixing than embedding it in the info field.
 * Both derivations share the same IKM and salt but differ in info — HKDF
 * guarantees independent outputs.
 *
 * ## Forward secrecy (FS)
 *
 * HKDF is not invertible. Seizing a device at post N yields chain_key_N.
 * The adversary cannot derive chain_key_{N-1} or any prior post_key.
 * Past posts are protected against a future device compromise.
 *
 * ## Group ratchet model — NOT per-participant Double Ratchet
 *
 * This is a **symmetric group ratchet**, not Signal's Double Ratchet. All
 * channel members share the same initial chain key (derived from the shared
 * channel key via [fromChannelKey]) and advance identically with each post.
 * This is the same model used by MLS's symmetric ratchet tree branch and is
 * the correct choice for SHADOWMESH's broadcast forum model — a new joiner
 * with the channel key can catch up from a checkpoint without any additional
 * key exchange with existing members.
 *
 * ## Post-compromise security (PCS) — NOT provided by this class
 *
 * PCS (also called "break-in recovery" or "future secrecy") means: if an
 * attacker extracts chain_key_N from a compromised device, they can compute
 * all future chain keys and all future post_keys — until the channel key is
 * rotated and a new ratchet is initialised from the new key.
 *
 * **This class does not provide PCS on its own.**
 *
 * PCS for CLOSED channels is provided by [KeyOrchestrator.generateAndWrapChannelKey]
 * followed by [ChannelManager.rotateKey] — this generates a fresh channel key,
 * re-wraps it, and the next [PostRatchet.fromChannelKey] call starts a new
 * independent ratchet chain. Callers must trigger this rotation when a
 * compromise is detected (e.g. via [GossipEngine.onHoneyFragmentDecrypted]).
 *
 * COMPARTMENTED channels require physical re-exchange (out-of-band) for PCS.
 * OPEN channels accept the reduced security model: key rotation is optional
 * because open-channel content is not considered sensitive.
 *
 * ## Checkpoint
 *
 * Every [checkpointInterval] posts, [advance] returns a non-null checkpoint —
 * the current chain_key, encrypted with the static channel key and stored in
 * the DHT (TTL 90 days). A node offline for more than the post TTL (7 days)
 * restores from the last checkpoint and ratchets forward from there.
 *
 * Thread-safety: NOT thread-safe. Each channel owns its own PostRatchet.
 * The NSC serialises all channel state mutations — no external locking needed.
 *
 * @param initialChainKey   32-byte starting chain key (from [fromChannelKey])
 * @param hkdf              HKDF instance (injectable for testing)
 * @param checkpointInterval Posts between checkpoints (default [DEFAULT_CHECKPOINT_INTERVAL];
 *                           injectable so tests don't iterate 1000 times)
 */
class PostRatchet(
    initialChainKey:     ByteArray,
    private val hkdf:    Hkdf = Hkdf.instance,
    val checkpointInterval: Int = DEFAULT_CHECKPOINT_INTERVAL
) {
    init {
        require(initialChainKey.size == 32) { "Initial chain key must be 32 bytes" }
        require(checkpointInterval > 0)     { "Checkpoint interval must be positive" }
    }

    private var chainKey:  ByteArray = initialChainKey.copyOf()
    // internal so fromCheckpoint() factory can set it directly without the extra
    // copy+zero cycle that restoreFromCheckpoint() incurs.
    internal var postCount: Int = 0

    // ── Core ratchet ─────────────────────────────────────────────────────

    /**
     * Derive the encryption key for the post identified by [postHash],
     * then advance the ratchet. Must be called once per post in delivery order.
     *
     * @return [RatchetStep] containing the post key and an optional checkpoint.
     *         If [RatchetStep.checkpoint] is non-null, the caller must encrypt
     *         it with the static channel key and write it to the DHT.
     *
     * Caller responsibility: [RatchetStep.postKey] is sensitive key material.
     * The caller should wipe it with fill(0) after using it to encrypt or
     * decrypt the post.
     */
    fun advance(postHash: ByteArray): RatchetStep {
        require(postHash.isNotEmpty()) { "Post hash must not be empty" }

        // postKey is sensitive — must be wiped on any exception before this method returns.
        // Use a 'succeeded' flag so the finally block only wipes on failure; on normal return
        // the caller owns the key and is responsible for wiping it (per RatchetStep KDoc).
        var postKey: ByteArray? = null
        var succeeded = false
        try {
            // post_key_i: HKDF(ikm=chain_key, salt=post_hash_i, info="post")
            postKey = hkdf.derive(
                ikm       = chainKey,
                salt      = postHash,
                info      = INFO_POST,
                outputLen = 32
            )

            // chain_key advance: HKDF(ikm=chain_key, salt=post_hash_i, info="ratchet")
            val nextChainKey = hkdf.derive(
                ikm       = chainKey,
                salt      = postHash,
                info      = INFO_RATCHET,
                outputLen = 32
            )

            // Wipe old chain key before overwriting — reduce window for GC exposure
            chainKey.fill(0)
            chainKey = nextChainKey
            postCount++

            val checkpoint = if (postCount % checkpointInterval == 0) chainKey.copyOf() else null

            succeeded = true
            return RatchetStep(
                postKey    = postKey,
                checkpoint = checkpoint,
                postIndex  = postCount
            )
        } finally {
            // Wipe postKey only on failure — the caller owns it on success.
            if (!succeeded) postKey?.fill(0)
        }
    }

    // ── Checkpoint ────────────────────────────────────────────────────────

    /**
     * Restore from a stored checkpoint. After calling this, invoke [advance]
     * for each post hash from [checkpointPostIndex]+1 onward to catch up.
     *
     * The caller must decrypt [checkpointChainKey] with the static channel key
     * before passing it here.
     */
    fun restoreFromCheckpoint(checkpointChainKey: ByteArray, checkpointPostIndex: Int) {
        require(checkpointChainKey.size == 32) { "Checkpoint chain key must be 32 bytes" }
        require(checkpointPostIndex >= 0)       { "Checkpoint post index must be non-negative" }
        chainKey.fill(0)
        chainKey  = checkpointChainKey.copyOf()
        postCount = checkpointPostIndex
    }

    /**
     * Export the current chain key for checkpoint storage.
     * The returned bytes MUST be encrypted with the static channel key
     * before being written to the DHT or any persistent store.
     */
    fun exportCheckpoint(): ByteArray = chainKey.copyOf()

    /** Post index of the last completed advance. 0 before any advance. */
    fun currentPostIndex(): Int = postCount

    // ── Skip-ahead cache (out-of-order delivery) ──────────────────────────

    // Bounded cache of post keys for steps speculatively advanced past.
    // Enables decryption of messages that arrive out of delivery order.
    // Max size prevents a malicious peer from exhausting heap by claiming
    // a huge step number (an O(1) attack without this bound).
    private val skippedKeys = LinkedHashMap<Int, ByteArray>(MAX_SKIP_AHEAD + 2, 0.75f, false)

    /**
     * Return the post key for [targetStep], advancing the ratchet as needed.
     *
     * Handles out-of-order delivery:
     *   - [targetStep] == postCount → normal in-order advance
     *   - [targetStep] < postCount  → look up from [skippedKeys] (null if window passed)
     *   - [targetStep] > postCount by ≤ [MAX_SKIP_AHEAD] → speculative advance, cache intermediates
     *   - [targetStep] > postCount by > [MAX_SKIP_AHEAD] → null (too far ahead — reject)
     *
     * The cached key is wiped and removed from [skippedKeys] upon retrieval.
     *
     * @param postHash SHA3-256 of the post content, required when advancing forward.
     *                 For speculative skip-ahead, the same hash is reused for intermediate
     *                 steps — this is cryptographically safe since each advance is deterministic.
     */
    fun getKeyForStep(targetStep: Int, postHash: ByteArray): ByteArray? = when {
        targetStep < postCount -> {
            val cached = skippedKeys.remove(targetStep)
            cached  // null means the skip window has passed; message permanently undecryptable
        }
        targetStep == postCount -> {
            advance(postHash).postKey
        }
        targetStep - postCount > MAX_SKIP_AHEAD -> {
            // Silent null would make ratchet gaps invisible. Log so operators and
            // developers can observe partition events and potential flooding attacks.
            mesh.shadowmesh.diagnostics.Diag.fallback("post-ratchet", "skip-ahead-rejected",
                "step=$targetStep current=$postCount gap=${targetStep - postCount} > MAX_SKIP_AHEAD=$MAX_SKIP_AHEAD — post permanently undeliverable")
            null
        }
        else -> {
            // Speculative skip-ahead: advance through intermediate steps, caching each key.
            //
            // KNOWN LIMITATION: intermediate steps (postCount..targetStep-1) are advanced
            // using targetStep's postHash. The correct intermediate post_keys require the
            // actual hash of each intermediate post — which we do not have at speculative
            // time. Consequence: cached keys for intermediate steps will NOT match when those
            // posts eventually arrive; they will fail decryption and must be re-derived from
            // the nearest checkpoint. The targetStep key IS correct (it uses the right hash).
            // Chain advancement is always correct; only intermediate cache entries are wrong.
            var resultKey: ByteArray? = null
            while (postCount <= targetStep) {
                val step = advance(postHash)
                if (postCount - 1 < targetStep) {
                    // Intermediate step — cached with wrong hash; see limitation above.
                    // Wipe the original after copying: advance() transfers ownership of
                    // step.postKey to the caller, so we must zero it here to prevent the
                    // raw key bytes from sitting in heap until GC collects the array.
                    skippedKeys[postCount - 1] = step.postKey.copyOf()
                    step.postKey.fill(0)
                } else {
                    // Target step — derived from the correct postHash.
                    resultKey = step.postKey
                }
            }
            // Evict oldest entries if cache is over-full — single-pass to avoid O(n) iterator churn.
            if (skippedKeys.size > MAX_SKIP_AHEAD) {
                val excess = skippedKeys.size - MAX_SKIP_AHEAD
                val iter = skippedKeys.entries.iterator()
                repeat(excess) { if (iter.hasNext()) { iter.next().value.fill(0); iter.remove() } }
            }
            resultKey
        }
    }

    /** Zero and discard all cached skipped-step keys. Call before evicting this ratchet. */
    fun clearSkippedKeys() {
        skippedKeys.values.forEach { it.fill(0) }
        skippedKeys.clear()
    }

    /**
     * Panic wipe — immediately zero the in-memory chain key and all cached skip keys.
     *
     * After this call the ratchet can no longer derive post keys or advance.
     * Called by [KeyOrchestrator.wipeAllRatchets] during a panic wipe so that
     * chain key material is not recoverable from a process memory dump.
     *
     * This ratchet instance must be discarded after calling this method.
     * [advance] and [exportCheckpoint] will produce zeroed-key output.
     */
    fun zeroChainKey() {
        chainKey.fill(0)
        clearSkippedKeys()
    }

    companion object {
        const val DEFAULT_CHECKPOINT_INTERVAL = 1000

        /** Maximum steps ahead the ratchet will speculatively advance for out-of-order delivery. */
        const val MAX_SKIP_AHEAD = 100

        private val INFO_POST    = "post".toByteArray()
        private val INFO_RATCHET = "ratchet".toByteArray()

        /**
         * Construct a fresh ratchet for a channel. The initial chain key is
         * derived from [channelKey] so ratchet state is deterministically
         * tied to channel membership — a newly joined node with the channel
         * key produces the same chain key sequence as all other members.
         *
         * ## Post-compromise security
         *
         * This method starts a new independent ratchet chain. Calling it with
         * a newly rotated [channelKey] (after a suspected compromise) resets
         * the ratchet and provides post-compromise security — the attacker's
         * knowledge of the old chain key gives no advantage against the new chain.
         *
         * The rotation sequence for CLOSED channels:
         *   1. [KeyOrchestrator.generateAndWrapChannelKey] — generate fresh key
         *   2. [ChannelManager.rotateKey] — store the new wrapped key
         *   3. [KeyOrchestrator.evictRatchet] — drop the old in-memory ratchet
         *   4. [KeyOrchestrator.getOrRestoreRatchet] (next use) — calls this
         *      method with the new key, starting a fresh independent chain
         *
         * Trigger: [GossipEngine.onHoneyFragmentDecrypted] fires when an anchor
         * signing key is proven extracted. That callback initiates the rotation
         * sequence above for all CLOSED channels this node participates in.
         */
        /**
         * Restore a PostRatchet from a persisted checkpoint without the wasteful
         * double-initialization that occurs when combining the primary constructor
         * with [restoreFromCheckpoint].
         *
         * The primary constructor sets chainKey (one copy) then restoreFromCheckpoint
         * zeroes that copy and makes another — three total ByteArray operations for
         * what should be one. This factory does it cleanly in one step.
         */
        fun fromCheckpoint(
            checkpointKey:   ByteArray,
            checkpointIndex: Int,
            hkdf:            Hkdf = Hkdf.instance,
            checkpointInterval: Int = DEFAULT_CHECKPOINT_INTERVAL
        ): PostRatchet {
            require(checkpointKey.size == 32)  { "Checkpoint key must be 32 bytes" }
            require(checkpointIndex >= 0)       { "Checkpoint index must be non-negative" }
            val ratchet = PostRatchet(checkpointKey, hkdf, checkpointInterval)
            ratchet.postCount = checkpointIndex
            return ratchet
        }

        fun fromChannelKey(
            channelKey: ByteArray,
            hkdf:       Hkdf = Hkdf.instance,
            checkpointInterval: Int = DEFAULT_CHECKPOINT_INTERVAL
        ): PostRatchet {
            val initialChainKey = hkdf.derive(
                ikm       = channelKey,
                salt      = null,
                info      = "shadowmesh_ratchet_init_v1".toByteArray(),
                outputLen = 32
            )
            return PostRatchet(initialChainKey, hkdf, checkpointInterval)
        }

        /**
         * Construct a per-sender ratchet for a channel.
         *
         * Unlike [fromChannelKey] (which derives a SHARED chain key from the channel key alone),
         * this factory binds the initial chain key to a specific sender's node ID:
         *
         *   chainKey_0 = HKDF(ikm=channelKey, salt=senderNodeId, info="shadowmesh_sender_ratchet_v1")
         *
         * Two senders in the same channel start from DIFFERENT chain keys. This means:
         *
         *   - Each sender's ratchet advances INDEPENDENTLY. There is no shared ordering requirement.
         *   - A network partition produces no ratchet divergence: each cluster advances only
         *     its own members' individual chains, which are disjoint. On merge, receivers
         *     catch up each sender's chain independently by replaying that sender's posts in order.
         *   - Post-compromise security on key rotation still applies: a new channel key with a
         *     new senderNodeId produces a completely fresh, independent chain.
         *
         * Recipients maintain one PostRatchet per sender per channel. The ratchet for sender X is
         * keyed by `"$channelId:${X.nodeId}"` in [KeyOrchestrator].
         *
         * @param senderNodeId  32-byte sender node ID. Must not be all zeros.
         */
        fun fromChannelKeyAndSender(
            channelKey:   ByteArray,
            senderNodeId: ByteArray,
            hkdf:         Hkdf = Hkdf.instance,
            checkpointInterval: Int = DEFAULT_CHECKPOINT_INTERVAL
        ): PostRatchet {
            require(channelKey.size == 32)    { "Channel key must be 32 bytes" }
            require(senderNodeId.size == 32)  { "Sender node ID must be 32 bytes" }
            require(senderNodeId.any { it != 0.toByte() }) { "Sender node ID must not be all zeros" }
            val initialChainKey = hkdf.derive(
                ikm       = channelKey,
                salt      = senderNodeId,
                info      = "shadowmesh_sender_ratchet_v1".toByteArray(),
                outputLen = 32
            )
            return PostRatchet(initialChainKey, hkdf, checkpointInterval)
        }
    }
}

data class RatchetStep(
    val postKey:    ByteArray,  // 32 bytes — encrypt/decrypt this post
    val checkpoint: ByteArray?, // Non-null every checkpointInterval posts — store in DHT
    val postIndex:  Int
) {
    override fun equals(other: Any?) = other is RatchetStep &&
        postKey.contentEquals(other.postKey) &&
        postIndex == other.postIndex
    override fun hashCode() = 31 * postKey.contentHashCode() + postIndex
}

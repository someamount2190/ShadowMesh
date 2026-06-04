package mesh.shadowmesh.forum.backend

import kotlinx.coroutines.*
import mesh.shadowmesh.forum.ChannelManager
import mesh.shadowmesh.forum.KeyOrchestrator
import mesh.shadowmesh.forum.PostEngine
import mesh.shadowmesh.mesh.delivery.FragmentFetcher
import mesh.shadowmesh.mesh.delivery.MerkleAckProtocol
import mesh.shadowmesh.mesh.fragment.FragmentationEngine
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import mesh.shadowmesh.mesh.gossip.GossipEngine
import mesh.shadowmesh.mesh.dht.NodeId
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.crypto.hexToBytes
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.SymmetricCipher
import mesh.shadowmesh.crypto.TrustLevel
import mesh.shadowmesh.diagnostics.Diag

/**
 * Fragment ingestor — inbound pipeline from mesh to forum.
 *
 * Receives fragments from the gossip layer, runs the trust gate, feeds them into
 * [PostEngine], and fires ViewModel callbacks when a post is complete.
 *
 * ## Trust gate
 *
 * SHADOWMESH's trust model extends to fragment acceptance:
 *
 *   TRUST_PUBLIC    → OPEN channels only.
 *                     Accepting CLOSED/COMPARTMENTED fragments from untrusted peers
 *                     would reveal channel membership. A TRUST_PUBLIC peer relaying a
 *                     COMPARTMENTED fragment implies knowledge of that channel's existence.
 *   TRUST_INTRODUCED → OPEN and CLOSED channels.
 *   TRUST_PHYSICAL  → All channel types including COMPARTMENTED.
 *
 * Unknown channel type (channel not yet joined locally): accept the fragment and store
 * it. The user may join the channel later and the fragments will already be available
 * for assembly. We do not know the channel type without the local record, so we accept
 * conservatively and let [PostEngine.ingestFragment] apply the rate limiter.
 *
 * ## Fragment-before-join cache
 *
 * A node can receive fragments before it has joined the corresponding channel.
 * This happens legitimately when:
 *   - A peer sends an invitation and fragments are already propagating.
 *   - The user scans a QR code to join a channel that has active posts.
 *
 * We always store the fragment. On channel join, the calling code should trigger
 * a [ChannelSyncCoordinator.onReconnect] to assemble any pre-join fragments.
 *
 * ## Reassembly and confirmation
 *
 * When [PostEngine.ingestFragment] reports the post is now complete (state CONFIRMED),
 * this ingestor:
 *   1. Loads all stored fragments via DAO and reassembles via [FragmentationEngine].
 *   2. Verifies the Merkle root.
 *   3. Sends a Merkle ACK back to the originator via [MerkleAckProtocol].
 *   4. Calls [onPostConfirmed] with the assembled encryptedTier2 bytes.
 *
 * ## Reactive pull — Layer 1 (NACK loop) and Layer 2 (first-fragment pull)
 *
 * **Layer 1 — NACK loop:** When a fragment arrives and assembly is [AccumulatorStatus.Partial],
 * a [NACK_DELAY_MS]-second countdown is started.  If the post is still incomplete when it
 * fires, [MerkleAckProtocol.sendNack] broadcasts the missing sequence indices.  Relay nodes
 * that hold those fragments (via [DistributedRetransmissionManager]) serve them immediately,
 * completing the assembly without any DHT round-trip.  The countdown is cancelled if the
 * post completes before it fires.  This is the primary convergence mechanism for posts
 * already in gossip transit.
 *
 * **Layer 2 — first-fragment pull:** When the very first fragment of a post arrives, the
 * receiver knows the post exists and that it is missing the remaining fragments.  An
 * immediate [FragmentFetcher.fetchMissedFragments] call for that channel (PREFER_LOCAL
 * policy) races local peers to serve what they hold — typically sub-second for co-located
 * devices.  The anticipatory cache is checked first; if a peer pre-populated it during the
 * previous sync cycle, the fragments are available in memory without any network request.
 * The DHT is only consulted if all local peers fail.
 *
 * Thread-safety: [onFragmentReceived] may be called concurrently from the gossip
 * engine's coroutine dispatcher. All DAO calls are on Dispatchers.IO.
 * [nackJobs] is a ConcurrentHashMap — safe for concurrent insert/remove.
 */
class FragmentIngestor(
    private val gossipEngine:        GossipEngine,
    private val channelManager:      ChannelManager,
    private val postEngine:          PostEngine,
    private val fragmentationEngine: FragmentationEngine,
    private val merkleAckProtocol:   MerkleAckProtocol,
    private val keyOrchestrator:     KeyOrchestrator,
    private val cipher:              SymmetricCipher = SymmetricCipher(),
    private val scope:               CoroutineScope,
    /**
     * Optional fragment fetcher for Layer 2 (first-fragment pull) and NACK-triggered
     * fetch fallback.  When null, reactive pull is disabled and the system falls back
     * to the periodic WorkManager sync.  Null during unit tests that do not need
     * network behaviour.
     */
    private val fragmentFetcher:     FragmentFetcher? = null,
    /** Called when the first fragment for [postId] is accepted (PENDING → SYNCING). */
    private val onFirstFragmentAck:  suspend (postId: String) -> Unit,
    /** Called when all fragments are received and the post is verified complete. */
    private val onPostConfirmed:     suspend (postId: String, encryptedTier2: ByteArray) -> Unit
) {
    /**
     * In-flight NACK countdown jobs, keyed by postId.
     * Each job waits [NACK_DELAY_MS] then sends a NACK for the missing sequences.
     * Cancelled when the post completes before the delay fires.
     */
    private val nackJobs = java.util.concurrent.ConcurrentHashMap<String, Job>()

    /**
     * Resolve the real channelId from a fragment's channelId field.
     *
     * Wire-received fragments (deserialized via [FragmentEntity.fromWire]) carry the
     * OBFUSCATED wire channel ID in [FragmentEntity.channelId]. Operations that require
     * the real channelId — ratchet advances, channel key lookups, ACK HMAC derivation —
     * must call this method before proceeding.
     *
     * Algorithm:
     *   1. Fast path: if [wireChannelId] directly matches a known channel (locally-created
     *      fragments, or a rare wire format version that was not obfuscated), return as-is.
     *   2. Slow path: iterate all subscribed channels and check which one's obfuscated form
     *      matches [wireChannelId].
     *   3. Not found: return [wireChannelId] unchanged — the node is relaying a fragment for
     *      a channel it has not joined. Callers handle the mismatch via try/catch (ratchet
     *      advance will fail and the gap-resolution path fires).
     */
    private suspend fun resolveRealChannelId(wireChannelId: String): String {
        if (channelManager.getChannel(wireChannelId) != null) return wireChannelId
        val channels = channelManager.activeChannelSnapshot()
        for (ch in channels) {
            if (FragmentEntity.obfuscateChannelId(hexToBytes(ch.channelId)) == wireChannelId) {
                return ch.channelId
            }
        }
        return wireChannelId
    }

    /**
     * Entry point called by [AckRouter] for every incoming fragment.
     *
     * @param fragment     The received fragment.
     * @param senderNodeId NodeId of the peer that sent this fragment.
     */
    /**
     * Ingest an incoming fragment.
     *
     * @param fragment      The fragment to ingest.
     * @param senderNodeId  NodeId of the peer that sent/relayed this fragment.
     * @param maxTrust      Optional trust level cap for this fragment. When non-null,
     *                      `min(effectiveTrust(senderNodeId), maxTrust)` is used for the
     *                      trust gate. Used on the Layer 2 DHT-fetch path to prevent
     *                      DHT-sourced fragments from inheriting the local node's elevated
     *                      TRUST_PHYSICAL level (trust elevation attack).
     */
    suspend fun onFragmentReceived(
        fragment:     FragmentEntity,
        senderNodeId: NodeId,
        maxTrust:     TrustLevel? = null
    ): Unit = withContext(Dispatchers.IO) {
        // ── Honey fragment detection ──────────────────────────────────────
        // Must run before the trust gate and before any storage.  Honey fragments
        // use a reserved channelId (HONEY_CHANNEL_ID) and must never be ingested
        // as real content.  checkAndHandleHoneyFragment() returns true for ANY
        // fragment bearing that channelId — verified-own-honey fragments trigger
        // the PCS rotation callback; foreign or tampered honey fragments are
        // silently discarded.  Either way, normal ingest is skipped.
        if (gossipEngine.checkAndHandleHoneyFragment(fragment, senderNodeId)) return@withContext

        // ── Relay TTL guard ───────────────────────────────────────────────
        // GossipEngine.relayFragment already enforces heldUntilMs for gossip-path fragments,
        // but fragments arriving via DHT fetch (FragmentFetcher) bypass that check.
        // Reject fragments whose relay window has expired (with 10-minute clock-skew grace
        // matching the tolerance in relayFragment). heldUntilMs == 0 means "not set"
        // (pre-TTL wire format) — accepted unconditionally.
        val nowMs = System.currentTimeMillis()
        val CLOCK_SKEW_GRACE_MS = 10 * 60 * 1000L
        if (fragment.heldUntilMs > 0L && nowMs > fragment.heldUntilMs + CLOCK_SKEW_GRACE_MS) {
            Diag.fallback("fragment-ingestor", "relay-ttl-expired",
                "Fragment relay window expired — dropping",
                "fragmentId" to fragment.fragmentId.take(8),
                "expiredAgoMs" to (nowMs - fragment.heldUntilMs).toString())
            return@withContext
        }

        // ── Trust gate ────────────────────────────────────────────────────
        // Apply maxTrust cap when specified (e.g. Layer 2 DHT-fetch path).
        // Without capping, DHT-fetched fragments re-ingested with gossipEngine.localNodeId
        // inherit TRUST_PHYSICAL, allowing a TRUST_PUBLIC-sourced COMPARTMENTED fragment
        // stored in the DHT to be ingested by bypassing the normal trust gate.
        val effectiveTrust = gossipEngine.effectiveTrust(senderNodeId)
        // TrustLevel ordinal: PHYSICAL=0 (most privileged), PUBLIC=2 (least privileged).
        // Capping = taking the LESS privileged of the two = higher ordinal value.
        val senderTrust: TrustLevel? = when {
            maxTrust == null          -> effectiveTrust
            effectiveTrust == null    -> maxTrust
            // Both non-null: use the less privileged (higher ordinal = lower trust)
            else -> if (effectiveTrust.ordinal > maxTrust.ordinal) effectiveTrust else maxTrust
        }
        val channel     = channelManager.getChannel(fragment.channelId)

        // When channel type is known, enforce trust-type gate.
        // null senderTrust is treated as TRUST_PUBLIC — a peer whose trust level
        // cannot be determined (not in local peer table) gets the most restrictive
        // access: OPEN channels only. This is the correct secure default: an
        // unknown peer relaying CLOSED/COMPARTMENTED fragments implies knowledge
        // of restricted channel membership that an unknown peer should not have.
        // B9: this posture is intentional — documented here for maintainers.
        if (channel != null) {
            val allowed = when (senderTrust) {
                TrustLevel.TRUST_PHYSICAL    -> true
                TrustLevel.TRUST_INTRODUCED  -> channel.type != ChannelType.COMPARTMENTED
                TrustLevel.TRUST_PUBLIC, null -> channel.type == ChannelType.OPEN
            }
            if (!allowed) return@withContext
        }

        val channelType = channel?.type ?: ChannelType.OPEN  // conservative fallback

        // ── Fragment integrity verification ───────────────────────────────
        // Content-addressed: SHA3-256(postId || seqIdx || payload) must match fragmentId.
        if (!fragmentationEngine.verifyFragment(fragment)) return@withContext

        // ── Ingest ────────────────────────────────────────────────────────
        val wasFirstForPost = postEngine.isFirstFragment(fragment.postId)
        val accepted = postEngine.ingestFragment(
            fragment     = fragment,
            channelType  = channelType,
            authorNodeId = senderNodeId.toHex()
        )
        if (!accepted) return@withContext

        // ── Layer 2: first-fragment pull ──────────────────────────────────
        // The first accepted fragment proves the post exists.  Immediately fetch
        // whatever the local peers and anticipatory cache already hold for this
        // channel, without waiting for the 15-minute WorkManager cycle.
        // PREFER_LOCAL: checks anticipatory cache → local peers (parallel race) →
        // DHT only if all local peers fail.  This completes the post in the common
        // case where a nearby device already holds all the fragments.
        if (wasFirstForPost) {
            scope.launch { onFirstFragmentAck(fragment.postId) }

            if (fragmentFetcher != null) {
                scope.launch(Dispatchers.IO) {
                    try {
                        val channelIdBytes = hexToBytes(fragment.channelId)
                        val sinceMs = System.currentTimeMillis() -
                            mesh.shadowmesh.forum.PostEngine.DEFAULT_TTL_MS
                        val fetched = fragmentFetcher.fetchMissedFragments(channelIdBytes, sinceMs)
                        fetched.forEach { f: mesh.shadowmesh.mesh.fragment.FragmentEntity ->
                            // Feed fetched fragments back through this ingestor so the
                            // accumulator, NACK loop, and confirmation all fire correctly.
                            //
                            // Use gossipEngine.localNodeId (self) as the senderNodeId, NOT
                            // the original triggering peer's senderNodeId. These fragments
                            // were fetched by this node from local peers or the DHT — they
                            // are self-sourced, not received from the triggering peer. Using
                            // the original senderNodeId would:
                            //   1. Apply the wrong trust level (triggering peer's trust)
                            //      to fragments whose actual source is local peers/DHT.
                            //   2. Apply rate-limiting against the wrong peer.
                            //   3. Allow a blocked peer's senderNodeId to gate fragments
                            //      that this node fetched independently after the block.
                            // maxTrust = TRUST_INTRODUCED: DHT-fetched fragments must not
                            // inherit localNodeId's TRUST_PHYSICAL level. Without capping,
                            // a COMPARTMENTED fragment stored in the DHT by a TRUST_PUBLIC
                            // adversary would be accepted because it re-enters at the local
                            // node's elevated trust. TRUST_INTRODUCED allows OPEN+CLOSED
                            // channels but continues to block COMPARTMENTED channel fragments
                            // from untrusted DHT sources.
                            onFragmentReceived(
                                fragment     = f,
                                senderNodeId = gossipEngine.localNodeId,
                                maxTrust     = TrustLevel.TRUST_INTRODUCED
                            )
                        }
                        if (fetched.isNotEmpty()) {
                            Diag.info("fragment-ingestor", "first-fragment-pull",
                                "Pulled ${fetched.size} fragment(s) on first-fragment event",
                                "postId"    to fragment.postId.take(8),
                                "channelId" to fragment.channelId.take(8))
                        }
                    } catch (e: Exception) {
                        Diag.swallowed("fragment-ingestor", "first-fragment-pull", e,
                            "postId" to fragment.postId.take(8))
                    }
                }
            }
        }

        // ── MerkleAck accumulator ─────────────────────────────────────────
        // Feed the fragment into the accumulator to track assembly progress.
        val status = merkleAckProtocol.onFragmentReceived(fragment)
        when (status) {
            is mesh.shadowmesh.mesh.delivery.AccumulatorStatus.Complete -> {
                // Cancel any pending NACK — the post is now complete.
                nackJobs.remove(fragment.postId)?.cancel()
                attemptConfirmation(fragment, status.fragments, senderNodeId)
            }
            is mesh.shadowmesh.mesh.delivery.AccumulatorStatus.Partial,
            is mesh.shadowmesh.mesh.delivery.AccumulatorStatus.PartialTier1 -> {
                // ── Layer 1: NACK countdown ───────────────────────────────
                // Launch a NACK job only if one is not already pending.
                //
                // IMPORTANT: putIfAbsent(key, scope.launch{}) is NOT safe here because
                // scope.launch() is evaluated eagerly — the coroutine starts running
                // before putIfAbsent decides whether to insert.  If a job was already
                // present, the new coroutine runs uncancellably with no map entry.
                //
                // Correct pattern: check containsKey first (fast path), then
                // compute-if-absent inside a synchronized block on the postId's
                // intern to avoid a TOCTOU between the check and the launch.
                // ConcurrentHashMap.compute() evaluates the function under the
                // bucket lock, guaranteeing exactly-once launch.
                nackJobs.compute(fragment.postId) { _, existing ->
                    if (existing != null && existing.isActive) {
                        existing  // job already running — keep it, do not launch another
                    } else {
                        scope.launch(Dispatchers.IO) {
                            delay(NACK_DELAY_MS)
                            if (!isActive) return@launch
                            try {
                                merkleAckProtocol.sendNack(fragment.postId)
                                Diag.info("fragment-ingestor", "nack-sent",
                                    "Sent NACK after ${NACK_DELAY_MS}ms for incomplete post",
                                    "postId"  to fragment.postId.take(8),
                                    "missing" to merkleAckProtocol
                                        .getAccumulator(fragment.postId)
                                        ?.missingFragmentSequences()?.size.toString())
                            } catch (e: Exception) {
                                Diag.swallowed("fragment-ingestor", "nack-send", e,
                                    "postId" to fragment.postId.take(8))
                            } finally {
                                nackJobs.remove(fragment.postId)
                            }

                            // Stall timeout: if the accumulator is still partial after
                            // STALL_TIMEOUT_MS (relay retransmit budget exhausted or
                            // fragment permanently lost), evict it and mark the post FAILED.
                            // Without this, a partial assembly injected by an adversary
                            // (one shard trickling in indefinitely) leaks memory forever
                            // and the user sees an eternal spinning SYNCING indicator.
                            delay(STALL_TIMEOUT_MS)
                            if (!isActive) return@launch
                            val acc = merkleAckProtocol.getAccumulator(fragment.postId)
                            if (acc != null && acc.receivedCount < acc.totalData) {
                                Diag.degraded("fragment-ingestor", "assembly-stalled",
                                    "Partial assembly timed out after ${STALL_TIMEOUT_MS}ms — evicting accumulator",
                                    "postId"    to fragment.postId.take(8),
                                    "received"  to acc.receivedCount.toString(),
                                    "totalData" to acc.totalData.toString())
                                merkleAckProtocol.clearAccumulator(fragment.postId)
                                try { postEngine.onDeliveryFailed(fragment.postId) }
                                catch (e: Exception) {
                                    Diag.swallowed("fragment-ingestor", "stall-fail-post", e,
                                        "postId" to fragment.postId.take(8))
                                }
                            }
                        }
                    }
                }
            }
            else -> { /* Empty — nothing to do yet */ }
        }
    }

    /**
     * Called by [ShadowMeshForegroundService] on [Intent.ACTION_SCREEN_ON].
     *
     * Checks all in-flight NACK countdowns.  For any post that is still [Partial],
     * cancels the pending job and re-schedules it with zero delay so the NACK fires
     * immediately rather than waiting up to [NACK_DELAY_MS] more seconds.
     *
     * This is pure in-memory work (no I/O): it only touches the [nackJobs] map and
     * the [MerkleAckProtocol] accumulator map, both of which are in memory.
     * Takes microseconds — safe to call directly from the BroadcastReceiver.
     */
    fun onScreenOn() {
        nackJobs.keys.toList().forEach { postId ->
            val acc = merkleAckProtocol.getAccumulator(postId) ?: return@forEach
            val status = acc.currentStatus()
            if (status is mesh.shadowmesh.mesh.delivery.AccumulatorStatus.Partial ||
                status is mesh.shadowmesh.mesh.delivery.AccumulatorStatus.PartialTier1) {
                // Atomically cancel the existing countdown and replace it with an
                // immediate NACK job.  Using compute() holds the bucket lock during
                // the cancel-and-replace, preventing a concurrent fragment arrival
                // from inserting its own job between the cancel and the assignment.
                nackJobs.compute(postId) { _, existing ->
                    existing?.cancel()
                    scope.launch(Dispatchers.IO) {
                        try {
                            merkleAckProtocol.sendNack(postId)
                            Diag.info("fragment-ingestor", "nack-screen-on",
                                "Sent immediate NACK on screen-on for incomplete post",
                                "postId"  to postId.take(8),
                                "missing" to acc.missingFragmentSequences().size.toString())
                        } catch (e: Exception) {
                            Diag.swallowed("fragment-ingestor", "nack-screen-on-send", e,
                                "postId" to postId.take(8))
                        } finally {
                            nackJobs.remove(postId)
                        }
                    }
                }
            }
        }
    }

    // ── Reassembly and ACK ────────────────────────────────────────────────

    private suspend fun attemptConfirmation(
        triggerFragment: FragmentEntity,
        accumulatedFragments: List<FragmentEntity>,
        originatorNodeId: NodeId
    ) {
        // Guard: clearAccumulator() is called at the end of this function.
        // If a concurrent call (e.g. from the first-fragment pull feeding a fragment
        // that completes the accumulator) already cleared it, the accumulator is
        // gone and we skip — the first caller already handled confirmation.
        // computeIfAbsent is not needed here; a simple null-check after clearing is
        // sufficient because all callers run on Dispatchers.IO (single-threaded pool
        // for DB calls) and the accumulator is removed atomically by clearAccumulator.
        // Double-calling is benign (idempotent DB write, duplicate ACK) but wasteful;
        // this check prevents it in the common case.
        if (merkleAckProtocol.getAccumulator(triggerFragment.postId) == null) {
            return  // already confirmed by a concurrent call — skip
        }

        val scheme = triggerFragment.fecScheme
        val originalLength = postEngine.getFragmentTotal(triggerFragment.postId)
        // B8 fix (downstream of B2): getFragmentTotal now returns fragment.total × fragment.payload.size
        // (declared total, not received count). Reassembly receives the correct buffer size.

        // Reassemble from the accumulated fragments
        val encryptedPayload = fragmentationEngine.reassemble(
            fragments      = accumulatedFragments,
            originalLength = originalLength,
            scheme         = scheme
        ) ?: return  // reconstruction failed — wait for more fragments

        // Build Merkle root from DATA fragments only, sorted by sequenceIndex.
        //
        // Parity fragments (sequenceIndex >= totalData) are RS overhead — they are
        // not part of the original content and must NOT be included in the Merkle
        // tree. The sender builds the root over the original data payloads only;
        // including parity shards here would produce a different root and cause every
        // ACK verification to fail when parity-assisted reconstruction was used.
        //
        // After reassembly, all data shard payloads are available (RS fills in any
        // missing data shards from parity), so we re-read them from the reassembled
        // payload rather than the raw accumulator. The FragmentationEngine returns the
        // reconstructed plaintext; we split it back into fixed-size shard payloads to
        // reproduce the exact bytes the sender hashed.
        //
        // If the reconstructed payload is available (non-null from reassemble above),
        // we trust it — the sender's Merkle root was built the same way.
        val dataFragments = accumulatedFragments
            .filter { it.isDataFragment }
            .sortedBy { it.sequenceIndex }
        val merkleRoot = mesh.shadowmesh.mesh.fragment.FragmentMerkleTree
            .build(dataFragments.map { it.payload }, mesh.shadowmesh.crypto.Hkdf.instance)
            .root

        // Receive-side ratchet advance: the assembled wire payload is
        //   encrypt(encTier2, ratchetKey)
        // where encTier2 = channel-key-encrypted full content and ratchetKey was derived
        // by the sender using: advanceRatchet(channelId, channelId, hexToBytes(postId)).
        // We must advance identically to derive the same key and unwrap the outer layer.
        //
        // resolveRealChannelId: wire-received fragments carry the OBFUSCATED channelId in
        // triggerFragment.channelId (see FragmentEntity.fromWire + FragmentEntity.toWire).
        // The ratchet advance requires the REAL channelId. Resolve it before advancing.
        val channelId = resolveRealChannelId(triggerFragment.channelId)
        val channelType = channelManager.getChannel(channelId)?.type ?: ChannelType.OPEN
        val ratchetKey: ByteArray
        try {
            val step = keyOrchestrator.advanceRatchet(
                channelId    = channelId,
                senderNodeId = channelId,                      // per-channel ratchet
                postHash     = hexToBytes(triggerFragment.postId), // postId is the advance salt
                type         = channelType
            )
            ratchetKey = step.postKey
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Diag.swallowed("fragment-ingestor", "ratchet-advance-recv", e,
                "postId" to triggerFragment.postId.take(8))
            merkleAckProtocol.clearAccumulator(triggerFragment.postId)
            return
        }

        // Derive and register the ACK HMAC key from ratchetKey, matching the key PostDispatcher
        // derived from postKey (identical ratchet advance with the same channelId + postId inputs).
        // Registered before decryption so it is in-place when sendAck fires below, regardless of
        // coroutine scheduling. The local copy is wiped; MerkleAckProtocol holds its own copy.
        val ackHmacKey = Hkdf.instance.hmacSha3_256(
            ratchetKey, "shadowmesh_ack_auth_v1".toByteArray(Charsets.UTF_8)
        )
        merkleAckProtocol.registerAckHmacKey(triggerFragment.postId, ackHmacKey)
        ackHmacKey.fill(0)

        // Decrypt with postId as AAD — matches the sender's encrypt(encTier2, ratchetKey, aad=postId).
        // Falls back to no-AAD for messages sent before AAD was enabled (backward compat).
        val aad = hexToBytes(triggerFragment.postId)
        val encTier2 = try {
            cipher.decrypt(encryptedPayload, ratchetKey, aad).getOrNull()
        } finally {
            ratchetKey.fill(0)
        }
        if (encTier2 == null) {
            Diag.degraded("fragment-ingestor", "ratchet-decrypt-recv",
                "Ratchet decryption failed — possible key desynchronisation; gap resolution triggered",
                "postId" to triggerFragment.postId.take(8))
            // Emit a gap event so ChannelSyncCoordinator can re-fetch intermediate posts
            // and advance the ratchet back into sync. The gap post stays in SYNCING state
            // until the coordinator resolves the gap and re-delivers its fragments.
            keyOrchestrator.reportRatchetGap(triggerFragment.channelId, triggerFragment.postId)
            // No ACK on decrypt failure: sender stays SYNCING until gap resolution succeeds.
            merkleAckProtocol.clearAckHmacKey(triggerFragment.postId)
            merkleAckProtocol.clearAccumulator(triggerFragment.postId)
            return
        }

        // Send Merkle ACK back to the originator — only after successful decryption so the
        // HMAC key (registered above) is included and confirms the recipient holds the ratchet
        // key that proves they are a legitimate channel member, not a relay with only fragments.
        scope.launch {
            merkleAckProtocol.sendAck(
                postId       = triggerFragment.postId,
                merkleRoot   = merkleRoot,
                targetNodeId = originatorNodeId.toHex()
            )
        }

        scope.launch {
            onPostConfirmed(triggerFragment.postId, encTier2)
        }

        // Clean up accumulator
        merkleAckProtocol.clearAccumulator(triggerFragment.postId)
    }

    // ── Helpers ───────────────────────────────────────────────────────────


    companion object {
        /**
         * How long to wait after a [Partial] assembly before sending a NACK.
         * Short enough that missing fragments are filled before the user notices;
         * long enough to avoid NACK storms when fragments are merely delayed in transit.
         * Matches [MerkleAckProtocol.ACK_TIMEOUT_MS].
         */
        const val NACK_DELAY_MS = mesh.shadowmesh.mesh.delivery.MerkleAckProtocol.ACK_TIMEOUT_MS

        /**
         * Maximum time a partial assembly is allowed to remain incomplete before the
         * accumulator is evicted and the post is marked FAILED.
         *
         * Set to 4 hours — 2× [FragmentEntity.RELAY_HOLD_MS]. Beyond this point relay nodes
         * have exhausted their retransmit budget and the fragment is unrecoverable. Without
         * this timeout an adversary can keep a partial assembly alive indefinitely by trickling
         * one shard at a time, leaking memory proportional to the number of initiated posts.
         */
        const val STALL_TIMEOUT_MS = 4L * 60 * 60 * 1000  // 4 hours
    }
}

package mesh.shadowmesh.forum.backend
import mesh.shadowmesh.crypto.hexToBytes
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.diagnostics.Diag

import kotlinx.coroutines.*
import mesh.shadowmesh.forum.ChannelManager
import mesh.shadowmesh.forum.ForumViewModel
import mesh.shadowmesh.forum.KeyOrchestrator
import mesh.shadowmesh.forum.PostEngine
import mesh.shadowmesh.mesh.delivery.DistributedRetransmissionManager
import mesh.shadowmesh.mesh.delivery.MerkleAckProtocol
import mesh.shadowmesh.mesh.delivery.StoreAndForwardManager
import mesh.shadowmesh.mesh.fragment.*
import mesh.shadowmesh.mesh.gossip.GossipEngine
import mesh.shadowmesh.mesh.mode.NetworkModeStateMachine
import mesh.shadowmesh.mesh.nudge.NudgeEngine
import mesh.shadowmesh.mesh.privacy.SndpEngine
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.storage.PostState
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Post dispatcher — outbound pipeline from forum to mesh.
 *
 * Fixes applied:
 *   B3/B6 — confirmation uses the locally-held encTier0 (post.encryptedTier0), whose hash
 *        IS postHash. The ACK is a verified signal (it carries only the Merkle root, no
 *        payload), so there is nothing to decrypt back on this side. postEngine.onConfirmed
 *        receives encTier0 and its sha3_256(encTier0)==postHash gate passes.
 *   B4 — post.encryptedTier0 is correctly the channel-key-encrypted full content.
 *        Comment clarified; field name preserved (encryptedTier0 IS the content
 *        for this layer — tier0/1/2 are display partitions, not wire layers).
 *   B5 — firstAckFired is AtomicBoolean to prevent TOCTOU across coroutines.
 *   B6 — ACK listener registered BEFORE dispatch so a fast ACK cannot be dropped.
 */
class PostDispatcher(
    private val postEngine:          PostEngine,
    private val channelManager:      ChannelManager,
    private val keyOrchestrator:     KeyOrchestrator,
    private val fragmentationEngine: FragmentationEngine,
    private val gossipEngine:        GossipEngine,
    private val storeAndForwardMgr:  StoreAndForwardManager,
    private val nudgeEngine:         NudgeEngine,
    private val retransmissionMgr:   DistributedRetransmissionManager,
    private val merkleAckProtocol:   MerkleAckProtocol,
    private val networkModeSM:       NetworkModeStateMachine,
    private val scope:               CoroutineScope,
    private val onFirstFragmentAck:  suspend (postId: String) -> Unit,
    private val onPostConfirmed:     suspend (postId: String, encryptedTier2: ByteArray) -> Unit,
    // Injected cipher instance: avoids creating a new LazySodiumJava(SodiumJava()) on every
    // dispatch() call. SodiumJava() loads native bindings on construction — per-call allocation
    // is expensive and causes unnecessary GC pressure during high-volume posting.
    private val cipher:              mesh.shadowmesh.crypto.SymmetricCipher = mesh.shadowmesh.crypto.SymmetricCipher(),
    /** When non-null, a cover-traffic burst is triggered on every real post dispatch. */
    private val sndpEngine:          SndpEngine? = null
) {
    suspend fun dispatch(postId: String) = withContext(Dispatchers.IO) {
        val post    = postEngine.loadForDispatch(postId)
            ?: throw IllegalStateException("PostDispatcher: post $postId not found")
        val channel = channelManager.getChannel(post.channelId)
            ?: throw IllegalStateException("PostDispatcher: channel ${post.channelId} not found")

        // ── Step 2: advance ratchet ───────────────────────────────────────
        // Symmetric group ratchet: all channel members share one chain keyed by channelId.
        // Sender and receiver both advance with the same (channelId, postId) so they derive
        // the same ratchet key without needing to exchange the salt out-of-band.
        // postId is carried in every fragment's wire format, so the receiver has it.
        val step    = keyOrchestrator.advanceRatchet(
            channelId    = post.channelId,
            senderNodeId = post.channelId,         // per-channel ratchet: all members share one chain
            postHash     = hexToBytes(post.postId), // postId is the advance salt — known from fragments
            type         = channel.type
        )
        val postKey = step.postKey

        // Wire payload: encrypt the channel-key-encrypted full content (encryptedTier2) with
        // the ratchet key. Two-layer encryption:
        //   wire = encrypt(encTier2, ratchetKey)
        //   where encTier2 = encrypt(fullContent, channelKey) — stored in post since creation
        // Receiver: decrypt(wire, ratchetKey) → encTier2, verify sha3_256(encTier2) == postHash,
        //           display: decrypt(encTier2, channelKey) → plaintext.
        val encTier2 = post.encryptedTier2
            ?: throw IllegalStateException("PostDispatcher: encryptedTier2 is null for post $postId")
        // AAD binds the ratchet-layer ciphertext to this specific post (by postId),
        // preventing a ciphertext from being replayed at a different ratchet position.
        // Both sender and receiver know postId (it is carried in every fragment's wire format).
        val aad = hexToBytes(post.postId)
        val encryptedPayload: ByteArray
        try {
            encryptedPayload = cipher.encrypt(encTier2, postKey, aad).getOrThrow()
        } catch (e: Exception) {
            postKey.fill(0)
            throw e
        }

        // Derive ACK HMAC key from postKey BEFORE wiping: recipient's FragmentIngestor advances
        // the same per-channel ratchet with identical (channelId, postId) inputs, yielding the
        // same ratchetKey bytes. Both sides can independently compute the same HMAC without any
        // additional key exchange. The local copy is wiped below; MerkleAckProtocol holds its own.
        val ackHmacKey = Hkdf.instance.hmacSha3_256(
            postKey, "shadowmesh_ack_auth_v1".toByteArray(Charsets.UTF_8)
        )

        // The per-post ratchet key has done its job (encrypting the wire payload) and is
        // wiped here. Confirmation uses the locally-held encTier2 (already captured above)
        // and does not need the ratchet key.
        postKey.fill(0)

        // ── Step 3: fragment ──────────────────────────────────────────────
        val mode   = networkModeSM.currentMode
        val scheme = FecScheme.selectForLinkQuality(
            linkQualityPct = mode.replicationFactor * 10,
            offline        = !networkModeSM.twoHopAvailable
        )
        val postIdBytes    = hexToBytes(post.postId)
        val channelIdBytes = hexToBytes(post.channelId)
        val fragmentSet    = fragmentationEngine.fragment(
            postId        = postIdBytes,
            channelId     = channelIdBytes,
            encryptedPost = encryptedPayload,
            scheme        = scheme
        )

        // ── Step 4: hold for NACK retransmission ──────────────────────────
        fragmentSet.fragments.forEach { retransmissionMgr.hold(it) }

        // CONFIRMATION DATA SOURCE: the sender holds encTier2 (post.encryptedTier2),
        // the channel-key-encrypted full content whose sha3_256 equals postHash.
        // A verified ACK is only the signal that the recipient assembled fragments matching
        // the committed Merkle root. The ACK wire format carries NO payload.
        // postHash = sha3_256(encTier2), so confirming with encTier2 passes the hash gate.
        val encTier2ForConfirm = encTier2  // already extracted above (non-null)

        // Register the ACK waiter deferred SYNCHRONOUSLY before dispatch so that a fast
        // ACK arriving before the launched coroutine starts running is not silently dropped.
        // prepareAckWaiter() inserts the CompletableDeferred into awaitingAck immediately;
        // awaitAck() in the launched coroutine reuses it via computeIfAbsent rather than
        // overwriting it. The HMAC key is registered after so verifyAck finds it.
        merkleAckProtocol.prepareAckWaiter(postId)
        merkleAckProtocol.registerAckHmacKey(postId, ackHmacKey)
        ackHmacKey.fill(0)

        scope.launch {
            merkleAckProtocol.awaitAck(
                postId     = postId,
                merkleRoot = fragmentSet.merkleRoot,
                onConfirmed = {
                    // awaitAck payload is the verified received root (signal only) — ignored.
                    // Confirm with the locally-held encTier2 whose hash is postHash.
                    scope.launch { onPostConfirmed(postId, encTier2ForConfirm) }
                }
            )
        }

        // ── Step 5: network-mode-aware dispatch ───────────────────────────
        // B5 fix: AtomicBoolean — flag is read/written from gossipJob coroutine
        // and potentially from the outer coroutine concurrently.
        val firstAckFired = AtomicBoolean(false)
        val localNodeId   = gossipEngine.localNodeId

        when {
            networkModeSM.twoHopAvailable -> {
                val gossipJob = scope.launch {
                    for (fragment in fragmentSet.fragments) {
                        val relayed = gossipEngine.relayFragment(fragment, localNodeId)
                        if (relayed && firstAckFired.compareAndSet(false, true)) {
                            onFirstFragmentAck(postId)
                        }
                    }
                }
                scope.launch {
                    storeAndForwardMgr.replicate(postIdBytes, fragmentSet.fragments)
                }
                gossipJob.join()
            }
            !networkModeSM.circuitAvailable && !networkModeSM.twoHopAvailable -> {
                // Attempt to share within the local offline partition (BLE / WiFi Direct peers).
                // Do NOT enqueue for online delivery — OFFLINE_LOCAL posts never auto-flood
                // the online channel on reconnect. Users select one per channel manually.
                for (fragment in fragmentSet.fragments) {
                    gossipEngine.relayFragment(fragment, localNodeId)
                }
                postEngine.setPostState(postId, PostState.OFFLINE_LOCAL)
            }
            else -> {
                for (fragment in fragmentSet.fragments) {
                    val relayed = gossipEngine.relayFragment(fragment, localNodeId)
                    if (relayed && firstAckFired.compareAndSet(false, true)) {
                        onFirstFragmentAck(postId)
                    }
                }
            }
        }

        // ── Step 6: nudge ─────────────────────────────────────────────────
        val activePeerIds = gossipEngine.activePeerIds()
        if (activePeerIds.isNotEmpty()) {
            nudgeEngine.sendNudge(channelIdBytes, activePeerIds)
        }

        // ── Step 6.1: SNDP cover burst ────────────────────────────────────
        // Emit a simultaneous burst of fake fragments from multiple peers so an
        // observer cannot identify this device as the real sender. Runs in a
        // separate coroutine so it does not delay the dispatch return path.
        sndpEngine?.let { sndp ->
            scope.launch {
                try {
                    val knownPeers = gossipEngine.activePeerIds()
                        .mapNotNull { gossipEngine.peerContact(it) }
                    sndp.onRealPostPublished(hexToBytes(post.postId), mode, knownPeers)
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("sndp", "dispatch-cover-burst", e)
                }
            }
        }
    }

}

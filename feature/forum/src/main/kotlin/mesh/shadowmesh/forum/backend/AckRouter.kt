package mesh.shadowmesh.forum.backend

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import mesh.shadowmesh.crypto.TrustLevel
import mesh.shadowmesh.mesh.delivery.AckVerification
import mesh.shadowmesh.mesh.delivery.DistributedRetransmissionManager
import mesh.shadowmesh.mesh.delivery.MerkleAckProtocol
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import mesh.shadowmesh.mesh.dht.NodeId
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag
import java.util.concurrent.ConcurrentHashMap

/**
 * ACK/NACK/Fragment router — dispatches incoming packets to the correct handler.
 *
 * Sits between the circuit/gossip transport layer and the forum delivery components.
 * Every packet arriving from the onion circuit or from a direct peer passes through here.
 *
 * ## Packet types
 *
 *   FRAGMENT: mesh.shadowmesh.mesh.fragment.FragmentEntity — routed to [FragmentIngestor].
 *   ACK:      4-byte "ACK\0" magic + 32-byte postId + 32-byte Merkle root.
 *             Verified by [MerkleAckProtocol.verifyAck] then fires registered listeners.
 *   NACK:     4-byte "NACK" magic + 32-byte postId + 2-byte count + N×2-byte seqIdx.
 *             [DistributedRetransmissionManager.serveNack] retransmits missing fragments.
 *
 * ## ACK listeners
 *
 * [PostDispatcher] registers a one-shot listener per post via [registerAckListener].
 * On ACK arrival, the listener fires [onPostConfirmed] with the assembled encryptedTier2.
 * The listener is removed after firing — no memory leak from completed posts.
 *
 * ## Why not a sealed class dispatch
 *
 * Packets arrive as raw byte arrays from the transport layer. The transport has no
 * knowledge of the forum protocol. Routing by magic byte prefix is the correct
 * approach: it is transport-agnostic and adds zero overhead per packet.
 *
 * Thread-safety: [onRawPacketReceived] may be called concurrently from the circuit
 * reader coroutine. [ackListeners] uses ConcurrentHashMap.
 */
class AckRouter(
    private val merkleAckProtocol: MerkleAckProtocol,
    private val retransmissionMgr: DistributedRetransmissionManager,
    private val fragmentIngestor:  FragmentIngestor,
    private val scope:             CoroutineScope,
    /**
     * Returns the [TrustLevel] of [nodeId], or null if the peer is unknown.
     *
     * ACKs from completely unknown peers (null trust) are rejected. An unknown peer
     * cannot legitimately be a channel recipient because they would not have the channel
     * key required to produce a valid HMAC-authenticated ACK. Rejecting unknown-sender
     * ACKs prevents relay-node forgery on legacy posts that lack HMAC keys.
     *
     * Wire in production: `gossipEngine::effectiveTrust`.
     * Default `{ null }` (reject all) is safe for tests that set a non-null function.
     * Set to `{ TrustLevel.TRUST_PUBLIC }` to accept ACKs from all peers without trust
     * filtering (e.g. in integration tests where peers haven't been registered yet).
     */
    private val senderTrustLevel: (NodeId) -> TrustLevel? = { null }
) {
    /**
     * One-shot ACK listeners registered by [PostDispatcher].
     * Key: postId hex. Value: lambda called on verified ACK with the received Merkle root.
     */
    private val ackListeners = ConcurrentHashMap<String, (merkleRoot: ByteArray) -> Unit>()

    // ── Per-sender rate limiting ───────────────────────────────────────────
    //
    // ACKs and NACKs are cheap for a sender to flood — each ACK needs only magic + postId
    // (68 bytes for an unauthenticated ACK; 100 bytes for an authenticated one). Without
    // rate limiting, a malicious peer can exhaust the retransmission manager or fill the
    // awaitingAck map. Limits are generous (10 ACKs / 20 NACKs per minute per peer) to
    // accommodate legitimate reconnect bursts without cutting off honest nodes.
    private val ackRateMap  = ConcurrentHashMap<String, ArrayDeque<Long>>()
    private val nackRateMap = ConcurrentHashMap<String, ArrayDeque<Long>>()

    private fun isAckRateLimited(senderId: String): Boolean =
        isSlidingWindowLimited(ackRateMap,  senderId, MAX_ACKS_PER_WINDOW)
    private fun isNackRateLimited(senderId: String): Boolean =
        isSlidingWindowLimited(nackRateMap, senderId, MAX_NACKS_PER_WINDOW)

    private fun isSlidingWindowLimited(
        map:      ConcurrentHashMap<String, ArrayDeque<Long>>,
        key:      String,
        maxCount: Int
    ): Boolean {
        val now   = System.currentTimeMillis()
        // Size cap: without this, a botnet flooding unique node IDs grows the map to OOM.
        // Keys are peer hex node IDs (64 chars each). At MAX_RATE_TRACKED_PEERS = 10_000,
        // the map occupies ~10_000 × (64B key + 10 × 8B timestamp ArrayDeque) ≈ ~1.5MB.
        // An untracked new peer (over cap) is rate-limited by default — it receives no
        // allowance until the map drains naturally as existing windows expire.
        if (!map.containsKey(key) && map.size >= MAX_RATE_TRACKED_PEERS) return true
        val times = map.computeIfAbsent(key) { ArrayDeque() }
        synchronized(times) {
            val iter = times.iterator()
            while (iter.hasNext()) { if (now - iter.next() > RATE_WINDOW_MS) iter.remove() }
            // Prune the map entry entirely when the window is empty and we would rate-limit
            // anyway — avoids stale keys accumulating after peers go quiet.
            if (times.isEmpty() && map.size > MAX_RATE_TRACKED_PEERS / 2) {
                map.remove(key, times)
            }
            if (times.size >= maxCount) return true
            times.addLast(now)
            return false
        }
    }

    /**
     * B10 fix: locally-computed expected Merkle roots, keyed by postId hex.
     * Set at registration time from the value computed during fragmentation.
     * ACK verification compares the received root against THIS value, not
     * against the root extracted from the ACK packet itself.
     *
     * Without this, verifyAck(packet, receivedRoot) trivially passes for any
     * packet — an attacker can forge a valid ACK for any postId by constructing
     * a packet where the embedded root matches whatever they choose.
     */
    private val expectedMerkleRoots = ConcurrentHashMap<String, ByteArray>()

    /**
     * Register a one-shot ACK listener for [postId].
     *
     * @param expectedMerkleRoot  The Merkle root computed locally at fragmentation time.
     *                            ACK packets whose embedded root does not match this
     *                            value are silently rejected — forgery protection.
     * @param onAck               Called with the verified Merkle root on valid ACK receipt.
     */
    fun registerAckListener(
        postId:             String,
        expectedMerkleRoot: ByteArray,
        onAck:              (merkleRoot: ByteArray) -> Unit
    ) {
        expectedMerkleRoots[postId] = expectedMerkleRoot.copyOf()
        ackListeners[postId]        = onAck
    }

    fun removeAckListener(postId: String) {
        ackListeners.remove(postId)
        expectedMerkleRoots.remove(postId)?.fill(0)
        merkleAckProtocol.clearAckHmacKey(postId)
    }

    /**
     * Optional handler for gossip-layer control packets not handled by the forum layer.
     * Set from the composition root for packet types such as [RevocationUpdateFrame].
     * Called before the fragment fallthrough so these packets are not misrouted.
     */
    @Volatile var onGossipControlPacket: ((packet: ByteArray, sender: NodeId) -> Unit)? = null

    fun onRawPacketReceived(packet: ByteArray, senderNodeId: NodeId) {
        if (packet.size < 4) return
        when {
            packet.startsWith(MerkleAckProtocol.ACK_MAGIC)  -> handleAck(packet, senderNodeId)
            packet.startsWith(MerkleAckProtocol.NACK_MAGIC) -> handleNack(packet, senderNodeId)
            packet.startsWith(mesh.shadowmesh.mesh.gossip.RevocationUpdateFrame.MAGIC_BYTES) ->
                onGossipControlPacket?.invoke(packet, senderNodeId)
            else                                             -> handleFragment(packet, senderNodeId)
        }
    }

    // ── ACK handling ──────────────────────────────────────────────────────

    private fun handleAck(packet: ByteArray, senderNodeId: NodeId) {
        if (isAckRateLimited(senderNodeId.toHex())) {
            Diag.fallback("ack-router", "ack-rate-limited",
                "ACK rate limit exceeded for ${senderNodeId.toHex().take(8)} — dropping")
            return
        }
        // Trust gate: reject ACKs from completely unknown peers (null trust level).
        // A legitimate recipient must be registered in the peer table — they would have
        // joined the channel and been introduced through a physical or digital exchange.
        // Unknown peers cannot produce valid HMAC-authenticated ACKs (no channel ratchet key)
        // and are excluded as defence-in-depth for non-HMAC legacy posts.
        if (senderTrustLevel(senderNodeId) == null) {
            Diag.fallback("ack-router", "ack-unknown-sender",
                "ACK from unknown peer ${senderNodeId.toHex().take(8)} — rejected (not in peer table)")
            return
        }
        // ACK wire format: [4B magic][32B postId][32B merkleRoot] = 68 bytes
        if (packet.size < 68) return
        val postIdBytes    = packet.copyOfRange(4, 36)
        val receivedRoot   = packet.copyOfRange(36, 68)
        val postIdHex      = postIdBytes.toHex()

        val listener       = ackListeners[postIdHex]      ?: return
        // B10 fix: use the locally-stored expected root, not the received root, as
        // the expected value for verification. An ACK is only valid if the root the
        // sender claims matches what we computed at fragmentation time.
        val expectedRoot   = expectedMerkleRoots[postIdHex] ?: return

        // Pass postIdHex so verifyAck can check the HMAC when an ackHmacKey is registered
        // for this post (see MerkleAckProtocol.registerAckHmacKey). 100-byte ACKs from
        // upgraded recipients carry a MAC that binds the ACK to the shared encTier2 secret,
        // preventing relays from forging confirmations using only the public Merkle root.
        val verification = merkleAckProtocol.verifyAck(packet, expectedRoot, postIdHex)
        if (verification is AckVerification.Valid) {
            // Atomic conditional remove — prevents double-fire when two concurrent valid ACKs
            // arrive for the same postId. Both callers capture `listener` from ackListeners
            // above (before either removes it). Without this guard, both would proceed to fire
            // scope.launch { listener(receivedRoot) } after the sequential remove below.
            //
            // ConcurrentHashMap.remove(key, value) removes the entry only if the current
            // mapping still equals `listener` (reference equality). The first caller wins and
            // removes it; the second call returns false (entry is already gone) → return early.
            // All other ACK cleanup (expectedMerkleRoots, hmacKey, notifyAckReceived) happens
            // only once, inside the winning branch.
            if (!ackListeners.remove(postIdHex, listener)) return
            val rootToNotify = expectedMerkleRoots.remove(postIdHex)
            merkleAckProtocol.clearAckHmacKey(postIdHex)
            // Pass the locally-stored expected root (authoritative) rather than the
            // wire-received root. Both are equal after verifyAck() confirms the match,
            // but using the local value is semantically correct — it avoids propagating
            // a wire-originated value to the awaitAck deferred. If a future refactor
            // allows partial ACK matches, using receivedRoot here would be a live bug.
            merkleAckProtocol.notifyAckReceived(postIdHex, rootToNotify ?: expectedRoot)
            rootToNotify?.fill(0)
            scope.launch { listener(receivedRoot) }
        }
        // Invalid ACK (wrong root, HMAC mismatch, or replay): silently discard.
        // No feedback to sender — avoids confirming what the expected root or key is.
    }

    // ── NACK handling ─────────────────────────────────────────────────────

    private fun handleNack(packet: ByteArray, senderNodeId: NodeId) {
        if (isNackRateLimited(senderNodeId.toHex())) return   // silently drop — no feedback to sender
        // NACK: [4B magic][32B postId][2B count][N×2B seqIdx]
        if (packet.size < 38) return
        val postIdBytes = packet.copyOfRange(4, 36)
        val postIdHex   = postIdBytes.toHex()

        val missingSequences = merkleAckProtocol.parseMissingSequences(packet)
        if (missingSequences.isEmpty()) return

        scope.launch {
            try {
                retransmissionMgr.serveNack(postIdHex, missingSequences)
            } catch (e: Exception) {
                if (e is CancellationException) throw e
                Diag.swallowed("ack-router", "nack-serve", e,
                    "postId" to postIdHex.take(8),
                    "seqCount" to missingSequences.size.toString())
            }
        }
    }

    // ── Fragment handling ─────────────────────────────────────────────────

    private fun handleFragment(packet: ByteArray, senderNodeId: NodeId) {
        // Deserialize FragmentEntity from wire bytes.
        // FragmentEntity.fromWire() is defined in FragmentModels.kt.
        val fragment = FragmentEntity.fromWire(packet) ?: return
        scope.launch {
            fragmentIngestor.onFragmentReceived(fragment, senderNodeId)
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    companion object {
        /** Sliding window duration for ACK/NACK rate limiting. */
        private const val RATE_WINDOW_MS        = 60_000L
        /** Max ACKs accepted from a single peer per [RATE_WINDOW_MS]. Generous for reconnect bursts. */
        private const val MAX_ACKS_PER_WINDOW   = 10
        /** Max NACKs accepted from a single peer per [RATE_WINDOW_MS]. */
        private const val MAX_NACKS_PER_WINDOW  = 20
        /**
         * Maximum number of unique sender IDs tracked in the ACK/NACK rate-limit maps.
         * Without this cap, a botnet with unique node IDs (one packet each) fills the maps
         * indefinitely. New senders over the cap are treated as rate-limited (denied).
         * At 10_000 entries the maps occupy ~1.5MB — well within Android's heap budget.
         */
        private const val MAX_RATE_TRACKED_PEERS = 10_000
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (size < prefix.size) return false
        return prefix.indices.all { this[it] == prefix[it] }
    }
}

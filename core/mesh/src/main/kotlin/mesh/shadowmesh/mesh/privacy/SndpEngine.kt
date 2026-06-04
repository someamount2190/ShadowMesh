package mesh.shadowmesh.mesh.privacy

import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import mesh.shadowmesh.mesh.fragment.FecScheme
import mesh.shadowmesh.mesh.mode.NetworkMode
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.security.SecureRandom
import mesh.shadowmesh.diagnostics.Diag

/**
 * SNDP — Synthetic Network Disguise Protocol, design doc Phase 8.
 *
 * Two layers:
 *
 *   Layer 1 — Scheduled baseline fake traffic:
 *     Every sync cycle, ~10% of posts in HEALTHY mode (5% in DEGRADED) trigger
 *     a burst of fake fragments indistinguishable from real post fragments.
 *     The trigger is deterministic: SHA3-256(post_hash || cycle_nonce) < threshold.
 *     State per cycle: ~1KB of metadata, purged after cycle completion.
 *     Disabled in CRITICAL and SURVIVAL modes.
 *
 *   Layer 2 — Triggered burst on real post:
 *     When a real post is published, a simultaneous burst from multiple nodes
 *     buries the real post in fake traffic. An observer cannot identify which
 *     node is the real sender because many nodes are simultaneously sending
 *     structurally identical fragments.
 *
 * Fake fragments:
 *   - Identical in size and structure to real fragments (same wire format)
 *   - Random payload encrypted with a throwaway key
 *   - Content-addressed fragmentId derived from the random payload
 *   - Will fail Merkle verification at the recipient (correct — they are never reassembled)
 *   - Recipients drop them silently via bloom filter dedup
 *
 * Design doc guarantees preserved:
 *   - SNDP never emits on CRITICAL or SURVIVAL
 *   - Layer 2 burst timing is coordinated via gossip SNDP_BURST signal
 *   - State is per-cycle — no persistent SNDP state
 *
 * Thread-safety: [cycleNonce] is a plain var, rotated at the end of each sync cycle.
 * [onSyncCycleStart] is expected to be called from a single-threaded sync coordinator;
 * concurrent calls to [onSyncCycleStart] would race on [cycleNonce] rotation.
 * Fake fragment generation via [emitFakeBurst] is stateless and thread-safe.
 */
class SndpEngine(
    private val localNodeId: NodeId,
    private val hkdf:        Hkdf      = Hkdf.instance,
    private val scope:       CoroutineScope,
    private val transport:   SndpTransport
) {
    private val rng              = SecureRandom()
    private var cycleNonce: ByteArray = ByteArray(32).also { rng.nextBytes(it) }
    // Guards cycleNonce read-advance-assign in onSyncCycleStart against concurrent callers.
    // The original design assumed single-threaded calls, but WorkManager may fire multiple
    // workers concurrently (e.g., a nudge sync overlapping with the periodic 15-min sync),
    // causing two callers to both read the same cycleNonce before either advances it — the
    // nonce would be used twice, violating the per-cycle independence guarantee.
    private val nonceMutex = Mutex()

    // ── Layer 1: Scheduled baseline ───────────────────────────────────────

    /**
     * Called at the start of each sync cycle with the current [mode].
     * For each [recentPostHashes], probabilistically decides whether to emit
     * fake traffic — deterministic given the post hash and cycle nonce.
     *
     * Threshold: HEALTHY = 10%, DEGRADED = 5%, CRITICAL/SURVIVAL = 0%
     */
    suspend fun onSyncCycleStart(
        mode:             NetworkMode,
        recentPostHashes: List<ByteArray>,
        knownPeers:       List<DhtContact>
    ) {
        // Rotate nonce FIRST — before the sndpEnabled check — so the nonce chain
        // advances every cycle regardless of mode. If cycleNonce were only rotated
        // when sndpEnabled=true, a period of CRITICAL/SURVIVAL mode would freeze the
        // nonce. When mode recovers, the first SNDP cycle would reuse the same nonce
        // that was active before the downgrade, allowing a passive observer to correlate
        // pre- and post-downgrade traffic patterns via the common nonce.
        // nonceMutex ensures two concurrent callers cannot both observe the same cycleNonce
        // before either advances it (which would violate per-cycle independence).
        val currentNonce = nonceMutex.withLock {
            val n = cycleNonce
            cycleNonce = hkdf.sha3_256(cycleNonce)   // advance for next cycle unconditionally
            n
        }

        if (!mode.sndpEnabled) return

        val threshold = (mode.sndpRate.toDouble() * UInt.MAX_VALUE.toLong()).toLong()

        recentPostHashes.forEach { postHash ->
            val trigger = triggerValue(postHash, currentNonce)
            if (trigger < threshold) {
                scope.launch { emitFakeBurst(postHash, knownPeers) }
            }
        }
    }

    // ── Layer 2: Triggered burst on real post ─────────────────────────────

    /**
     * Called immediately when a real post is published.
     * Gossips a SNDP_BURST signal to all peers; each peer that receives it
     * independently emits fake fragments.
     *
     * The burst buries the real sender — an observer sees simultaneous fragment
     * emission from many nodes and cannot identify the origin.
     *
     * [postHash] is transmitted in the gossip signal only to coordinate burst
     * timing (so peers burst at approximately the same time as the real emission).
     * It is NOT used in fake fragment construction on any node — each node
     * generates fully independent fake postIds via [generateFakeFragment].
     *
     * Protocol note: a future version could replace the postHash in the gossip
     * signal with a random burst token, removing even the timing correlation
     * from the wire signal. That is a protocol change; for now, postHash is
     * kept in the signal but explicitly excluded from fragment content.
     */
    suspend fun onRealPostPublished(
        postHash:   ByteArray,
        mode:       NetworkMode,
        knownPeers: List<DhtContact>
    ) {
        if (!mode.sndpEnabled) return
        // Emit local fakes BEFORE gossiping the burst signal.
        // Previous: scope.launch { emitFakeBurst } then gossip — the gossip signal and
        // fake fragments were emitted simultaneously (launch schedules a concurrent coroutine).
        // A passive observer correlating "node X sent gossip AND fakes at t=0" could identify
        // the real sender. Emitting fakes first, then gossiping after a random delay, breaks
        // this timing correlation: by the time the gossip signal reaches other nodes, the local
        // fakes are already in flight and the signal is temporally separated.
        emitFakeBurst(postHash, knownPeers)
        // Random jitter 50–250 ms before gossip to further decouple fake emission from gossip.
        delay(50L + (rng.nextInt(200)).toLong())
        transport.gossipSndpBurst(postHash, knownPeers)
    }

    /**
     * Called when a SNDP_BURST signal is received from another node.
     * This node emits its own fake burst for [postHash].
     */
    suspend fun onSndpBurstReceived(
        postHash:   ByteArray,
        mode:       NetworkMode,
        knownPeers: List<DhtContact>
    ) {
        if (!mode.sndpEnabled) return
        scope.launch { emitFakeBurst(postHash, knownPeers) }
    }

    // ── Fake fragment generation ───────────────────────────────────────────

    /**
     * Emit [BURST_FRAGMENT_COUNT] fake fragments for a burst triggered by [postHash].
     *
     * [postHash] is used ONLY to decide whether and when to trigger the burst
     * (via [triggerValue] in Layer 1, or directly in Layer 2). It is NOT used
     * in the construction of any fake fragment — fake fragments are built from
     * independent entropy only. The only observable link between a burst and a
     * real post is temporal, which is unavoidable and documented.
     */
    private suspend fun emitFakeBurst(
        @Suppress("UNUSED_PARAMETER")
        postHash:   ByteArray,   // kept for call-site symmetry; NOT used in fragment construction
        knownPeers: List<DhtContact>
    ) {
        // Generate one random channelId per burst so all fragments in the burst share a
        // plausible channel (as real fragments do) but differ across bursts. Using a random
        // per-burst ID instead of the static all-zeros SNDP_FAKE_CHANNEL_ID prevents trivial
        // cover-traffic identification by any observer who knows the protocol constants.
        val fakeChannelIdHex = ByteArray(32).also { rng.nextBytes(it) }
            .toHex()
        val fakeFragments = (0 until BURST_FRAGMENT_COUNT).map { i ->
            generateFakeFragment(i, fakeChannelIdHex)
        }
        val targets = knownPeers.shuffled().take(BURST_TARGET_PEERS)
        fakeFragments.forEach { fake ->
            targets.forEach { peer ->
                try { transport.sendFakeFragment(peer, fake) }
                catch (e: Exception) {
                    Diag.swallowed("sndp", "send-fake-fragment", e,
                        "peer" to peer.nodeId.toHex().take(8))
                }
            }
        }
    }

    /**
     * Generate a single fake fragment that is structurally indistinguishable
     * from a real fragment on the wire.
     *
     * Independence guarantee:
     *   - [fakePostId] is 32 bytes of fresh [SecureRandom] output, independent
     *     of any real post hash or node identity. A new random ID is generated
     *     for every call, so no two bursts share a postId.
     *   - [fakeChannelId] is a fresh per-burst random 32-byte value, indistinguishable
     *     from real channel IDs. The static all-zeros SNDP_FAKE_CHANNEL_ID constant was
     *     removed — it was a publicly-known marker that allowed any observer to trivially
     *     filter cover traffic, defeating the anonymity guarantee entirely.
     *   - Payload is random bytes of a fixed size bucket — normalized by
     *     [PacketNormalizer] to be indistinguishable from real fragment packets
     *     at the transport layer.
     *
     * Failure semantics:
     *   Fake fragments carry random payloads. Merkle verification will fail at
     *   any recipient that attempts reassembly — this is correct and expected.
     *   Recipients drop them silently via Bloom filter dedup on fragmentId.
     */
    private fun generateFakeFragment(index: Int, fakeChannelIdHex: String): FragmentEntity {
        // Independent entropy — no relationship to any real post or identity
        val fakePostIdBytes = ByteArray(32).also { rng.nextBytes(it) }
        val fakePostIdHex   = fakePostIdBytes.toHex()

        // Random payload — fixed size bucket so PacketNormalizer treats it identically
        val payload = ByteArray(FAKE_PAYLOAD_SIZE).also { rng.nextBytes(it) }

        // Content-addressed fragmentId from the fake postId + index + payload
        // This is structurally identical to how real fragmentIds are computed.
        val fragmentId = FragmentEntity.computeFragmentId(
            postId        = fakePostIdBytes,
            sequenceIndex = index,
            payload       = payload
        )

        return FragmentEntity(
            fragmentId    = fragmentId,
            postId        = fakePostIdHex,
            // Per-burst random channelId instead of the static all-zeros constant.
            // The static constant (SNDP_FAKE_CHANNEL_ID) was a publicly-known protocol
            // marker that allowed any observer to trivially filter cover traffic by inspecting
            // a single field, defeating the anonymity guarantee entirely.
            channelId     = fakeChannelIdHex,
            sequenceIndex = index,
            totalData     = BURST_FRAGMENT_COUNT,
            totalParity   = 0,
            payload       = payload,
            fecScheme     = FecScheme.NONE
        )
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Deterministic trigger value in [0, UInt.MAX_VALUE].
     * Used to decide whether a given post triggers fake traffic this cycle.
     */
    private fun triggerValue(postHash: ByteArray, nonce: ByteArray): Long {
        val hash = hkdf.sha3_256(postHash + nonce)
        return ((hash[0].toLong() and 0xFF) shl 24) or
               ((hash[1].toLong() and 0xFF) shl 16) or
               ((hash[2].toLong() and 0xFF) shl  8) or
                (hash[3].toLong() and 0xFF)
    }

    companion object {
        const val BURST_FRAGMENT_COUNT = 7        // fragments per burst
        const val BURST_TARGET_PEERS   = 3        // peers per fragment
        const val FAKE_PAYLOAD_SIZE    = 512      // bytes — matches decoy fragment size

        /**
         * DEPRECATED — no longer used in fragment construction.
         *
         * Was the channelId field on every SNDP fake fragment. Being a publicly-known
         * all-zeros constant, any observer who knew the protocol could trivially separate
         * cover traffic from real traffic by inspecting channelId == "000...0", completely
         * defeating the anonymity guarantee of SNDP.
         *
         * Replaced by a fresh per-burst random 32-byte channelId generated in
         * [emitFakeBurst], making fake fragments structurally indistinguishable from real
         * fragments to any observer without the channel key.
         */
        @Deprecated("Use per-burst random channelId generated in emitFakeBurst(). This constant enabled trivial SNDP cover-traffic fingerprinting.")
        const val SNDP_FAKE_CHANNEL_ID = "0000000000000000000000000000000000000000000000000000000000000000"
    }
}

// ── Transport interface ────────────────────────────────────────────────────────

interface SndpTransport {
    suspend fun sendFakeFragment(peer: DhtContact, fragment: FragmentEntity)
    suspend fun gossipSndpBurst(postHash: ByteArray, peers: List<DhtContact>)
}

package mesh.shadowmesh.mesh.gossip

import mesh.shadowmesh.mesh.dht.DhtContact
import mesh.shadowmesh.mesh.dht.NodeId
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * Hardened challenge layer — design doc §4 "Hardened challenge layer".
 *
 * Enforces exactly ONE challenge per active peer per sync cycle.
 * The four challenge types (FRAGMENT_ECHO, RATCHET_ADVANCEMENT,
 * GOSSIP_INTEGRITY, TIMING_CONSISTENCY) are rotated round-robin so
 * that each type is issued to each peer at most once every 4 cycles.
 * This prevents an adversary from adapting to a predictable challenge
 * pattern by specialising their fake responses.
 *
 * Relationship to GossipEngine.issueChallenge():
 *   GossipEngine.issueChallenge() handles the async send + failure recording.
 *   This class controls the cadence — which peer gets challenged when,
 *   which type, and that no peer is challenged more than once per cycle.
 *   Call [onSyncCycleStart] at the top of each sync cycle; it issues
 *   exactly one challenge per active peer and advances the type rotator.
 *
 * Thread-safety: [onSyncCycleStart] is called by the sync cycle coordinator
 * which is single-threaded. [markPeerActive]/[removePeer] are ConcurrentHashMap ops.
 */
class HardenedChallengeLayer(
    private val gossipEngine: GossipEngine,
    private val scope:        CoroutineScope
) {
    // Tracks the next challenge type index (0–3) per peer for round-robin rotation
    private val peerChallengeRotator = ConcurrentHashMap<NodeId, Int>()

    private val challengeTypes = ChallengeType.values()

    /**
     * Register a peer as active. Must be called before the peer will receive challenges.
     * Safe to call multiple times — idempotent.
     */
    fun markPeerActive(contact: DhtContact) {
        peerChallengeRotator.putIfAbsent(contact.nodeId, 0)
    }

    /**
     * Remove a peer — no more challenges issued after this.
     */
    fun removePeer(nodeId: NodeId) {
        peerChallengeRotator.remove(nodeId)
    }

    /**
     * Called at the start of each sync cycle by the sync coordinator.
     *
     * Issues exactly one challenge per registered active peer.
     * The challenge type rotates round-robin (FRAGMENT_ECHO → RATCHET_ADVANCEMENT
     * → GOSSIP_INTEGRITY → TIMING_CONSISTENCY → FRAGMENT_ECHO → ...).
     *
     * Challenges are fired-and-forgotten via [GossipEngine.issueChallenge] which
     * handles the async transport send and failure recording internally.
     *
     * @param activePeers  Current set of active peers from the routing table.
     *                     Only peers present in [peerChallengeRotator] are challenged.
     */
    fun onSyncCycleStart(activePeers: List<DhtContact>) {
        // Remove stale peers (no longer in active set)
        val activeIds = activePeers.map { it.nodeId }.toSet()
        peerChallengeRotator.keys.removeIf { it !in activeIds }

        // Auto-register newly discovered peers so they are challenged from this cycle.
        // Without this, a peer appearing in activePeers for the first time would be
        // silently skipped until markPeerActive() was explicitly called — a contract
        // hazard easy to miss at call sites.
        activePeers.forEach { peer ->
            peerChallengeRotator.putIfAbsent(peer.nodeId, 0)
        }

        // Issue exactly one challenge per active peer
        activePeers.forEach { peer ->
            val typeIndex     = peerChallengeRotator[peer.nodeId] ?: return@forEach
            val challengeType = challengeTypes[typeIndex % challengeTypes.size]
            peerChallengeRotator[peer.nodeId] = (typeIndex + 1) % challengeTypes.size
            scope.launch {
                gossipEngine.issueChallengeOfType(peer, challengeType)
            }
        }
    }

    /** Total number of registered active peers. */
    fun activePeerCount(): Int = peerChallengeRotator.size
}

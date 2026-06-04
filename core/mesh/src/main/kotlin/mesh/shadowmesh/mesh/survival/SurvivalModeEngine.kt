package mesh.shadowmesh.mesh.survival

import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import mesh.shadowmesh.mesh.mode.NetworkMode
import mesh.shadowmesh.mesh.transport.wifi.WiFiDirectTransport
import mesh.shadowmesh.mesh.transport.lan.LanSubnetTransport
import kotlinx.coroutines.*
import java.util.Collections
import mesh.shadowmesh.diagnostics.Diag
import java.util.concurrent.ConcurrentHashMap

/**
 * SURVIVAL mode engine — design doc Phase 6/7.
 *
 * Active when anchor count drops to 1-3 (NetworkMode.SURVIVAL).
 * Provides bare minimum forum operation with zero infrastructure:
 *
 *   - No DHT routing
 *   - No gossip protocol
 *   - No Tier structure
 *   - No SNDP cover traffic
 *   - No onion circuit
 *   - No VRF election
 *
 * What SURVIVAL mode provides:
 *   - Direct peer-to-peer fragment exchange via WiFi Direct or LAN
 *   - All fragments stored on all devices (no relay slots, no replication factor)
 *   - Fragment sync: push everything to every connected peer every cycle
 *   - BLE presence detection to find nearby peers
 *   - Basic Merkle ACK (no NACK retransmit from relay — sender must be present)
 *   - Post TTL and duplicate rejection still enforced
 *
 * Entering SURVIVAL:
 *   Called by [NetworkModeStateMachine] when anchor count drops below threshold.
 *   NSC transition P3_TOPOLOGY (mode change) triggers [activate()].
 *   All in-flight DHT queries and gossip cycles are cancelled.
 *
 * Exiting SURVIVAL:
 *   When anchor count recovers, [NetworkModeStateMachine] triggers CRITICAL or
 *   DEGRADED mode. [deactivate()] is called; DHT bootstrap resumes.
 *
 * Thread-safety: [connectedPeers] uses ConcurrentHashMap.
 *   [fragmentStore] is thread-safe. Sync is serialised per peer.
 */
class SurvivalModeEngine(
    private val localNodeId:       NodeId,
    private val wifiDirect:        WiFiDirectTransport?,   // null in LAN-only deployment
    private val lanTransport:      LanSubnetTransport?,    // null in WiFi Direct-only deployment
    private val scope:             CoroutineScope,
    private val onFragmentReceived:(FragmentEntity) -> Unit
) {
    // All fragments this node knows about — pushed to every peer on connect
    private val fragmentStore = ConcurrentHashMap<String, FragmentEntity>()

    // Connected peers in SURVIVAL mode: peerKey → SurvivalPeer
    private val connectedPeers = ConcurrentHashMap<String, SurvivalPeer>()

    @Volatile private var active = false
    private var syncJob: Job? = null

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Activate SURVIVAL mode. Cancels all DHT/gossip operations and starts
     * the direct sync cycle.
     */
    fun activate() {
        active = true
        startDirectSyncCycle()
    }

    /**
     * Deactivate SURVIVAL mode. Normal DHT/gossip resumes from the caller.
     */
    fun deactivate() {
        active = false
        syncJob?.cancel()
        syncJob = null
    }

    fun isActive(): Boolean = active

    // ── Fragment store ────────────────────────────────────────────────────

    /**
     * Store a fragment locally. In SURVIVAL mode, every device stores everything.
     * No relay slots, no replication factor limits.
     *
     * [MAX_SURVIVAL_FRAGMENT_STORE] caps the in-memory store to prevent OOM in long
     * SURVIVAL sessions where many posts accumulate. When full, new fragments are
     * dropped (with a Diag.degraded log) until the session ends or fragments expire.
     */
    fun storeFragment(fragment: FragmentEntity) {
        if (fragmentStore.size >= MAX_SURVIVAL_FRAGMENT_STORE) {
            Diag.degraded("survival-mode", "fragment-store-full",
                "fragmentStore is full (${fragmentStore.size}/${MAX_SURVIVAL_FRAGMENT_STORE}); " +
                "dropping fragment ${fragment.fragmentId.take(8)}. " +
                "Long SURVIVAL sessions accumulate content until the store cap is hit.",
                "postId" to fragment.postId.take(8))
            return
        }
        fragmentStore[fragment.fragmentId] = fragment
        onFragmentReceived(fragment)
    }

    fun fragmentCount(): Int = fragmentStore.size

    fun getFragmentsForPost(postId: String): List<FragmentEntity> =
        fragmentStore.values.filter { it.postId == postId }

    // ── Peer management ───────────────────────────────────────────────────

    fun addPeer(peer: SurvivalPeer) {
        if (connectedPeers.putIfAbsent(peer.peerKey, peer) == null) {
            // New peer — push all fragments immediately
            scope.launch { pushAllFragmentsToPeer(peer) }
        }
    }

    fun removePeer(peerKey: String) {
        connectedPeers.remove(peerKey)
    }

    fun connectedPeerCount(): Int = connectedPeers.size

    // ── Direct sync cycle ─────────────────────────────────────────────────

    /**
     * Sync cycle in SURVIVAL mode: every [SURVIVAL_SYNC_INTERVAL_MS], push
     * all locally-known fragments to all connected peers.
     *
     * This is flood-fill — no routing, no selection. Every device gets everything.
     * Bloom filter dedup is still applied to avoid sending the same fragment twice
     * within one cycle.
     */
    private fun startDirectSyncCycle() {
        syncJob = scope.launch {
            // Use currentCoroutineContext().isActive explicitly to distinguish it from
            // the class field active. Both are checked: the coroutine may be cancelled
            // independently of deactivate() being called (e.g. scope cancellation).
            while (coroutineContext.isActive && active) {
                val peers = connectedPeers.values.toList()
                peers.forEach { peer ->
                    launch { pushNewFragmentsToPeer(peer) }
                }
                delay(SURVIVAL_SYNC_INTERVAL_MS)
            }
        }
    }

    /** Push all fragments to a newly-connected peer (full sync on join). */
    private suspend fun pushAllFragmentsToPeer(peer: SurvivalPeer) {
        fragmentStore.values.toList().forEach { fragment ->
            sendFragmentToPeer(peer, fragment)
            // Mark as seen so the next pushNewFragmentsToPeer cycle does not resend them.
            // Without this, every fragment is sent twice to a newly-connected peer:
            // once here and again on the first sync cycle tick.
            peer.seenFragmentIds.add(fragment.fragmentId)
        }
    }

    /** Push only fragments the peer hasn't seen (tracked by seenSet). */
    private suspend fun pushNewFragmentsToPeer(peer: SurvivalPeer) {
        val toSend = fragmentStore.values.filter { it.fragmentId !in peer.seenFragmentIds }
        toSend.forEach { fragment ->
            sendFragmentToPeer(peer, fragment)
            peer.seenFragmentIds.add(fragment.fragmentId)
        }
    }

    private suspend fun sendFragmentToPeer(peer: SurvivalPeer, fragment: FragmentEntity) {
        try {
            when (peer.transport) {
                TransportType.WIFI_DIRECT ->
                    wifiDirect?.sendFragment(peer.peerKey, fragment)
                TransportType.LAN -> {
                    val lanPeer = peer.lanPeer ?: return
                    lanTransport?.sendFragment(lanPeer, fragment)
                }
            }
        } catch (e: Exception) {
            Diag.swallowed("survival-mode", "send-to-peer", e,
                "peer" to peer.peerKey, "transport" to peer.transport.name)
            connectedPeers.remove(peer.peerKey)
        }
    }

    companion object {
        const val SURVIVAL_SYNC_INTERVAL_MS = 15_000L  // 15s = 1 sync cycle

        /**
         * Maximum fragments held in [fragmentStore] during a single SURVIVAL session.
         * At 4KB average fragment size this is ~200MB — acceptable on modern Android devices.
         * Without this cap, a long SURVIVAL session with many posts could OOM the process.
         */
        const val MAX_SURVIVAL_FRAGMENT_STORE = 50_000
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

enum class TransportType { WIFI_DIRECT, LAN }

data class SurvivalPeer(
    val peerKey:          String,
    val nodeId:           NodeId,
    val transport:        TransportType,
    val lanPeer:          mesh.shadowmesh.mesh.transport.lan.LanPeer? = null,
    // Capped at MAX_SEEN_FRAGMENT_IDS entries. When full, oldest entries are evicted
    // (LinkedHashMap access-order LRU). Prevents unbounded growth in long SURVIVAL sessions.
    // At MAX=10_000 entries × ~64 bytes each = ~640KB per peer — acceptable for SURVIVAL.
    val seenFragmentIds:  MutableSet<String> = Collections.newSetFromMap(
        object : LinkedHashMap<String, Boolean>(256, 0.75f, true) {
            override fun removeEldestEntry(eldest: Map.Entry<String, Boolean>) =
                size > MAX_SEEN_FRAGMENT_IDS
        }
    )
) {
    companion object {
        const val MAX_SEEN_FRAGMENT_IDS = 10_000
    }
}

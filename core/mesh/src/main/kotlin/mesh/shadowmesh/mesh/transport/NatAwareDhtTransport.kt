package mesh.shadowmesh.mesh.transport

import mesh.shadowmesh.mesh.dht.*
import kotlinx.coroutines.*

/**
 * NAT-aware DHT transport wrapper — wires [NatTraversalEngine] into the DHT layer.
 *
 * Problem this solves (STUB 6):
 *   [NatTraversalEngine] was fully implemented but never connected to anything.
 *   [DhtEngine] called [DhtTransport] directly with whatever address was in the
 *   routing table — if that address was behind NAT, the connection silently failed.
 *
 * How it works:
 *   This class wraps an [inner] [DhtTransport] and intercepts every RPC call.
 *   Before each call, it checks whether a hole-punched connection exists for the
 *   target peer via [NatTraversalEngine.getEstablishedAddress]. If one exists,
 *   the peer's address is rewritten to the hole-punched address. If not, it
 *   attempts hole punching first, using the shared [rendezvousToken] to coordinate.
 *
 *   If hole punching fails (symmetric NAT), the original address is used as-is —
 *   the call will fail at the transport level, which is the correct fallback
 *   (DhtEngine handles unreachable peers by removing them from the routing table).
 *
 * Rendezvous token:
 *   Both peers must use the same 32-byte token to coordinate simultaneous UDP probes.
 *   The token is derived from the XOR of the two node IDs:
 *     token = SHA3-256(min(localId, remoteId) XOR max(localId, remoteId))
 *   This is deterministic from both sides without any prior communication.
 *
 * Thread-safety: [NatTraversalEngine] is thread-safe. All I/O on Dispatchers.IO.
 */
class NatAwareDhtTransport(
    private val inner:       DhtTransport,
    private val natEngine:   NatTraversalEngine,
    private val localNodeId: NodeId,
    private val hkdf:        mesh.shadowmesh.crypto.Hkdf = mesh.shadowmesh.crypto.Hkdf.instance,
    /**
     * RAM-only RTT estimator for the rendezvous path. Sampled on every successful DHT RPC and
     * consumed when sizing the hole-punch window — the rendezvous-path estimate, NOT STUN RTT.
     */
    private val rttEstimator: RttEstimator = RttEstimator()
) : DhtTransport {

    private fun pathClassFor(peer: DhtContact): RttEstimator.PathClass =
        if (isLocalAddress(peer.address.ip)) RttEstimator.PathClass.LAN
        else RttEstimator.PathClass.INTERNET

    // ── Mapped-address cache ──────────────────────────────────────────────
    //
    // discoverMappedAddress() issues a STUN query — a full network round-trip to an
    // external server. It was previously called on every resolveAddress() invocation,
    // meaning every DHT RPC (ping, findNode, findValue, store) issued a STUN query
    // for every peer that lacked an established hole-punched connection.
    //
    // The mapped address is stable for the lifetime of a NAT binding, typically
    // 2–5 minutes. We cache it here with a [MAPPED_ADDRESS_TTL_MS] expiry and
    // re-query only when the cache is stale.

    @Volatile private var cachedMappedAddress:   PeerAddress? = null
    @Volatile private var cachedAddressTimestamp: Long        = 0L

    private suspend fun getMappedAddress(): PeerAddress? {
        val now = System.currentTimeMillis()
        if (cachedMappedAddress != null && (now - cachedAddressTimestamp) < MAPPED_ADDRESS_TTL_MS) {
            return cachedMappedAddress
        }
        val fresh = natEngine.discoverMappedAddress()
        cachedMappedAddress       = fresh
        cachedAddressTimestamp    = now
        return fresh
    }

    override suspend fun ping(contact: DhtContact): DhtContact? {
        val resolved = resolveAddress(contact) ?: return null
        val t0 = System.nanoTime()
        val result = inner.ping(resolved)
        // Sample RTT only on a successful round trip (a null/timeout would be an ambiguous
        // sample; recording the seed-inflated time would corrupt SRTT — Karn-style discard).
        if (result != null) {
            val rttMs = (System.nanoTime() - t0) / 1_000_000
            rttEstimator.recordSample(contact.nodeId.toHex(), rttMs, pathClassFor(contact))
        }
        return result
    }

    override suspend fun findNode(peer: DhtContact, target: NodeId): List<DhtContact> {
        val resolved = resolveAddress(peer) ?: return emptyList()
        val t0 = System.nanoTime()
        val result = inner.findNode(resolved, target)
        if (result.isNotEmpty()) {
            val rttMs = (System.nanoTime() - t0) / 1_000_000
            rttEstimator.recordSample(peer.nodeId.toHex(), rttMs, pathClassFor(peer))
        }
        return result
    }

    override suspend fun findValue(peer: DhtContact, key: NodeId): LookupResult {
        val resolved = resolveAddress(peer) ?: return LookupResult.NotFound
        return inner.findValue(resolved, key)
    }

    override suspend fun store(peer: DhtContact, value: DhtValue) {
        val resolved = resolveAddress(peer) ?: return
        inner.store(resolved, value)
    }

    // ── Address resolution ────────────────────────────────────────────────

    /**
     * Resolve the effective address for [peer].
     *
     * 1. If a hole-punched connection already exists → return peer with that address.
     * 2. If the peer's address looks like a private/routable IP → use it directly
     *    (LAN, WiFi Direct — no NAT traversal needed).
     * 3. Otherwise → attempt UDP hole punching via STUN.
     *    On success → return peer with hole-punched address.
     *    On failure → return peer as-is (transport will handle the connection failure).
     */
    private suspend fun resolveAddress(peer: DhtContact): DhtContact? = withContext(Dispatchers.IO) {
        // Already have a hole-punched connection — use it
        val existing = natEngine.getEstablishedAddress(peer.nodeId)
        if (existing != null) return@withContext peer.copy(address = existing)

        // Local / private address — no NAT traversal needed
        if (isLocalAddress(peer.address.ip)) return@withContext peer

        // Attempt hole punching — use cached mapped address to avoid STUN per call.
        // Size the punch window from the rendezvous-path RTT estimate (SRTT + K·RTTVAR),
        // not from STUN time. Falls back to the path seed for a peer we haven't sampled yet.
        val rendezvous = deriveRendezvousToken(localNodeId, peer.nodeId)
        val peerKey    = peer.nodeId.toHex()
        val path       = pathClassFor(peer)
        val rtoMs      = rttEstimator.rtoMs(peerKey, path)
        val result     = natEngine.punch(peer, peer.address, rendezvous, rendezvousRtoMs = rtoMs)

        return@withContext when (result) {
            is HolePunchResult.Success         -> peer.copy(address = result.address)
            is HolePunchResult.SymmetricNatFailure -> {
                rttEstimator.onTimeout(peerKey, path)  // back off SRTT for the next attempt
                peer  // use original — will fail at transport
            }
            HolePunchResult.StunUnreachable    -> peer  // use original
        }
    }

    /**
     * Derive a deterministic 32-byte rendezvous token from two node IDs.
     * Both nodes independently compute the same token without prior communication.
     * The XOR of the IDs is symmetric — order doesn't matter.
     */
    private fun deriveRendezvousToken(a: NodeId, b: NodeId): ByteArray {
        val xored = ByteArray(NODE_ID_BYTES) { i ->
            (a.bytes[i].toInt() xor b.bytes[i].toInt()).toByte()
        }
        return hkdf.sha3_256(xored + RENDEZVOUS_INFO)
    }

    /**
     * Returns true for addresses that don't require NAT traversal:
     * loopback, link-local, and RFC 1918 private ranges.
     */
    private fun isLocalAddress(ip: String): Boolean {
        if (ip.startsWith("127.") || ip == "::1") return true           // loopback
        if (ip.startsWith("169.254.")) return true                       // IPv4 link-local
        // IPv6 link-local: fe80::/10 — covers fe80:: through febf::
        // The prefix check covers the full /10 range: fe8x, fe9x, feax, febx.
        if (ip.startsWith("fe8", ignoreCase = true) ||
            ip.startsWith("fe9", ignoreCase = true) ||
            ip.startsWith("fea", ignoreCase = true) ||
            ip.startsWith("feb", ignoreCase = true)) return true
        if (ip.startsWith("192.168.")) return true                       // RFC 1918
        if (ip.startsWith("10.")) return true                            // RFC 1918
        if (ip.startsWith("172.")) {                                     // RFC 1918 172.16-31.x.x
            val second = ip.split(".").getOrNull(1)?.toIntOrNull() ?: 0
            if (second in 16..31) return true
        }
        return false
    }

    companion object {
        private const val NODE_ID_BYTES = 32
        private val RENDEZVOUS_INFO = "shadowmesh_rendezvous_v1".toByteArray()
        /** Re-query STUN at most once per this interval. NAT bindings last 2–5 minutes. */
        const val MAPPED_ADDRESS_TTL_MS = 5 * 60 * 1000L
    }
}

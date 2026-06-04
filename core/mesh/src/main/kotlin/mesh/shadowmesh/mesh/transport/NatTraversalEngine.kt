package mesh.shadowmesh.mesh.transport

import mesh.shadowmesh.mesh.dht.DhtContact
import mesh.shadowmesh.mesh.dht.NodeId
import mesh.shadowmesh.mesh.dht.PeerAddress
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.diagnostics.Diag

/**
 * NAT traversal engine — design doc §4 "Peer NAT traversal — WebRTC ICE/STUN".
 *
 * Implements UDP hole punching via STUN server coordination to establish
 * direct peer-to-peer connections between NATted Android devices.
 * No TURN relay server is used — if hole punching fails, the connection
 * fails honestly (design doc: "Falls back to relay peer on symmetric NAT failure").
 *
 * Protocol:
 *   1. Both nodes independently query a STUN server to discover their
 *      reflexive (public) IP:port — this is their mapped address.
 *   2. Both nodes exchange mapped addresses via the DHT (stored as a
 *      short-lived DhtValue keyed by a shared rendezvous token).
 *   3. Both nodes send simultaneous UDP packets to each other's mapped
 *      address — this opens the NAT pinhole on both sides (hole punching).
 *   4. After a successful hole punch, the connection is confirmed by a
 *      lightweight PING/PONG exchange. The [HolePunchResult] is returned.
 *
 * Symmetric NAT:
 *   Symmetric NATs assign a different external port for each destination.
 *   Hole punching does not work reliably with symmetric NATs. If punching
 *   fails after [MAX_PUNCH_ATTEMPTS] attempts, the caller falls back to
 *   routing fragments via a relay peer already in the routing table.
 *
 * STUN servers:
 *   [stunServers] is a list of public STUN server addresses. At least one
 *   must be reachable for mapped address discovery. The list is tried in
 *   order; the first successful response is used.
 *
 * WebRTC ICE integration note:
 *   Full WebRTC ICE (candidate exchange, DTLS-SRTP) is deferred to Phase 5.
 *   This implementation covers the core STUN-based UDP hole punching.
 *   The [IceCandidateExchanger] interface below is the Phase 5 extension point.
 *
 * Thread-safety: all operations dispatched on Dispatchers.IO.
 * Active connections stored in [activeConnections] (ConcurrentHashMap).
 *
 * NOTE: The actual UDP socket operations require android.net permissions
 * (INTERNET, CHANGE_NETWORK_STATE). This class uses [UdpSocketAdapter]
 * which is injectable for testing (no-op adapter in unit tests).
 */
/**
 * Privacy posture for STUN reflexive-address discovery.
 *
 * STUN is a metadata leak in two ways the rest of this app is built to avoid:
 *   1. DNS: resolving a hostname like "stun.l.google.com" sends a clear-text lookup to the
 *      local/ISP resolver, revealing that this device runs a P2P/NAT-traversal app BEFORE a
 *      single packet is sent. This is the classic DNS-leak-around-the-tunnel problem.
 *   2. IP: a direct STUN binding request shows this node's real source IP to a third-party
 *      STUN operator (Google/Cloudflare), linking real-IP <-> "ShadowMesh user".
 *
 * Policy:
 *   CIRCUIT_ONLY (default) — never resolve DNS, never send STUN in the clear. The binding
 *       request is tunnelled through the onion circuit and egresses from the exit hop, so
 *       neither the local resolver nor the STUN operator sees this node. Requires a built
 *       circuit; if none is available, discovery returns null (caller falls back to relay).
 *   DIRECT_IP_ONLY — no DNS (IP-pinned servers only) but STUN sent directly. The operator
 *       sees this node's IP. Use only where circuit latency is unacceptable AND the operator
 *       is acceptable in the threat model. Still never leaks DNS.
 *   DISABLED — no STUN at all; rely entirely on mesh-relayed connectivity.
 *
 * Hostname-based STUN servers are NOT supported in any mode: servers are pinned by IP so a
 * DNS lookup is structurally impossible.
 */
enum class StunPrivacyPolicy { CIRCUIT_ONLY, DIRECT_IP_ONLY, DISABLED }

class NatTraversalEngine(
    private val localNodeId:   NodeId,
    private val stunServers:   List<StunServer> = DEFAULT_STUN_SERVERS,
    private val socketAdapter: UdpSocketAdapter,
    private val scope:         CoroutineScope,
    private val stunPolicy:    StunPrivacyPolicy = StunPrivacyPolicy.CIRCUIT_ONLY,
    /**
     * Tunnelled STUN sender. Wraps a STUN binding request in the onion circuit so the
     * binding egresses from the exit hop — neither the local resolver nor the STUN operator
     * sees this node. Null when no circuit is available; in CIRCUIT_ONLY that means discovery
     * returns null and the caller falls back to a mesh relay. Supplied by CircuitManager.
     *
     * Late-bound via [setCircuitStun] after CircuitManager is constructed (Phase 9).
     * NatTraversalEngine is built in Phase 8 — before CircuitManager — so the sender
     * cannot be injected at construction time without a forward reference.
     */
    circuitStun: CircuitStunSender? = null
) {
    // Mutable so CircuitManager can inject the sender after Phase 9 construction.
    @Volatile private var _circuitStun: CircuitStunSender? = circuitStun

    /** Wire the circuit STUN sender once CircuitManager is available (Phase 9). */
    fun setCircuitStun(stun: CircuitStunSender) { _circuitStun = stun }
    // Active peer connections keyed by nodeId — maps to their hole-punched address
    private val activeConnections = ConcurrentHashMap<NodeId, PeerAddress>()

    // ── STUN mapped address discovery ─────────────────────────────────────

    /**
     * Discover this node's reflexive (public) IP:port via STUN, honouring [stunPolicy].
     * Tries [stunServers] (IP-pinned — no DNS) in order; returns the first success, or null.
     *
     * CIRCUIT_ONLY: each binding request is tunnelled via [circuitStun]; if no circuit is
     * available the method returns null without sending anything in the clear — no DNS, no
     * direct STUN, no leak. DIRECT_IP_ONLY: sends directly to the pinned IP (operator sees
     * this node's IP, but still no DNS). DISABLED: returns null immediately.
     */
    suspend fun discoverMappedAddress(): PeerAddress? = withContext(Dispatchers.IO) {
        if (stunPolicy == StunPrivacyPolicy.DISABLED) return@withContext null
        for (stun in stunServers) {
            try {
                val mapped = when (stunPolicy) {
                    StunPrivacyPolicy.CIRCUIT_ONLY -> {
                        val sender = _circuitStun
                        if (sender == null) {
                            // No circuit → do NOT fall back to clear-text. Fail closed.
                            Diag.degraded("nat-traversal", "stun-no-circuit",
                                "CIRCUIT_ONLY but no circuit available; skipping STUN to avoid a DNS/IP leak. " +
                                "Caller should use a mesh relay.")
                            return@withContext null
                        }
                        sender.sendStunBindingViaCircuit(stun.ip, stun.port)
                    }
                    StunPrivacyPolicy.DIRECT_IP_ONLY ->
                        socketAdapter.sendStunBindingRequest(stun.ip, stun.port)
                    StunPrivacyPolicy.DISABLED -> null
                }
                if (mapped != null) return@withContext mapped
            } catch (e: Exception) {
                Diag.swallowed("nat-traversal", "stun-query", e,
                    "stun" to "${stun.ip}:${stun.port}", "policy" to stunPolicy.name)
            }
        }
        null
    }

    // ── Hole punching ──────────────────────────────────────────────────────

    /**
     * Attempt UDP hole punching to [remotePeer].
     *
     * @param remoteMappedAddress  The peer's reflexive address (from a DIRECT STUN query).
     * @param rendezvousToken      32-byte shared token agreed out-of-band (via DHT).
     * @param rendezvousRtoMs     Jacobson/Karels RTO (SRTT + K·RTTVAR) for the DHT rendezvous
     *                             path to this peer, from [RttEstimator.rtoMs]. The variance
     *                             term already covers the skew tail, so the first probe window
     *                             equals this directly. Defaults to a conservative cold-start RTO.
     *
     * Both nodes call this within the (adaptive) timeout. Returns [HolePunchResult.Success]
     * on success, [HolePunchResult.SymmetricNatFailure] after the plan is exhausted — caller
     * falls back to relay.
     *
     * NOTE: this path requires a DIRECT mapped address (StunPrivacyPolicy.DIRECT_IP_ONLY).
     * A CIRCUIT_ONLY-discovered address is the exit hop's, not this node's NAT mapping, so it
     * is not punchable — see CircuitStunSenderImpl. Circuit STUN therefore adds NO latency
     * here, because the two modes do not coexist.
     */
    suspend fun punch(
        remotePeer:           DhtContact,
        remoteMappedAddress:  PeerAddress,
        rendezvousToken:      ByteArray,
        rendezvousRtoMs:      Long = DEFAULT_COORDINATION_RTT_MS
    ): HolePunchResult = withContext(Dispatchers.IO) {
        val plan = estimateAdaptivePunchPlanFromRto(rendezvousRtoMs)
        Diag.info("nat-traversal", "punch-plan",
            "attempts=${plan.attempts} firstWindowMs=${plan.firstWindowMs} totalMs=${plan.totalBudgetMs}",
            "rtoMs" to rendezvousRtoMs.toString(),
            "predictedSuccess" to "%.2f".format(plan.predictedSuccess))

        repeat(plan.attempts) { attempt ->
            try {
                val probePayload = buildProbePayload(rendezvousToken, attempt)
                socketAdapter.sendUdp(remoteMappedAddress.ip, remoteMappedAddress.port, probePayload)

                // Adaptive per-attempt window: starts at firstWindowMs (>= coordination skew)
                // and backs off, so early attempts already tolerate the skew introduced by the
                // rendezvous path rather than relying on luck.
                val windowMs = plan.firstWindowMs shl attempt
                val response = withTimeoutOrNull(windowMs) {
                    socketAdapter.receiveUdp(expectedToken = rendezvousToken)
                }

                if (response != null) {
                    socketAdapter.sendUdp(
                        remoteMappedAddress.ip,
                        remoteMappedAddress.port,
                        buildPongPayload(rendezvousToken)
                    )
                    activeConnections[remotePeer.nodeId] = remoteMappedAddress
                    return@withContext HolePunchResult.Success(remoteMappedAddress)
                }
            } catch (e: Exception) {
                Diag.swallowed("nat-traversal", "punch-attempt", e,
                    "attempt" to attempt.toString(), "peer" to remotePeer.nodeId.toHex().take(8))
            }
        }
        HolePunchResult.SymmetricNatFailure(remotePeer.nodeId)
    }

    /**
     * Model relating coordination latency to hole-punch success, and derive an adaptive
     * probe schedule from it. This is the answer to "did you model the latency effect?".
     *
     * Model:
     *   - A UDP NAT mapping, once created by an outbound probe, lives for T_nat (typically
     *     30_000–120_000 ms). STUN *discovery* latency (sub-second, even over a circuit) is
     *     three orders of magnitude below T_nat, so it does NOT meaningfully reduce the punch
     *     window. Discovery latency is a non-factor.
     *   - The real latency sensitivity is RENDEZVOUS SKEW: the two peers learn "punch now" via
     *     the DHT at slightly different times. Skew Δ ≈ coordinationRttMs (worst case the full
     *     RTT difference between the two coordination paths). A probe attempt can only succeed
     *     if its receive window is open while the peer's probe is in flight — i.e. the window
     *     must exceed Δ.
     *   - Per attempt, given a window that covers Δ, success prob ≈ p0 (governed by NAT type;
     *     ~0.8 for full-cone/restricted, ~0 for symmetric — handled by SymmetricNatFailure).
     *     Over n attempts whose windows cover Δ: P(success) ≈ 1 − (1 − p0)^n.
     *
     * Adaptive schedule:
     *   - firstWindowMs covers the coordination skew on the FIRST attempt (the previous fixed
     *     200 ms first window missed whenever skew > 200 ms, e.g. any multi-hop/cross-continent
     *     path). Two entry points:
     *       • estimateAdaptivePunchPlan(rtoMs = …)  — preferred. Pass RttEstimator.rtoMs(), which
     *         is SRTT + K·RTTVAR; the variance tail is already folded in, so the first window
     *         equals the RTO directly. This is the Jacobson/Karels path.
     *       • estimateAdaptivePunchPlan(coordinationRttMs = …) — fallback when only a raw RTT
     *         sample is available; applies a flat SKEW_COVER_FACTOR as a crude variance proxy.
     *   - attempts chosen so total budget stays within PUNCH_BUDGET_CEIL_MS while keeping
     *     predictedSuccess high. Windows back off (×2) so later attempts also cover larger skew.
     */
    fun estimateAdaptivePunchPlan(coordinationRttMs: Long): PunchPlan {
        val skew        = coordinationRttMs.coerceAtLeast(0)
        // Flat multiplier as a variance proxy — only used when no RTTVAR is available.
        val firstWindow = maxOf(BASE_PROBE_WINDOW_MS, (skew * SKEW_COVER_FACTOR))
            .coerceAtMost(MAX_FIRST_WINDOW_MS)
        return buildPlanFromFirstWindow(firstWindow)
    }

    /**
     * Preferred entry point: [rtoMs] is a Jacobson/Karels timeout (SRTT + K·RTTVAR) from
     * [RttEstimator.rtoMs]. The variance term already accounts for the tail, so the first
     * window IS the RTO — no flat multiplier applied.
     */
    fun estimateAdaptivePunchPlanFromRto(rtoMs: Long): PunchPlan {
        val firstWindow = rtoMs.coerceIn(BASE_PROBE_WINDOW_MS, MAX_FIRST_WINDOW_MS)
        return buildPlanFromFirstWindow(firstWindow)
    }

    private fun buildPlanFromFirstWindow(firstWindow: Long): PunchPlan {
        var attempts = 1
        var budget    = firstWindow
        while (attempts < MAX_PUNCH_ATTEMPTS) {
            val next = firstWindow shl attempts        // window of the next attempt
            if (budget + next > PUNCH_BUDGET_CEIL_MS) break
            budget += next
            attempts++
        }
        val predicted = 1.0 - Math.pow(1.0 - PER_ATTEMPT_SUCCESS_P0, attempts.toDouble())
        return PunchPlan(
            attempts          = attempts,
            firstWindowMs     = firstWindow,
            totalBudgetMs     = budget,
            predictedSuccess  = predicted
        )
    }

    /**
     * Attempt hole punching to up to [MAX_PARALLEL_PUNCH_PEERS] peers in parallel.
     * Returns the first successful result, cancelling all remaining attempts immediately.
     * Returns null if all peers fail.
     *
     * Uses kotlinx.coroutines.selects.select to race all jobs simultaneously —
     * the previous sequential await() loop waited for each job in order, meaning
     * a slow first job delayed discovery of a fast second job's success.
     */
    suspend fun punchParallel(
        peers:           List<Pair<DhtContact, PeerAddress>>,
        rendezvousToken: ByteArray
    ): HolePunchResult? = withContext(Dispatchers.IO) {
        val limited = peers.take(MAX_PARALLEL_PUNCH_PEERS)
        if (limited.isEmpty()) return@withContext null

        val jobs = limited.map { (peer, addr) ->
            async { punch(peer, addr, rendezvousToken) }
        }

        var firstSuccess: HolePunchResult? = null
        try {
            // Collect results as they complete — cancel all on first success.
            //
            // supervisorScope isolates the collector from individual job failures.
            // Without it, a CancellationException thrown by job.await() on a cancelled
            // Deferred propagates through the inner launch to the outer withContext scope,
            // cancelling all remaining peer punch attempts. supervisorScope makes each
            // inner launch independent so one job's failure or cancellation does not
            // affect the others.
            val channel = kotlinx.coroutines.channels.Channel<HolePunchResult>(limited.size)
            kotlinx.coroutines.supervisorScope {
                jobs.forEach { job ->
                    launch {
                        try {
                            channel.send(job.await())
                        } catch (_: kotlinx.coroutines.CancellationException) {
                            // Job was cancelled (e.g. after a sibling found success) — skip send.
                            // Send a failure sentinel so channel.receive() in the collector doesn't block.
                            channel.trySend(HolePunchResult.SymmetricNatFailure(NodeId(ByteArray(32))))
                        } catch (_: Exception) {
                            // Any other exception: send a failure sentinel so receive() doesn't block.
                            channel.trySend(HolePunchResult.SymmetricNatFailure(NodeId(ByteArray(32))))
                        }
                    }
                }
            }
            repeat(limited.size) {
                val result = channel.receive()
                if (result is HolePunchResult.Success && firstSuccess == null) {
                    firstSuccess = result
                    return@withContext firstSuccess
                }
            }
        } finally {
            jobs.forEach { it.cancel() }
        }
        firstSuccess
    }

    // ── Connection management ──────────────────────────────────────────────

    /** Returns the established address for [nodeId] if a hole-punched connection exists. */
    fun getEstablishedAddress(nodeId: NodeId): PeerAddress? = activeConnections[nodeId]

    /** Close and forget a connection. */
    fun closeConnection(nodeId: NodeId) { activeConnections.remove(nodeId) }

    fun activeConnectionCount(): Int = activeConnections.size

    // ── Probe payload helpers ──────────────────────────────────────────────

    private fun buildProbePayload(token: ByteArray, attempt: Int): ByteArray {
        // Per-attempt authenticator: first 16 bytes of SHA-256(token || attempt).
        // Prevents replaying attempt N as attempt M — each attempt produces a distinct
        // payload the receiver can verify. 16 bytes (128 bits) gives adequate collision
        // resistance for the small number of concurrent punch sessions per node.
        // Note: this is a collision tag, not a keyed MAC — it does not authenticate the
        // probe originator. The rendezvous token itself (32 bytes from DHT exchange) is
        // the authenticator for the punch session.
        val mac = java.security.MessageDigest.getInstance("SHA-256")
            .also { it.update(token); it.update(byteArrayOf(attempt.toByte())) }
            .digest().copyOfRange(0, 16)
        return PROBE_MAGIC + token + byteArrayOf(attempt.toByte()) + mac
    }

    private fun buildPongPayload(token: ByteArray): ByteArray =
        PONG_MAGIC + token

    companion object {
        const val MAX_PUNCH_ATTEMPTS       = 6       // ceiling on attempts in the adaptive plan
        const val MAX_PARALLEL_PUNCH_PEERS = 5

        // ── Adaptive punch-plan parameters (see estimateAdaptivePunchPlan) ──
        const val BASE_PROBE_WINDOW_MS     = 200L     // min first-attempt window (LAN/low-RTT)
        const val MAX_FIRST_WINDOW_MS      = 4_000L   // cap so a huge RTT estimate can't stall
        const val SKEW_COVER_FACTOR        = 2L       // first window must cover ~2× the skew
        const val PUNCH_BUDGET_CEIL_MS     = 20_000L  // total budget ceiling (<< NAT mapping TTL)
        const val PER_ATTEMPT_SUCCESS_P0   = 0.80     // per-attempt success for non-symmetric NAT
        const val DEFAULT_COORDINATION_RTT_MS = 800L  // conservative DHT rendezvous RTT estimate

        @Deprecated("Superseded by the adaptive plan; retained for reference.")
        const val PUNCH_TIMEOUT_MS         = 5_000L
        @Deprecated("Superseded by adaptive firstWindowMs.")
        const val INITIAL_PROBE_DELAY_MS   = 200L

        private val PROBE_MAGIC = "SMPROBE".toByteArray()
        private val PONG_MAGIC  = "SMPONG".toByteArray()

        // IP-PINNED — never hostnames. A hostname here would mean a clear-text DNS lookup
        // before any tunnelling, leaking "this device runs a P2P app" to the local resolver.
        // These are well-known public STUN anycast IPs; rotate via signed gossip like seeds.
        // (Google stun.l.google.com and Cloudflare stun.cloudflare.com resolved IPs.)
        val DEFAULT_STUN_SERVERS = listOf(
            StunServer("74.125.250.129", 19302),   // Google STUN (stun.l.google.com)
            StunServer("142.250.82.127", 19302),   // Google STUN alt
            StunServer("172.64.155.209", 3478)     // Cloudflare STUN (stun.cloudflare.com)
        )
    }
}

// ── Data types ────────────────────────────────────────────────────────────────

/**
 * Output of the adaptive punch model: how many attempts, the first receive window, the total
 * time budget, and the predicted success probability under the model. [predictedSuccess] is
 * an estimate for diagnostics/telemetry, not a guarantee.
 */
data class PunchPlan(
    val attempts:         Int,
    val firstWindowMs:    Long,
    val totalBudgetMs:    Long,
    val predictedSuccess: Double
)

/**
 * STUN server pinned by IP (never a hostname). Storing an IP makes a DNS lookup structurally
 * impossible. Rotated via signed gossip like the seed list, not resolved at runtime.
 *
 * The [init] block validates [ip] at construction time. Any hostname or malformed string
 * throws [IllegalArgumentException], preventing a future developer or a gossip-propagated
 * update from accidentally introducing a hostname that would trigger a DNS lookup and
 * defeat the no-DNS-leak guarantee (even in DIRECT_IP_ONLY mode, DNS is never acceptable).
 */
data class StunServer(val ip: String, val port: Int) {
    init {
        require(port in 1..65535) { "StunServer: port $port is out of range [1, 65535]" }
        // Validate ip is a numeric IP literal (IPv4 or IPv6). InetAddress.getByName() on a
        // numeric IP returns immediately with no DNS lookup. If the returned hostAddress differs
        // from the input, the input was a hostname (DNS was attempted) — reject it.
        val validated = try {
            java.net.InetAddress.getByName(ip)
        } catch (e: Exception) {
            throw IllegalArgumentException(
                "StunServer: '$ip' is not a valid IP address — hostnames are forbidden to prevent DNS leaks",
                e
            )
        }
        require(validated.hostAddress == ip) {
            "StunServer: '$ip' resolved to '${validated.hostAddress}' — must be a numeric IP literal, not a hostname"
        }
    }
}

/**
 * Sends a STUN binding request through the onion circuit so it egresses from the exit hop.
 * Implemented over CircuitManager. Returns the reflexive address as seen by the exit hop's
 * view — note that under CIRCUIT_ONLY the discovered "mapped address" is the circuit egress,
 * not this node's own NAT mapping, which is the intended privacy trade-off: peers reach this
 * node via the circuit/relay, not via a directly-punched hole tied to its real IP.
 */
interface CircuitStunSender {
    suspend fun sendStunBindingViaCircuit(stunIp: String, stunPort: Int): PeerAddress?
}

sealed class HolePunchResult {
    /** Hole punch succeeded — [address] is the confirmed peer address. */
    data class Success(val address: PeerAddress)              : HolePunchResult()
    /** Peer is behind symmetric NAT — hole punching not possible. Fall back to relay. */
    data class SymmetricNatFailure(val nodeId: NodeId)        : HolePunchResult()
    /** STUN server unreachable — cannot discover mapped address. */
    object StunUnreachable                                    : HolePunchResult()
}

// ── Transport interface ────────────────────────────────────────────────────────

/**
 * UDP socket abstraction — injectable for testing.
 * Production implementation uses java.net.DatagramSocket (Android INTERNET permission).
 */
interface UdpSocketAdapter {
    /** Send a raw UDP payload to [host]:[port]. */
    suspend fun sendUdp(host: String, port: Int, payload: ByteArray)

    /** Receive a UDP payload matching [expectedToken]. Returns null on timeout. */
    suspend fun receiveUdp(expectedToken: ByteArray): ByteArray?

    /** Send a STUN Binding Request to a PINNED IP (never a hostname) and return the mapped address. */
    suspend fun sendStunBindingRequest(stunIp: String, stunPort: Int): PeerAddress?
}

/**
 * Fail-closed adapter used until a real DatagramSocket-backed implementation exists. Every
 * operation is a safe no-op: sends are dropped, receives time out, STUN returns null. This
 * keeps NatTraversalEngine constructible and the build honest — the engine degrades to
 * "no NAT traversal, use mesh relay" rather than referencing a missing implementation. A
 * production adapter (Android INTERNET permission, java.net.DatagramSocket) replaces this.
 */
object NoOpUdpSocketAdapter : UdpSocketAdapter {
    override suspend fun sendUdp(host: String, port: Int, payload: ByteArray) { /* dropped */ }
    override suspend fun receiveUdp(expectedToken: ByteArray): ByteArray? = null
    override suspend fun sendStunBindingRequest(stunIp: String, stunPort: Int): PeerAddress? = null
}

/**
 * Phase 5 extension point: ICE candidate exchange for full WebRTC ICE integration.
 * Deferred — NAT traversal with STUN hole punching covers the Phase 4 requirement.
 */
interface IceCandidateExchanger {
    suspend fun exchangeCandidates(peer: DhtContact): List<String>  // SDP ice-candidates
}

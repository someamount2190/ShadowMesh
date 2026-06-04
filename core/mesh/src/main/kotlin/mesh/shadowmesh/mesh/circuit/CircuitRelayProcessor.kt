package mesh.shadowmesh.mesh.circuit

import mesh.shadowmesh.crypto.HybridCiphertext
import mesh.shadowmesh.crypto.HybridFullKeyPair
import mesh.shadowmesh.crypto.HybridKem
import mesh.shadowmesh.crypto.HybridPublicKey
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.diagnostics.Diag
import mesh.shadowmesh.mesh.dht.NodeId
import mesh.shadowmesh.mesh.dht.PeerAddress
import kotlinx.coroutines.CancellationException
import java.util.concurrent.ConcurrentHashMap

/**
 * Relay-side onion circuit processor.
 *
 * Handles three phases for circuits that route THROUGH this node:
 *
 * Phase 1 — KEM negotiation (circuit build time):
 *   Builder calls the transport's requestHopPublicKey → [handlePublicKeyRequest]:
 *     Generates an ephemeral hybrid keypair, stores the private half indexed by circuitId,
 *     returns the public key to the builder.
 *   Builder calls sendKemCiphertext → [handleKemCiphertext]:
 *     Decapsulates the ciphertext, derives the session key matching the builder's derivation,
 *     stores the session key, wipes the ephemeral private key.
 *
 * Phase 2 — Packet relay (steady state):
 *   Builder/previous hop sends onion packets → [handleInboundPacket]:
 *     Wire format: [16B circuitId ASCII][encrypted ciphertext]
 *     Strips the circuitId, looks up the session key, calls [OnionCircuit.decryptLayer]:
 *       LayerResult.Forward → prepend circuitId, forward to nextAddress via [forwardPacket]
 *       LayerResult.Exit    → hand to [exitHandler] for control messages, or [onExitIpPacket]
 *       LayerResult.Malformed → log and evict the session key (circuit is corrupt)
 *
 * Phase 3 — Cleanup:
 *   [cleanupExpiredSessions]: evicts session keys older than [MAX_SESSION_AGE_MS].
 *   Call from a periodic WorkManager job or sync cycle.
 *   [teardownCircuit]: immediate eviction (used when a circuit teardown signal is received).
 *
 * Key derivation mirrors [OnionCircuit.handshake]:
 *   sessionKey = HKDF(sharedSecret, localNodeId.bytes + circuitId.toByteArray(),
 *                     "shadowmesh_circuit_session_v1", 32)
 * Both sides (builder and relay) derive the same key because:
 *   - Builder uses `hop.nodeId` = this relay's nodeId
 *   - Relay uses `localNodeId` = its own nodeId = same value
 *
 * Thread-safety: ConcurrentHashMap for all state; [handleKemCiphertext] and
 * [handleInboundPacket] may be called from concurrent coroutines.
 *
 * Telescoping extension:
 *   When [TelescopingCells.CTRL_REPLY_MAGIC] (0xFF) appears at offset [CIRCUIT_ID_BYTES]
 *   in an inbound packet, the relay passes the entire packet unchanged to its upstream
 *   (the node that originally sent traffic for this circuit). This allows relays to
 *   propagate EXTEND_ACK and EXTEND_DONE replies back toward the circuit builder without
 *   requiring per-hop re-encryption on the backward path.
 *
 *   When a relay sees [TelescopingCells.EXTEND_REQ_BYTE] at offset 0 of an EXIT-layer
 *   payload, it acts as a mini-builder for the next hop: contacts the next hop directly
 *   via [directKemSetup], obtains that hop's ephemeral public key, sends an EXTEND_ACK
 *   reply upstream, waits for EXTEND_CT, forwards the ciphertext to the next hop, and
 *   sends EXTEND_DONE upstream.
 *
 * @param localNodeId    This node's DHT identity — bound into the session key salt.
 * @param kem            Hybrid KEM implementation.
 * @param hkdf           HKDF instance.
 * @param onionCircuit   [OnionCircuit] for [OnionCircuit.decryptLayer].
 * @param exitHandler    Handles control payloads at the exit layer (e.g., STUN-over-circuit).
 *                       Pass null if this node is not an exit node.
 * @param forwardPacket  Sends a wire packet (circuitId + payload) to a downstream relay address.
 *                       Called for [LayerResult.Forward] results.
 * @param onExitIpPacket Handles a fully-decrypted exit payload that is not a control message.
 *                       Wired to TUN/IP forwarding at the exit node.
 * @param directKemSetup Transport for the relay-side mini-KEM setup with next hops during EXTEND.
 *                       Null if this node cannot act as an intermediate EXTEND relay.
 */
class CircuitRelayProcessor(
    private val localNodeId:     NodeId,
    private val kem:             HybridKem,
    private val hkdf:            Hkdf,
    private val onionCircuit:    OnionCircuit,
    private val exitHandler:     CircuitExitHandler? = null,
    private val forwardPacket:   suspend (address: PeerAddress, wireBytes: ByteArray) -> Unit,
    private val onExitIpPacket:  suspend (bytes: ByteArray) -> Unit = {},
    private val directKemSetup:  DirectKemSetup? = null
) {
    // Ephemeral keypairs waiting for the builder's KEM ciphertext.
    // Keyed by circuitId. Evicted on ciphertext arrival or session cleanup.
    private val pendingKemPairs = ConcurrentHashMap<String, PendingKem>()

    // Active session keys for circuits currently routing through this node.
    // Keyed by circuitId.
    private val sessionKeys = ConcurrentHashMap<String, SessionEntry>()

    // Upstream address for each circuit — the address that sent us the first packet for
    // this circuit. Used to forward CTRL_REPLY backward packets toward the builder.
    private val upstreamAddresses = ConcurrentHashMap<String, PeerAddress>()

    // In-flight EXTEND state: a relay that has sent EXTEND_ACK but is waiting for the
    // corresponding EXTEND_CT from the builder. Keyed by circuitId.
    private val pendingExtends = ConcurrentHashMap<String, PendingExtend>()

    // ── KEM handshake ─────────────────────────────────────────────────────

    /**
     * Handle a circuit-build public key request.
     *
     * Called when the circuit builder sends a CIRCUIT_KEM_PUBKEY_REQ to this node.
     * Generates an ephemeral hybrid keypair, stores the private half, and returns
     * the public key for the builder to encapsulate against.
     *
     * Returns null if key generation fails (rare — liboqs error).
     */
    suspend fun handlePublicKeyRequest(circuitId: String): HybridPublicKey? {
        // Cap pending KEM pairs to prevent OOM DoS: any peer can flood requests with unique
        // circuitIds. Each PendingKem holds a Kyber-1024 private key (~2.4 KB) + X25519 key.
        // At MAX_PENDING_SESSIONS = 1000, worst-case heap impact is ~2.5 MB — bounded.
        if (pendingKemPairs.size >= MAX_PENDING_SESSIONS) {
            Diag.fallback("circuit-relay", "pending-kem-full",
                "pendingKemPairs at capacity (${pendingKemPairs.size}/$MAX_PENDING_SESSIONS) — rejecting circuit build for $circuitId")
            return null
        }
        val kp = kem.generateKeyPair().getOrNull()
        if (kp == null) {
            Diag.degraded("circuit-relay", "keygen-failed",
                "Failed to generate ephemeral keypair for circuit $circuitId")
            return null
        }
        pendingKemPairs[circuitId] = PendingKem(
            keyPair    = kp,
            createdAtMs = System.currentTimeMillis()
        )
        return kp.publicKey
    }

    /**
     * Handle the KEM ciphertext from the circuit builder.
     *
     * Decapsulates the ciphertext with the stored ephemeral private key, derives the
     * session key (matching the builder's derivation in [OnionCircuit.handshake]),
     * stores it, and wipes the ephemeral private key immediately.
     *
     * Silent failure (Diag.degraded logged) on:
     *   - No pending keypair for this circuitId (replay or out-of-order message)
     *   - Decapsulation failure (wrong ciphertext or corrupted key material)
     */
    suspend fun handleKemCiphertext(circuitId: String, ct: HybridCiphertext) {
        val pending = pendingKemPairs.remove(circuitId)
        if (pending == null) {
            Diag.fallback("circuit-relay", "kem-no-pending",
                "Received KEM ciphertext for unknown circuitId $circuitId — discarding")
            return
        }
        val sharedSecret = kem.decapsulate(ct, pending.keyPair.privateKey).getOrNull()
        // Wipe ephemeral private key immediately — it is no longer needed
        pending.keyPair.privateKey.kyberPrivateKey.fill(0)
        pending.keyPair.privateKey.x25519PrivateKey.fill(0)

        if (sharedSecret == null) {
            Diag.degraded("circuit-relay", "decapsulate-failed",
                "KEM decapsulation failed for circuit $circuitId — circuit not established")
            return
        }

        // Derive session key matching OnionCircuit.handshake():
        //   salt = localNodeId.bytes + circuitId.toByteArray()
        // The builder uses hop.nodeId (= this relay's localNodeId) as the salt prefix.
        val sessionKey = hkdf.derive(
            ikm       = sharedSecret,
            salt      = localNodeId.bytes + circuitId.toByteArray(),
            info      = SESSION_KEY_INFO,
            outputLen = 32
        )
        sharedSecret.fill(0)

        sessionKeys[circuitId] = SessionEntry(
            key        = sessionKey,
            createdAtMs = System.currentTimeMillis()
        )
    }

    // ── Packet routing ────────────────────────────────────────────────────

    /**
     * Process an inbound circuit packet arriving from [senderAddress].
     *
     * Wire format (forward direction):
     *   [16B circuitId ASCII][encrypted onion layer]
     *
     * Wire format (backward CTRL_REPLY — see [TelescopingCells.CTRL_REPLY_MAGIC]):
     *   [16B circuitId ASCII][0xFF][16B nonce][reply body]
     *
     * Steps:
     *  1. Record [senderAddress] as the upstream for this circuit (first packet wins).
     *  2. Check for CTRL_REPLY magic byte (0xFF at offset 16). If present, forward the
     *     entire packet unchanged to the upstream address — do NOT decrypt.
     *  3. For forward packets: look up session key, call [OnionCircuit.decryptLayer].
     *  4. Route decrypted result:
     *     - [LayerResult.Forward]: prepend circuitId, call [forwardPacket] to next hop.
     *     - [LayerResult.Exit]: dispatch on cell-type byte:
     *         0x01 EXTEND_REQ  → [handleExtendReq] (telescoping build step)
     *         0x03 EXTEND_CT   → [handleExtendCt]  (telescoping build step)
     *         0x05 DESTROY     → [teardownCircuit]
     *         otherwise        → [exitHandler] (STUN) or [onExitIpPacket] (IP traffic)
     *     - [LayerResult.Malformed]: log, evict session key, drop packet.
     */
    suspend fun handleInboundPacket(wireBytes: ByteArray, senderAddress: PeerAddress? = null) {
        if (wireBytes.size < CIRCUIT_ID_BYTES + 1) {
            Diag.fallback("circuit-relay", "packet-too-short",
                "Inbound circuit packet too short (${wireBytes.size}B) — discarding")
            return
        }
        val circuitId      = String(wireBytes, 0, CIRCUIT_ID_BYTES, Charsets.US_ASCII)
        val circuitIdBytes = wireBytes.copyOfRange(0, CIRCUIT_ID_BYTES)

        // Record upstream address on first packet for this circuit.
        if (senderAddress != null) upstreamAddresses.putIfAbsent(circuitId, senderAddress)

        // ── CTRL_REPLY passthrough (backward path for telescoping ACK/DONE) ──────
        // Byte at offset CIRCUIT_ID_BYTES is the CTRL_REPLY_MAGIC (0xFF). These backward
        // packets are NOT encrypted with this relay's session key — they are pre-encrypted
        // for the builder and must be passed through unchanged until they reach the builder's
        // OnionCircuitPacketRouter.onCircuitResponse.
        if (wireBytes[CIRCUIT_ID_BYTES] == TelescopingCells.CTRL_REPLY_MAGIC) {
            val upstream = upstreamAddresses[circuitId]
            if (upstream != null) {
                try { forwardPacket(upstream, wireBytes) }
                catch (e: Exception) {
                    if (e is CancellationException) throw e
                    Diag.swallowed("circuit-relay", "ctrl-reply-forward-failed", e,
                        "circuitId" to circuitId)
                }
            }
            return
        }

        // ── Forward-direction DATA / EXTEND cells ─────────────────────────────────
        val ciphertext = wireBytes.copyOfRange(CIRCUIT_ID_BYTES, wireBytes.size)
        val entry      = sessionKeys[circuitId]
        if (entry == null) return  // unknown circuit — silently drop

        when (val result = onionCircuit.decryptLayer(ciphertext, entry.key)) {
            is LayerResult.Forward -> {
                val relayed = circuitIdBytes + result.payload
                try {
                    forwardPacket(result.nextAddress, relayed)
                } catch (e: Exception) {
                    if (e is CancellationException) throw e
                    Diag.swallowed("circuit-relay", "forward-failed", e,
                        "circuitId" to circuitId,
                        "nextHop"   to "${result.nextAddress.ip}:${result.nextAddress.port}")
                }
            }

            is LayerResult.Exit -> {
                val payload = result.payload
                when {
                    // ── Telescoping EXTEND_REQ — relay must contact next hop ───────
                    payload.isNotEmpty() && payload[0] == TelescopingCells.EXTEND_REQ_BYTE ->
                        handleExtendReq(circuitId, circuitIdBytes, payload.copyOfRange(1, payload.size))

                    // ── Telescoping EXTEND_CT — forward KEM ciphertext to next hop ─
                    payload.isNotEmpty() && payload[0] == TelescopingCells.EXTEND_CT_BYTE ->
                        handleExtendCt(circuitId, payload.copyOfRange(1, payload.size))

                    // ── Circuit teardown ──────────────────────────────────────────
                    payload.isNotEmpty() && payload[0] == TelescopingCells.DESTROY_BYTE -> {
                        teardownCircuit(circuitId)
                        // Propagate DESTROY downstream if we have a known next hop
                        pendingExtends[circuitId]?.let { pe ->
                            try { forwardPacket(pe.nextAddr, circuitIdBytes + byteArrayOf(TelescopingCells.DESTROY_BYTE)) }
                            catch (_: Exception) {}
                        }
                    }

                    // ── STUN-over-circuit and other nonce-prefixed control messages ─
                    exitHandler != null && payload.size >= CircuitManager.REPLY_NONCE_BYTES -> {
                        val nonce = payload.copyOfRange(0, CircuitManager.REPLY_NONCE_BYTES)
                        val body  = payload.copyOfRange(CircuitManager.REPLY_NONCE_BYTES, payload.size)
                        exitHandler.handle(nonce, body) { replyBytes -> onExitIpPacket(replyBytes) }
                    }

                    // ── Normal IP packet for TUN ──────────────────────────────────
                    else -> onExitIpPacket(payload)
                }
            }

            is LayerResult.Malformed -> {
                Diag.fallback("circuit-relay", "malformed-layer",
                    "Malformed onion layer for circuit $circuitId — evicting session key",
                    "ciphertextLen" to ciphertext.size.toString())
                sessionKeys.remove(circuitId)?.key?.fill(0)
            }
        }
    }

    // ── Telescoping EXTEND handling ───────────────────────────────────────

    /**
     * Handle EXTEND_REQ: the builder wants to extend this circuit to a new hop.
     *
     * This relay acts as a mini-builder for the next hop's KEM setup:
     *   1. Parse the target address from [body].
     *   2. Contact the next hop directly via [directKemSetup], obtain its public key.
     *   3. Send EXTEND_ACK back toward the builder via CTRL_REPLY.
     *   4. Store [PendingExtend] state — waiting for EXTEND_CT from the builder.
     */
    private suspend fun handleExtendReq(
        circuitId:      String,
        circuitIdBytes: ByteArray,
        body:           ByteArray  // nonce + targetNodeId + targetAddr
    ) {
        val ks = directKemSetup
        if (ks == null) {
            Diag.degraded("circuit-relay", "extend-no-kem-setup",
                "Received EXTEND_REQ but directKemSetup is null — cannot act as extend relay")
            return
        }

        val req = TelescopingCells.decodeExtendReq(body)
        if (req == null) {
            Diag.fallback("circuit-relay", "extend-req-malformed",
                "EXTEND_REQ body malformed for circuit $circuitId")
            return
        }

        // Contact next hop directly to get its ephemeral public key
        val nextPubKey = ks.requestPublicKey(req.targetAddr, circuitId)
        if (nextPubKey == null) {
            Diag.degraded("circuit-relay", "extend-next-hop-unreachable",
                "Could not obtain KEM public key from ${req.targetAddr.ip}:${req.targetAddr.port}")
            return
        }

        // Cap pendingExtends to prevent OOM DoS analogous to pendingKemPairs.
        if (pendingExtends.size >= MAX_PENDING_SESSIONS) {
            Diag.fallback("circuit-relay", "pending-extend-full",
                "pendingExtends at capacity ($MAX_PENDING_SESSIONS) — rejecting EXTEND_REQ for $circuitId")
            return
        }
        // Store the pending state so we can handle the incoming EXTEND_CT
        pendingExtends[circuitId] = PendingExtend(
            nextNodeId  = req.targetNodeId,
            nextAddr    = req.targetAddr,
            nonce       = req.nonce.copyOf(),
            createdAtMs = System.currentTimeMillis()
        )

        // Send EXTEND_ACK back toward the builder via CTRL_REPLY passthrough.
        // encodeExtendAck takes only the pubKey — the nonce is carried at the CTRL_REPLY
        // transport level by sendCtrlReply and must NOT be duplicated in the body.
        val ackBody = TelescopingCells.encodeExtendAck(nextPubKey)
        sendCtrlReply(circuitId, circuitIdBytes, req.nonce, ackBody)
    }

    /**
     * Handle EXTEND_CT: the builder's KEM ciphertext for the next hop.
     *
     * Forwards the ciphertext to the next hop via [directKemSetup], then sends
     * EXTEND_DONE back toward the builder via CTRL_REPLY.
     */
    private suspend fun handleExtendCt(circuitId: String, body: ByteArray) {
        val ks = directKemSetup
        if (ks == null) { return }

        // body: [16B nonce][ciphertext bytes]
        if (body.size < TelescopingCells.NONCE_BYTES + 4) {
            Diag.fallback("circuit-relay", "extend-ct-malformed",
                "EXTEND_CT body too short for circuit $circuitId")
            return
        }
        val nonce = body.copyOfRange(0, TelescopingCells.NONCE_BYTES)
        val ctBytes = body.copyOfRange(TelescopingCells.NONCE_BYTES, body.size)

        val pending = pendingExtends.remove(circuitId)
        if (pending == null) {
            Diag.fallback("circuit-relay", "extend-ct-no-pending",
                "Received EXTEND_CT for circuit $circuitId with no pending extend state")
            return
        }

        val ct = try { HybridCiphertext.fromBytes(ctBytes) }
        catch (e: Exception) {
            Diag.swallowed("circuit-relay", "extend-ct-parse", e, "circuitId" to circuitId)
            return
        }

        // Forward ciphertext directly to the next hop so it can decapsulate and derive S_next
        ks.sendKemCiphertext(pending.nextAddr, circuitId, ct)

        // Acknowledge to the builder that the extend is complete
        val circuitIdBytes = circuitId.toByteArray(Charsets.US_ASCII)
        val doneBody = TelescopingCells.encodeExtendDone(nonce)
        sendCtrlReply(circuitId, circuitIdBytes, nonce, doneBody)
    }

    /**
     * Send a CTRL_REPLY packet toward the builder.
     *
     * Wire: [16B circuitId][0xFF CTRL_REPLY_MAGIC][16B nonce][body bytes]
     *
     * Intermediate relays see 0xFF at offset 16 and pass the packet upstream without
     * decrypting. At the builder, [OnionCircuitPacketRouter.onCircuitResponse] strips
     * the 0xFF and delivers `nonce + body` to [CircuitManager.onReply].
     */
    private suspend fun sendCtrlReply(
        circuitId:      String,
        circuitIdBytes: ByteArray,
        nonce:          ByteArray,
        body:           ByteArray
    ) {
        val upstream = upstreamAddresses[circuitId] ?: run {
            Diag.fallback("circuit-relay", "ctrl-reply-no-upstream",
                "No upstream address for circuit $circuitId — cannot send CTRL_REPLY")
            return
        }
        val wireBytes = circuitIdBytes +
            byteArrayOf(TelescopingCells.CTRL_REPLY_MAGIC) +
            nonce +
            body
        try { forwardPacket(upstream, wireBytes) }
        catch (e: Exception) {
            if (e is CancellationException) throw e
            Diag.swallowed("circuit-relay", "ctrl-reply-send-failed", e,
                "circuitId" to circuitId)
        }
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────

    /**
     * Immediately tear down a specific circuit, wiping and removing its session key.
     * Call when a CIRCUIT_TEARDOWN control message is received from the circuit builder.
     */
    fun teardownCircuit(circuitId: String) {
        sessionKeys.remove(circuitId)?.key?.fill(0)
        pendingKemPairs.remove(circuitId)?.let { p ->
            p.keyPair.privateKey.kyberPrivateKey.fill(0)
            p.keyPair.privateKey.x25519PrivateKey.fill(0)
        }
        upstreamAddresses.remove(circuitId)
        pendingExtends.remove(circuitId)
    }

    /**
     * Evict session keys and pending KEM state older than [MAX_SESSION_AGE_MS].
     *
     * A circuit that has rotated ([CircuitManager.ROTATION_INTERVAL_MS] = 10 min) will
     * not send traffic through the old session any more. Evicting at 15 minutes ensures
     * in-flight packets are served while bounded memory growth is maintained.
     *
     * Call from the composition root's periodic sync worker.
     */
    fun cleanupExpiredSessions(nowMs: Long = System.currentTimeMillis()) {
        val cutoff = nowMs - MAX_SESSION_AGE_MS
        val staleKeys = sessionKeys.entries
            .filter { it.value.createdAtMs < cutoff }
            .map { it.key }
        staleKeys.forEach { id ->
            sessionKeys.remove(id)?.key?.fill(0)
            upstreamAddresses.remove(id)
        }

        val stalePending = pendingKemPairs.entries
            .filter { it.value.createdAtMs < cutoff }
            .map { it.key }
        stalePending.forEach { id ->
            pendingKemPairs.remove(id)?.let { p ->
                p.keyPair.privateKey.kyberPrivateKey.fill(0)
                p.keyPair.privateKey.x25519PrivateKey.fill(0)
            }
        }

        pendingExtends.entries
            .filter { it.value.createdAtMs < cutoff }
            .forEach { pendingExtends.remove(it.key) }
    }

    /** Number of active relay sessions (for diagnostics). */
    fun activeSessionCount(): Int = sessionKeys.size

    // ── Internal data ─────────────────────────────────────────────────────

    private data class PendingKem(
        val keyPair:     HybridFullKeyPair,
        val createdAtMs: Long
    )

    private data class SessionEntry(
        val key:         ByteArray,
        val createdAtMs: Long
    )

    /**
     * In-flight state for a relay that sent EXTEND_ACK and is waiting for EXTEND_CT.
     * Keyed by circuitId in [pendingExtends].
     */
    private data class PendingExtend(
        val nextNodeId:  NodeId,
        val nextAddr:    PeerAddress,
        val nonce:       ByteArray,   // nonce from the EXTEND_REQ — echoed in EXTEND_DONE
        val createdAtMs: Long
    )

    companion object {
        /** Must match [OnionCircuit.CIRCUIT_ID_BYTES]. */
        const val CIRCUIT_ID_BYTES = OnionCircuit.CIRCUIT_ID_BYTES

        /** HKDF info label — must match [OnionCircuit.handshake] exactly. */
        private val SESSION_KEY_INFO = "shadowmesh_circuit_session_v1".toByteArray()

        /**
         * Session keys older than this are evicted by [cleanupExpiredSessions].
         * Set to 15 minutes — 5 minutes longer than [CircuitManager.ROTATION_INTERVAL_MS]
         * (10 minutes) to drain in-flight packets before the session is cleaned up.
         */
        const val MAX_SESSION_AGE_MS = 15 * 60 * 1000L

        /**
         * Maximum concurrent pending KEM pairs and in-flight EXTEND operations.
         * Each PendingKem holds a Kyber-1024 private key (~2.4 KB). At 1000 entries
         * that is ~2.5 MB — bounded. Without this cap, any peer can flood
         * handlePublicKeyRequest with unique circuitIds to exhaust heap.
         */
        const val MAX_PENDING_SESSIONS = 1000
    }
}

// ── DirectKemSetup ────────────────────────────────────────────────────────────

/**
 * Transport interface for relay-side direct KEM negotiation with the next hop
 * during a telescoping EXTEND operation.
 *
 * When a relay receives EXTEND_REQ, it acts as a mini-builder for the next hop:
 *   1. [requestPublicKey]: sends a direct setup request to the next hop's address
 *      (using the same CIRCUIT_SETUP_REQ / CIRCUIT_SETUP_ACK protocol that the builder
 *      uses for the first hop) and returns the next hop's ephemeral public key.
 *   2. [sendKemCiphertext]: sends the builder's KEM ciphertext to the next hop so it
 *      can decapsulate and derive its session key.
 *
 * The next hop processes these messages through its own [CircuitRelayProcessor]:
 *   [handlePublicKeyRequest] for [requestPublicKey]
 *   [handleKemCiphertext]    for [sendKemCiphertext]
 *
 * Thread-safety: implementations must be coroutine-safe.
 */
interface DirectKemSetup {
    /**
     * Request an ephemeral KEM public key from the node at [address] for [circuitId].
     * Returns the public key on success, or null if the node is unreachable or refuses.
     * Timeout: [OnionCircuit.EXTEND_TIMEOUT_MS].
     */
    suspend fun requestPublicKey(address: PeerAddress, circuitId: String): HybridPublicKey?

    /**
     * Send the KEM ciphertext to the node at [address] for [circuitId].
     * The node decapsulates this to derive its session key for the circuit.
     */
    suspend fun sendKemCiphertext(address: PeerAddress, circuitId: String, ct: HybridCiphertext)
}

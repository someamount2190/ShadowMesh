package mesh.shadowmesh.mesh.circuit

import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.mesh.dht.*
import kotlinx.coroutines.*
import mesh.shadowmesh.diagnostics.Diag

/**
 * Four-hop onion circuit — design doc §13, Phase 8 (Entry Node Split).
 *
 * Topology: Sender → Entry → Guard → Middle → Exit → Destination
 *
 * Confidentiality guarantees per hop:
 *   Entry:  sees sender's real IP + Entry's IP. Sender-chosen trusted peer.
 *           Does NOT know Guard, Middle, Exit, destination, or content.
 *   Guard:  sees Entry's IP only. Does NOT see sender's real IP, destination, or content.
 *   Middle: sees Guard IP + Exit IP only. Does NOT see sender, Entry, or destination.
 *   Exit:   sees Middle IP + destination IP only. Does NOT see sender or content.
 *   Carrier observer: sees sender IP → Entry IP only.
 *
 * Why Entry is separated from Guard:
 *   The original Guard conflated two distinct functions: receiving the sender's real
 *   IP (trust-sensitive) and acting as the first anonymizing relay (pool-sensitive).
 *   Entry handles IP exposure — the sender explicitly chooses who sees their IP from
 *   their TRUST_PHYSICAL peers. Guard handles anonymizing relay — selected randomly
 *   from the full mesh including TRUST_INTRODUCED nodes, so the anonymity set scales
 *   with total mesh size rather than TRUST_PHYSICAL count alone.
 *
 * Encryption: four-layer onion built in reverse hop order:
 *   M_exit   = Encrypt(exit_key,   payload)
 *   M_middle = Encrypt(middle_key, exit_addr   || M_exit)    [4-hop only]
 *   M_guard  = Encrypt(guard_key,  middle_addr || M_middle)  [3-hop: exit_addr || M_exit]
 *   M_entry  = Encrypt(entry_key,  guard_addr  || M_guard)   [2-hop: exit_addr || M_exit]
 * Each hop decrypts its layer and forwards the inner payload.
 *
 * Degraded mode fallbacks (guard and middle are nullable):
 *   HEALTHY  — Entry + Guard + Middle + Exit (4-hop, all present)
 *   DEGRADED — Entry + Guard + Exit          (3-hop, middle == null)
 *   CRITICAL — Entry + Exit                  (2-hop, guard == null, middle == null)
 *
 * Key exchange: Hybrid KEM (Kyber-1024 + X25519) per hop, at circuit build time.
 * Each hop's session key is derived via HKDF from the KEM shared secret.
 * Keys are ephemeral — purged immediately on circuit teardown.
 *
 * Active-circuit ownership:
 *   [OnionCircuit] does NOT maintain an internal current-circuit reference.
 *   [CircuitManager] holds the single authoritative AtomicReference for the active
 *   CircuitState and passes it explicitly to [send].
 *
 * Circuit lifecycle:
 *   1. [build]    — KEM handshake with each hop sequentially; returns CircuitState.
 *   2. [send]     — caller supplies CircuitState; encrypts in N layers; dispatches to Entry.
 *   3. [teardown] — wipe all session keys for the given CircuitState.
 *   4. CircuitManager atomically swaps old→new and calls teardown on old.
 *
 * Thread-safety: [build] and [teardown] serialised by caller (CircuitManager).
 * [send] is safe to call concurrently — operates only on the immutable CircuitState
 * supplied by the caller.
 */
class OnionCircuit(
    private val localNodeId: NodeId,
    private val kem:         HybridKem,
    private val hkdf:        Hkdf = Hkdf.instance,
    private val cipher:      SymmetricCipher = SymmetricCipher()
) {
    data class HopKey(
        val nodeId:     NodeId,
        val address:    PeerAddress,
        val sessionKey: ByteArray   // 32 bytes — wipe on teardown
    ) {
        fun wipe() { sessionKey.fill(0) }
    }

    data class CircuitState(
        val id:        String,      // random 16-hex circuit ID
        val entry:     HopKey,      // always present — sender-chosen trusted Entry
        val guard:     HopKey?,     // null = Entry+Exit 2-hop critical fallback
        val middle:    HopKey?,     // null = Entry+Guard+Exit 3-hop degraded fallback
        val exit:      HopKey,      // always present
        val builtAtMs: Long = System.currentTimeMillis()
    ) {
        val is4Hop: Boolean get() = guard != null && middle != null
        val is3Hop: Boolean get() = guard != null && middle == null
        val is2Hop: Boolean get() = guard == null

        fun wipeKeys() {
            entry.wipe()
            guard?.wipe()
            middle?.wipe()
            exit.wipe()
        }
    }

    // ── Build ─────────────────────────────────────────────────────────────

    /**
     * Build a new circuit through [entry], [guard] (nullable), [middle] (nullable), [exit].
     * Performs KEM handshake with each present hop, deriving a session key per hop.
     *
     * On success, returns [BuildResult.Success] containing the new [CircuitState].
     * Does NOT install any internal reference — [CircuitManager] owns the active state.
     *
     * On any handshake failure, all session keys derived so far are wiped before
     * returning [BuildResult.HandshakeFailed].
     */
    suspend fun build(
        entry:     DhtContact,
        guard:     DhtContact?,
        middle:    DhtContact?,
        exit:      DhtContact,
        transport: CircuitTransport
    ): BuildResult = withContext(Dispatchers.IO) {
        val circuitId = generateCircuitId()

        // Entry — always first; wipe on failure
        val entryKey = handshake(entry, circuitId, transport)
        if (entryKey == null) {
            return@withContext BuildResult.HandshakeFailed("entry")
        }

        // Guard — nullable (2-hop critical fallback)
        val guardKey = if (guard != null) {
            val k = handshake(guard, circuitId, transport)
            if (k == null) {
                entryKey.fill(0)
                return@withContext BuildResult.HandshakeFailed("guard")
            }
            k
        } else null

        // Middle — nullable (3-hop degraded fallback)
        val middleKey = if (middle != null) {
            val k = handshake(middle, circuitId, transport)
            if (k == null) {
                entryKey.fill(0)
                guardKey?.fill(0)
                return@withContext BuildResult.HandshakeFailed("middle")
            }
            k
        } else null

        // Exit — always last
        val exitKey = handshake(exit, circuitId, transport)
        if (exitKey == null) {
            entryKey.fill(0)
            guardKey?.fill(0)
            middleKey?.fill(0)
            return@withContext BuildResult.HandshakeFailed("exit")
        }

        val state = CircuitState(
            id     = circuitId,
            entry  = HopKey(entry.nodeId, entry.address, entryKey),
            guard  = if (guard  != null && guardKey  != null) HopKey(guard.nodeId,  guard.address,  guardKey)  else null,
            middle = if (middle != null && middleKey != null) HopKey(middle.nodeId, middle.address, middleKey) else null,
            exit   = HopKey(exit.nodeId, exit.address, exitKey)
        )
        BuildResult.Success(state)
    }

    // ── Send ──────────────────────────────────────────────────────────────

    /**
     * Encrypt [payload] in N onion layers and dispatch to the Entry node.
     *
     * [state] must be the caller's ([CircuitManager]'s) authoritative circuit state.
     * The sender dispatches to [state.entry.address] — the Entry node peels its layer
     * and forwards to Guard (or directly to Exit in 2-hop critical fallback).
     *
     * Layer construction order (innermost first):
     *   exit_layer   = encrypt(exit_key,   payload)
     *   middle_layer = encrypt(middle_key, exit_addr   || exit_layer)    [4-hop only]
     *   guard_layer  = encrypt(guard_key,  next_addr   || inner)         [3/4-hop]
     *   entry_layer  = encrypt(entry_key,  next_addr   || inner)         [outermost]
     */
    suspend fun send(
        payload:   ByteArray,
        state:     CircuitState,
        transport: CircuitTransport
    ): SendResult {
        return withContext(Dispatchers.IO) {
            try {
                val onion = buildOnion(payload, state)
                // Prepend the circuitId (16 ASCII bytes) so relay nodes can look up their
                // session key for this circuit without trying every known key.
                // Wire: [16B circuitId ASCII][encrypted onion layers]
                val wirePacket = state.id.toByteArray(Charsets.US_ASCII) + onion
                transport.sendToEntry(state.entry.address, wirePacket)
                SendResult.Sent
            } catch (e: Exception) {
                Diag.swallowed("onion-circuit", "send", e, "circuitId" to state.id)
                SendResult.Failed(e.message ?: "Unknown error")
            }
        }
    }

    // ── Teardown ──────────────────────────────────────────────────────────

    /**
     * Tear down [state], wiping all session key material immediately.
     * Called by [CircuitManager] AFTER the replacement circuit has been
     * atomically installed. Entry, Guard, Middle, and Exit keys are all wiped.
     */
    fun teardown(state: CircuitState) {
        state.wipeKeys()
    }

    // ── Relay-side: decrypt one layer ─────────────────────────────────────

    /**
     * Called by a relay node acting as a hop in someone else's circuit.
     * Decrypts the outermost layer using [hopSessionKey] and returns the
     * next-hop address and inner payload.
     */
    suspend fun decryptLayer(
        ciphertext:    ByteArray,
        hopSessionKey: ByteArray
    ): LayerResult = withContext(Dispatchers.IO) {
        try {
            val plain = cipher.decrypt(ciphertext, hopSessionKey).getOrThrow()
            // Wire format: [4B addrLen][addr bytes][remaining = inner payload]
            if (plain.size < 4) return@withContext LayerResult.Malformed
            val addrLen = ((plain[0].toInt() and 0xFF) shl 24) or
                          ((plain[1].toInt() and 0xFF) shl 16) or
                          ((plain[2].toInt() and 0xFF) shl  8) or
                           (plain[3].toInt() and 0xFF)
            // Overflow-safe length check: addrLen is attacker-controlled from the decrypted
            // plaintext. Without the negative check, addrLen = Int.MAX_VALUE causes
            // (4 + addrLen) to overflow to Int.MIN_VALUE — the bounds check passes trivially
            // and copyOfRange throws an ArrayIndexOutOfBoundsException (caught safely, but
            // exploitable as relay-node DoS). Reject negative or oversized values explicitly.
            if (addrLen < 0 || addrLen > plain.size - 4) return@withContext LayerResult.Malformed
            val innerPayload = plain.copyOfRange(4 + addrLen, plain.size)
            // addrLen == 0 is the Exit signal: no next-hop address — payload is the final content.
            // Calling PeerAddress.fromBytes on an empty array would throw; return Exit instead.
            if (addrLen == 0) return@withContext LayerResult.Exit(innerPayload)
            val addrBytes   = plain.copyOfRange(4, 4 + addrLen)
            val nextAddress = PeerAddress.fromBytes(addrBytes)
            LayerResult.Forward(nextAddress, innerPayload)
        } catch (e: Exception) {
            Diag.swallowed("onion-circuit", "decrypt-layer", e)
            LayerResult.Malformed
        }
    }

    // ── Internal ──────────────────────────────────────────────────────────

    private suspend fun handshake(
        hop:       DhtContact,
        circuitId: String,
        transport: CircuitTransport
    ): ByteArray? {
        val hopPubKey = transport.requestHopPublicKey(hop, circuitId) ?: return null
        val kemResult = kem.encapsulate(hopPubKey).getOrNull() ?: return null
        transport.sendKemCiphertext(hop, circuitId, kemResult.ciphertext)
        // Bind hop.nodeId into the session key so a MITM that substitutes the hop's
        // KEM public key with their own derives a different key — the circuit builder's
        // expected key is tied to the identity of the intended hop, not just the
        // circuit ID. Without this binding, an adversary controlling the transport
        // between builder and any hop can substitute their own public key and read
        // that onion layer while the builder remains unaware.
        //
        // Salt = hop.nodeId.bytes + circuitId.toByteArray() ensures the key is
        // simultaneously bound to:
        //   - the specific hop identity (hop.nodeId — prevents cross-hop key reuse)
        //   - the circuit session (circuitId — prevents cross-circuit key reuse)
        val sessionKey = hkdf.derive(
            ikm       = kemResult.sharedSecret,
            salt      = hop.nodeId.bytes + circuitId.toByteArray(),
            info      = "shadowmesh_circuit_session_v1".toByteArray(),
            outputLen = 32
        )
        kemResult.sharedSecret.fill(0)
        return sessionKey
    }

    private suspend fun buildOnion(payload: ByteArray, state: CircuitState): ByteArray {
        // Exit layer — innermost
        val exitLayer = encryptLayer(payload, state.exit.sessionKey, null)

        // Middle layer — 4-hop only
        val afterMiddle = if (state.middle != null) {
            encryptLayer(exitLayer, state.middle.sessionKey, state.exit.address)
        } else {
            exitLayer
        }

        // Guard layer — 3-hop and 4-hop; null in 2-hop critical fallback
        val afterGuard = if (state.guard != null) {
            val nextAfterGuard = state.middle?.address ?: state.exit.address
            encryptLayer(afterMiddle, state.guard.sessionKey, nextAfterGuard)
        } else {
            afterMiddle
        }

        // Entry layer — outermost; always present
        val nextAfterEntry = state.guard?.address ?: state.exit.address
        return encryptLayer(afterGuard, state.entry.sessionKey, nextAfterEntry)
    }

    private suspend fun encryptLayer(
        inner:      ByteArray,
        sessionKey: ByteArray,
        nextAddr:   PeerAddress?
    ): ByteArray {
        val addrBytes = nextAddr?.toBytes() ?: ByteArray(0)
        val addrLen   = ByteArray(4) {
            when (it) {
                0    -> (addrBytes.size shr 24).toByte()
                1    -> (addrBytes.size shr 16).toByte()
                2    -> (addrBytes.size shr  8).toByte()
                else -> addrBytes.size.toByte()
            }
        }
        val plain = addrLen + addrBytes + inner
        return cipher.encrypt(plain, sessionKey).getOrThrow()
    }

    // ── Telescoping build ─────────────────────────────────────────────────

    /**
     * Build a circuit using telescoping KEM negotiation.
     *
     * Unlike [build], which contacts all hops directly and exposes their identities
     * to a network observer, telescoping negotiates each hop's session key THROUGH
     * the already-established tunnel. The result is that:
     *   - Guard/Middle/Exit IPs are never visible to a network observer during build.
     *   - Guard only sees Entry's IP, not the builder's real IP.
     *   - Each intermediate relay cannot learn the full circuit path.
     *
     * Protocol per hop (after Entry):
     *   1. Builder sends EXTEND_REQ (cell type 0x01) wrapped in the onion layers of all
     *      already-established hops. The outermost built hop sees addrLen=0 → EXIT → it
     *      processes the EXTEND_REQ control cell rather than forwarding IP traffic.
     *   2. That relay contacts the next hop directly (mini-KEM setup) and obtains its
     *      ephemeral public key. Relay sends EXTEND_ACK back toward the builder via
     *      CTRL_REPLY (0xFF magic — passed through intermediate hops without decryption).
     *   3. Builder encapsulates against the next hop's pubkey, derives session key,
     *      sends EXTEND_CT wrapped in the same onion layers.
     *   4. Relay forwards the ciphertext to the next hop, receives DONE confirmation,
     *      sends EXTEND_DONE back toward the builder via CTRL_REPLY.
     *
     * @param sendCell    Sends a wire packet ([circuitId prefix][onion bytes]) to Entry.
     * @param awaitReply  Waits for a nonce-matched CTRL_REPLY from any relay hop.
     *                    Backed by [CircuitManager.waitForReply].
     */
    suspend fun buildTelescoping(
        entry:      DhtContact,
        guard:      DhtContact?,
        middle:     DhtContact?,
        exit:       DhtContact,
        transport:  CircuitTransport,
        awaitReply: suspend (nonce: ByteArray, timeoutMs: Long) -> ByteArray?
    ): BuildResult = withContext(Dispatchers.IO) {
        val circuitId     = generateCircuitId()
        val circuitIdBytes = circuitId.toByteArray(Charsets.US_ASCII)
        val builtHops     = mutableListOf<HopKey>()

        fun wipeBuilt() = builtHops.forEach { it.wipe() }

        // ── Step 1: Entry — direct KEM (same as non-telescoping) ──────────
        val entryKey = handshake(entry, circuitId, transport)
        if (entryKey == null) { return@withContext BuildResult.HandshakeFailed("entry") }
        builtHops.add(HopKey(entry.nodeId, entry.address, entryKey))

        // ── Steps 2-4: each subsequent hop via in-tunnel EXTEND ───────────
        val subsequentHops = listOfNotNull(guard, middle, exit)
        for (nextHop in subsequentHops) {
            val sessionKey = extendTelescoping(
                nextHop       = nextHop,
                circuitId     = circuitId,
                circuitIdBytes = circuitIdBytes,
                builtHops     = builtHops,
                transport     = transport,
                awaitReply    = awaitReply
            )
            if (sessionKey == null) {
                wipeBuilt()
                return@withContext BuildResult.HandshakeFailed(nextHop.nodeId.toHex().take(8))
            }
            builtHops.add(HopKey(nextHop.nodeId, nextHop.address, sessionKey))
        }

        // Map builtHops list back to the named CircuitState fields
        val h = builtHops
        BuildResult.Success(CircuitState(
            id     = circuitId,
            entry  = h[0],
            guard  = if (guard  != null && h.size >= 2) h[1] else null,
            middle = if (middle != null && h.size >= 3) h[2] else null,
            exit   = h.last()
        ))
    }

    /**
     * Perform one EXTEND step: negotiate session key with [nextHop] through the tunnel
     * formed by [builtHops]. Returns the 32-byte session key on success, null on failure.
     */
    private suspend fun extendTelescoping(
        nextHop:        DhtContact,
        circuitId:      String,
        circuitIdBytes: ByteArray,
        builtHops:      List<HopKey>,
        transport:      CircuitTransport,
        awaitReply:     suspend (nonce: ByteArray, timeoutMs: Long) -> ByteArray?
    ): ByteArray? {
        val rng   = java.security.SecureRandom()
        val nonce = ByteArray(CIRCUIT_ID_BYTES).also { rng.nextBytes(it) }

        // ── Phase A: send EXTEND_REQ, receive next hop's KEM public key ───

        val reqBody = TelescopingCells.encodeExtendReq(nonce, nextHop.nodeId, nextHop.address)
        val reqOnion = buildControlOnion(reqBody, builtHops)
        transport.sendToEntry(builtHops.first().address, circuitIdBytes + reqOnion)

        val ackBody = awaitReply(nonce, EXTEND_TIMEOUT_MS) ?: run {
            Diag.degraded("onion-circuit", "extend-ack-timeout",
                "No EXTEND_ACK within ${EXTEND_TIMEOUT_MS}ms for hop ${nextHop.nodeId.toHex().take(8)}")
            return null
        }
        // ackBody: [1B EXTEND_ACK_BYTE][pubKey bytes]  (nonce already consumed by awaitReply)
        if (ackBody.isEmpty() || ackBody[0] != TelescopingCells.EXTEND_ACK_BYTE) {
            Diag.degraded("onion-circuit", "extend-ack-bad-type",
                "Expected EXTEND_ACK (0x02), got 0x${ackBody.firstOrNull()?.let { "%02x".format(it) } ?: "empty"}")
            return null
        }
        val nextPubKey = try {
            HybridPublicKey.fromBytes(ackBody.copyOfRange(1, ackBody.size))
        } catch (e: Exception) {
            Diag.swallowed("onion-circuit", "extend-pubkey-parse", e)
            return null
        }

        // ── Phase B: encapsulate, send EXTEND_CT, wait for EXTEND_DONE ───

        val kemResult = kem.encapsulate(nextPubKey).getOrNull() ?: return null

        val ctNonce = ByteArray(CIRCUIT_ID_BYTES).also { rng.nextBytes(it) }
        val ctBody  = TelescopingCells.encodeExtendCt(ctNonce, kemResult.ciphertext)
        val ctOnion = buildControlOnion(ctBody, builtHops)
        transport.sendToEntry(builtHops.first().address, circuitIdBytes + ctOnion)

        val doneBody = awaitReply(ctNonce, EXTEND_TIMEOUT_MS)
        if (doneBody == null || doneBody.isEmpty() || doneBody[0] != TelescopingCells.EXTEND_DONE_BYTE) {
            kemResult.sharedSecret.fill(0)
            Diag.degraded("onion-circuit", "extend-done-timeout",
                "No EXTEND_DONE for hop ${nextHop.nodeId.toHex().take(8)}")
            return null
        }

        // ── Phase C: derive session key (mirrors handshake() derivation) ──

        val sessionKey = hkdf.derive(
            ikm       = kemResult.sharedSecret,
            salt      = nextHop.nodeId.bytes + circuitId.toByteArray(),
            info      = SESSION_KEY_INFO,
            outputLen = 32
        )
        kemResult.sharedSecret.fill(0)
        return sessionKey
    }

    /**
     * Build an onion wrapping [payload] in the session keys of [hops].
     *
     * The innermost layer (last hop in [hops]) uses addrLen=0 so that hop's relay
     * processor receives [LayerResult.Exit] and dispatches the cell type byte.
     * Each outer layer uses the next-inner hop's address as the forwarding target,
     * exactly mirroring [buildOnion]'s structure but limited to [hops] rather than
     * the full four-hop circuit.
     *
     * Used to wrap EXTEND_REQ and EXTEND_CT control cells during telescoping build.
     */
    internal suspend fun buildControlOnion(payload: ByteArray, hops: List<HopKey>): ByteArray {
        require(hops.isNotEmpty()) { "buildControlOnion requires at least one hop" }
        // Innermost: addressed to the last hop (addrLen=0 → EXIT signal)
        var layer = encryptLayer(payload, hops.last().sessionKey, null)
        // Outer layers: each wraps with the NEXT hop's address as forwarding target
        for (i in hops.size - 2 downTo 0) {
            layer = encryptLayer(layer, hops[i].sessionKey, hops[i + 1].address)
        }
        return layer
    }

    private fun generateCircuitId(): String {
        val bytes = ByteArray(8).also { java.security.SecureRandom().nextBytes(it) }
        return bytes.toHex()
    }

    companion object {
        /**
         * Number of bytes used for the circuit ID prefix in the wire packet.
         * generateCircuitId() produces 8 random bytes encoded as 16 hex chars — 16 ASCII bytes.
         * Relay nodes extract this prefix to look up their session key for the circuit.
         */
        const val CIRCUIT_ID_BYTES = 16

        /** How long the builder waits for EXTEND_ACK or EXTEND_DONE per hop. */
        const val EXTEND_TIMEOUT_MS = 15_000L

        private val SESSION_KEY_INFO = "shadowmesh_circuit_session_v1".toByteArray()
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

sealed class BuildResult {
    data class Success(val circuit: OnionCircuit.CircuitState) : BuildResult()
    data class HandshakeFailed(val hop: String)               : BuildResult()
    object InsufficientPeers                                   : BuildResult()
}

sealed class SendResult {
    object Sent                          : SendResult()
    object NoCircuit                     : SendResult()
    data class Failed(val reason: String): SendResult()
}

sealed class LayerResult {
    data class Forward(val nextAddress: PeerAddress, val payload: ByteArray) : LayerResult()
    object Malformed                                                          : LayerResult()
    /** Exit layer: addrLen == 0. [payload] is the final decrypted content for the destination. */
    data class Exit(val payload: ByteArray)                                  : LayerResult()
}

// ── Transport interface ────────────────────────────────────────────────────────

interface CircuitTransport {
    /** Request a hop's KEM public key for circuit establishment. */
    suspend fun requestHopPublicKey(hop: DhtContact, circuitId: String): HybridPublicKey?
    /** Send KEM ciphertext to a hop so it can decapsulate the session key. */
    suspend fun sendKemCiphertext(hop: DhtContact, circuitId: String, ct: HybridCiphertext)
    /**
     * Send the fully-layered onion to the Entry node.
     * The Entry node peels its layer and forwards to Guard (or Exit in 2-hop fallback).
     * Named sendToEntry to reflect that the sender dispatches to their chosen Entry,
     * not directly to Guard — Guard no longer sees the sender's real IP.
     */
    suspend fun sendToEntry(entryAddress: PeerAddress, onion: ByteArray)
}

// ── PeerAddress wire serialization extension ──────────────────────────────────

fun PeerAddress.toBytes(): ByteArray {
    val ipBytes   = ip.toByteArray(Charsets.UTF_8)
    val portBytes = byteArrayOf((port shr 8).toByte(), port.toByte())
    val lenByte   = byteArrayOf(ipBytes.size.toByte())
    return lenByte + ipBytes + portBytes
}

fun PeerAddress.Companion.fromBytes(bytes: ByteArray): PeerAddress {
    require(bytes.size >= 3)
    val ipLen = bytes[0].toInt() and 0xFF
    require(bytes.size >= 1 + ipLen + 2)
    val ip   = String(bytes, 1, ipLen, Charsets.UTF_8)
    val port = ((bytes[1 + ipLen].toInt() and 0xFF) shl 8) or (bytes[2 + ipLen].toInt() and 0xFF)
    // Validate that the parsed string is a legitimate IP address (IPv4 or IPv6), not an
    // arbitrary UTF-8 string from attacker-controlled onion-layer plaintext. Without this
    // check, a relay node can inject a hostname (e.g. "stun.attacker.com") as a next-hop
    // address, triggering a DNS lookup that defeats the no-DNS-leak guarantee, or a
    // loopback/RFC-1918 address for SSRF-style redirection.
    //
    // InetAddress.getByName() on a numeric IP returns immediately (no DNS); on a hostname
    // it would do a DNS lookup. We compare the result's hostAddress to the original string:
    // if they differ, the input was a hostname (DNS was attempted) — reject it. If they
    // match, the input was already a valid IP literal. This works for both IPv4 and IPv6.
    val validated: String = try {
        val addr = java.net.InetAddress.getByName(ip)
        require(addr.hostAddress == ip) {
            "PeerAddress: '$ip' is a hostname, not an IP literal — rejected to prevent DNS leak"
        }
        ip
    } catch (e: Exception) {
        throw IllegalArgumentException("PeerAddress: invalid IP address '$ip': ${e.message}")
    }
    return PeerAddress(validated, port)
}

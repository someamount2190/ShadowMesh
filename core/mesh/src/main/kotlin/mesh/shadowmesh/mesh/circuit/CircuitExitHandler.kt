package mesh.shadowmesh.mesh.circuit

import mesh.shadowmesh.diagnostics.Diag
import mesh.shadowmesh.mesh.transport.UdpSocketAdapter

/**
 * Exit-node handler for circuit control messages.
 *
 * When a node acts as the exit hop of someone else's circuit, it receives the fully-
 * decrypted inner payload via [LayerResult.Exit]. If the payload begins with a recognised
 * control magic prefix it is a control request — the exit node processes it and routes
 * a reply back toward the initiator. If the payload is a normal IP packet it is forwarded
 * to the destination (outside the scope of this interface).
 *
 * The reply path:
 *   - [CircuitManager.sendWithReply] prepends a 16-byte nonce to every sent payload.
 *   - The exit node MUST include this nonce as the first 16 bytes of any reply.
 *   - [OnionCircuitPacketRouter.onCircuitResponse] strips the nonce and delivers the body
 *     to the waiting [CircuitManager.sendWithReply] coroutine.
 *
 * Wiring note: the production relay pipeline calls [handle] on every [LayerResult.Exit]
 * payload it decrypts. As of Phase 8, only STUN-over-circuit control messages are handled;
 * normal IP payloads bypass this handler and are forwarded directly to the IP layer.
 *
 * Thread-safety: implementations must be coroutine-safe — [handle] may be called from
 * multiple concurrent coroutines.
 */
interface CircuitExitHandler {
    /**
     * Handle an exit-layer payload that begins with a known control magic.
     *
     * @param nonce   The 16-byte request nonce prepended by [CircuitManager.sendWithReply].
     *                MUST be included as the first [REPLY_NONCE_BYTES] bytes of any reply.
     * @param payload The control payload after the nonce. Begins with a magic prefix
     *                identifying the control type (e.g., [StunCircuitExitHandler.CIRCUIT_STUN_MAGIC]).
     * @param replyFn Callback that routes `nonce + responseBody` back through the circuit
     *                toward the initiator. Implementations call this exactly once per
     *                successful request; on failure they return without calling it (the
     *                initiator's timeout fires and falls back gracefully).
     */
    suspend fun handle(
        nonce:   ByteArray,
        payload: ByteArray,
        replyFn: suspend (ByteArray) -> Unit
    )

    companion object {
        /** Must match [CircuitManager.REPLY_NONCE_BYTES]. */
        const val REPLY_NONCE_BYTES = 16
    }
}

/**
 * Handles STUN-over-circuit requests from the circuit initiator.
 *
 * Protocol (exit-node side):
 *   1. Detects [CIRCUIT_STUN_MAGIC] prefix in the decrypted exit payload.
 *   2. Parses stunIp:stunPort from the payload.
 *   3. Validates that stunIp is a dotted-decimal IPv4 literal (prevents DNS leak and SSRF).
 *   4. Issues a real RFC 5389 STUN Binding Request via [udpAdapter].
 *   5. Builds a synthetic STUN Binding Response carrying the XOR-MAPPED-ADDRESS.
 *   6. Sends `nonce + syntheticStunResponse` back via [replyFn].
 *
 * The initiator's [CircuitStunSenderImpl.parseStunXorMappedAddress] decodes the synthetic
 * response directly — it sees a valid RFC 5389 Binding Response with the exit node's
 * public address, not the initiator's. This is the correct privacy posture for CIRCUIT_ONLY
 * mode (see [CircuitStunSenderImpl] KDoc for the full security model).
 *
 * Failure handling: on any error (malformed payload, DNS-rejected IP, STUN timeout) the
 * handler returns without calling [replyFn]. The initiator's [sendWithReply] times out
 * after [CircuitStunSenderImpl.STUN_REPLY_TIMEOUT_MS] and returns null — fail-closed.
 *
 * @param udpAdapter  UDP socket for issuing the real STUN request.
 */
class StunCircuitExitHandler(
    private val udpAdapter: UdpSocketAdapter
) : CircuitExitHandler {

    override suspend fun handle(
        nonce:   ByteArray,
        payload: ByteArray,
        replyFn: suspend (ByteArray) -> Unit
    ) {
        if (!payload.startsWith(CIRCUIT_STUN_MAGIC)) return

        val body = payload.copyOfRange(CIRCUIT_STUN_MAGIC.size, payload.size)
        // Payload after magic: [1B ipLen][ipLen B ASCII ip][2B port big-endian]
        if (body.size < 3) {
            Diag.fallback("circuit-exit", "stun-malformed",
                "CIRCUIT_STUN payload too short after magic: ${body.size}B")
            return
        }
        val ipLen = body[0].toInt() and 0xFF
        if (body.size < 1 + ipLen + 2) {
            Diag.fallback("circuit-exit", "stun-malformed",
                "CIRCUIT_STUN payload truncated: ipLen=$ipLen totalSize=${body.size}")
            return
        }
        val stunIp   = String(body, 1, ipLen, Charsets.US_ASCII)
        val stunPort = ((body[1 + ipLen].toInt() and 0xFF) shl 8) or
                        (body[2 + ipLen].toInt() and 0xFF)

        // IP validation: must be a dotted-decimal IPv4 numeric literal.
        //   - Prevents DNS resolution (would leak the target hostname through the exit node).
        //   - Rejects RFC-1918 and loopback addresses (SSRF: prevents the exit node from
        //     probing its LAN on behalf of an adversarial initiator).
        val validatedIp = try {
            val addr = java.net.InetAddress.getByName(stunIp)
            require(addr.hostAddress == stunIp) {
                "STUN IP '$stunIp' is a hostname, not a numeric literal — DNS leak rejected"
            }
            require(!addr.isSiteLocalAddress) {
                "STUN IP '$stunIp' is an RFC-1918 private address — SSRF rejected"
            }
            require(!addr.isLoopbackAddress) {
                "STUN IP '$stunIp' is a loopback address — SSRF rejected"
            }
            stunIp
        } catch (e: Exception) {
            Diag.fallback("circuit-exit", "stun-invalid-ip",
                "CIRCUIT_STUN IP '$stunIp' rejected: ${e.message}")
            return
        }

        val mapped = udpAdapter.sendStunBindingRequest(validatedIp, stunPort)
        if (mapped == null) {
            Diag.degraded("circuit-exit", "stun-no-response",
                "No STUN response from $validatedIp:$stunPort — no reply sent to initiator")
            return
        }

        // Build a synthetic RFC 5389 Binding Response so the initiator's existing
        // parseStunXorMappedAddress() can decode it without changes.
        val syntheticResponse = buildSyntheticStunResponse(mapped.ip, mapped.port)
            ?: run {
                Diag.fallback("circuit-exit", "stun-build-response-failed",
                    "Could not build synthetic STUN response for mapped=${mapped.ip}:${mapped.port}")
                return
            }

        replyFn(nonce + syntheticResponse)
    }

    /**
     * Build a minimal RFC 5389 Binding Response carrying [ip]:[port] as an
     * XOR-MAPPED-ADDRESS attribute.
     *
     * Layout:
     *   [0..1]   type   = 0x0101 (Binding Response)
     *   [2..3]   length = 12    (one XOR-MAPPED-ADDRESS attribute = 4B header + 8B value)
     *   [4..7]   magic  = 0x2112A442
     *   [8..19]  txId   = 12 zero bytes (no real transaction to verify in this path)
     *   [20..21] attr type  = 0x0020 (XOR-MAPPED-ADDRESS)
     *   [22..23] attr len   = 8
     *   [24]     reserved   = 0
     *   [25]     family     = 0x01 (IPv4)
     *   [26..27] x-port     = port XOR (magic >> 16)
     *   [28..31] x-address  = ipOctets XOR magic (byte-by-byte)
     *
     * Returns null if [ip] is not a valid dotted-decimal IPv4 string.
     */
    private fun buildSyntheticStunResponse(ip: String, port: Int): ByteArray? {
        val magic  = 0x2112A442
        val octets = ip.split(".").mapNotNull { it.toIntOrNull() }
        if (octets.size != 4 || octets.any { it < 0 || it > 255 }) return null

        val xPort = port xor (magic ushr 16)
        val xA0   = octets[0] xor ((magic shr 24) and 0xFF)
        val xA1   = octets[1] xor ((magic shr 16) and 0xFF)
        val xA2   = octets[2] xor ((magic shr  8) and 0xFF)
        val xA3   = octets[3] xor  (magic         and 0xFF)

        val buf = ByteArray(32)
        buf[0]  = 0x01; buf[1]  = 0x01          // Binding Response
        buf[2]  = 0x00; buf[3]  = 0x0C          // message length = 12 bytes of attributes
        buf[4]  = 0x21; buf[5]  = 0x12; buf[6]  = 0xA4.toByte(); buf[7]  = 0x42  // magic cookie
        // bytes 8..19 = transaction ID (zeros — not echoed, no verification needed here)
        buf[20] = 0x00; buf[21] = 0x20          // XOR-MAPPED-ADDRESS attribute type
        buf[22] = 0x00; buf[23] = 0x08          // attribute value length = 8
        buf[24] = 0x00                           // reserved
        buf[25] = 0x01                           // address family = IPv4
        buf[26] = (xPort shr 8).toByte(); buf[27] = xPort.toByte()
        buf[28] = xA0.toByte(); buf[29] = xA1.toByte()
        buf[30] = xA2.toByte(); buf[31] = xA3.toByte()
        return buf
    }

    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (size < prefix.size) return false
        for (i in prefix.indices) if (this[i] != prefix[i]) return false
        return true
    }

    companion object {
        /**
         * Magic prefix for STUN-over-circuit payloads.
         * Must match [CircuitStunSenderImpl.CIRCUIT_STUN_MAGIC] exactly — both sides
         * must use the same 7-byte ASCII string "SMCSTUN".
         */
        val CIRCUIT_STUN_MAGIC: ByteArray = "SMCSTUN".toByteArray(Charsets.US_ASCII)
    }
}

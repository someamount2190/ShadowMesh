package mesh.shadowmesh.mesh.transport

import mesh.shadowmesh.diagnostics.Diag
import mesh.shadowmesh.mesh.circuit.CircuitManager
import mesh.shadowmesh.mesh.circuit.SendResult
import mesh.shadowmesh.mesh.dht.PeerAddress
import kotlinx.coroutines.TimeoutCancellationException

/**
 * Routes STUN through the onion circuit so no clear-text DNS or direct STUN ever leaves this
 * node. Implemented over [CircuitManager].
 *
 * IMPORTANT ARCHITECTURAL TRUTH (this is why the latency question has a surprising answer):
 *
 * A STUN binding request sent through the circuit egresses from the EXIT hop. The reflexive
 * address the STUN server reports is therefore the EXIT HOP's public address, NOT this node's
 * own NAT mapping. That has two consequences:
 *
 *   1. You cannot use a circuit-discovered address to do classic UDP hole punching to your
 *      OWN NAT — you never learned your own mapping. Hole punching requires a DIRECT STUN
 *      query (StunPrivacyPolicy.DIRECT_IP_ONLY). So CIRCUIT_ONLY is not "hole punching but
 *      slower" — it is a DIFFERENT connectivity mode: peers reach this node THROUGH the
 *      circuit/relay, not via a punched hole tied to its real IP. That is the privacy posture,
 *      by design.
 *
 *   2. Because CIRCUIT_ONLY does not feed the hole-punch path, routing STUN through the
 *      circuit does NOT add latency to hole punching — the two don't coexist. The latency
 *      that matters for hole punching lives entirely in the DIRECT_IP_ONLY path and in the
 *      DHT rendezvous coordination, which is modelled in NatTraversalEngine's adaptive
 *      punch schedule (see [NatTraversalEngine.estimateAdaptivePunchPlan]).
 *
 * Protocol status: implemented as a request-reply over the circuit. [CircuitManager.sendWithReply]
 * prepends an 8-byte nonce to the payload and waits for [OnionCircuitPacketRouter.onCircuitResponse]
 * to deliver a matching reply. The exit node must detect the [CIRCUIT_STUN_MAGIC] prefix, issue the
 * real STUN binding request, and send the XOR-MAPPED-ADDRESS reply back prefixed with the nonce.
 * If no reply arrives within [STUN_REPLY_TIMEOUT_MS], returns null — fail-closed, never a direct query.
 */
class CircuitStunSenderImpl(
    private val circuitManager: CircuitManager
) : CircuitStunSender {

    override suspend fun sendStunBindingViaCircuit(stunIp: String, stunPort: Int): PeerAddress? {
        // Send the STUN request through the circuit and wait for the exit node's reply.
        //
        // Protocol (both sides must implement):
        //   Sender side (this method):
        //     1. CircuitManager.sendWithReply() prepends an 8-byte nonce and sends through circuit.
        //     2. Waits up to STUN_REPLY_TIMEOUT_MS for OnionCircuitPacketRouter.onCircuitResponse
        //        to deliver the reply (identified by the nonce prefix).
        //
        //   Exit node side (OnionCircuitPacketRouter / exit handler):
        //     1. Detects CIRCUIT_STUN_MAGIC in the decrypted exit payload.
        //     2. Parses stunIp:stunPort from the payload.
        //     3. Issues a real STUN binding request via its own UDP socket.
        //     4. Wraps the XOR-MAPPED-ADDRESS bytes with the original 8-byte nonce prefix.
        //     5. Sends the reply back through the circuit toward the initiator.
        //
        // The exit-node handler is implemented in the circuit packet processing path and
        // requires the exit node to have a live UDP socket (UdpSocketAdapter). When the exit
        // node is running the same app build, this handler is always available.
        val request = buildCircuitStunRequest(stunIp, stunPort)
        val replyBytes = circuitManager.sendWithReply(request, timeoutMs = STUN_REPLY_TIMEOUT_MS)
        if (replyBytes == null) {
            Diag.degraded("nat-traversal", "circuit-stun-no-reply",
                "No STUN reply received within ${STUN_REPLY_TIMEOUT_MS}ms via circuit " +
                "(CIRCUIT_ONLY privacy mode) — circuit STUN unavailable, caller falls back to mesh relay.")
            return null
        }
        return parseStunXorMappedAddress(replyBytes)
    }

    /*
     * Parse the XOR-MAPPED-ADDRESS attribute from a STUN binding response.
     * Returns null if the attribute is absent or the response is malformed.
     *
     * STUN response layout (RFC 5389):
     *   2B type, 2B length, 4B magic 0x2112A442, 12B txn-id, attributes...
     * XOR-MAPPED-ADDRESS attribute (type 0x0020):
     *   2B type=0x0020, 2B len, 1B reserved, 1B family=0x01, 2B port XOR (magic>>16), 4B IP XOR magic
     */
    private fun parseStunXorMappedAddress(bytes: ByteArray): PeerAddress? {
        if (bytes.size < 20) return null
        val magic = 0x2112A442
        var off = 20  // skip 20-byte STUN header
        while (off + 4 <= bytes.size) {
            val attrType = ((bytes[off    ].toInt() and 0xFF) shl 8) or (bytes[off + 1].toInt() and 0xFF)
            val attrLen  = ((bytes[off + 2].toInt() and 0xFF) shl 8) or (bytes[off + 3].toInt() and 0xFF)
            off += 4
            if (attrType == 0x0020 && attrLen >= 8 && off + attrLen <= bytes.size) {
                // off+0 = reserved, off+1 = family, off+2..3 = XOR'd port, off+4..7 = XOR'd IPv4
                val port = (((bytes[off + 2].toInt() and 0xFF) shl 8) or
                             (bytes[off + 3].toInt() and 0xFF)) xor ((magic ushr 16) and 0xFFFF)
                val ip0  = (bytes[off + 4].toInt() and 0xFF) xor ((magic shr 24) and 0xFF)
                val ip1  = (bytes[off + 5].toInt() and 0xFF) xor ((magic shr 16) and 0xFF)
                val ip2  = (bytes[off + 6].toInt() and 0xFF) xor ((magic shr  8) and 0xFF)
                val ip3  = (bytes[off + 7].toInt() and 0xFF) xor  (magic         and 0xFF)
                return PeerAddress("$ip0.$ip1.$ip2.$ip3", port and 0xFFFF)
            }
            // Advance to next attribute (4-byte aligned)
            off += (attrLen + 3) and 3.inv()
        }
        return null
    }

    private fun buildCircuitStunRequest(stunIp: String, stunPort: Int): ByteArray {
        // [4B magic]["STUN"][ip utf8 len + ip][2B port] — consumed by the (future) exit handler.
        val ipBytes = stunIp.toByteArray(Charsets.US_ASCII)
        return CIRCUIT_STUN_MAGIC +
            byteArrayOf(ipBytes.size.toByte()) + ipBytes +
            byteArrayOf((stunPort shr 8).toByte(), stunPort.toByte())
    }

    companion object {
        private val CIRCUIT_STUN_MAGIC = "SMCSTUN".toByteArray(Charsets.US_ASCII)

        /** How long to wait for the exit node's STUN reply before giving up. */
        private const val STUN_REPLY_TIMEOUT_MS = 10_000L
    }
}

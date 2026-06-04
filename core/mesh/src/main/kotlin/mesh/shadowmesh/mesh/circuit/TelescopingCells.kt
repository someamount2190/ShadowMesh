package mesh.shadowmesh.mesh.circuit

import mesh.shadowmesh.crypto.HybridCiphertext
import mesh.shadowmesh.crypto.HybridPublicKey
import mesh.shadowmesh.mesh.dht.NodeId
import mesh.shadowmesh.mesh.dht.PeerAddress

/**
 * Cell-type constants and wire encode/decode helpers for the telescoping circuit protocol.
 *
 * All cells travel inside an onion-encrypted layer. When a relay's [OnionCircuit.decryptLayer]
 * returns [LayerResult.Exit] (addrLen == 0), the inner payload's first byte identifies the
 * cell type. This byte is positioned after the 4-byte addrLen field that [decryptLayer] already
 * parses. Callers receive the raw inner bytes and dispatch on [payload[0]].
 *
 * ## Cell types
 *
 *   DATA         (0x00) — Normal IP / application payload (current behavior when byte absent).
 *   EXTEND_REQ   (0x01) — Builder asks this relay to extend the circuit to a next hop.
 *   EXTEND_ACK   (0x02) — Relay replies with the next hop's KEM public key.
 *   EXTEND_CT    (0x03) — Builder sends the KEM ciphertext for the next hop.
 *   EXTEND_DONE  (0x04) — Relay confirms the next hop has completed KEM setup.
 *   DESTROY      (0x05) — Tear down this circuit.
 *
 * ## Backward (relay → builder) wire format
 *
 * Backward packets do NOT use session-key encryption for the backward path — instead, they
 * are passed through intermediate relays unmodified using the CTRL_REPLY prefix:
 *
 *   [16B circuitId ASCII][CTRL_REPLY_MAGIC: 0xFF][16B nonce][reply body]
 *
 * Each relay that sees 0xFF after the circuitId immediately forwards the entire packet to
 * its stored upstream address ([CircuitRelayProcessor.upstreamAddresses]).
 * At the builder, [OnionCircuitPacketRouter.onCircuitResponse] strips the 0xFF prefix and
 * delivers `nonce + body` to [CircuitManager.onReply].
 *
 * ## EXTEND_REQ payload encoding
 *
 *   [1B EXTEND_REQ_BYTE]
 *   [16B nonce]              — used to match EXTEND_ACK and EXTEND_CT replies
 *   [32B targetNodeId]       — bound into session key HKDF salt
 *   [1B addrLen][addrLen B ascii ip][2B port BE]  — next hop address
 *
 * ## EXTEND_ACK payload encoding
 *
 *   [1B EXTEND_ACK_BYTE]
 *   [HybridPublicKey.toBytes()]  — next hop's ephemeral KEM public key
 *
 * ## EXTEND_CT payload encoding
 *
 *   [1B EXTEND_CT_BYTE]
 *   [16B nonce]              — same nonce as the originating EXTEND_REQ
 *   [HybridCiphertext.toBytes()]
 *
 * ## EXTEND_DONE payload encoding
 *
 *   [1B EXTEND_DONE_BYTE]
 *   [16B nonce]              — same nonce as the originating EXTEND_REQ/CT
 */
object TelescopingCells {

    const val DATA_BYTE        : Byte = 0x00
    const val EXTEND_REQ_BYTE  : Byte = 0x01
    const val EXTEND_ACK_BYTE  : Byte = 0x02
    const val EXTEND_CT_BYTE   : Byte = 0x03
    const val EXTEND_DONE_BYTE : Byte = 0x04
    const val DESTROY_BYTE     : Byte = 0x05

    /**
     * Magic prefix for backward (relay-to-builder) CTRL_REPLY packets.
     * Occupies the byte at offset [OnionCircuit.CIRCUIT_ID_BYTES] in the wire packet,
     * where DATA packets have encrypted ciphertext (never 0xFF as the first byte after
     * the circuitId header — AES/ChaCha20 output is uniformly distributed).
     */
    const val CTRL_REPLY_MAGIC : Byte = 0xFF.toByte()

    // ── Encode ─────────────────────────────────────────────────────────────

    /**
     * Encode an EXTEND_REQ cell body.
     *
     * @param nonce       16-byte request nonce for reply matching.
     * @param targetNodeId 32-byte nodeId of the next hop — bound into the HKDF salt.
     * @param targetAddr  Network address of the next hop.
     */
    fun encodeExtendReq(
        nonce:        ByteArray,
        targetNodeId: NodeId,
        targetAddr:   PeerAddress
    ): ByteArray {
        require(nonce.size == NONCE_BYTES) { "nonce must be $NONCE_BYTES bytes" }
        val addrBytes = targetAddr.toBytes()   // [1B ipLen][ip ASCII][2B port]
        return byteArrayOf(EXTEND_REQ_BYTE) + nonce + targetNodeId.bytes + addrBytes
    }

    /**
     * Encode an EXTEND_ACK cell body carrying the next hop's KEM public key.
     *
     * Wire: [1B EXTEND_ACK_BYTE][HybridPublicKey.toBytes()]
     * The nonce is NOT repeated here — it is already carried at the CTRL_REPLY transport
     * level by [CircuitRelayProcessor.sendCtrlReply]. Including it in the body caused
     * [OnionCircuit.extendTelescoping] to pass [nonce || pubKey] to
     * [HybridPublicKey.fromBytes], which rejected the 16-byte prefix and made every
     * telescoping circuit build fail.
     */
    fun encodeExtendAck(pubKey: HybridPublicKey): ByteArray {
        return byteArrayOf(EXTEND_ACK_BYTE) + pubKey.toBytes()
    }

    /** Encode an EXTEND_CT cell body carrying the KEM ciphertext for the next hop. */
    fun encodeExtendCt(nonce: ByteArray, ct: HybridCiphertext): ByteArray {
        require(nonce.size == NONCE_BYTES)
        return byteArrayOf(EXTEND_CT_BYTE) + nonce + ct.toBytes()
    }

    /** Encode an EXTEND_DONE cell body signalling that the next hop completed KEM setup. */
    fun encodeExtendDone(nonce: ByteArray): ByteArray {
        require(nonce.size == NONCE_BYTES)
        return byteArrayOf(EXTEND_DONE_BYTE) + nonce
    }

    // ── Decode ─────────────────────────────────────────────────────────────

    data class ExtendReq(
        val nonce:        ByteArray,
        val targetNodeId: NodeId,
        val targetAddr:   PeerAddress
    )

    /**
     * Decode an EXTEND_REQ payload (first byte already consumed by caller).
     * Returns null if the payload is malformed.
     */
    fun decodeExtendReq(payload: ByteArray): ExtendReq? {
        // payload: [16B nonce][32B nodeId][addrBytes…]
        val minSize = NONCE_BYTES + 32 + 3  // 3 = minimum addr: 1B len + 0B ip + 2B port
        if (payload.size < minSize) return null
        var off = 0
        val nonce = payload.copyOfRange(off, off + NONCE_BYTES); off += NONCE_BYTES
        val nodeId = NodeId(payload.copyOfRange(off, off + 32)); off += 32
        return try {
            val addr = PeerAddress.fromBytes(payload.copyOfRange(off, payload.size))
            ExtendReq(nonce, nodeId, addr)
        } catch (_: Exception) { null }
    }

    /** Extract the nonce from any cell body whose first byte is a known type (offset 0..15). */
    fun extractNonce(payload: ByteArray): ByteArray? {
        if (payload.size < NONCE_BYTES) return null
        return payload.copyOfRange(0, NONCE_BYTES)
    }

    const val NONCE_BYTES = 16   // must match CircuitManager.REPLY_NONCE_BYTES
}

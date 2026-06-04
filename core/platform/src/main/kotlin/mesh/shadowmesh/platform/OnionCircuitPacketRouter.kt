package mesh.shadowmesh.platform

import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.mesh.circuit.CircuitManager
import mesh.shadowmesh.mesh.circuit.CircuitManager.Companion.REPLY_NONCE_BYTES
import mesh.shadowmesh.mesh.circuit.SendResult
import kotlinx.coroutines.CoroutineScope

/**
 * Concrete [CircuitPacketRouter] that bridges the VPN tunnel to the mesh onion circuit.
 * Phase 8 — VPN circuit integration.
 *
 * Outbound: each IP packet captured from TUN is dispatched through [circuitManager]'s active
 * circuit via [CircuitManager.send]. The packet is the opaque circuit payload; the Exit node
 * is responsible for forwarding it to its destination.
 *
 * Inbound: when a response arrives back through the circuit, the mesh transport layer calls
 * [onCircuitResponse], which forwards the bytes to the sink the VpnService registered
 * (see [setInboundSink]). The transport→router wiring lives in the mesh/app composition root;
 * this class only exposes the entry point.
 *
 * This is the file that makes the platform module depend on core:mesh — the dependency
 * direction is platform → mesh (the OS-integration layer sits above the portable mesh core).
 */
class OnionCircuitPacketRouter(
    private val circuitManager: CircuitManager,
    private val scope:          CoroutineScope,
    /** Invoked when [CircuitManager.send] reports no circuit is currently available. */
    private val onNoCircuit:    () -> Unit = {}
) : CircuitPacketRouter {

    @Volatile private var inboundSink: ((ByteArray) -> Unit)? = null

    override suspend fun routeOutbound(ipPacket: ByteArray) {
        when (circuitManager.send(ipPacket)) {
            is SendResult.Sent      -> Unit
            is SendResult.NoCircuit -> onNoCircuit()
            is SendResult.Failed    -> Unit  // drop; IP is best-effort, upper layers retransmit
        }
    }

    override fun setInboundSink(sink: (ByteArray) -> Unit) { inboundSink = sink }

    /**
     * Entry point for the mesh transport to deliver a circuit response packet back to TUN.
     *
     * Before forwarding to the TUN sink, checks whether the payload begins with an 8-byte
     * nonce that matches a pending [CircuitManager.sendWithReply] or
     * [CircuitManager.waitForReply] call. If it does, the packet is consumed as a reply
     * (the deferred is completed) and is NOT written to TUN.
     *
     * Telescoping CTRL_REPLY packets (from relay EXTEND_ACK / EXTEND_DONE) arrive with
     * [TelescopingCells.CTRL_REPLY_MAGIC] (0xFF) as the first byte, followed by the nonce
     * and reply body. This byte is stripped before the nonce check so both telescoping
     * control replies and regular STUN-over-circuit replies use the same nonce-matching path.
     *
     * If no matching nonce is found the payload (after any magic stripping) is forwarded
     * to the TUN sink as a normal IP response.
     */
    fun onCircuitResponse(payload: ByteArray) {
        // Strip CTRL_REPLY_MAGIC (0xFF) emitted by relay nodes for telescoping EXTEND replies.
        val effective = if (payload.isNotEmpty() &&
            payload[0] == mesh.shadowmesh.mesh.circuit.TelescopingCells.CTRL_REPLY_MAGIC) {
            payload.copyOfRange(1, payload.size)
        } else {
            payload
        }
        if (effective.size >= REPLY_NONCE_BYTES) {
            val nonceHex = effective.copyOfRange(0, REPLY_NONCE_BYTES).toHex()
            val body     = effective.copyOfRange(REPLY_NONCE_BYTES, effective.size)
            if (circuitManager.onReply(nonceHex, body)) return  // consumed as reply
        }
        inboundSink?.invoke(effective)
    }

    override fun close() { inboundSink = null }
}

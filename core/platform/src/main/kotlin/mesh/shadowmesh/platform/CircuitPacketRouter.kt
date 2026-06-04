package mesh.shadowmesh.platform

/**
 * Seam between Android's [ShadowMeshVpnService] (which owns the TUN interface)
 * and the mesh onion circuit (which carries the bytes). Phase 8 — VPN circuit integration.
 *
 * The VpnService captures raw IP packets from the device's TUN file descriptor and
 * hands each one to [routeOutbound]. The implementation (see
 * `mesh.shadowmesh.platform.OnionCircuitPacketRouter`) wraps the packet and dispatches
 * it through the active onion circuit via `CircuitManager.send`.
 *
 * Return traffic that arrives back through the circuit is handed to the sink registered
 * via [setInboundSink]; the VpnService writes those bytes back to the TUN fd so the
 * device's network stack sees the response.
 *
 * Keeping this as an interface means [ShadowMeshVpnService] (a low-level Android Service)
 * does not depend on the mesh module directly — the concrete router is injected at runtime
 * via [ShadowMeshVpnService.routerProvider]. This keeps the dependency direction one-way
 * (platform → mesh) and lets the VPN service be unit-reasoned in isolation.
 */
interface CircuitPacketRouter {

    /**
     * Route a single outbound IP packet (captured from TUN) through the onion circuit.
     * Implementations must be non-blocking from the caller's perspective — the VpnService
     * read loop must not stall on circuit latency. Returns once the packet has been
     * accepted for dispatch (not once it has been delivered).
     */
    suspend fun routeOutbound(ipPacket: ByteArray)

    /**
     * Register the sink that receives packets arriving back through the circuit.
     * The VpnService sets this to a function that writes to the TUN output stream.
     * Replacing the sink (or passing a no-op) detaches the previous one.
     */
    fun setInboundSink(sink: (ByteArray) -> Unit)

    /**
     * Release any resources and detach the inbound sink. Called when the VpnService
     * tears down the tunnel (revoke, stop, or process death).
     */
    fun close()
}

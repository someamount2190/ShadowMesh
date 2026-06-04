package mesh.shadowmesh.platform

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import kotlinx.coroutines.*
import mesh.shadowmesh.diagnostics.Diag
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * SHADOWMESH VPN tunnel — Phase 8 (VPN circuit integration).
 *
 * This is the Android [VpnService] subclass referenced by [MeshForegroundService]'s
 * KDoc and by [VpnServiceBridge]. It establishes a local TUN interface, captures every
 * outbound IP packet, and routes it through the onion circuit via a [CircuitPacketRouter].
 * Return traffic from the circuit is written back into TUN so the device's network stack
 * sees a normal response.
 *
 * Routing model:
 *   device app → TUN → [readLoop] → router.routeOutbound() → onion circuit → Exit → internet
 *   internet → Exit → onion circuit → router inbound sink → [writeInbound] → TUN → device app
 *
 * Why a separate service from [MeshForegroundService]:
 *   A VpnService requires the `BIND_VPN_SERVICE` permission and the one-time system
 *   consent dialog obtained via [VpnService.prepare]. [MeshForegroundService] keeps the
 *   mesh process alive; this service owns only the packet tunnel. They run independently
 *   so revoking the VPN does not kill the mesh.
 *
 * Router injection:
 *   Android instantiates Services with a no-arg constructor, so the concrete
 *   [CircuitPacketRouter] (which depends on the mesh module) cannot be passed in. The app
 *   layer sets [routerProvider] once at startup; [onStartCommand] resolves it. If no
 *   provider is set the service stops immediately rather than tunnelling into a black hole.
 *
 * MTU and addressing:
 *   A link-local TUN address (10.x) is assigned and all traffic (0.0.0.0/0) is routed in.
 *   No DNS server is set on the interface — name resolution must happen Exit-side to avoid
 *   leaking lookups outside the circuit. MTU is conservative ([TUN_MTU]) to keep onion
 *   layering overhead within a single fragment where possible.
 */
class ShadowMeshVpnService : VpnService() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var tunInterface: ParcelFileDescriptor? = null
    private var readJob: Job? = null
    private var router: CircuitPacketRouter? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            teardown()
            stopSelf()
            return START_NOT_STICKY
        }

        val provider = routerProvider
        if (provider == null) {
            Log.e(TAG, "No CircuitPacketRouter provider set — refusing to start tunnel")
            stopSelf()
            return START_NOT_STICKY
        }

        if (tunInterface == null) {
            startTunnel(provider())
        }
        return START_STICKY
    }

    private fun startTunnel(router: CircuitPacketRouter) {
        this.router = router

        val builder = Builder()
            .setSession(SESSION_NAME)
            .setMtu(TUN_MTU)
            .addAddress(TUN_ADDRESS, TUN_PREFIX)
            .addRoute("0.0.0.0", 0)   // capture all IPv4 traffic
            // Deliberately no addDnsServer(): DNS must resolve Exit-side, never on-device,
            // or lookups would leak outside the circuit.
            .setBlocking(true)

        val tun = builder.establish()
        if (tun == null) {
            Log.e(TAG, "VpnService.Builder.establish() returned null — permission missing?")
            stopSelf()
            return
        }
        tunInterface = tun

        val output = FileOutputStream(tun.fileDescriptor)
        // Inbound: circuit responses get written straight back to TUN.
        router.setInboundSink { packet ->
            try {
                synchronized(output) { output.write(packet); output.flush() }
            } catch (e: Exception) {
                Log.w(TAG, "Inbound write to TUN failed: ${e.message}")
                Diag.swallowed("vpn", "inbound-write", e)
            }
        }

        readJob = scope.launch { readLoop(FileInputStream(tun.fileDescriptor), router) }
        Log.d(TAG, "Tunnel established (mtu=$TUN_MTU)")
    }

    /** Read raw IP packets off TUN and route each through the circuit. */
    private suspend fun readLoop(input: FileInputStream, router: CircuitPacketRouter) {
        val buffer = ByteArray(TUN_MTU)
        try {
            while (currentCoroutineContext().isActive) {
                val n = input.read(buffer)
                if (n <= 0) {
                    // 0 = no data this cycle; negative = EOF. Yield to avoid a busy spin.
                    yield()
                    continue
                }
                val packet = buffer.copyOf(n)
                // Validate IP header before routing to prevent malformed packets from
                // propagating through the circuit and wasting bandwidth or causing exit-node errors.
                if (!isValidIpPacket(packet)) continue
                router.routeOutbound(packet)
            }
        } catch (_: CancellationException) {
            // normal teardown
        } catch (e: Exception) {
            Log.w(TAG, "TUN read loop ended: ${e.message}")
            Diag.swallowed("vpn", "read-loop", e)
        }
    }

    override fun onRevoke() {
        // User revoked VPN consent (or another VPN took over). Tear down cleanly.
        Log.d(TAG, "VPN consent revoked — tearing down tunnel")
        teardown()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        teardown()
        scope.cancel()
        super.onDestroy()
    }

    /**
     * Minimal IP header sanity check — rejects structurally invalid packets before
     * they are routed through the onion circuit.
     *
     * Checks: packet is non-empty, version is 4 (IPv4) or 6 (IPv6), and the packet
     * is at least as long as the minimum header for that version (20B for IPv4, 40B for IPv6).
     * Does NOT perform a full checksum — the circuit layer adds its own integrity via
     * ChaCha20-Poly1305 AEAD, so an invalid checksum inside the tunnel is caught there.
     */
    private fun isValidIpPacket(packet: ByteArray): Boolean {
        if (packet.isEmpty()) return false
        return when ((packet[0].toInt() shr 4) and 0xF) {
            4 -> packet.size >= 20   // IPv4: minimum header is 20 bytes
            6 -> packet.size >= 40   // IPv6: minimum header is 40 bytes
            else -> false
        }
    }

    private fun teardown() {
        readJob?.cancel()
        readJob = null
        router?.close()
        router = null
        runCatching { tunInterface?.close() }
        tunInterface = null
        // Clear the router reference — do NOT null routerProvider (that's the app-level
        // factory, not our router instance). The factory persists; our resolved instance
        // is cleared so a subsequent onStartCommand resolves a fresh one.
    }

    companion object {
        const val TAG             = "ShadowMeshVpnService"
        const val SESSION_NAME    = "SHADOWMESH"
        const val ACTION_DISCONNECT = "mesh.shadowmesh.ACTION_VPN_DISCONNECT"

        // Link-local TUN config — never routable on the real network.
        const val TUN_ADDRESS = "10.111.0.2"
        const val TUN_PREFIX  = 32
        // Conservative MTU: leaves headroom for ChaCha20-Poly1305 tags + onion address
        // headers across up to four hops without IP-layer fragmentation on a 1500 link.
        const val TUN_MTU     = 1280

        /**
         * Set once by the app layer at startup. Supplies the concrete
         * [CircuitPacketRouter] bound to the live mesh [CircuitManager].
         *
         * Android constructs Services independently — this static provider is the
         * only injection point available without a bound service architecture.
         *
         * Stale-reference risk: if the [CircuitManager] is replaced (e.g. on full
         * mesh restart), the app layer MUST update this provider before the service's
         * next [onStartCommand]. On START_STICKY restart, the OS re-delivers the
         * intent before the Application's mesh init completes. Set this BEFORE
         * calling [VpnServiceBridge.start] so the service always resolves a live router.
         *
         * Cleanup: the app layer should null this out on shutdown to avoid holding a
         * reference to a torn-down CircuitManager after the mesh stops.
         */
        @Volatile
        var routerProvider: (() -> CircuitPacketRouter)? = null
    }
}

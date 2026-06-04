package mesh.shadowmesh.mesh.transport

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import mesh.shadowmesh.mesh.dht.PeerAddress
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Production [UdpSocketAdapter] backed by [java.net.DatagramSocket].
 *
 * ## Single-socket demultiplexing
 *
 * Both DHT RPCs ([UdpDhtTransport]) and NAT traversal probes ([NatTraversalEngine]) must
 * share one bound UDP port. A single [DatagramSocket] is bound to [localPort] on construction.
 * The listener loop ([startListening]) reads every incoming datagram and routes it by magic:
 *
 *   - [DHT_MAGIC] prefix  → forwarded to [onDhtDatagram] callback (wired to UdpDhtTransport)
 *   - [PROBE_MAGIC] prefix → matched against token waiters (hole-punch probes)
 *   - [PONG_MAGIC] prefix  → matched against token waiters (hole-punch pong replies)
 *   - Anything else        → discarded with a Diag.fallback entry
 *
 * ## STUN wire format (RFC 5389 §6 — Binding Request / §10 — XOR-MAPPED-ADDRESS)
 *
 * [sendStunBindingRequest] builds a minimal RFC 5389 Binding Request and parses the
 * XOR-MAPPED-ADDRESS attribute from the response. Only IPv4 is supported in this
 * implementation (STUN servers see our public IPv4; IPv6 STUN is a Phase 5 concern).
 *
 * ## Lifecycle
 *
 * Call [startListening] once after construction to start the receive loop.
 * Call [close] on shutdown — closes the socket and cancels the loop.
 * The socket is created eagerly; if binding fails the constructor throws.
 *
 * ## Threading
 *
 * [startListening] launches the receive loop on [Dispatchers.IO] under [scope].
 * Send operations also run on [Dispatchers.IO] via [withContext].
 * Token-waiter completions run on the caller's dispatcher (ContinuationInterceptor).
 *
 * @param localPort       UDP port to bind. Must match [UdpDhtTransport.DHT_PORT].
 * @param scope           CoroutineScope for the receive loop lifetime.
 * @param onDhtDatagram   Called for every datagram whose first two bytes are [DHT_MAGIC].
 *                        Receives the raw payload, sender IP string, and sender port.
 *                        Null until [UdpDhtTransport] registers itself — DHT datagrams
 *                        arriving before registration are discarded (Diag.fallback logged).
 * @param receiveTimeoutMs Per-datagram receive timeout. Kept short so the loop notices
 *                        socket closure promptly without blocking indefinitely.
 */
class DatagramSocketUdpAdapter(
    val localPort:     Int = DHT_PORT,
    private val scope: CoroutineScope,
    @Volatile var onDhtDatagram: ((payload: ByteArray, senderIp: String, senderPort: Int) -> Unit)? = null,
    private val receiveTimeoutMs: Int = SOCKET_RECEIVE_TIMEOUT_MS,
    /**
     * Optional callback invoked with the native file descriptor immediately after the socket
     * is bound. In production, wire this to `VpnService.protect(fd)` so DHT/UDP datagrams
     * bypass the VPN tunnel and reach the internet directly.
     *
     * Without this, when the VPN tunnel is active, UDP datagrams are routed THROUGH the
     * tunnel (wrapped in the circuit) rather than going directly to the peer — this creates
     * a routing loop for DHT bootstrap traffic and breaks peer discovery.
     *
     * Example wiring in ShadowMeshApplication:
     *   socketProtect = { fd -> shadowMeshVpnService?.protect(fd) }
     */
    private val socketProtect: ((fd: Int) -> Unit)? = null
) : UdpSocketAdapter {

    // Bound socket — created eagerly so callers know immediately if the port is in use.
    // VPN protect() must be called before the socket is used to send/receive, so it is
    // applied immediately after bind.
    val socket: DatagramSocket = DatagramSocket(localPort).also {
        it.soTimeout = receiveTimeoutMs
        socketProtect?.let { protect ->
            val pfd = android.os.ParcelFileDescriptor.fromDatagramSocket(it)
            try { protect(pfd.fd) } finally { pfd.close() }
        }
    }

    // Pending token waiters for hole-punch probes/pongs.
    // Key: first TOKEN_KEY_LEN bytes of the rendezvous token (hex string for map key).
    // Value: CompletableDeferred that completes with the full received payload.
    private val tokenWaiters = ConcurrentHashMap<String, CompletableDeferred<ByteArray>>()

    // Pending STUN response waiters, keyed by 12-byte transaction ID (hex string).
    // Routing STUN responses through the same dispatch path as all other datagrams
    // eliminates the race between sendStunBindingRequest's direct socket.receive() call
    // and the listener loop — only one coroutine ever calls socket.receive() at a time.
    private val stunWaiters = ConcurrentHashMap<String, CompletableDeferred<ByteArray>>()

    private val sendMutex = Mutex()   // DatagramSocket.send is not thread-safe on all JVMs

    // ── UdpSocketAdapter ──────────────────────────────────────────────────

    /**
     * Send [payload] to [host]:[port] as a single UDP datagram.
     * [host] must be a dotted-decimal IP string — no DNS resolution is ever performed.
     */
    override suspend fun sendUdp(host: String, port: Int, payload: ByteArray) =
        withContext(Dispatchers.IO) {
            val addr   = InetAddress.getByName(host)  // works for IP strings without DNS lookup
            val packet = DatagramPacket(payload, payload.size, addr, port)
            sendMutex.withLock { socket.send(packet) }
        }

    /**
     * Wait for a datagram whose payload begins with [PROBE_MAGIC] or [PONG_MAGIC] followed
     * by [expectedToken]. Returns the full payload, or null if [STUN_RECEIVE_TIMEOUT_MS]
     * elapses with no matching datagram. The match uses the first [TOKEN_KEY_LEN] bytes of
     * [expectedToken] as the lookup key — callers generate 32-byte tokens so collision
     * probability is negligible.
     *
     * Called by [NatTraversalEngine.punch] inside a [withTimeoutOrNull] block, so the
     * overall punch-window timeout is controlled externally — this method's internal timeout
     * is a backstop to avoid leaked waiters if the caller is cancelled without cleanup.
     */
    override suspend fun receiveUdp(expectedToken: ByteArray): ByteArray? {
        val key      = tokenKey(expectedToken)
        val deferred = CompletableDeferred<ByteArray>()
        tokenWaiters[key] = deferred
        return try {
            withTimeoutOrNull(STUN_RECEIVE_TIMEOUT_MS) { deferred.await() }
        } finally {
            tokenWaiters.remove(key)
        }
    }

    /**
     * Send an RFC 5389 STUN Binding Request to a pinned IP:port and parse the
     * XOR-MAPPED-ADDRESS from the response.
     *
     * [stunIp] must be a dotted-decimal IPv4 string — hostname resolution is structurally
     * excluded (see StunPrivacyPolicy). Returns null on timeout or parse failure.
     *
     * The response is received through the shared listener loop (via [stunWaiters]) rather
     * than a direct [socket.receive()] call. This avoids two bugs that the previous design
     * had:
     *   1. Race: if the listener loop received the STUN response first, dispatch() would
     *      drop it as "unknown magic" and sendStunBindingRequest's own socket.receive()
     *      would block until timeout — STUN would appear broken intermittently.
     *   2. soTimeout mutation: changing socket.soTimeout while the listener loop was
     *      blocked in socket.receive() had implementation-defined behaviour on Android
     *      and could stall the listener for 3000ms instead of 200ms.
     *
     * Wire format (RFC 5389 §6):
     *   Binding Request:  type=0x0001, length=0, magic=0x2112A442, txId=12 random bytes
     *   Binding Response: type=0x0101, length=variable, magic=0x2112A442, txId echoed
     *   XOR-MAPPED-ADDRESS attr: type=0x0020, family=0x01(IPv4),
     *     x-port = port XOR (magic >> 16), x-addr = addr XOR magic
     */
    override suspend fun sendStunBindingRequest(stunIp: String, stunPort: Int): PeerAddress? =
        withContext(Dispatchers.IO) {
            val txId     = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
            val txKey    = txId.toStunKey()
            val deferred = CompletableDeferred<ByteArray>()
            stunWaiters[txKey] = deferred
            try {
                val req = buildStunBindingRequest(txId)
                sendUdp(stunIp, stunPort, req)
                val rsp = withTimeoutOrNull(STUN_RECEIVE_TIMEOUT_MS) { deferred.await() }
                if (rsp == null) {
                    Diag.fallback("udp-adapter", "stun-timeout",
                        "STUN server $stunIp:$stunPort did not respond within ${STUN_RECEIVE_TIMEOUT_MS}ms")
                    return@withContext null
                }
                parseStunMappedAddress(rsp, rsp.size, txId)
            } catch (e: Exception) {
                Diag.swallowed("udp-adapter", "stun-request", e, "stun" to "$stunIp:$stunPort")
                null
            } finally {
                stunWaiters.remove(txKey)
            }
        }

    // ── Listener loop ─────────────────────────────────────────────────────

    /**
     * Start the background receive loop. Call once after construction.
     * The loop reads datagrams and dispatches by magic prefix until [socket] is closed.
     */
    fun startListening(): Job = scope.launch(Dispatchers.IO) {
        val buf = ByteArray(MAX_DATAGRAM_BYTES)
        val pkt = DatagramPacket(buf, buf.size)
        while (isActive && !socket.isClosed) {
            try {
                pkt.length = buf.size   // reset length before each receive
                socket.receive(pkt)
                val payload   = buf.copyOf(pkt.length)
                val senderIp  = pkt.address.hostAddress ?: continue
                val senderPort = pkt.port
                dispatch(payload, senderIp, senderPort)
            } catch (e: java.net.SocketTimeoutException) {
                // Normal — soTimeout fires periodically so we can check isActive
                continue
            } catch (e: java.net.SocketException) {
                if (!socket.isClosed) {
                    Diag.swallowed("udp-adapter", "receive-loop", e)
                }
                break  // socket closed — exit cleanly
            } catch (e: Exception) {
                Diag.swallowed("udp-adapter", "receive-dispatch", e)
            }
        }
    }

    /** Route an incoming datagram by magic prefix. */
    private fun dispatch(payload: ByteArray, senderIp: String, senderPort: Int) {
        when {
            // STUN Binding Response: type field = 0x01 0x01, magic cookie = 0x2112A442.
            // Check bytes [0..7] before anything else so STUN responses are matched before
            // the DHT/probe checks (STUN magic does not start with 'D','H' or "SM" anyway,
            // but being explicit about ordering prevents future ambiguity).
            isStunResponse(payload) -> {
                // txId is bytes [8..19] of the STUN message.
                if (payload.size >= 20) {
                    val key = payload.sliceArray(8 until 20).toStunKey()
                    stunWaiters[key]?.complete(payload)
                }
            }
            payload.startsWith(DHT_MAGIC) -> {
                val cb = onDhtDatagram
                if (cb != null) cb(payload, senderIp, senderPort)
                else Diag.fallback("udp-adapter", "dht-no-handler",
                    "DHT datagram received before UdpDhtTransport registered; discarded")
            }
            payload.startsWith(PROBE_MAGIC_BYTES) || payload.startsWith(PONG_MAGIC_BYTES) -> {
                // Extract the token starting after the magic prefix and match a waiter.
                val magicLen = if (payload.startsWith(PROBE_MAGIC_BYTES))
                    PROBE_MAGIC_BYTES.size else PONG_MAGIC_BYTES.size
                if (payload.size >= magicLen + TOKEN_KEY_LEN) {
                    val key = tokenKey(payload.sliceArray(magicLen until payload.size))
                    tokenWaiters[key]?.complete(payload)
                }
            }
            else -> Diag.fallback("udp-adapter", "unknown-magic",
                "received datagram with unrecognised magic prefix; discarded (size=${payload.size})")
        }
    }

    /** Shut down the socket and cancel the listener loop. */
    fun close() {
        socket.close()
        // Complete all pending waiters with a cancellation so callers don't leak
        tokenWaiters.values.forEach { it.cancel() }
        tokenWaiters.clear()
        stunWaiters.values.forEach { it.cancel() }
        stunWaiters.clear()
    }

    // ── STUN wire format helpers ──────────────────────────────────────────

    private fun buildStunBindingRequest(txId: ByteArray): ByteArray {
        // RFC 5389 §6: 20-byte header, no attributes
        // [type:2][length:2][magic:4][txId:12]
        val buf = ByteArray(20)
        buf[0] = 0x00; buf[1] = 0x01   // Binding Request
        buf[2] = 0x00; buf[3] = 0x00   // message length = 0 (no attributes)
        // Magic cookie 0x2112A442
        buf[4] = 0x21; buf[5] = 0x12; buf[6] = 0xA4.toByte(); buf[7] = 0x42
        System.arraycopy(txId, 0, buf, 8, 12)
        return buf
    }

    /**
     * Parse XOR-MAPPED-ADDRESS (0x0020) from a STUN Binding Response.
     * Falls back to MAPPED-ADDRESS (0x0001) for RFC 3489 servers.
     * Returns null if the response is malformed or the txId doesn't match.
     */
    private fun parseStunMappedAddress(buf: ByteArray, len: Int, txId: ByteArray): PeerAddress? {
        if (len < 20) return null
        // Verify message type = 0x0101 (Binding Response)
        if (buf[0] != 0x01.toByte() || buf[1] != 0x01.toByte()) return null
        // Verify magic cookie
        if (buf[4] != 0x21.toByte() || buf[5] != 0x12.toByte() ||
            buf[6] != 0xA4.toByte() || buf[7] != 0x42.toByte()) return null
        // Verify txId
        for (i in 0..11) if (buf[8 + i] != txId[i]) return null

        val msgLen = ((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF)
        var off = 20   // start of attributes
        while (off + 4 <= 20 + msgLen && off + 4 <= len) {
            val attrType = ((buf[off].toInt() and 0xFF) shl 8) or (buf[off + 1].toInt() and 0xFF)
            val attrLen  = ((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)
            off += 4
            if (attrType == STUN_ATTR_XOR_MAPPED_ADDRESS || attrType == STUN_ATTR_MAPPED_ADDRESS) {
                if (attrLen < 8 || off + attrLen > len) break
                val family = buf[off + 1].toInt() and 0xFF
                if (family != 0x01) break  // IPv6 not supported in this implementation
                val xor = attrType == STUN_ATTR_XOR_MAPPED_ADDRESS
                val rawPort = ((buf[off + 2].toInt() and 0xFF) shl 8) or (buf[off + 3].toInt() and 0xFF)
                val port = if (xor) rawPort xor 0x2112 else rawPort
                val a0 = (buf[off + 4].toInt() and 0xFF) xor (if (xor) 0x21 else 0)
                val a1 = (buf[off + 5].toInt() and 0xFF) xor (if (xor) 0x12 else 0)
                val a2 = (buf[off + 6].toInt() and 0xFF) xor (if (xor) 0xA4 else 0)
                val a3 = (buf[off + 7].toInt() and 0xFF) xor (if (xor) 0x42 else 0)
                return PeerAddress("$a0.$a1.$a2.$a3", port)
            }
            // Attributes are padded to 4-byte boundaries
            off += (attrLen + 3) and -4
        }
        return null
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /** First [TOKEN_KEY_LEN] bytes of [token] as a hex string — map key for token waiters. */
    private fun tokenKey(token: ByteArray): String =
        token.copyOfRange(0, TOKEN_KEY_LEN).toHex()

    /**
     * Returns true if [payload] is an RFC 5389 STUN Binding Success Response.
     * Checks: message type = 0x0101, magic cookie = 0x2112A442, minimum length 20 bytes.
     * This is sufficient to distinguish STUN responses from DHT and probe traffic without
     * a full parse, because none of our other magic prefixes start with 0x01.
     */
    private fun isStunResponse(payload: ByteArray): Boolean {
        if (payload.size < 20) return false
        return payload[0] == 0x01.toByte() && payload[1] == 0x01.toByte() &&
               payload[4] == 0x21.toByte() && payload[5] == 0x12.toByte() &&
               payload[6] == 0xA4.toByte() && payload[7] == 0x42.toByte()
    }

    /** 12-byte STUN transaction ID as a 24-char hex string — map key for [stunWaiters]. */
    private fun ByteArray.toStunKey(): String = toHex()

    /** Returns true if this byte array starts with [prefix]. */
    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (size < prefix.size) return false
        for (i in prefix.indices) if (this[i] != prefix[i]) return false
        return true
    }

    companion object {
        /** Shared DHT + probe port. Matches SeedList example and LAN port allocation. */
        const val DHT_PORT = 7400

        /** Maximum datagram size — safe Ethernet MTU minus IP/UDP headers. */
        const val MAX_DATAGRAM_BYTES = 1400

        /** soTimeout for the receive loop — short enough to notice socket closure promptly. */
        const val SOCKET_RECEIVE_TIMEOUT_MS = 200

        /** Timeout for a STUN response or a receiveUdp waiter backstop. */
        const val STUN_RECEIVE_TIMEOUT_MS = 3_000L

        /** Number of token bytes used as the waiter map key (collision-negligible at 16 bytes). */
        const val TOKEN_KEY_LEN = 16

        /**
         * Magic prefix for DHT datagrams. Two bytes: 'D'=0x44, 'H'=0x48.
         * Every [UdpDhtTransport] datagram starts with these bytes so the listener loop
         * can route DHT traffic to the transport and probe traffic to token waiters without
         * inspecting the full payload.
         */
        val DHT_MAGIC = byteArrayOf(0x44, 0x48)   // 'D', 'H'

        // Probe/pong magic from NatTraversalEngine (must match exactly)
        val PROBE_MAGIC_BYTES = "SMPROBE".toByteArray()
        val PONG_MAGIC_BYTES  = "SMPONG".toByteArray()

        // STUN attribute types (RFC 5389)
        private const val STUN_ATTR_MAPPED_ADDRESS     = 0x0001
        private const val STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020
    }
}

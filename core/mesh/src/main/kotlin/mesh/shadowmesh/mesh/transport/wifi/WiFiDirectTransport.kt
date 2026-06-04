package mesh.shadowmesh.mesh.transport.wifi

import android.content.Context
import android.net.wifi.p2p.*
import android.net.wifi.p2p.WifiP2pManager.*
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.io.*
import java.net.*
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.diagnostics.Diag

/**
 * WiFi Direct transport — design doc Phase 7, §Annex A.
 *
 * Provides peer discovery and fragment exchange over Android WifiP2pManager.
 * Zero internet by design: all communication is device-to-device over the
 * WiFi Direct link-local address space. No DNS, no public IPs.
 *
 * Protocol:
 *   Discovery: WifiP2pManager.discoverPeers() — Android broadcasts service info
 *   Connection: WifiP2pManager.connect() — forms a P2P group
 *   Transport:  Raw TCP socket on group owner IP:PORT_FRAGMENT
 *               Fragment wire: [4B len][fragment bytes]
 *
 * Group owner election: Android selects GO automatically via intent
 *   (WifiP2pInfo.isGroupOwner). The GO binds a server socket; the client
 *   connects to GO's groupOwnerAddress.
 *
 * Zero-internet verification: the exit gate requires packet capture showing
 *   zero DNS queries and zero public IP connections during a session.
 *   This is enforced architecturally — WifiP2pManager uses link-local
 *   addressing and never contacts external servers.
 *
 * Range: ~200m line of sight as per design doc.
 *
 * Thread-safety: [connectedPeers] uses ConcurrentHashMap.
 *   Socket I/O is dispatched to Dispatchers.IO.
 *
 * Android permission requirements:
 *   ACCESS_FINE_LOCATION, ACCESS_WIFI_STATE, CHANGE_WIFI_STATE,
 *   CHANGE_NETWORK_STATE, INTERNET (for socket creation — local only)
 */
class WiFiDirectTransport(
    private val context:   Context,
    private val scope:     CoroutineScope,
    private val onFragmentReceived: (FragmentEntity) -> Unit,
    /**
     * Optional security configuration. When provided, every TCP connection performs a
     * mutual STS handshake (ephemeral P-256 ECDH + Ed25519 node-key authentication)
     * and all fragment exchange is AEAD-encrypted with XChaCha20-Poly1305.
     *
     * When null, the transport operates in plaintext mode and logs a security-degraded
     * event. Plaintext mode is provided for backward compatibility during rollout only;
     * production builds MUST supply a non-null config.
     */
    security: WifiDirectSecurityConfig? = null
) {
    private val securityImpl: WifiDirectTransportSecurity? = security?.let {
        WifiDirectTransportSecurity(it.localIdentity, it.signer, it.cipher, it.hkdf, it.trustedPeerLookup)
    }

    init {
        if (security == null) {
            Diag.degraded("wifi-direct", "no-security",
                "WiFiDirectTransport created without security config — running in " +
                "plaintext mode. Fragment metadata and payloads are unencrypted " +
                "and unauthenticated on the P2P subnet. Supply WifiDirectSecurityConfig.")
        }
    }
    // Internal visibility so WifiP2pBroadcastReceiver (same module) can call
    // manager.requestPeers() and manager.requestConnectionInfo() on the live channel.
    internal val manager: WifiP2pManager by lazy {
        context.getSystemService(Context.WIFI_P2P_SERVICE) as WifiP2pManager
    }
    internal val channel: WifiP2pManager.Channel by lazy {
        manager.initialize(context, context.mainLooper, null)
    }

    // Active peer connections: nodeId hex → PeerConnection
    private val connectedPeers = ConcurrentHashMap<String, PeerConnection>()

    // Fragment receive channel — buffers incoming fragments for processing
    private val receiveChannel = Channel<FragmentEntity>(capacity = 256)

    // Server socket for group owner role
    @Volatile private var serverSocket: ServerSocket? = null

    // Set by WifiP2pBroadcastReceiver when WIFI_P2P_STATE_CHANGED_ACTION fires.
    // startDiscovery() checks this before calling discoverPeers() — calling it while
    // P2P is disabled fails silently on most devices.
    @Volatile var p2pEnabled: Boolean = false

    // ── Discovery ─────────────────────────────────────────────────────────

    /**
     * Start peer discovery. [onPeersChanged] is called when the peer list updates
     * (via [WifiP2pBroadcastReceiver] routing WIFI_P2P_PEERS_CHANGED_ACTION here).
     *
     * Requires [p2pEnabled] == true (set by [WifiP2pBroadcastReceiver] on
     * WIFI_P2P_STATE_CHANGED_ACTION). Calling discoverPeers() while P2P is disabled
     * silently fails on most devices.
     *
     * Must be called from the main thread (Android WifiP2pManager constraint).
     *
     * Note: do NOT call requestPeers() here — discovery is asynchronous and the peer
     * list is empty at this point. requestPeers() is called by [WifiP2pBroadcastReceiver]
     * when WIFI_P2P_PEERS_CHANGED_ACTION fires.
     */
    fun startDiscovery(onPeersChanged: (List<WifiP2pDevice>) -> Unit) {
        if (!p2pEnabled) {
            Diag.degraded("wifi-direct", "p2p-not-enabled",
                "discoverPeers() skipped — WiFi Direct is not enabled")
            return
        }
        this.onPeersChangedCallback = onPeersChanged
        manager.discoverPeers(channel, object : ActionListener {
            override fun onSuccess() {}
            override fun onFailure(reason: Int) {
                Diag.degraded("wifi-direct", "discover-peers-failed",
                    "discoverPeers() failed: reason=$reason " +
                    "(0=ERROR, 1=P2P_UNSUPPORTED, 2=BUSY)")
            }
        })
    }

    /** Callback set by startDiscovery(); called by WifiP2pBroadcastReceiver on peer list change. */
    @Volatile internal var onPeersChangedCallback: ((List<WifiP2pDevice>) -> Unit)? = null

    fun stopDiscovery() {
        onPeersChangedCallback = null
        manager.stopPeerDiscovery(channel, object : ActionListener {
            override fun onSuccess() {}
            override fun onFailure(reason: Int) {
                Diag.degraded("wifi-direct", "stop-discovery-failed",
                    "stopPeerDiscovery() failed: reason=$reason")
            }
        })
    }

    // ── Connection ────────────────────────────────────────────────────────

    /**
     * Initiate a connection to [device]. Returns [ConnectionResult.PendingInfo] immediately
     * on manager acceptance — the actual link is NOT yet established at this point.
     *
     * Android WifiP2p is a two-step model:
     *   Step 1: call connect() → manager accepts → [PendingInfo] returned here
     *   Step 2: Android delivers a WifiP2pInfo broadcast → call [onConnectionInfoAvailable]
     *           → TCP sockets are established → [ConnectionResult.Success] is emitted
     *           via the callback passed to [onConnectionInfoAvailable].
     *
     * The caller must observe WIFI_P2P_CONNECTION_CHANGED_ACTION broadcasts and route
     * WifiP2pInfo to [onConnectionInfoAvailable]. Without that, no fragment exchange is possible.
     */
    suspend fun connect(device: WifiP2pDevice): ConnectionResult = withContext(Dispatchers.IO) {
        val config = WifiP2pConfig().apply { deviceAddress = device.deviceAddress }
        val resultDeferred = CompletableDeferred<ConnectionResult>()

        manager.connect(channel, config, object : ActionListener {
            override fun onSuccess() {
                // Step 1 complete — waiting for WifiP2pInfo broadcast (Step 2)
                resultDeferred.complete(ConnectionResult.PendingInfo(device.deviceAddress))
            }
            override fun onFailure(reason: Int) {
                val reasonStr = when (reason) {
                    ERROR           -> "ERROR"
                    P2P_UNSUPPORTED -> "P2P_UNSUPPORTED"
                    BUSY            -> "BUSY"
                    else            -> "reason=$reason"
                }
                Diag.degraded("wifi-direct", "connect-failed", "connect() failed: $reasonStr")
                resultDeferred.complete(ConnectionResult.Failed("WifiP2p connect failed: $reasonStr"))
            }
        })

        withTimeoutOrNull(CONNECTION_TIMEOUT_MS) { resultDeferred.await() }
            ?: ConnectionResult.Failed("Connection timeout after ${CONNECTION_TIMEOUT_MS}ms")
    }

    /**
     * Called when WifiP2pInfo is received (via broadcast receiver) after [connect] returns
     * [ConnectionResult.PendingInfo]. This is Step 2 of the Android WifiP2p connection model.
     *
     * Starts the server socket if this device is the group owner, or connects to the GO.
     * [onConnected] is called with [ConnectionResult.Success] when the TCP layer is ready.
     */
    fun onConnectionInfoAvailable(
        info:        WifiP2pInfo,
        onConnected: (ConnectionResult) -> Unit = {}
    ) {
        if (info.isGroupOwner) {
            scope.launch(Dispatchers.IO) {
                startFragmentServer()
                onConnected(ConnectionResult.Success("localhost:$PORT_FRAGMENT"))
            }
        } else {
            info.groupOwnerAddress?.let { goAddress ->
                scope.launch(Dispatchers.IO) {
                    connectToGroupOwner(goAddress)
                    onConnected(ConnectionResult.Success(goAddress.hostAddress ?: "unknown"))
                }
            } ?: onConnected(ConnectionResult.Failed("No group owner address in WifiP2pInfo"))
        }
    }

    // ── Group owner: server socket ────────────────────────────────────────

    private suspend fun startFragmentServer() = withContext(Dispatchers.IO) {
        val server = ServerSocket(PORT_FRAGMENT)
        serverSocket = server
        while (isActive) {
            try {
                val client = server.accept()
                scope.launch(Dispatchers.IO) { handleClientConnection(client) }
            } catch (e: Exception) {
                Diag.swallowed("wifi-direct", "server-accept", e)
                break
            }
        }
    }

    private suspend fun handleClientConnection(socket: Socket) = withContext(Dispatchers.IO) {
        // Bound read latency in both plaintext and security paths. In the plaintext path,
        // input.readInt() blocks indefinitely on a partial (1-3 byte) send, holding a
        // Dispatchers.IO thread per stalled connection. The security path's readFrame()
        // already has its own internal timeout, but a uniform socket-level timeout is a
        // belt-and-suspenders guard that also protects against partial TLS/AEAD framing hangs.
        socket.soTimeout = SOCKET_READ_TIMEOUT_MS.toInt()
        try {
            if (securityImpl != null) {
                // Run STS handshake; socket is closed inside handshake() on failure.
                val session = securityImpl.handshake(socket, isGroupOwner = true)
                    ?: return@withContext  // authentication failed — socket already closed
                while (isActive) {
                    // readFrame returns null on oversized frame or AEAD failure — break the
                    // loop to close the connection; do not continue reading from a broken session.
                    val plain    = securityImpl.readFrame(session.input, session.decryptKey)
                        ?: break
                    val fragment = deserializeFragment(plain) ?: continue
                    onFragmentReceived(fragment)
                }
            } else {
                val input = DataInputStream(socket.getInputStream())
                while (true) {
                    val len = input.readInt()
                    if (len <= 0 || len > MAX_FRAGMENT_BYTES) break
                    val bytes = ByteArray(len)
                    input.readFully(bytes)
                    val fragment = deserializeFragment(bytes) ?: continue
                    onFragmentReceived(fragment)
                }
            }
        } catch (e: Exception) {
            Diag.swallowed("wifi-direct", "client-recv", e)
        } finally {
            socket.close()
        }
    }

    // ── Client: connect to group owner ────────────────────────────────────

    private suspend fun connectToGroupOwner(goAddress: InetAddress) = withContext(Dispatchers.IO) {
        try {
            val socket  = Socket(goAddress, PORT_FRAGMENT)
            val peerKey = goAddress.hostAddress ?: run { socket.close(); return@withContext }
            if (securityImpl != null) {
                // Run STS handshake; socket is closed inside handshake() on failure.
                val session = securityImpl.handshake(socket, isGroupOwner = false)
                    ?: return@withContext  // authentication failed — socket already closed
                connectedPeers[peerKey] = PeerConnection(socket, peerKey, session)
            } else {
                connectedPeers[peerKey] = PeerConnection(socket, peerKey, null)
            }
        } catch (e: Exception) {
            Diag.swallowed("wifi-direct", "connect-go", e,
                "goAddress" to (goAddress.hostAddress ?: "unknown"))
        }
    }

    // ── Fragment send ─────────────────────────────────────────────────────

    /**
     * Send a fragment to [peer] via the active WiFi Direct connection.
     * When security is configured: AEAD-encrypted frame [4B len][24B nonce][ciphertext+tag].
     * Plaintext fallback: [4B len][fragment bytes].
     */
    suspend fun sendFragment(peerKey: String, fragment: FragmentEntity) =
        withContext(Dispatchers.IO) {
            val conn = connectedPeers[peerKey] ?: return@withContext
            try {
                val bytes  = serializeFragment(fragment)
                val output = DataOutputStream(conn.socket.getOutputStream())
                val session = conn.session
                if (session != null && securityImpl != null) {
                    securityImpl.writeFrame(output, bytes, session.encryptKey)
                } else {
                    output.writeInt(bytes.size)
                    output.write(bytes)
                    output.flush()
                }
            } catch (e: Exception) {
                Diag.swallowed("wifi-direct", "send-fragment", e, "peerKey" to peerKey)
                connectedPeers.remove(peerKey)
                conn.socket.close()
            }
        }

    // ── Disconnect ────────────────────────────────────────────────────────

    fun disconnect() {
        manager.removeGroup(channel, object : ActionListener {
            override fun onSuccess() {}
            override fun onFailure(reason: Int) {
                Diag.degraded("wifi-direct", "remove-group-failed",
                    "removeGroup() failed: reason=$reason")
            }
        })
        // channel.close() is required (API 27+) to release the WifiP2pManager channel and
        // avoid leaking the underlying system socket when the transport is torn down.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O_MR1) {
            channel.close()
        }
        serverSocket?.close()
        serverSocket = null
        connectedPeers.values.forEach { conn ->
            conn.session?.encryptKey?.fill(0)
            conn.session?.decryptKey?.fill(0)
            conn.socket.close()
        }
        connectedPeers.clear()
        onPeersChangedCallback = null
    }

    // ── Wire serialization ────────────────────────────────────────────────

    /**
     * Wire format matches FragmentModels.kt spec:
     *   [32B fragmentId hex][32B postId hex][32B channelId hex]
     *   [2B seqIdx][2B totalData][2B totalParity][4B payloadLen][payload][1B fecWire]
     */
    private fun serializeFragment(f: FragmentEntity): ByteArray {
        val out = ByteArrayOutputStream()
        val dos = DataOutputStream(out)
        dos.writeBytes(f.fragmentId.padEnd(64, '0').take(64))
        dos.writeBytes(f.postId.padEnd(64, '0').take(64))
        dos.writeBytes(f.channelId.padEnd(64, '0').take(64))
        dos.writeShort(f.sequenceIndex)
        dos.writeShort(f.totalData)
        dos.writeShort(f.totalParity)
        dos.writeInt(f.payload.size)
        dos.write(f.payload)
        dos.writeByte(f.fecScheme.wire)
        dos.flush()
        return out.toByteArray()
    }

    private fun deserializeFragment(bytes: ByteArray): FragmentEntity? = try {
        val dis = DataInputStream(ByteArrayInputStream(bytes))
        val fragmentId  = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val postId      = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val channelId   = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        // Use readUnsignedShort() — same sign-extension fix as LanSubnetTransport and
        // FragmentEntity.fromWire(). readShort().toInt() sign-extends 0xFFFF to -1;
        // a negative totalData causes phantom-Complete in the fragment accumulator.
        val seqIdx      = dis.readUnsignedShort()
        val totalData   = dis.readUnsignedShort()
        val totalParity = dis.readUnsignedShort()
        if (totalData == 0 || totalData > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS ||
            totalParity > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS)
            throw IllegalArgumentException("Invalid shard counts: totalData=$totalData totalParity=$totalParity")
        val payloadLen  = dis.readInt()
        // Guard payloadLen before allocation — missing in the original; mirror FragmentEntity.fromWire().
        if (payloadLen < 0 || payloadLen > MAX_FRAGMENT_BYTES)
            throw IllegalArgumentException("Invalid payload length: $payloadLen")
        val payload     = ByteArray(payloadLen).also { dis.readFully(it) }
        val fecWire     = dis.readByte().toInt()
        val fecScheme   = mesh.shadowmesh.mesh.fragment.FecScheme.fromWire(fecWire)
        FragmentEntity(fragmentId, postId, channelId, seqIdx, totalData, totalParity, payload, fecScheme ?: mesh.shadowmesh.mesh.fragment.FecScheme.NONE)
    } catch (e: Exception) {
        Diag.swallowed("wifi-direct", "deserialize-fragment", e)
        null
    }

    fun connectedPeerCount(): Int = connectedPeers.size

    companion object {
        const val PORT_FRAGMENT         = 7401
        const val CONNECTION_TIMEOUT_MS = 10_000L
        const val MAX_FRAGMENT_BYTES    = 64 * 1024  // 64KB max fragment
        /**
         * Socket-level read timeout for inbound TCP connections.
         * Prevents a stalled peer from holding a Dispatchers.IO thread indefinitely
         * by blocking on a partial [DataInputStream.readInt] or [DataInputStream.readFully].
         */
        const val SOCKET_READ_TIMEOUT_MS = 30_000
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

data class PeerConnection(
    val socket:  Socket,
    val peerKey: String,
    val session: EstablishedSession? = null  // null = plaintext (security config not provided)
)

sealed class ConnectionResult {
    /**
     * Connection initiation accepted by Android WifiP2pManager.
     * The actual link is not yet established — the caller must observe a
     * WifiP2pInfo broadcast and call [WiFiDirectTransport.onConnectionInfoAvailable].
     * This is the correct two-step Android WifiP2p model:
     *   Step 1: manager.connect() → [PendingInfo] (this result)
     *   Step 2: WifiP2pInfo broadcast → onConnectionInfoAvailable() → [Success]
     */
    data class PendingInfo(val deviceAddress: String) : ConnectionResult()

    /**
     * Full link established — group owner address is known and the TCP socket
     * layer is ready. Set by [WiFiDirectTransport.onConnectionInfoAvailable].
     */
    data class Success(val groupOwnerAddress: String) : ConnectionResult()

    data class Failed(val reason: String) : ConnectionResult()
}

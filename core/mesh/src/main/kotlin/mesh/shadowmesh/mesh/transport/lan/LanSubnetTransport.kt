package mesh.shadowmesh.mesh.transport.lan

import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import mesh.shadowmesh.mesh.privacy.PacketNormalizer
import kotlinx.coroutines.*
import java.net.*
import java.io.*
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag

/**
 * LAN subnet transport — design doc §Annex A "Improvised WiFi Networks".
 *
 * Devices on the same LAN subnet (connected via old routers, WiFi extenders,
 * or ethernet cables) discover each other via broadcast and exchange fragments
 * over standard TCP/UDP. No internet required. No ISP, no carrier, no registry.
 *
 * Discovery protocol:
 *   1. This node sends a UDP broadcast to 255.255.255.255:[PORT_DISCOVERY]
 *      containing a [DiscoveryBeacon]: [8B magic][32B nodeId][2B tcpPort]
 *   2. Peers respond with their own [DiscoveryBeacon] (unicast reply)
 *   3. All responding peers are added to [discoveredPeers]
 *
 * Fragment exchange:
 *   TCP server on [PORT_FRAGMENT]. Framing: [4B len][fragment bytes].
 *   Same serialization format as WiFiDirectTransport.
 *
 * Kilometre-scale:
 *   With ethernet-chained routers in AP mode (Annex A deployment), this
 *   transport extends indefinitely across the LAN chain. Fragments hop
 *   peer-to-peer across the subnet — the LAN backbone provides the physical
 *   reach, this transport provides the logical exchange.
 *
 * No-internet enforcement:
 *   All sockets bind to the local network interface. No external hostnames
 *   are resolved. Fragment exchange is LAN-internal by construction.
 *
 * Thread-safety: [discoveredPeers] uses ConcurrentHashMap.
 *   All I/O dispatched to Dispatchers.IO.
 */
class LanSubnetTransport(
    private val localNodeId: NodeId,
    private val scope:       CoroutineScope,
    /**
     * Called when a fragment arrives over TCP from an authenticated LAN peer.
     * [senderNodeId] is cryptographically confirmed when Ed25519 auth is wired;
     * falls back to synthetic IP-derived NodeId only when auth is not configured.
     */
    private val onFragmentReceived: (FragmentEntity, NodeId) -> Unit,
    private val onPeerDiscovered:   (LanPeer) -> Unit,
    /**
     * Raw 32-byte Ed25519 public key component of this node's signing keypair.
     * Sent to LAN TCP servers as part of the mutual auth handshake.
     * Null disables outbound authentication (server may refuse connection).
     */
    private val localEd25519PubKey: ByteArray? = null,
    /**
     * Signs (serverChallenge || localNodeId) with Ed25519 → 64-byte signature.
     * Called when connecting to a server that requires authentication.
     */
    private val signChallengeEd25519Only: (suspend (message: ByteArray) -> ByteArray)? = null,
    /**
     * Verifies a 64-byte Ed25519 signature from a connecting peer.
     * Called in the TCP server handler after receiving the peer's auth response.
     * Null disables inbound authentication (synthetic NodeId fallback used).
     */
    private val verifyEd25519Only: (suspend (message: ByteArray, sig: ByteArray, pubKey: ByteArray) -> Boolean)? = null,
    /**
     * Called when the server receives bytes that do not parse as a [FragmentEntity]
     * (e.g. ACK/NACK control packets). Routes raw payloads to the ACK router.
     * Null silently discards non-fragment packets (backward-compatible default).
     */
    private val onRawPacketReceived: ((ByteArray, NodeId) -> Unit)? = null
) {
    // Discovered peers on the subnet: nodeId hex → LanPeer
    private val discoveredPeers = ConcurrentHashMap<String, LanPeer>()

    // Reverse-address lookup for inbound TCP connections: IP address → LanPeer.
    // Populated alongside discoveredPeers; used in handleClient() to resolve the
    // sender's NodeId from the TCP connection's remote address.
    private val peerByAddress = ConcurrentHashMap<String, LanPeer>()

    @Volatile private var tcpServer:        ServerSocket?      = null
    @Volatile private var discoverySocket:  DatagramSocket?    = null
    @Volatile private var isRunning = false

    init {
        if (verifyEd25519Only == null || signChallengeEd25519Only == null || localEd25519PubKey == null) {
            Diag.degraded("lan-transport", "auth-not-wired",
                "LAN TCP peer authentication is not fully wired — " +
                "inbound peers may be accepted without cryptographic proof of identity")
        }
    }

    // ── Discovery ─────────────────────────────────────────────────────────

    /**
     * Start subnet peer discovery. Broadcasts a beacon and listens for responses.
     * Runs continuously until [stop] is called.
     */
    fun startDiscovery(tcpPort: Int = PORT_FRAGMENT) {
        isRunning = true
        scope.launch(Dispatchers.IO) {
            val socket = DatagramSocket(PORT_DISCOVERY).also { discoverySocket = it }
            socket.broadcast = true

            // Listen for incoming beacons
            scope.launch(Dispatchers.IO) {
                val buf = ByteArray(BEACON_SIZE)
                val packet = DatagramPacket(buf, buf.size)
                while (isRunning) {
                    try {
                        socket.receive(packet)
                        // Copy received data immediately: socket.receive() overwrites buf
                        // in-place on the next call. Holding a reference to packet.data
                        // across any processing is a data race on the next receive().
                        val dataCopy = packet.data.copyOf(packet.length)
                        val beacon = parseBeacon(dataCopy) ?: continue
                        if (beacon.nodeId.contentEquals(localNodeId.bytes)) continue // skip self

                        val peer = LanPeer(
                            nodeId  = NodeId(beacon.nodeId),
                            address = packet.address.hostAddress ?: continue,
                            tcpPort = beacon.tcpPort
                        )
                        val peerKey = peer.nodeId.bytes.toHex()
                        val isNew = discoveredPeers.putIfAbsent(peerKey, peer) == null
                        // Always update reverse-address map so handleClient() can resolve
                        // the sender even when the same nodeId reconnects from a new IP.
                        peerByAddress[peer.address] = peer
                        if (isNew) {
                            onPeerDiscovered(peer)
                        }
                        // Reply with our own beacon (unicast)
                        sendBeacon(socket, packet.address, PORT_DISCOVERY, tcpPort)
                    } catch (e: Exception) {
                        if (!isRunning) break
                        Diag.swallowed("lan-transport", "beacon-recv", e)
                    }
                }
            }

            // Periodically broadcast our beacon
            while (isRunning) {
                try {
                    sendBroadcastBeacon(socket, tcpPort)
                    delay(DISCOVERY_INTERVAL_MS)
                } catch (e: Exception) {
                    Diag.swallowed("lan-transport", "broadcast-beacon", e)
                    break
                }
            }
        }
    }

    private fun sendBroadcastBeacon(socket: DatagramSocket, tcpPort: Int) {
        val beaconBytes = buildBeacon(tcpPort)
        val broadcast   = InetAddress.getByName("255.255.255.255")
        val packet      = DatagramPacket(beaconBytes, beaconBytes.size, broadcast, PORT_DISCOVERY)
        socket.send(packet)
    }

    private fun sendBeacon(socket: DatagramSocket, target: InetAddress, port: Int, tcpPort: Int) {
        val beaconBytes = buildBeacon(tcpPort)
        val packet = DatagramPacket(beaconBytes, beaconBytes.size, target, port)
        socket.send(packet)
    }

    private fun buildBeacon(tcpPort: Int): ByteArray {
        val out = ByteArrayOutputStream(BEACON_SIZE)
        val dos = DataOutputStream(out)
        dos.write(BEACON_MAGIC)
        dos.write(localNodeId.bytes)
        dos.writeShort(tcpPort)
        dos.flush()
        return out.toByteArray()
    }

    private fun parseBeacon(data: ByteArray): BeaconPayload? {
        if (data.size < BEACON_SIZE) return null
        val dis = DataInputStream(ByteArrayInputStream(data))
        val magic = ByteArray(8).also { dis.readFully(it) }
        if (!magic.contentEquals(BEACON_MAGIC)) return null
        val nodeId  = ByteArray(NODE_ID_BYTES).also { dis.readFully(it) }
        val tcpPort = dis.readShort().toInt() and 0xFFFF
        return BeaconPayload(nodeId, tcpPort)
    }

    // ── TCP fragment server ────────────────────────────────────────────────

    /**
     * Start the TCP fragment server. Listens on [PORT_FRAGMENT] for inbound
     * fragment streams from peers.
     */
    fun startServer(port: Int = PORT_FRAGMENT) {
        scope.launch(Dispatchers.IO) {
            val server = ServerSocket(port).also { tcpServer = it }
            while (isRunning) {
                try {
                    val client = server.accept()
                    scope.launch(Dispatchers.IO) { handleClient(client) }
                } catch (e: Exception) {
                        if (!isRunning) break
                        Diag.swallowed("lan-transport", "tcp-accept", e)
                    }
            }
        }
    }

    private suspend fun handleClient(socket: Socket) = withContext(Dispatchers.IO) {
        // Set a read timeout so a peer that connects and then sends partial data cannot
        // hold a Dispatchers.IO thread indefinitely. Without this, input.readInt() blocks
        // forever on 1–3 bytes, exhausting the thread pool under a slow-send flood attack.
        socket.soTimeout = SOCKET_READ_TIMEOUT_MS.toInt()
        val senderIp = socket.inetAddress.hostAddress ?: ""
        val input    = DataInputStream(socket.getInputStream())

        // Authenticate the connecting peer before processing any fragments.
        // The server sends an auth-required flag (+ challenge if auth is wired); the client
        // responds with its NodeId, Ed25519 public key, and a signature.
        // If auth is not wired (verifyEd25519Only == null), the server falls back to the
        // synthetic IP-derived NodeId for backward compatibility.
        val senderNodeId = performServerAuth(socket, input, senderIp)
        if (senderNodeId == null) {
            // Auth required but peer failed — reject the connection.
            runCatching { socket.close() }
            return@withContext
        }
        // Reject self-connections (loop-back via adb forward or NAT hairpin).
        if (senderNodeId.bytes.contentEquals(localNodeId.bytes)) {
            Diag.info("lan-transport", "self-connection-rejected", "inbound TCP from self — closing")
            runCatching { socket.close() }
            return@withContext
        }

        // Register the authenticated peer so ACKs and fragment deliveries can route back.
        // On a direct LAN, senderIp is the peer's actual subnet address; on an emulator
        // bridge (10.0.2.2) it is the host gateway — either way PORT_FRAGMENT is the
        // peer's TCP server port. Without this, the gossip engine keeps the peer at the
        // IP from their UDP beacon (which may be unreachable via NAT/bridge), ACKs are
        // dropped, and PostStateMachine stays in PENDING ("Waiting for relay contact…").
        val authenticatedPeer = LanPeer(nodeId = senderNodeId, address = senderIp, tcpPort = PORT_FRAGMENT)
        discoveredPeers[senderNodeId.bytes.toHex()] = authenticatedPeer
        peerByAddress[senderIp]                     = authenticatedPeer
        onPeerDiscovered(authenticatedPeer)

        try {
            while (true) {
                val len = runCatching { input.readInt() }.getOrNull() ?: break
                if (len <= 0 || len > MAX_FRAGMENT_BYTES) break
                val bytes = ByteArray(len).also { input.readFully(it) }
                // Strip normalization padding if present. PacketNormalizer.denormalize()
                // returns null for non-bucket sizes (large un-normalized fragments) — fall
                // back to raw bytes so large fragments are still accepted correctly.
                val payload  = PacketNormalizer.denormalize(bytes) ?: bytes
                val fragment = deserializeFragment(payload)
                if (fragment != null) {
                    onFragmentReceived(fragment, senderNodeId)
                } else {
                    // Not a fragment — route to the control packet handler (ACK/NACK).
                    // AckRouter identifies packet type by magic prefix and dispatches accordingly.
                    onRawPacketReceived?.invoke(payload, senderNodeId)
                }
            }
        } finally { socket.close() }
    }

    /**
     * Server-side LAN TCP authentication handshake.
     *
     * If [verifyEd25519Only] is null (auth not configured):
     *   - Sends AUTH_NOT_REQUIRED (0x00) to client.
     *   - Returns the synthetic NodeId derived from [senderIp], or the beacon-resolved NodeId
     *     if the peer has already announced a discovery beacon.
     *
     * If [verifyEd25519Only] is wired (auth required):
     *   - Sends AUTH_REQUIRED_V1 (0x01) + 32-byte random challenge.
     *   - Reads 128-byte response: [clientNodeId (32B)][clientEd25519Pub (32B)][Ed25519 sig (64B)].
     *   - Verifies Ed25519(challenge || clientNodeId, sig, clientEd25519Pub).
     *   - Returns the authenticated NodeId, or null on failure (caller closes the socket).
     */
    private suspend fun performServerAuth(
        socket:   Socket,
        input:    DataInputStream,
        senderIp: String
    ): NodeId? {
        val verifyFn  = verifyEd25519Only
        val serverOut = DataOutputStream(socket.getOutputStream())

        if (verifyFn == null) {
            // Announce no-auth and return synthetic identity (backward-compat mode).
            runCatching { withContext(Dispatchers.IO) { serverOut.writeByte(AUTH_NOT_REQUIRED.toInt()); serverOut.flush() } }
            return peerByAddress[senderIp]?.nodeId
                ?: NodeId(Hkdf.instance.sha3_256("lan-anon:$senderIp".toByteArray(Charsets.UTF_8)))
        }

        // Send: AUTH_REQUIRED_V1 flag + 32-byte random challenge
        val challenge = ByteArray(TCP_AUTH_CHALLENGE_BYTES).also { java.security.SecureRandom().nextBytes(it) }
        try {
            withContext(Dispatchers.IO) {
                serverOut.writeByte(AUTH_REQUIRED_V1.toInt())
                serverOut.write(challenge)
                serverOut.flush()
            }
        } catch (e: Exception) {
            Diag.swallowed("lan-transport", "auth-write-challenge", e)
            return null
        }

        // Read: [clientNodeId (32B)][clientEd25519Pub (32B)][sig (64B)] = 128 bytes
        // Wrap readFully in try-catch for IOException: probe() connects and immediately
        // closes the socket, causing readFully to throw EOFException. withTimeoutOrNull
        // only catches TimeoutCancellationException, so EOFException propagates uncaught
        // and is logged as "Unhandled exception in applicationScope" every probe cycle.
        val authResponse = withTimeoutOrNull(TCP_AUTH_TIMEOUT_MS) {
            try {
                withContext(Dispatchers.IO) {
                    val buf = ByteArray(TCP_AUTH_RESPONSE_BYTES)
                    input.readFully(buf)
                    buf
                }
            } catch (_: java.io.IOException) { null }
        }
        if (authResponse == null) {
            // Normal path for probe() connections — not logged to avoid log spam.
            return null
        }

        val clientNodeId     = authResponse.copyOfRange(0, 32)
        val clientEd25519Pub = authResponse.copyOfRange(32, 64)
        val sig              = authResponse.copyOfRange(64, 128)

        return try {
            if (verifyFn(challenge + clientNodeId, sig, clientEd25519Pub)) {
                NodeId(clientNodeId)
            } else {
                Diag.degraded("lan-transport", "auth-failed",
                    "LAN peer at $senderIp failed Ed25519 challenge-response — connection rejected")
                null
            }
        } catch (e: Exception) {
            Diag.swallowed("lan-transport", "auth-verify", e)
            null
        }
    }

    // ── Fragment send ─────────────────────────────────────────────────────

    // Persistent TCP connections to discovered peers — reused across fragments.
    // Opened lazily on first send; auth handshake runs on connection creation; removed on error.
    private val peerConnections = ConcurrentHashMap<String, PeerStream>()

    /** Send [fragment] to all discovered LAN peers using persistent connections. */
    suspend fun broadcastFragment(fragment: FragmentEntity) = withContext(Dispatchers.IO) {
        val bytes = serializeFragment(fragment)
        discoveredPeers.values.forEach { peer ->
            scope.launch(Dispatchers.IO) {
                sendBytesToPeer(peer, bytes)
            }
        }
    }

    /** Send [fragment] to a specific [peer] using a persistent connection. */
    suspend fun sendFragment(peer: LanPeer, fragment: FragmentEntity) =
        withContext(Dispatchers.IO) {
            sendBytesToPeer(peer, serializeFragment(fragment))
        }

    /**
     * Send raw control bytes (ACK/NACK) to [peer] over a persistent TCP connection.
     * The bytes go through the same PacketNormalizer padding as fragments so the
     * wire size reveals nothing about packet type. The peer's [onRawPacketReceived]
     * callback is invoked after denormalization when the bytes are not a valid fragment.
     */
    suspend fun sendRawBytes(peer: LanPeer, bytes: ByteArray) =
        withContext(Dispatchers.IO) {
            sendBytesToPeer(peer, bytes)
        }

    private suspend fun sendBytesToPeer(peer: LanPeer, bytes: ByteArray) {
        val peerKey = peer.nodeId.bytes.toHex()
        try {
            // Get an existing authenticated connection or create a new one.
            // ConcurrentHashMap.getOrPut cannot be used here because connection creation
            // is a suspend operation; use putIfAbsent to handle the rare concurrent-open race.
            val peerStream = peerConnections[peerKey] ?: run {
                val sock = withContext(Dispatchers.IO) { Socket(peer.address, peer.tcpPort) }
                val inp  = DataInputStream(sock.getInputStream())
                val out  = DataOutputStream(sock.getOutputStream())
                // Perform client-side auth handshake before sending any fragments.
                val authOk = performClientAuth(inp, out)
                if (!authOk) {
                    runCatching { sock.close() }
                    Diag.degraded("lan-transport", "client-auth-failed",
                        "LAN TCP auth failed with ${peer.address}:${peer.tcpPort} — skipping send")
                    return  // abort this send; do NOT remove from discoveredPeers (server may accept unauthenticated)
                }
                val stream = PeerStream(sock, out)
                val existing = peerConnections.putIfAbsent(peerKey, stream)
                if (existing != null) {
                    // Another coroutine opened a connection first — close ours, use theirs.
                    runCatching { sock.close() }
                    existing
                } else stream
            }
            // Normalize to a fixed-size packet bucket (128/512/1024/4096 bytes) to prevent
            // DPI inference of fragment content from wire size. Falls back to the raw bytes
            // when the serialized fragment exceeds the largest bucket (4096 bytes).
            val wireBytes = PacketNormalizer.normalize(bytes) ?: bytes
            synchronized(peerStream.out) {
                peerStream.out.writeInt(wireBytes.size)
                peerStream.out.write(wireBytes)
                peerStream.out.flush()
            }
        } catch (e: Exception) {
            Diag.swallowed("lan-transport", "send-bytes", e, "peerKey" to peerKey)
            // Connection broken — close and remove so next send reopens a fresh connection.
            peerConnections.remove(peerKey)?.socket?.close()
            val removed = discoveredPeers.remove(peerKey)
            if (removed != null) peerByAddress.remove(removed.address)
        }
    }

    /**
     * Client-side LAN TCP authentication handshake.
     *
     * Reads the server's auth flag byte:
     *   AUTH_NOT_REQUIRED (0x00): server does not require auth — return true.
     *   AUTH_REQUIRED_V1 (0x01):  server requires Ed25519 proof.
     *     - If [signChallengeEd25519Only] is null: log and return false (connection will be rejected).
     *     - Otherwise: read 32-byte challenge, sign (challenge || localNodeId),
     *       send [localNodeId (32B)][localEd25519Pub (32B)][sig (64B)].
     *
     * Returns true if the handshake completes successfully or no auth is required.
     */
    private suspend fun performClientAuth(inp: DataInputStream, out: DataOutputStream): Boolean {
        val signFn = signChallengeEd25519Only
        val pubKey = localEd25519PubKey

        val authFlag = withTimeoutOrNull(TCP_AUTH_TIMEOUT_MS) {
            withContext(Dispatchers.IO) { inp.readByte() }
        }
        if (authFlag == null) {
            Diag.degraded("lan-transport", "auth-flag-timeout", "server did not send auth flag")
            return false
        }

        if (authFlag == AUTH_NOT_REQUIRED) return true  // server does not require auth

        if (authFlag != AUTH_REQUIRED_V1) {
            Diag.degraded("lan-transport", "auth-unknown-flag",
                "server sent unknown auth flag 0x${authFlag.toInt().and(0xFF).toString(16)}")
            return false
        }

        // Server requires auth
        if (signFn == null || pubKey == null) {
            Diag.degraded("lan-transport", "auth-not-wired",
                "LAN server requires authentication but signing key is not wired — connection refused")
            return false
        }

        // Read server's 32-byte challenge
        val challenge = withTimeoutOrNull(TCP_AUTH_TIMEOUT_MS) {
            withContext(Dispatchers.IO) {
                val buf = ByteArray(TCP_AUTH_CHALLENGE_BYTES)
                inp.readFully(buf)
                buf
            }
        }
        if (challenge == null) {
            Diag.degraded("lan-transport", "auth-challenge-timeout", "server challenge read timed out")
            return false
        }

        // Sign (challenge || localNodeId)
        val message = challenge + localNodeId.bytes
        val sig = try {
            signFn(message)
        } catch (e: Exception) {
            Diag.swallowed("lan-transport", "client-sign", e)
            return false
        }
        if (sig.size != 64) {
            Diag.degraded("lan-transport", "sign-bad-size", "Ed25519 sign returned ${sig.size} bytes (expected 64)")
            return false
        }

        // Send [localNodeId (32B)][localEd25519Pub (32B)][sig (64B)]
        try {
            withContext(Dispatchers.IO) {
                out.write(localNodeId.bytes)
                out.write(pubKey)
                out.write(sig)
                out.flush()
            }
        } catch (e: Exception) {
            Diag.swallowed("lan-transport", "auth-send-response", e)
            return false
        }

        return true
    }

    // ── Wire serialization (matches WiFiDirectTransport format) ───────────

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
        val dis         = DataInputStream(ByteArrayInputStream(bytes))
        val fragmentId  = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val postId      = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        val channelId   = ByteArray(64).also { dis.readFully(it) }.decodeToString().trim()
        // Use readUnsignedShort() (0..65535) — readShort().toInt() sign-extends: wire 0xFFFF → -1.
        // A negative totalData causes FragmentAccumulator.currentStatus() to return Complete
        // immediately for any single fragment (count >= -1 always true) — phantom-Complete attack
        // that suppresses real post delivery. Same class of bug fixed in FragmentEntity.fromWire().
        val seqIdx      = dis.readUnsignedShort()
        val totalData   = dis.readUnsignedShort()
        val totalParity = dis.readUnsignedShort()
        if (totalData == 0 || totalData > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS ||
            totalParity > mesh.shadowmesh.mesh.fragment.FragmentEntity.MAX_SHARDS)
            throw IllegalArgumentException("Invalid shard counts: totalData=$totalData totalParity=$totalParity")
        val payloadLen  = dis.readInt()
        // Guard against negative or oversized values before allocation. A crafted peer
        // packet with payloadLen = Integer.MAX_VALUE would OOM the process before the
        // trust gate runs. Mirror the same check in FragmentEntity.fromWire().
        if (payloadLen < 0 || payloadLen > MAX_FRAGMENT_BYTES)
            throw IllegalArgumentException("Invalid payload length: $payloadLen")
        val payload     = ByteArray(payloadLen).also { dis.readFully(it) }
        val fecWire     = dis.readByte().toInt()
        val fecScheme   = mesh.shadowmesh.mesh.fragment.FecScheme.fromWire(fecWire)
        FragmentEntity(fragmentId, postId, channelId, seqIdx, totalData, totalParity, payload, fecScheme ?: mesh.shadowmesh.mesh.fragment.FecScheme.NONE)
    } catch (e: Exception) {
        Diag.swallowed("lan-transport", "deserialize-fragment", e)
        null
    }

    // ── Queries ───────────────────────────────────────────────────────────

    fun discoveredPeerCount(): Int = discoveredPeers.size
    fun discoveredPeers(): List<LanPeer> = discoveredPeers.values.toList()

    /**
     * Actively probe LAN reachability by attempting a TCP connection to a known peer.
     * Uses a fresh socket so it does not touch the fragment connection pool.
     * Returns TCP connect latency in ms on success, null if no peers are known or all fail.
     *
     * Used by TransportHealthMonitor's LAN probe lambda. This replaces the gossip
     * lastSeenMs heuristic which aged out after 5 minutes with no real traffic and
     * permanently showed ISOLATED on emulators / quiet real-device LANs.
     */
    suspend fun probe(): Long? = withContext(Dispatchers.IO) {
        var result: Long? = null
        for (peer in discoveredPeers.values.toList()) {
            val start = System.currentTimeMillis()
            try {
                Socket().use { s ->
                    s.connect(InetSocketAddress(peer.address, peer.tcpPort), 2_000)
                    // TCP handshake succeeded — peer's server is up.
                    // Close immediately; the server's handleClient times out on auth read.
                }
                result = System.currentTimeMillis() - start
                break
            } catch (_: Exception) { /* try next peer */ }
        }
        result
    }

    /**
     * Directly register a remote peer without UDP discovery — for testing / bridging
     * environments (e.g. two Android emulators connected via adb TCP forward).
     *
     * The synthetic nodeId is derived from the address so it is stable across retries.
     * Self-connections are silently ignored (same address as our own TCP server causes
     * a loop-back that the server rejects via the self-connection guard in handleClient).
     *
     * When the gossip engine later sends a fragment to this peer the TCP connection is
     * opened lazily; the REAL nodeId is then confirmed via the Ed25519 auth handshake.
     */
    fun connectDirectPeer(ip: String, tcpPort: Int) {
        val synthNodeId = NodeId(Hkdf.instance.sha3_256("lan-direct:$ip:$tcpPort".toByteArray(Charsets.UTF_8)))
        val peer     = LanPeer(nodeId = synthNodeId, address = ip, tcpPort = tcpPort)
        val peerKey  = synthNodeId.bytes.toHex()
        if (discoveredPeers.putIfAbsent(peerKey, peer) == null) {
            peerByAddress[ip] = peer
            onPeerDiscovered(peer)
            Diag.info("lan-transport", "direct-peer-injected",
                "injected direct peer $ip:$tcpPort for emulator-bridge testing")
        }
    }

    fun stop() {
        isRunning = false
        tcpServer?.close()
        discoverySocket?.close()
        peerConnections.values.forEach { runCatching { it.socket.close() } }
        peerConnections.clear()
        discoveredPeers.clear()
        peerByAddress.clear()
    }

    // NodeId.toHex() is defined on the NodeId class — no local extension needed.

    companion object {
        const val PORT_DISCOVERY        = 7402
        const val PORT_FRAGMENT         = 7403
        const val DISCOVERY_INTERVAL_MS = 15_000L
        const val MAX_FRAGMENT_BYTES    = 64 * 1024
        const val NODE_ID_BYTES         = 32
        // Magic: "SMESH001"
        val BEACON_MAGIC = byteArrayOf(0x53, 0x4D, 0x45, 0x53, 0x48, 0x30, 0x30, 0x31)
        const val BEACON_SIZE = 8 + NODE_ID_BYTES + 2  // magic + nodeId + port

        // LAN TCP mutual authentication protocol constants.
        // Server sends 1-byte flag then (if 0x01) a 32-byte challenge.
        // Client responds with 128 bytes: nodeId(32) + ed25519Pub(32) + Ed25519Sig(64).
        private const val AUTH_NOT_REQUIRED: Byte   = 0x00
        private const val AUTH_REQUIRED_V1: Byte    = 0x01
        const val TCP_AUTH_CHALLENGE_BYTES: Int      = 32
        const val TCP_AUTH_RESPONSE_BYTES: Int       = 128  // nodeId(32) + ed25519Pub(32) + sig(64)
        const val TCP_AUTH_TIMEOUT_MS: Long          = 3_000L

        /**
         * TCP socket read timeout applied to inbound connections in [handleClient].
         * Without this, a peer that connects and sends only 1-3 bytes causes input.readInt()
         * to block indefinitely, holding a Dispatchers.IO thread per connection. An attacker
         * on the LAN can exhaust the IO thread pool with a handful of half-open connections.
         * 30 seconds is generous for legitimate fragment delivery while bounding exposure.
         */
        const val SOCKET_READ_TIMEOUT_MS: Long = 30_000L
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

data class LanPeer(
    val nodeId:  NodeId,
    val address: String,
    val tcpPort: Int
)

/** Holds an authenticated persistent TCP connection to a LAN peer. */
private data class PeerStream(val socket: Socket, val out: DataOutputStream)

private data class BeaconPayload(val nodeId: ByteArray, val tcpPort: Int)

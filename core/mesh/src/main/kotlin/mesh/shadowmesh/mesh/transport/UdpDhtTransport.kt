package mesh.shadowmesh.mesh.transport

import kotlinx.coroutines.*
import mesh.shadowmesh.crypto.intTo4Bytes
import mesh.shadowmesh.crypto.readInt4
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.diagnostics.Diag
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * UDP-backed [DhtTransport] — the concrete network layer for [DhtEngine].
 *
 * ## Responsibilities
 *
 * 1. **Outbound RPCs** (`ping`, `findNode`, `findValue`, `store`): serialise the request,
 *    send it via [adapter], register a pending [CompletableDeferred] keyed by nonce, and
 *    wait for a response or timeout.
 *
 * 2. **Inbound dispatch**: registers itself as [DatagramSocketUdpAdapter.onDhtDatagram].
 *    The adapter's receive loop calls [onDatagram] for every DHT-magic datagram. This
 *    method routes response messages to pending deferreds and request messages to the
 *    inbound RPC handlers below.
 *
 * 3. **Inbound RPC handling**: [DhtEngine] has no inbound dispatch method — it only issues
 *    outbound RPCs. This transport handles inbound requests itself:
 *    - PING_REQ → reply PING_RSP; insert sender into routing table.
 *    - FIND_NODE_REQ → query [engine.routingTable]; reply FIND_NODE_RSP.
 *    - FIND_VALUE_REQ → check [engine.getLocal]; if found reply with value; else closest nodes.
 *    - STORE_REQ → call [engine.storeLocal]; no response (fire-and-forget, Kademlia standard).
 *
 * ## Wire format
 *
 * Every datagram begins with [DHT_MAGIC] (2 bytes) for demux in the adapter.
 *
 * Fixed header (43 bytes after magic):
 *   [0..1]   magic:  0x44 0x48  ('D','H')
 *   [2]      msgType: see [MsgType]
 *   [3..10]  nonce:  8 random bytes (request) or echoed bytes (response)
 *   [11..42] senderNodeId: 32 bytes
 *
 * Payload follows the header, varies by message type:
 *
 *   PING_REQ     — no payload
 *   PING_RSP     — [1B format] then either:
 *                    format=0x01 (compact):  [6B address (4B IPv4 + 2B port)]
 *                    format=0x02 (extended): [6B address][4B identity length][NodePublicIdentity bytes]
 *                  The extended format is sent when the responder has a local public identity
 *                  configured, allowing the requester to build a verified DhtContact from a PING.
 *   FIND_NODE_REQ — targetNodeId: 32 bytes
 *   FIND_NODE_RSP — contact list: [count:1][contact…] each contact = 32B nodeId + 6B addr
 *   FIND_VALUE_REQ — key: 32 bytes
 *   FIND_VALUE_RSP — [found:1] then either:
 *                    found=1: [keyLen:0 implicit 32B][ttlMs:8B][valueLen:4B][value bytes]
 *                    found=0: contact list as FIND_NODE_RSP
 *   STORE_REQ    — [key:32B][ttlMs:8B][valueLen:4B][value bytes]
 *
 * IPv4-only in this implementation. IPv6 support is a straightforward extension
 * (add a family byte before the address, extend address field to 16 bytes).
 *
 * ## Timeout and retry
 *
 * Each RPC is attempted once. On timeout ([RPC_TIMEOUT_MS]) the deferred is cancelled and
 * the method throws [DhtRpcTimeoutException]. [DhtEngine] handles this by removing the peer
 * from the routing table — no retry loop needed here (retries at the Kademlia layer via
 * alpha-parallel lookups are more effective than transport-layer retries for a DHT).
 *
 * @param adapter    The shared UDP socket adapter. This transport registers itself as the
 *                   DHT datagram handler immediately on construction.
 * @param engine     The [DhtEngine] this transport serves. Used for inbound RPC handling
 *                   (routing table queries, local store reads/writes). Set after construction
 *                   via [setEngine] to break the circular dependency: Application constructs
 *                   transport → constructs engine(transport) → calls transport.setEngine(engine).
 * @param localNodeId  This node's 32-byte DHT identity.
 * @param scope      CoroutineScope for inbound RPC handler coroutines.
 */
class UdpDhtTransport(
    private val adapter:      DatagramSocketUdpAdapter,
    private val localNodeId:  NodeId,
    private val scope:        CoroutineScope
) : DhtTransport {

    // Set after construction to break the circular dependency.
    // Volatile so the assignment in setEngine is visible to inbound handler coroutines.
    @Volatile private var engine: DhtEngine? = null

    private val rng = SecureRandom()

    // Pending outbound RPCs: nonce hex → (expectedSenderIp, expectedSenderPort, deferred)
    // The expected sender IP:port is recorded when the RPC is sent so that responses
    // from unexpected senders (forged nonce injection attacks) are silently discarded.
    // An on-path attacker who observes the nonce in a PING_REQ can forge a PING_RSP
    // from any source — without this check any forged value response would be accepted.
    private data class PendingRpc(
        val expectedIp:   String,
        val expectedPort: Int,
        val deferred:     CompletableDeferred<ByteArray>
    )
    private val pending = ConcurrentHashMap<String, PendingRpc>()

    // Per-IP inbound RPC rate limiter: tracks request timestamps in a rolling 1-second window.
    // An attacker flooding FIND_NODE_REQ causes an O(n) routing table lock on each request.
    // Capping at MAX_INBOUND_RPS requests per IP per second bounds the CPU impact.
    // ConcurrentHashMap of (ip → deque of timestamps). Pruned on each access.
    private val inboundRateMap = ConcurrentHashMap<String, ArrayDeque<Long>>()

    private fun isInboundRateLimited(senderIp: String): Boolean {
        val now     = System.currentTimeMillis()
        val cutoff  = now - INBOUND_RATE_WINDOW_MS
        // Size cap: without this, a botnet with unique source IPs fills the map to OOM between
        // 60-second prune cycles. Each entry is ~String(15B key) + ArrayDeque(~80B overhead).
        // At MAX_TRACKED_IPS = 10_000 entries ≈ ~1MB — bounded. New IPs over the cap are
        // rate-limited by default (return true) — conservative but safe.
        if (!inboundRateMap.containsKey(senderIp) && inboundRateMap.size >= MAX_TRACKED_IPS) {
            return true
        }
        val deque   = inboundRateMap.computeIfAbsent(senderIp) { ArrayDeque() }
        synchronized(deque) {
            while (deque.isNotEmpty() && deque.first() < cutoff) deque.removeFirst()
            if (deque.size >= MAX_INBOUND_RPS) return true
            deque.addLast(now)
            return false
        }
    }

    init {
        // Register as the DHT datagram handler on the shared adapter.
        adapter.onDhtDatagram = ::onDatagram
        // Periodically prune stale entries from inboundRateMap. Without this, an attacker
        // using many source IPs creates an unbounded map (each unique IP → one deque entry).
        // At 1 minute pruning interval, the map holds at most ~(scan_rate × 60s) entries.
        scope.launch {
            while (isActive) {
                kotlinx.coroutines.delay(60_000L)
                val cutoff = System.currentTimeMillis() - INBOUND_RATE_WINDOW_MS
                inboundRateMap.entries.removeIf { (_, deque) ->
                    synchronized(deque) { deque.all { it < cutoff } }
                }
            }
        }
    }

    /**
     * Wire this transport to its [DhtEngine]. Must be called before the first RPC.
     * Exists because DhtEngine takes a DhtTransport in its constructor, creating a cycle:
     *   UdpDhtTransport → DhtEngine(transport) → transport.setEngine(engine)
     */
    fun setEngine(e: DhtEngine) {
        engine = e
    }

    // ── DhtTransport outbound ─────────────────────────────────────────────

    override suspend fun ping(contact: DhtContact): DhtContact? {
        val nonce = freshNonce()
        val req   = buildHeader(MsgType.PING_REQ, nonce)  // no payload
        val rsp   = rpc(contact, nonce, req) ?: return null
        if (rsp.size < HEADER_SIZE + 1) return null

        // ── Parse PING_RSP payload ────────────────────────────────────────
        // Format byte:
        //   0x01 = legacy compact (6B address only)
        //   0x02 = extended (6B address + 4B identity length + identity bytes)
        val format = rsp[HEADER_SIZE].toInt() and 0xFF
        val addrOff = HEADER_SIZE + 1
        if (rsp.size < addrOff + 6) return null
        val addr = decodeAddress(rsp, addrOff) ?: return null

        var publicIdentity: mesh.shadowmesh.crypto.NodePublicIdentity? = null
        if (format == PING_RSP_FORMAT_EXTENDED) {
            val identOff = addrOff + 6
            if (rsp.size >= identOff + 4) {
                val identLen = readInt4(rsp, identOff)
                val dataOff  = identOff + 4
                if (identLen > 0 && rsp.size >= dataOff + identLen) {
                    try {
                        publicIdentity = mesh.shadowmesh.crypto.NodePublicIdentity.fromBytes(
                            rsp.sliceArray(dataOff until dataOff + identLen)
                        )
                    } catch (e: Exception) {
                        Diag.swallowed("udp-dht", "ping-identity-parse", e,
                            "peer" to contact.nodeId.toHex().take(8))
                    }
                }
            }
        }

        return contact.copy(
            address        = addr,
            lastSeenMs     = System.currentTimeMillis(),
            publicIdentity = publicIdentity
        )
    }

    override suspend fun findNode(peer: DhtContact, target: NodeId): List<DhtContact> {
        val nonce   = freshNonce()
        val payload = target.bytes
        val req     = buildHeader(MsgType.FIND_NODE_REQ, nonce) + payload
        val rsp     = rpc(peer, nonce, req) ?: return emptyList()
        return decodeContactList(rsp, HEADER_SIZE)
    }

    override suspend fun findValue(peer: DhtContact, key: NodeId): LookupResult {
        val nonce   = freshNonce()
        val payload = key.bytes
        val req     = buildHeader(MsgType.FIND_VALUE_REQ, nonce) + payload
        val rsp     = rpc(peer, nonce, req) ?: return LookupResult.NotFound
        if (rsp.size < HEADER_SIZE + 1) return LookupResult.NotFound

        return when (rsp[HEADER_SIZE].toInt()) {
            1    -> decodeFoundValue(rsp, HEADER_SIZE + 1, peer.nodeId)
            0    -> LookupResult.Contacts(decodeContactList(rsp, HEADER_SIZE + 1))
            else -> LookupResult.NotFound
        }
    }

    /** STORE is fire-and-forget in Kademlia — no response is expected. */
    override suspend fun store(peer: DhtContact, value: DhtValue) {
        val nonce   = freshNonce()
        val payload = encodeValue(value)
        val req     = buildHeader(MsgType.STORE_REQ, nonce) + payload
        try {
            adapter.sendUdp(peer.address.ip, peer.address.port, req)
        } catch (e: Exception) {
            Diag.swallowed("udp-dht", "store-send", e,
                "peer" to peer.nodeId.toHex().take(8))
        }
    }

    // ── Inbound dispatch ──────────────────────────────────────────────────

    /**
     * Entry point for all DHT datagrams from [DatagramSocketUdpAdapter].
     * Called on the adapter's receive loop coroutine — must not block.
     * Response messages complete pending deferreds; request messages launch handler coroutines.
     */
    private fun onDatagram(payload: ByteArray, senderIp: String, senderPort: Int) {
        if (payload.size < HEADER_SIZE) {
            Diag.fallback("udp-dht", "short-datagram",
                "received datagram too short to parse: ${payload.size} bytes")
            return
        }
        // Verify magic
        if (payload[0] != DHT_MAGIC[0] || payload[1] != DHT_MAGIC[1]) return

        val msgTypeByte = payload[2].toInt() and 0xFF
        val nonce       = payload.sliceArray(3..10)
        val nonceKey    = nonce.toHex()
        val senderIdBytes = payload.sliceArray(11 until HEADER_SIZE)
        val senderId    = try { NodeId(senderIdBytes) } catch (e: Exception) { return }

        when (msgTypeByte) {
            // ── Responses: complete pending deferreds ─────────────────────
            // Validate that the response arrives from the IP:port we sent the
            // request to. An on-path attacker who observes our outbound nonce
            // could inject a forged FIND_VALUE_RSP carrying a malicious DHT value.
            // Verifying the source IP:port prevents off-network injection while still
            // handling legitimate NATted responses (the actual source IP is provided
            // by the OS network stack and cannot be trivially spoofed by a remote host).
            MsgType.PING_RSP.wire,
            MsgType.FIND_NODE_RSP.wire,
            MsgType.FIND_VALUE_RSP.wire -> {
                val entry = pending[nonceKey]
                if (entry != null &&
                    senderIp == entry.expectedIp &&
                    senderPort == entry.expectedPort) {
                    entry.deferred.complete(payload)
                } else if (entry != null) {
                    Diag.fallback("udp-dht", "rpc-sender-mismatch",
                        "Response nonce matched but sender ${senderIp}:${senderPort} != " +
                        "expected ${entry.expectedIp}:${entry.expectedPort} — discarding " +
                        "(possible nonce injection attack)",
                        "nonce" to nonceKey.take(16))
                }
            }

            // ── Requests: handle and reply ────────────────────────────────
            // Rate-limit inbound requests per source IP to bound the CPU cost of
            // routing table lookups on each request. Responses are NOT rate-limited
            // since they complete pending deferreds rather than spawning new work.
            MsgType.PING_REQ.wire -> {
                if (!isInboundRateLimited(senderIp)) scope.launch(Dispatchers.IO) {
                    handlePingReq(senderId, PeerAddress(senderIp, senderPort), nonce)
                } else {
                    Diag.fallback("udp-dht", "inbound-rate-limited",
                        "rate limit exceeded for $senderIp — dropping PING_REQ",
                        "ip" to senderIp)
                }
            }

            MsgType.FIND_NODE_REQ.wire -> {
                if (!isInboundRateLimited(senderIp)) scope.launch(Dispatchers.IO) {
                    handleFindNodeReq(senderId, PeerAddress(senderIp, senderPort), nonce, payload)
                }
            }

            MsgType.FIND_VALUE_REQ.wire -> {
                if (!isInboundRateLimited(senderIp)) scope.launch(Dispatchers.IO) {
                    handleFindValueReq(senderId, PeerAddress(senderIp, senderPort), nonce, payload)
                }
            }

            MsgType.STORE_REQ.wire -> {
                if (!isInboundRateLimited(senderIp)) scope.launch(Dispatchers.IO) {
                    handleStoreReq(senderId, PeerAddress(senderIp, senderPort), payload)
                }
            }

            else -> Diag.fallback("udp-dht", "unknown-msg-type",
                "received unknown DHT message type 0x${msgTypeByte.toString(16)}")
        }
    }

    // ── Inbound RPC handlers ──────────────────────────────────────────────

    private suspend fun handlePingReq(
        sender:    NodeId,
        senderAddr: PeerAddress,
        reqNonce:  ByteArray
    ) {
        touchSender(sender, senderAddr)
        // Build PING_RSP. If we have a local public identity, include it in the extended
        // format so the requester can build a verified DhtContact for us without a separate
        // out-of-band exchange.
        val addrBytes = encodeAddress(senderAddr)
        val identityBytes = engine?.localPublicIdentity?.toBytes()
        val rsp = if (identityBytes != null) {
            // Extended format: [format=0x02][6B addr][4B identity len][identity bytes]
            buildHeader(MsgType.PING_RSP, reqNonce) +
                byteArrayOf(PING_RSP_FORMAT_EXTENDED.toByte()) +
                addrBytes +
                intTo4Bytes(identityBytes.size) +
                identityBytes
        } else {
            // Compact format: [format=0x01][6B addr]
            buildHeader(MsgType.PING_RSP, reqNonce) +
                byteArrayOf(PING_RSP_FORMAT_COMPACT.toByte()) +
                addrBytes
        }
        send(senderAddr, rsp)
    }

    private suspend fun handleFindNodeReq(
        sender:    NodeId,
        senderAddr: PeerAddress,
        reqNonce:  ByteArray,
        payload:   ByteArray
    ) {
        touchSender(sender, senderAddr)
        if (payload.size < HEADER_SIZE + NODE_ID_BYTES) return
        val targetBytes = payload.sliceArray(HEADER_SIZE until HEADER_SIZE + NODE_ID_BYTES)
        val target = try { NodeId(targetBytes) } catch (e: Exception) { return }
        val closest = engine?.routingTable?.findClosest(target, K) ?: emptyList()
        val rsp = buildHeader(MsgType.FIND_NODE_RSP, reqNonce) + encodeContactList(closest)
        send(senderAddr, rsp)
    }

    private suspend fun handleFindValueReq(
        sender:    NodeId,
        senderAddr: PeerAddress,
        reqNonce:  ByteArray,
        payload:   ByteArray
    ) {
        touchSender(sender, senderAddr)
        if (payload.size < HEADER_SIZE + NODE_ID_BYTES) return
        val keyBytes = payload.sliceArray(HEADER_SIZE until HEADER_SIZE + NODE_ID_BYTES)
        val key = try { NodeId(keyBytes) } catch (e: Exception) { return }

        val local = engine?.getLocal(key)
        val rsp = if (local != null) {
            // found=1 + encoded value
            buildHeader(MsgType.FIND_VALUE_RSP, reqNonce) +
                byteArrayOf(1) + encodeValue(local)
        } else {
            // found=0 + closest contacts
            val closest = engine?.routingTable?.findClosest(key, K) ?: emptyList()
            buildHeader(MsgType.FIND_VALUE_RSP, reqNonce) +
                byteArrayOf(0) + encodeContactList(closest)
        }
        send(senderAddr, rsp)
    }

    private fun handleStoreReq(
        sender:    NodeId,
        senderAddr: PeerAddress,
        payload:   ByteArray
    ) {
        touchSender(sender, senderAddr)
        val value = decodeValue(payload, HEADER_SIZE) ?: run {
            Diag.fallback("udp-dht", "store-decode-fail",
                "STORE_REQ from ${sender.toHex().take(8)} had malformed value payload")
            return
        }
        engine?.storeLocal(value)
    }

    // ── RPC send/await ────────────────────────────────────────────────────

    /**
     * Send [req] to [peer], register a pending deferred for [nonce], and wait up to
     * [RPC_TIMEOUT_MS] for a response datagram. Returns the raw response payload on
     * success, or null on timeout (after logging). Throws on send failure.
     */
    private suspend fun rpc(peer: DhtContact, nonce: ByteArray, req: ByteArray): ByteArray? {
        val key      = nonce.toHex()
        val deferred = CompletableDeferred<ByteArray>()
        pending[key] = PendingRpc(
            expectedIp   = peer.address.ip,
            expectedPort = peer.address.port,
            deferred     = deferred
        )
        return try {
            adapter.sendUdp(peer.address.ip, peer.address.port, req)
            withTimeoutOrNull(RPC_TIMEOUT_MS) { deferred.await() }
                ?: run {
                    Diag.fallback("udp-dht", "rpc-timeout",
                        "DHT RPC to ${peer.nodeId.toHex().take(8)} timed out after ${RPC_TIMEOUT_MS}ms")
                    null
                }
        } catch (e: Exception) {
            Diag.swallowed("udp-dht", "rpc-send", e,
                "peer" to peer.nodeId.toHex().take(8))
            null
        } finally {
            pending.remove(key)
        }
    }

    private suspend fun send(addr: PeerAddress, payload: ByteArray) {
        try { adapter.sendUdp(addr.ip, addr.port, payload) }
        catch (e: Exception) {
            Diag.swallowed("udp-dht", "reply-send", e, "addr" to "${addr.ip}:${addr.port}")
        }
    }

    // ── Serialisation ─────────────────────────────────────────────────────

    private fun buildHeader(type: MsgType, nonce: ByteArray): ByteArray {
        val buf = ByteArray(HEADER_SIZE)
        buf[0] = DHT_MAGIC[0]; buf[1] = DHT_MAGIC[1]
        buf[2] = type.wire.toByte()
        System.arraycopy(nonce, 0, buf, 3, NONCE_BYTES)
        System.arraycopy(localNodeId.bytes, 0, buf, 3 + NONCE_BYTES, NODE_ID_BYTES)
        return buf
    }

    private fun encodeAddress(addr: PeerAddress): ByteArray {
        // Require exactly 4 valid octets. Silently filling missing octets with 0
        // (as getOrElse did previously) misrepresents a malformed address in the DHT
        // routing table and is a silent data-integrity failure.
        val segments = addr.ip.split(".")
        if (segments.size != 4) {
            Diag.degraded("udp-dht", "encode-addr-invalid",
                "IP '${addr.ip}' has ${segments.size} parts (expected 4) — skipping")
            return ByteArray(6)  // all-zero; port=0 is rejected by decodeAddress
        }
        val octets = segments.map { it.toIntOrNull()?.takeIf { v -> v in 0..255 } }
        if (octets.any { it == null }) {
            Diag.degraded("udp-dht", "encode-addr-invalid",
                "IP '${addr.ip}' contains non-integer or out-of-range octet — skipping")
            return ByteArray(6)
        }
        return byteArrayOf(
            (octets[0]!! and 0xFF).toByte(),
            (octets[1]!! and 0xFF).toByte(),
            (octets[2]!! and 0xFF).toByte(),
            (octets[3]!! and 0xFF).toByte(),
            ((addr.port shr 8) and 0xFF).toByte(),
            (addr.port and 0xFF).toByte()
        )
    }

    private fun decodeAddress(buf: ByteArray, off: Int): PeerAddress? {
        if (buf.size < off + 6) return null
        val ip   = "${buf[off].toInt() and 0xFF}.${buf[off+1].toInt() and 0xFF}" +
                   ".${buf[off+2].toInt() and 0xFF}.${buf[off+3].toInt() and 0xFF}"
        val port = ((buf[off+4].toInt() and 0xFF) shl 8) or (buf[off+5].toInt() and 0xFF)
        if (port == 0) return null
        return PeerAddress(ip, port)
    }

    private fun encodeContactList(contacts: List<DhtContact>): ByteArray {
        // [count:1][contact…] — cap at 20 to stay within MTU
        val capped = contacts.take(MAX_CONTACTS_PER_MSG)
        val buf = ByteArray(1 + capped.size * CONTACT_BYTES)
        buf[0] = (capped.size and 0xFF).toByte()
        var off = 1
        for (c in capped) {
            System.arraycopy(c.nodeId.bytes, 0, buf, off, NODE_ID_BYTES)
            off += NODE_ID_BYTES
            val addr = encodeAddress(c.address)
            System.arraycopy(addr, 0, buf, off, 6)
            off += 6
        }
        return buf
    }

    private fun decodeContactList(buf: ByteArray, off: Int): List<DhtContact> {
        if (buf.size < off + 1) return emptyList()
        val count = buf[off].toInt() and 0xFF
        val result = mutableListOf<DhtContact>()
        var cur = off + 1
        repeat(count) {
            if (cur + CONTACT_BYTES > buf.size) return@repeat
            val nodeIdBytes = buf.sliceArray(cur until cur + NODE_ID_BYTES)
            val nodeId = try { NodeId(nodeIdBytes) } catch (e: Exception) { return@repeat }
            cur += NODE_ID_BYTES
            val addr = decodeAddress(buf, cur) ?: return@repeat
            cur += 6
            result.add(DhtContact(nodeId, addr))
        }
        return result
    }

    private fun encodeValue(value: DhtValue): ByteArray {
        // [key:32][ttlMs:8][valueLen:4][value bytes]
        // Caller is responsible for ensuring value.value.size <= MAX_VALUE_BYTES.
        // DhtEngine.storeLocal and deadDropPut enforce this before calling the transport.
        val buf = ByteArray(NODE_ID_BYTES + 8 + 4 + value.value.size)
        var off = 0
        System.arraycopy(value.key.bytes, 0, buf, off, NODE_ID_BYTES); off += NODE_ID_BYTES
        writeLong(buf, off, value.ttlMs); off += 8
        writeInt(buf, off, value.value.size); off += 4
        System.arraycopy(value.value, 0, buf, off, value.value.size)
        return buf
    }

    private fun decodeValue(buf: ByteArray, off: Int): DhtValue? {
        if (buf.size < off + NODE_ID_BYTES + 8 + 4) return null
        val keyBytes  = buf.sliceArray(off until off + NODE_ID_BYTES)
        val key       = try { NodeId(keyBytes) } catch (e: Exception) { return null }
        val ttlMs     = readLong(buf, off + NODE_ID_BYTES)
        val valueLen  = readInt4(buf, off + NODE_ID_BYTES + 8)
        // Reject oversized or negative lengths — a peer cannot send a value that would
        // have exceeded our MTU, so a valueLen > MAX_VALUE_BYTES indicates a malformed
        // or malicious packet; drop it rather than allocate a large buffer.
        if (valueLen < 0 || valueLen > MAX_VALUE_BYTES) return null
        val dataStart = off + NODE_ID_BYTES + 8 + 4
        if (dataStart + valueLen > buf.size) return null
        val value = buf.sliceArray(dataStart until dataStart + valueLen)
        return DhtValue(key, value, ttlMs)
    }

    private fun decodeFoundValue(buf: ByteArray, off: Int, from: NodeId): LookupResult {
        val v = decodeValue(buf, off) ?: return LookupResult.NotFound
        return LookupResult.Found(v.value, from)
    }

    // ── Misc helpers ──────────────────────────────────────────────────────

    override suspend fun sendRaw(address: PeerAddress, bytes: ByteArray) =
        withContext(Dispatchers.IO) {
            adapter.sendUdp(address.ip, address.port, bytes)
        }

    private fun freshNonce(): ByteArray {
        val b = ByteArray(NONCE_BYTES)
        rng.nextBytes(b)
        return b
    }


    private fun touchSender(senderId: NodeId, senderAddr: PeerAddress) {
        // Insert as TIER_2 / isAnchor=false so the routing table's own tier-admission
        // logic applies. Using TIER_1 / isAnchor=true here bypassed all tier checks and
        // let any sender of a single valid UDP packet claim a Tier 1 routing slot, making
        // the entire tier-access model ineffective against Sybil senders.
        val contact = DhtContact(
            nodeId     = senderId,
            address    = senderAddr,
            lastSeenMs = System.currentTimeMillis(),
            tier       = NodeTier.TIER_2,
            isAnchor   = false
        )
        engine?.routingTable?.insert(contact)
    }

    private fun writeLong(buf: ByteArray, off: Int, v: Long) {
        for (i in 0..7) buf[off + i] = ((v shr ((7 - i) * 8)) and 0xFF).toByte()
    }

    private fun readLong(buf: ByteArray, off: Int): Long {
        var r = 0L
        for (i in 0..7) r = (r shl 8) or (buf[off + i].toLong() and 0xFF)
        return r
    }

    private fun writeInt(buf: ByteArray, off: Int, v: Int) {
        buf[off]     = ((v shr 24) and 0xFF).toByte()
        buf[off + 1] = ((v shr 16) and 0xFF).toByte()
        buf[off + 2] = ((v shr 8)  and 0xFF).toByte()
        buf[off + 3] = (v and 0xFF).toByte()
    }


    companion object {
        /** Magic prefix for all DHT datagrams. Must match [DatagramSocketUdpAdapter.DHT_MAGIC]. */
        val DHT_MAGIC = DatagramSocketUdpAdapter.DHT_MAGIC

        const val NONCE_BYTES    = 8
        const val NODE_ID_BYTES  = 32
        /**
         * Header: 2B magic + 1B type + 8B nonce + 32B senderNodeId = 43 bytes.
         */
        const val HEADER_SIZE    = 2 + 1 + NONCE_BYTES + NODE_ID_BYTES

        /** Per-RPC timeout before giving up and returning null. */
        const val RPC_TIMEOUT_MS = 2_000L

        /**
         * Inbound per-IP rate limit: max requests per [INBOUND_RATE_WINDOW_MS].
         * Each FIND_NODE/FIND_VALUE request takes a lock on the routing table —
         * bounding inbound RPS limits the CPU cost of a flooding DoS attack.
         * 20 requests/second from a single IP is generous for legitimate DHT use
         * and orders of magnitude below a realistic attack rate.
         */
        const val MAX_INBOUND_RPS        = 20
        const val INBOUND_RATE_WINDOW_MS = 1_000L
        /**
         * Maximum unique source IPs tracked in the inbound rate-limit map.
         * Without this cap, a botnet with unique source IPs fills the map between
         * 60-second prune cycles. New IPs over the cap are rate-limited by default.
         */
        const val MAX_TRACKED_IPS        = 10_000

        /** Kademlia K — must match [DhtModels.K]. */
        const val K = 20

        /** Max contacts per FIND_NODE_RSP / FIND_VALUE_RSP (contact list). */
        const val MAX_CONTACTS_PER_MSG = K

        /** Bytes per serialised contact: 32B nodeId + 4B IPv4 + 2B port. */
        const val CONTACT_BYTES = NODE_ID_BYTES + 6

        /**
         * Maximum DhtValue payload bytes that can be sent in a single UDP datagram
         * without exceeding the [DatagramSocketUdpAdapter.MAX_DATAGRAM_BYTES] MTU cap.
         *
         * Budget:
         *   MAX_DATAGRAM_BYTES(1400) - HEADER_SIZE(43) - found_byte(1) - value_header(44) = 1312
         *
         * Note: Kyber-1024 ciphertexts (1568 bytes) exceed this budget. Dead-drop blobs
         * (HybridKem.encapsulate result + channel key) must be kept under this limit by
         * the caller, or dead-drop delivery must use an alternative channel (SHADOWFILES,
         * BLE, WiFi Direct) when the blob is too large for a single DHT datagram.
         * [DhtEngine.storeLocal] and [DhtEngine.deadDropPut] enforce this cap and log a
         * Diag.degraded event when a value is too large to store via UDP DHT.
         *
         * This is an IPv4/UDP architectural constraint, not a protocol limitation —
         * a future TCP or QUIC transport would not have this restriction.
         */
        const val MAX_VALUE_BYTES = DatagramSocketUdpAdapter.MAX_DATAGRAM_BYTES -
            HEADER_SIZE - 1 - (NODE_ID_BYTES + 8 + 4)  // = 1312

        /**
         * PING_RSP format byte values.
         *   0x01 = compact: [1B format][6B address]
         *   0x02 = extended: [1B format][6B address][4B identity length][NodePublicIdentity bytes]
         *
         * The extended format allows a peer receiving a PING to obtain the responder's
         * public key material and build a verified DhtContact without a separate NFC exchange.
         * It is only sent when [DhtEngine.localPublicIdentity] is non-null.
         */
        const val PING_RSP_FORMAT_COMPACT  = 0x01
        const val PING_RSP_FORMAT_EXTENDED = 0x02
    }

    /** DHT RPC message types. [wire] is the single byte in the header. */
    private enum class MsgType(val wire: Int) {
        PING_REQ(0x01),
        PING_RSP(0x02),
        FIND_NODE_REQ(0x03),
        FIND_NODE_RSP(0x04),
        FIND_VALUE_REQ(0x05),
        FIND_VALUE_RSP(0x06),
        STORE_REQ(0x07)
        // No STORE_RSP — Kademlia STORE is fire-and-forget
    }
}

// ── Fallback ──────────────────────────────────────────────────────────────────

/**
 * Fail-closed [DhtTransport] used when the UDP socket cannot be bound (e.g. port conflict).
 * Every operation returns an empty / not-found result so [DhtEngine] constructs cleanly
 * and degrades gracefully — the routing table stays empty and the node operates as
 * LAN/WiFi Direct/BLE only until the port conflict is resolved and the app is restarted.
 */
object NoOpDhtTransport : DhtTransport {
    override suspend fun ping(contact: DhtContact): DhtContact? = null
    override suspend fun findNode(peer: DhtContact, target: NodeId): List<DhtContact> = emptyList()
    override suspend fun findValue(peer: DhtContact, key: NodeId): LookupResult = LookupResult.NotFound
    override suspend fun store(peer: DhtContact, value: DhtValue) { /* no-op */ }
}

package mesh.shadowmesh.crypto

/**
 * Node callsign — human-readable pseudonym bound to a nodeId.
 *
 * Design rationale:
 *   nodeId is 32 bytes — cryptographically correct but humanly unreadable.
 *   A callsign is a short, self-asserted, cryptographically signed label
 *   that gives a node a stable human identity across sessions.
 *
 * Properties:
 *   - Max 16 chars, alphanumeric + hyphen (e.g. "ALPHA-1", "RECON-7")
 *   - Signed with the node's HybridSigner key — any peer can verify it
 *     genuinely came from that nodeId
 *   - NOT unique — two nodes can pick the same callsign. The UI always
 *     shows callsign + truncated nodeId: "ALPHA-1 (a3f7…)"
 *   - Gossipped as a tiny signed packet alongside the first post per session
 *   - Stored locally by peers in KeyReputationEntity alongside the nodeId
 *
 * Wire format:
 *   [1B version][32B nodeId][1B callsign length N][NB callsign UTF-8][8B issuedAtMs]
 *   [4B sig length][sig bytes]
 *
 * Thread-safety: immutable data class — thread-safe by construction.
 */
data class NodeCallsign(
    val version:    Byte   = VERSION,
    val nodeId:     ByteArray,      // 32 bytes
    val callsign:   String,         // 1–16 chars, [A-Z0-9\-]
    val issuedAtMs: Long,
    val signature:  ByteArray       // HybridSigner over signedPayload()
) {
    init {
        require(nodeId.size == 32) { "nodeId must be 32 bytes" }
        require(callsign.isNotBlank() && callsign.length <= MAX_CALLSIGN_LENGTH) {
            "callsign must be 1–$MAX_CALLSIGN_LENGTH characters"
        }
        require(CALLSIGN_REGEX.matches(callsign)) {
            "callsign must match [A-Z0-9\\-]+ — got '$callsign'"
        }
    }

    // ── Signed payload ────────────────────────────────────────────────────

    fun signedPayload(): ByteArray {
        val callsignBytes = callsign.toByteArray(Charsets.UTF_8)
        return byteArrayOf(version) +
               nodeId +
               byteArrayOf(callsignBytes.size.toByte()) +
               callsignBytes +
               longToBytes(issuedAtMs)
    }

    fun toBytes(): ByteArray =
        signedPayload() + intTo4Bytes(signature.size) + signature

    // ── Display helper ────────────────────────────────────────────────────

    /**
     * Short display form: "ALPHA-1 (a3f7…)"
     * Shown in the UI when no local nickname is set for this nodeId.
     */
    fun displayName(): String {
        val shortId = nodeId.copyOfRange(0, 4).toHex()
        return "$callsign ($shortId…)"
    }

    override fun equals(other: Any?) = other is NodeCallsign &&
        nodeId.contentEquals(other.nodeId) && callsign == other.callsign
    override fun hashCode() = 31 * nodeId.contentHashCode() + callsign.hashCode()

    companion object {
        const val VERSION: Byte = 1
        const val MAX_CALLSIGN_LENGTH = 16
        private val CALLSIGN_REGEX = Regex("[A-Z0-9\\-]+")

        fun fromBytes(bytes: ByteArray): NodeCallsign {
            require(bytes.size >= 1 + 32 + 1 + 8 + 4) {
                "NodeCallsign: too short (${bytes.size} bytes)"
            }
            var off = 0
            val version       = bytes[off++]
            val nodeId        = bytes.copyOfRange(off, off + 32); off += 32
            val csLen         = bytes[off++].toInt() and 0xFF
            require(bytes.size >= off + csLen + 8 + 4) {
                "NodeCallsign: truncated at callsign"
            }
            val callsign      = bytes.copyOfRange(off, off + csLen).toString(Charsets.UTF_8); off += csLen
            val issuedAtMs    = bytesToLong(bytes, off); off += 8
            val sigLen        = fourBytesToInt(bytes, off); off += 4
            require(bytes.size == off + sigLen) {
                "NodeCallsign: wrong total length"
            }
            val signature     = bytes.copyOfRange(off, off + sigLen)
            return NodeCallsign(version, nodeId, callsign, issuedAtMs, signature)
        }

        /**
         * Build an unsigned callsign for signing.
         * Normalises to uppercase.
         */
        fun unsigned(nodeId: ByteArray, callsign: String): Unsigned =
            Unsigned(nodeId, callsign.uppercase().trim(), System.currentTimeMillis())
    }

    data class Unsigned(
        val nodeId:     ByteArray,
        val callsign:   String,
        val issuedAtMs: Long
    ) {
        fun payload(): ByteArray {
            val csBytes = callsign.toByteArray(Charsets.UTF_8)
            return byteArrayOf(VERSION) +
                   nodeId +
                   byteArrayOf(csBytes.size.toByte()) +
                   csBytes +
                   longToBytes(issuedAtMs)
        }
    }
}

// ── Callsign manager ──────────────────────────────────────────────────────────

/**
 * Issues, verifies, and caches callsigns.
 *
 * Local nickname override:
 *   For TRUST_PHYSICAL contacts, the user can assign a local nickname that
 *   only they see. Stored in NodeCallsignStore.localNicknames keyed by nodeId hex.
 *   The nickname is never transmitted — it is purely local.
 *
 * Display resolution order:
 *   1. Local nickname (if set by user)
 *   2. Verified callsign from peer
 *   3. "Unknown (a3f7…)" if neither available
 */
class NodeCallsignManager(private val signer: HybridSigner) {

    // In-memory cache — persisted in KeyReputationEntity.callsign column
    private val callsignCache    = HashMap<String, NodeCallsign>()  // nodeId hex → callsign
    private val localNicknames   = HashMap<String, String>()         // nodeId hex → nickname

    // ── Issue own callsign ────────────────────────────────────────────────

    suspend fun issueCallsign(
        localIdentity: NodeIdentity,
        callsign:      String
    ): CryptoResult<NodeCallsign> = cryptoRunCatching {
        val unsigned = NodeCallsign.unsigned(localIdentity.nodeId, callsign)
        val sig      = signer.sign(unsigned.payload(), localIdentity.privatePart.signingPrivateKey).getOrThrow()
        NodeCallsign(
            nodeId     = unsigned.nodeId,
            callsign   = unsigned.callsign,
            issuedAtMs = unsigned.issuedAtMs,
            signature  = sig
        )
    }

    // ── Receive and verify peer callsign ──────────────────────────────────

    /**
     * Verify and cache a callsign received from a peer.
     * Returns the callsign if valid, null if signature fails.
     *
     * @param callsign        The callsign received via gossip.
     * @param peerPublicId    The peer's NodePublicIdentity (already verified via DHT).
     */
    suspend fun receiveAndVerify(
        callsign:    NodeCallsign,
        peerPublicId:NodePublicIdentity
    ): NodeCallsign? {
        if (!callsign.nodeId.contentEquals(peerPublicId.nodeId)) return null
        val valid = signer.verify(
            callsign.signedPayload(),
            callsign.signature,
            peerPublicId.signingPublicKey
        ).getOrNull() ?: return null
        if (!valid) return null
        callsignCache[callsign.nodeId.toHex()] = callsign
        return callsign
    }

    // ── Local nickname ────────────────────────────────────────────────────

    fun setLocalNickname(nodeIdHex: String, nickname: String) {
        localNicknames[nodeIdHex] = nickname.trim()
    }

    fun clearLocalNickname(nodeIdHex: String) { localNicknames.remove(nodeIdHex) }

    // ── Display resolution ────────────────────────────────────────────────

    /**
     * Resolve the display name for a nodeId.
     *
     * Order:
     *   1. Local nickname (private — only visible to this node)
     *   2. Verified callsign + truncated nodeId
     *   3. "Unknown (a3f7…)"
     */
    fun displayName(nodeIdHex: String): String {
        localNicknames[nodeIdHex]?.let { return it }
        callsignCache[nodeIdHex]?.let { return it.displayName() }
        val short = nodeIdHex.take(8) + "…"
        return "Unknown ($short)"
    }

    fun getCallsign(nodeIdHex: String): NodeCallsign? = callsignCache[nodeIdHex]
}

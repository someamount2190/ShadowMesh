package mesh.shadowmesh.crypto

/**
 * Signed record of how a node entered the SHADOWMESH network.
 *
 * Trust levels (design doc §5.2):
 *   TRUST_PHYSICAL    — physical QR/NFC/BT exchange — eligible for Tier 1 anchor
 *   TRUST_INTRODUCED  — remote invite token — Tier 2 max, cannot introduce further
 *   TRUST_PUBLIC      — public beacon entry — Tier 3 read-only
 *
 * Trust Transitivity Cap (design doc §5.14):
 *   TRUST_PHYSICAL can introduce remotely → recipient gets TRUST_INTRODUCED
 *   TRUST_INTRODUCED attempting to introduce → recipient gets TRUST_PUBLIC only
 *   TRUST_PUBLIC cannot introduce at all
 *
 * Credential wire format:
 *   v2: [1B version=2][1B trust level][1B attestation tier][32B nodeId]
 *       [32B introducerNodeId (zeros if self)][8B issuedAtMs][4B sigLen][signature]
 *   v1 (legacy, still parsed): identical but with no attestation-tier byte.
 *   Signature covers all fields before the 4B sigLen, signed by the introducer's
 *   HybridSigningKey. The attestation byte is inside the signed payload, so a relay
 *   cannot upgrade a node's hardware tier after the fact.
 *
 * Self-issued credentials (TRUST_PUBLIC for first-contact beacon) are signed by
 * the node's own key. The trust level constrains network permissions regardless
 * of who signed it.
 */
data class TrustCredential(
    val version:         Byte          = VERSION,
    val trustLevel:      TrustLevel,
    val nodeId:          ByteArray,    // 32 bytes — the node being credentialed
    val introducerNodeId:ByteArray,    // 32 bytes — zeros if self-issued
    val issuedAtMs:      Long,
    val signature:       ByteArray,    // HybridSigner signature by introducer
    /**
     * Hardware-attestation tier verified at bootstrap and bound into the signature.
     * [CredentialAttestation.NONE] for v1 credentials and for any bootstrap that did
     * not verify hardware attestation. This is the durable record of the tier that
     * THREAT_MODEL.md §3 Tier B describes — previously it was lost at persistence time.
     */
    val attestation:     CredentialAttestation = CredentialAttestation.NONE
) {
    // ── Serialisation ─────────────────────────────────────────────────────

    /**
     * Signed payload — the bytes committed by the HybridSigner signature.
     *
     * Includes a domain-separation prefix ("shadowmesh_trustcred\x00") before the
     * version byte. This prevents cross-protocol confusion where a byte sequence
     * valid in one signing context (e.g. SignedContact, NodeCallsign) is accidentally
     * valid in another. SignedContact and NodeCallsign payloads start with 32-byte
     * nodeId (no ASCII prefix), making accidental collisions structurally impossible,
     * but the explicit prefix follows the same discipline applied in NfcHandshake
     * (RESPONSE_DOMAIN, SESSION_KEY_DOMAIN) and HKDF info strings.
     */
    fun signedPayload(): ByteArray {
        val head = if (version.toInt() and 0xFF >= 2)
            byteArrayOf(version, trustLevel.wire, attestation.wire)
        else
            byteArrayOf(version, trustLevel.wire)   // v1 layout — no attestation byte
        return DOMAIN_PREFIX + head + nodeId + introducerNodeId + longToBytes(issuedAtMs)
    }

    fun toBytes(): ByteArray = signedPayload() + intTo4Bytes(signature.size) + signature

    // ── Attestation query helpers ─────────────────────────────────────────

    /**
     * True if the peer's hardware attestation chain was successfully verified at bootstrap
     * and signed into this credential. This is the durable, wire-bound record of Tier B
     * attestation (THREAT_MODEL.md §3) — it cannot be forged after the fact because the
     * attestation byte is inside the signed payload.
     *
     * Use this for channel-level access control: a channel that requires hardware
     * attestation should reject members where isHardwareAttested == false.
     *
     * Note: HARDWARE_CUSTOM_OS (GrapheneOS/CalyxOS) is considered hardware-attested —
     * it is a SELF_SIGNED boot state verified by a pinned OEM key, not a software check.
     * Callers that want to further distinguish TEE vs StrongBox vs custom-OS should
     * inspect [attestation] directly.
     */
    val isHardwareAttested: Boolean get() = attestation != CredentialAttestation.NONE

    /**
     * Determine what trust level this credential holder may grant to a new node.
     * Enforces the transitivity cap: TRUST_INTRODUCED and TRUST_PUBLIC cannot
     * chain introduction; they can only grant TRUST_PUBLIC.
     */
    fun grantableTrustLevel(method: IntroductionMethod): TrustLevel = when (trustLevel) {
        TrustLevel.TRUST_PHYSICAL -> when (method) {
            IntroductionMethod.PHYSICAL -> TrustLevel.TRUST_PHYSICAL
            IntroductionMethod.REMOTE   -> TrustLevel.TRUST_INTRODUCED
        }
        TrustLevel.TRUST_INTRODUCED,
        TrustLevel.TRUST_PUBLIC -> TrustLevel.TRUST_PUBLIC  // cap enforced
    }

    // ── Equality ──────────────────────────────────────────────────────────

    override fun equals(other: Any?) = other is TrustCredential &&
        nodeId.contentEquals(other.nodeId) &&
        trustLevel == other.trustLevel &&
        issuedAtMs == other.issuedAtMs
    override fun hashCode(): Int {
        var r = nodeId.contentHashCode()
        r = 31 * r + trustLevel.hashCode()
        r = 31 * r + issuedAtMs.hashCode()
        return r
    }

    companion object {
        const val VERSION: Byte = 2
        private val ZEROS_32 = ByteArray(32)

        fun fromBytes(bytes: ByteArray): TrustCredential {
            require(bytes.size >= HEADER_BYTES) {
                "TrustCredential: too short — ${bytes.size} bytes"
            }
            var off = 0
            val version      = bytes[off++]
            val trustLevel   = TrustLevel.fromWire(bytes[off++])
            val attestation  = if (version.toInt() and 0xFF >= 2)
                CredentialAttestation.fromWire(bytes[off++])
            else
                CredentialAttestation.NONE                       // v1 had no attestation byte
            require(bytes.size >= off + 32 + 32 + 8 + 4) { "TrustCredential: truncated header" }
            val nodeId       = bytes.copyOfRange(off, off + 32); off += 32
            val introducerId = bytes.copyOfRange(off, off + 32); off += 32
            val issuedAtMs   = bytesToLong(bytes, off); off += 8
            // Range-check issuedAtMs so a freshly-minted credential claiming to be years old
            // cannot game the age-based reputation tier. An honest issuer's timestamp is within
            // a reasonable clock-skew window of the current time.
            // Lower bound: credentials pre-dating 2024-01-01 are implausible (project didn't exist).
            // Upper bound: credentials claiming future issue times are invalid.
            val nowMs = System.currentTimeMillis()
            require(issuedAtMs >= MIN_ISSUED_AT_MS) {
                "TrustCredential: issuedAtMs predates the project epoch ($issuedAtMs < $MIN_ISSUED_AT_MS)"
            }
            require(issuedAtMs <= nowMs + MAX_CLOCK_SKEW_MS) {
                "TrustCredential: issuedAtMs is in the future ($issuedAtMs > $nowMs + $MAX_CLOCK_SKEW_MS)"
            }
            val sigLen       = fourBytesToInt(bytes, off); off += 4
            require(sigLen >= 0) { "TrustCredential: negative signature length ($sigLen)" }
            require(bytes.size == off + sigLen) {
                "TrustCredential: wrong total length — expected ${off + sigLen}, got ${bytes.size}"
            }
            val signature = bytes.copyOfRange(off, off + sigLen)
            return TrustCredential(version, trustLevel, nodeId, introducerId, issuedAtMs, signature, attestation)
        }

        /** Minimum bytes before the variable-length signature (v1 layout — a safe lower bound). */
        private const val HEADER_BYTES = 1 + 1 + 32 + 32 + 8 + 4

        /**
         * Domain-separation prefix prepended to [signedPayload] before signing/verifying.
         * Prevents cross-protocol signature confusion with SignedContact and NodeCallsign
         * payloads that are also signed with the same HybridSigningKey type.
         * The trailing 0x00 byte guards against prefix extension attacks.
         */
        private val DOMAIN_PREFIX = "shadowmesh_trustcred ".toByteArray(Charsets.UTF_8)

        /** Earliest plausible issuedAtMs (2024-01-01 00:00:00 UTC). */
        private const val MIN_ISSUED_AT_MS = 1_704_067_200_000L

        /** Maximum allowed future clock skew for issuedAtMs (5 minutes). */
        private const val MAX_CLOCK_SKEW_MS = 5L * 60 * 1000

        fun selfIssued(nodeId: ByteArray): TrustCredential.Unsigned =
            TrustCredential.Unsigned(TrustLevel.TRUST_PUBLIC, nodeId, ZEROS_32.copyOf())

        fun physical(nodeId: ByteArray, introducerNodeId: ByteArray): TrustCredential.Unsigned =
            TrustCredential.Unsigned(TrustLevel.TRUST_PHYSICAL, nodeId, introducerNodeId)

        /**
         * TRUST_PHYSICAL credential that durably records the hardware-attestation tier
         * verified at bootstrap. Use this (not [physical]) when a bootstrap produced an
         * [AttestationTrustLevel] — see AttestedPhysicalExchange.toCredentialAttestation().
         */
        fun physicalAttested(
            nodeId:           ByteArray,
            introducerNodeId: ByteArray,
            attestation:      CredentialAttestation
        ): TrustCredential.Unsigned =
            TrustCredential.Unsigned(
                TrustLevel.TRUST_PHYSICAL, nodeId, introducerNodeId, attestation = attestation
            )

        fun introduced(nodeId: ByteArray, introducerNodeId: ByteArray): TrustCredential.Unsigned =
            TrustCredential.Unsigned(TrustLevel.TRUST_INTRODUCED, nodeId, introducerNodeId)
    }

    /** Unsigned builder — sign via TrustCredentialSigner. */
    data class Unsigned(
        val trustLevel:       TrustLevel,
        val nodeId:           ByteArray,
        val introducerNodeId: ByteArray,
        val issuedAtMs:       Long = System.currentTimeMillis(),
        val attestation:      CredentialAttestation = CredentialAttestation.NONE
    ) {
        fun payload(): ByteArray {
            val head = if (VERSION.toInt() and 0xFF >= 2)
                byteArrayOf(VERSION, trustLevel.wire, attestation.wire)
            else
                byteArrayOf(VERSION, trustLevel.wire)
            return head + nodeId + introducerNodeId + longToBytes(issuedAtMs)
        }
    }
}

enum class TrustLevel(val wire: Byte) {
    TRUST_PHYSICAL(0),
    TRUST_INTRODUCED(1),
    TRUST_PUBLIC(2);

    companion object {
        fun fromWire(b: Byte) = values().firstOrNull { it.wire == b }
            ?: throw IllegalArgumentException("Unknown TrustLevel wire byte: $b")
    }
}

enum class IntroductionMethod { PHYSICAL, REMOTE }

/**
 * Durable, signed record of the hardware-attestation tier a node achieved at bootstrap.
 *
 * Lives in core/crypto (the JVM base layer) so [TrustCredential] can carry it without a
 * dependency on core/attestation, which would create a crypto ↔ attestation cycle. The
 * attestation layer maps its runtime AttestationTrustLevel onto this via
 * AttestedPhysicalExchange.toCredentialAttestation() at credential-issuance time.
 */
enum class CredentialAttestation(val wire: Byte) {
    NONE(0),                // no hardware attestation verified (or legacy v1 credential)
    HARDWARE_VERIFIED(1),   // VERIFIED boot state, TEE-backed
    HARDWARE_STRONGBOX(2),  // VERIFIED boot state, StrongBox-backed (strongest)
    HARDWARE_CUSTOM_OS(3);  // SELF_SIGNED boot state (GrapheneOS/CalyxOS), hardware-rooted

    companion object {
        fun fromWire(b: Byte) = values().firstOrNull { it.wire == b }
            ?: throw IllegalArgumentException("Unknown CredentialAttestation wire byte: $b")
    }
}

// ── Signer helper ─────────────────────────────────────────────────────────────

class TrustCredentialSigner(private val signer: HybridSigner) {

    /**
     * Sign an unsigned credential with the introducer's signing key.
     * The introducer must be the node whose nodeId matches [introducerNodeId],
     * and must hold TRUST_PHYSICAL for physical introductions.
     */
    suspend fun sign(
        unsigned:         TrustCredential.Unsigned,
        introducerPrivKey:HybridSigningKey
    ): CryptoResult<TrustCredential> = cryptoRunCatching {
        val sig = signer.sign(unsigned.payload(), introducerPrivKey).getOrThrow()
        TrustCredential(
            version          = TrustCredential.VERSION,
            trustLevel       = unsigned.trustLevel,
            nodeId           = unsigned.nodeId,
            introducerNodeId = unsigned.introducerNodeId,
            issuedAtMs       = unsigned.issuedAtMs,
            signature        = sig,
            attestation      = unsigned.attestation
        )
    }

    /**
     * Verify a credential's signature using the introducer's public verify key.
     * Returns Success(true) if both signature and nodeId are valid.
     */
    suspend fun verify(
        credential:           TrustCredential,
        introducerVerifyKey:  HybridVerifyKey
    ): CryptoResult<Boolean> = cryptoRunCatching {
        signer.verify(
            message   = credential.signedPayload(),
            signature = credential.signature,
            publicKey = introducerVerifyKey
        ).getOrThrow()
    }
}

// ── Long ↔ ByteArray helpers (package-internal) ───────────────────────────────

internal fun longToBytes(v: Long): ByteArray = ByteArray(8) { i ->
    ((v shr ((7 - i) * 8)) and 0xFF).toByte()
}

internal fun bytesToLong(b: ByteArray, off: Int): Long {
    var result = 0L
    for (i in 0..7) result = (result shl 8) or (b[off + i].toLong() and 0xFF)
    return result
}

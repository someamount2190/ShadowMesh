package mesh.shadowmesh.bootstrap.nfc

import mesh.shadowmesh.bootstrap.QrIntroductionCode
import mesh.shadowmesh.crypto.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap

/**
 * NFC challenge-response handshake — mandatory second factor for TRUST_PHYSICAL.
 *
 * ## The relay-attack problem this solves
 *
 * The existing [buildQrIntroductionCode] / [receiveQrCode] flow is vulnerable to an
 * online relay attack: an attacker who photographs Device A's QR code, or intercepts
 * it in transit (screenshot, man-in-the-middle on screen sharing), can present it to
 * Device B and receive a TRUST_PHYSICAL credential without being physically near A.
 *
 * This is the core structural weakness of QR-only physical trust: QR codes are
 * optically readable at any distance, are easily screenshotted, and have no binding to
 * the physical location of the device that generated them.
 *
 * ## How NFC closes the gap
 *
 * NFC operates at ≤4 cm. Unlike QR, it cannot be relayed optically or digitally in a
 * way that preserves the physical proximity requirement — you must literally touch the
 * two devices together. Any relay adds latency measurable against the [NFC_MAX_ROUND_TRIP_MS]
 * timeout (500 ms); legitimate NFC completes in 50–200 ms.
 *
 * The QR code becomes an *invitation*, not a trust grant. The NFC step is mandatory.
 *
 * ## Protocol (6 steps as designed)
 *
 * ```
 * Device A (initiator, QR generator)       Device B (responder, QR scanner)
 * ─────────────────────────────────────    ─────────────────────────────────
 * 1. buildQrCode() → QR displayed          ─────────────────────────────────
 *    QR contains: nodeIdA, ed25519PubA,    2. scanQrCode() → nonce extracted
 *                 nonce_A (challenge)      ─────────────────────────────────
 *                                          3. Phones tapped together (NFC)
 * ─────────────────────────────────────    ─────────────────────────────────
 * 4a. A receives NfcChallengeMessage        4b. B sends NfcChallengeMessage:
 *     from B:                                   nodeIdB, ed25519PubB,
 *     - nodeIdB, ed25519PubB                    nonce_B (B's challenge),
 *     - nonce_B (B's challenge)                 response_to_A: Sign_B(nonce_A)
 *     - response_to_A: Sign_B(nonce_A)
 * ─────────────────────────────────────    ─────────────────────────────────
 * 5a. A verifies Sign_B(nonce_A)            5b. A sends NfcChallengeMessage:
 *     then sends NfcResponseMessage:            nodeIdA, ed25519PubA,
 *     response_to_B: Sign_A(nonce_B)            nonce_A (A's challenge),
 *                                               response_to_B: Sign_A(nonce_B)
 * ─────────────────────────────────────    ─────────────────────────────────
 *                                          6b. B verifies Sign_A(nonce_B)
 * ─────────────────────────────────────    ─────────────────────────────────
 * 7. Both: issue TRUST_PHYSICAL credential for the other
 * ```
 *
 * ## What each message proves
 *
 * - `Sign_B(nonce_A)`: B has A's nonce (obtained from A's QR), and B can sign with
 *   the key that corresponds to nodeIdB — same device that will receive TRUST_PHYSICAL.
 * - `Sign_A(nonce_B)`: A has B's nonce (obtained from B's NFC message), and A can sign
 *   with the key that corresponds to nodeIdA — same device that generated the QR.
 * - Together: mutual authentication. Neither device can be impersonated by a relay
 *   because the relay would need to sign the challenges in real-time while physically
 *   at the 4cm NFC range — defeating the purpose of relay.
 *
 * ## Timing bound
 *
 * [NFC_MAX_ROUND_TRIP_MS] (500 ms) is enforced at both ends. The [NfcChallengeMessage]
 * carries [sentAtMs] which is checked against the receiver's clock on arrival. A relay
 * that forwards the message over the internet (adding ~100–500 ms) fails this check.
 * Combined with NFC's physical proximity requirement, this makes relay impractical.
 *
 * ## Session key (optional step 5, [buildSessionKey])
 *
 * After mutual authentication, both devices derive a shared 32-byte session key via:
 *   session_key = HKDF(IKM = nonce_A || nonce_B || shared_kem_secret,
 *                      salt = nodeIdA || nodeIdB,
 *                      info = "shadowmesh_nfc_session_v1")
 * This provides an authenticated, forward-secret channel for the remainder of the
 * NFC session (e.g., to exchange the full [ExchangePayload] if the peer is not yet
 * in the DHT). The session key is ephemeral — it is never persisted.
 *
 * ## NFC transport abstraction
 *
 * This file is transport-agnostic. The actual Android NFC APIs
 * (`NfcAdapter`, `IsoDep`, HCE/NDEF tag emulation) live in the Android
 * platform layer — see [NfcTransport]. This keeps the protocol logic fully
 * unit-testable without an NFC-capable device.
 *
 * ## Fallback
 *
 * Devices without NFC fall back to BLE proximity ([NfcFallback.BLE_PROXIMITY]) or
 * QR-only ([NfcFallback.QR_ONLY_DEGRADED]). Both fallbacks are handled by
 * [NfcBootstrapCoordinator.completeFallbackAsResponder]: the responder earns a credential
 * ([BootstrapTrustLevel.TRUST_PHYSICAL_BLE] or [TRUST_INTRODUCED_QR_ONLY]) from the QR code
 * alone; the initiator cannot complete without an NFC or BLE back-channel.
 *
 * ## Integration with hardware attestation
 *
 * The [NfcChallengeMessage] has an optional [attestationEvidence] field. When populated,
 * the receiver calls [HardwareAttestation.verifyAttestationChain] with the QR nonce as
 * the challenge. This makes the NFC handshake simultaneously prove physical presence AND
 * hardware integrity — a TRUST_PHYSICAL_ATTESTED credential.
 *
 * Thread-safety: [usedQrNonces] is a ConcurrentHashMap — safe on any thread.
 * The class is nearly stateless; the only mutable state tracks consumed QR nonces.
 */
class NfcHandshake(
    private val signer: HybridSigner,
    private val hkdf:   Hkdf = Hkdf.instance
) {
    /**
     * QR nonces that have been consumed by a completed handshake.
     *
     * A QR code nonce is single-use. Once Device A's [verifyAndRespond] succeeds for a given
     * nonce, that nonce is added here. Subsequent handshake attempts using the same nonce
     * (e.g. from an attacker who photographed the QR and presents it to another device) are
     * rejected with [SecurityException] even if the Ed25519 signature is valid.
     *
     * Maps: nonce hex → time consumed (ms). Pruned by [pruneUsedNonces].
     */
    private val usedQrNonces = ConcurrentHashMap<String, Long>()

    /** Prune nonce entries older than [NONCE_PRUNE_MS]. Call from periodic maintenance. */
    fun pruneUsedNonces(nowMs: Long = System.currentTimeMillis()) {
        usedQrNonces.entries.removeIf { nowMs - it.value > NONCE_PRUNE_MS }
    }

    // ── Step 4b: Responder builds initial NFC message ─────────────────────

    /**
     * Called by the QR scanner (Device B) when NFC contact is established.
     *
     * Produces an [NfcChallengeMessage] that:
     *   - Identifies B (nodeId + Ed25519 public key)
     *   - Carries B's own challenge nonce (nonce_B) for A to sign
     *   - Contains B's signed response to A's QR challenge (Sign_B(nonce_A))
     *
     * @param localIdentity     B's node identity.
     * @param localPrivateKey   B's signing key — used to sign nonce_A.
     * @param qrCode            The QR code B scanned from A. Contains nonce_A.
     * @param nowMs             Current time (injectable for testing).
     */
    suspend fun buildChallengeMessage(
        localIdentity:              NodePublicIdentity,
        localPrivateKey:            HybridSigningKey,
        qrCode:                     QrIntroductionCode,
        attestationEvidence:        ByteArray? = null,
        attestationChallengeForPeer: ByteArray? = null,
        nowMs:                      Long = System.currentTimeMillis()
    ): CryptoResult<NfcChallengeMessage> = withContext(Dispatchers.IO) {
        cryptoRunCatching {
            // B generates its own challenge nonce for A to sign.
            // SecureRandom ensures the nonce is non-deterministic — the previous HKDF-based
            // derivation (sha3_256(nowMs || nodeId || domain)) was predictable: two devices
            // with the same identity starting NFC at the same second would generate identical
            // nonce_B values, potentially causing session key collisions. SecureRandom provides
            // the required 128-bit entropy without this determinism risk.
            val nonce_B = ByteArray(NONCE_BYTES).also { SecureRandom().nextBytes(it) }

            // B signs A's nonce to prove: (1) B received A's QR, (2) B controls its signing key
            val responsePayload = RESPONSE_DOMAIN +
                qrCode.nonce +
                localIdentity.nodeId +
                longToBytes(nowMs)
            val signatureOverNonceA = signer.signEd25519Only(responsePayload, localPrivateKey).getOrThrow()

            NfcChallengeMessage(
                version                    = NFC_VERSION,
                sentAtMs                   = nowMs,
                nodeId                     = localIdentity.nodeId,
                ed25519PublicKey           = localIdentity.signingPublicKey.ed25519PublicKey,
                challengeNonce             = nonce_B,
                responseToNonce            = signatureOverNonceA,
                respondingToNonce          = qrCode.nonce,
                attestationEvidence        = attestationEvidence,
                attestationChallengeForPeer = attestationChallengeForPeer
            )
        }
    }

    // ── Step 5a: Initiator verifies B's message and builds its response ───

    /**
     * Called by the QR generator (Device A) after receiving B's [NfcChallengeMessage].
     *
     * Verifies that:
     *   1. B's message is fresh (within [NFC_MAX_ROUND_TRIP_MS]).
     *   2. B correctly signed A's QR nonce (proves B scanned the real QR and controls its key).
     *   3. B's nodeId matches the signing key in the message.
     *
     * If verification passes, returns an [NfcResponseMessage] containing:
     *   - A's signed response to B's challenge nonce (Sign_A(nonce_B))
     *   - A's identity (nodeId + ed25519 public key)
     *
     * @param localIdentity      A's node identity.
     * @param localPrivateKey    A's signing key.
     * @param localQrNonce       The nonce A embedded in its QR code (nonce_A).
     * @param peerMessage        The [NfcChallengeMessage] received from B.
     */
    suspend fun verifyAndRespond(
        localIdentity:    NodePublicIdentity,
        localPrivateKey:  HybridSigningKey,
        localQrNonce:     ByteArray,
        peerMessage:      NfcChallengeMessage,
        localAttestation: ByteArray? = null,    // A's TEE evidence to embed in the response
        nowMs:            Long = System.currentTimeMillis()
    ): CryptoResult<NfcHandshakeStep> = withContext(Dispatchers.IO) {
        cryptoRunCatching {
            // 1. Timing check — reject if outside NFC round-trip window.
            // Allow a negative age up to NFC_CLOCK_SKEW_GRACE_MS (2 s) so that a device
            // whose clock is slightly AHEAD of ours does not fail the check — legitimate
            // NFC taps complete in 50–200 ms, so a 2 s grace still blocks all relay attacks.
            // age < 0 means the sender's clock is ahead; rejecting any negative age would
            // fail users whose devices have uncorrected clock drift.
            val age = nowMs - peerMessage.sentAtMs
            if (age < -NFC_CLOCK_SKEW_GRACE_MS || age > NFC_MAX_ROUND_TRIP_MS) {
                throw SecurityException(
                    "NFC message outside timing window: age=${age}ms, limit=${NFC_MAX_ROUND_TRIP_MS}ms"
                )
            }

            // 2. QR nonce replay check — single-use enforcement.
            // A QR nonce that has already completed a handshake is rejected, even if the
            // Ed25519 signature is valid. This prevents an attacker who photographed Device A's
            // QR code from presenting it to Device B a second time to obtain a duplicate
            // TRUST_PHYSICAL credential.
            val nonceHex = localQrNonce.toHex()
            if (usedQrNonces.containsKey(nonceHex)) {
                throw SecurityException(
                    "QR nonce already used — this QR code has already completed a handshake. " +
                    "Generate a new QR code to introduce another contact."
                )
            }

            // 3. Verify that the peer signed our QR nonce correctly
            val expectedPayload = RESPONSE_DOMAIN +
                localQrNonce +
                peerMessage.nodeId +
                longToBytes(peerMessage.sentAtMs)
            val sigValid = signer.verifyEd25519Only(
                message   = expectedPayload,
                signature = peerMessage.responseToNonce,
                publicKey = peerMessage.ed25519PublicKey
            ).getOrThrow()
            if (!sigValid) {
                throw SecurityException("Peer did not correctly sign our QR nonce — relay attack or wrong key")
            }

            // Mark nonce as used AFTER signature verification — only consumed on success.
            usedQrNonces[nonceHex] = nowMs

            // Build A's response: Sign_A(nonce_B), with optional attestation evidence
            val responsePayload = RESPONSE_DOMAIN +
                peerMessage.challengeNonce +
                localIdentity.nodeId +
                longToBytes(nowMs)
            val signatureOverNonceB = signer.signEd25519Only(responsePayload, localPrivateKey).getOrThrow()

            NfcHandshakeStep.InitiatorResponse(
                NfcResponseMessage(
                    version              = NFC_VERSION,
                    sentAtMs             = nowMs,
                    nodeId               = localIdentity.nodeId,
                    ed25519PublicKey     = localIdentity.signingPublicKey.ed25519PublicKey,
                    responseToNonce      = signatureOverNonceB,
                    respondingToNonce    = peerMessage.challengeNonce,
                    attestationEvidence  = localAttestation    // may be null — B handles absence gracefully
                ),
                verifiedPeerNodeId     = peerMessage.nodeId,
                verifiedPeerEd25519Key = peerMessage.ed25519PublicKey
            )
        }
    }

    // ── Step 6b: Responder verifies A's response ──────────────────────────

    /**
     * Called by the QR scanner (Device B) after receiving A's [NfcResponseMessage].
     *
     * Verifies that:
     *   1. A's response is fresh.
     *   2. A correctly signed B's challenge nonce (Sign_A(nonce_B)).
     *   3. A's nodeId and Ed25519 key match what was in the QR code.
     *
     * If verification passes, returns [NfcHandshakeStep.HandshakeComplete] — both sides
     * may now issue [TrustCredential] at [BootstrapTrustLevel.TRUST_PHYSICAL_NFC].
     *
     * @param localChallengeNonce  The nonce_B B sent to A in the [NfcChallengeMessage].
     * @param peerResponse         The [NfcResponseMessage] received from A.
     * @param qrCode               The original QR code B scanned — used to cross-check A's identity.
     */
    suspend fun verifyResponse(
        localChallengeNonce: ByteArray,
        peerResponse:        NfcResponseMessage,
        qrCode:              QrIntroductionCode,
        nowMs:               Long = System.currentTimeMillis()
    ): CryptoResult<NfcHandshakeStep> = withContext(Dispatchers.IO) {
        cryptoRunCatching {
            // 1. Timing check — same grace window as the challenge check above.
            val age = nowMs - peerResponse.sentAtMs
            if (age < -NFC_CLOCK_SKEW_GRACE_MS || age > NFC_MAX_ROUND_TRIP_MS) {
                throw SecurityException(
                    "NFC response outside timing window: age=${age}ms"
                )
            }

            // 2. Cross-check: A's nodeId and Ed25519 key must match the QR code
            if (!peerResponse.nodeId.contentEquals(qrCode.nodeId)) {
                throw SecurityException(
                    "NFC response nodeId does not match QR code — different device or relay attack"
                )
            }
            if (!peerResponse.ed25519PublicKey.contentEquals(qrCode.ed25519PubKey)) {
                throw SecurityException(
                    "NFC response Ed25519 key does not match QR code"
                )
            }

            // 3. Verify A signed B's challenge nonce correctly
            val expectedPayload = RESPONSE_DOMAIN +
                localChallengeNonce +
                peerResponse.nodeId +
                longToBytes(peerResponse.sentAtMs)
            val sigValid = signer.verifyEd25519Only(
                message   = expectedPayload,
                signature = peerResponse.responseToNonce,
                publicKey = peerResponse.ed25519PublicKey
            ).getOrThrow()
            if (!sigValid) {
                throw SecurityException("Initiator did not correctly sign our challenge nonce")
            }

            NfcHandshakeStep.HandshakeComplete(
                verifiedPeerNodeId     = peerResponse.nodeId,
                verifiedPeerEd25519Key = peerResponse.ed25519PublicKey
            )
        }
    }

    // ── Optional step 5: session key derivation ───────────────────────────

    /**
     * Derive a 32-byte ephemeral session key after a completed handshake.
     *
     * Both devices derive the same key without a key agreement round-trip by using
     * the two challenge nonces as combined IKM. The key is symmetric and ephemeral —
     * it is never persisted and is only valid for this NFC session.
     *
     * session_key = HKDF(
     *   IKM  = nonce_A || nonce_B,
     *   salt = sort(nodeIdA, nodeIdB) concatenated (deterministic across both sides),
     *   info = "shadowmesh_nfc_session_v1"
     * )
     *
     * The sort is lexicographic so both devices independently compute the same order.
     *
     * @param nonceA       The nonce from A's QR code.
     * @param nonceB       The nonce from B's [NfcChallengeMessage].
     * @param localNodeId  This device's nodeId.
     * @param peerNodeId   The peer's nodeId (from the verified handshake).
     */
    fun buildSessionKey(
        nonceA:       ByteArray,
        nonceB:       ByteArray,
        localNodeId:  ByteArray,
        peerNodeId:   ByteArray
    ): ByteArray {
        // Defense-in-depth: reject an all-zero peerNodeId at the protocol layer,
        // not just in NfcBootstrapCoordinator.  An all-zero id used as the HKDF salt
        // weakens the identity-binding guarantee (both sides would derive the same salt
        // contribution regardless of which peer they're talking to).  The primary entropy
        // comes from the two nonces, but belt-and-suspenders rejection here ensures
        // that any caller that bypasses the coordinator's guard is also protected.
        require(peerNodeId.size == 32 && peerNodeId.any { it != 0.toByte() }) {
            "peerNodeId must be a verified 32-byte node identity, not an all-zero placeholder"
        }
        require(localNodeId.size == 32) {
            "localNodeId must be 32 bytes"
        }
        // Sort nodeIds lexicographically so both sides compute the same IKM
        val (nodeIdFirst, nodeIdSecond) = if (compareBytes(localNodeId, peerNodeId) <= 0)
            localNodeId to peerNodeId else peerNodeId to localNodeId

        return hkdf.derive(
            ikm       = nonceA + nonceB,
            salt      = nodeIdFirst + nodeIdSecond,
            info      = SESSION_KEY_DOMAIN,
            outputLen = 32
        )
    }

    // ── Helpers ───────────────────────────────────────────────────────────


    private fun compareBytes(a: ByteArray, b: ByteArray): Int {
        for (i in 0 until minOf(a.size, b.size)) {
            val diff = (a[i].toInt() and 0xFF) - (b[i].toInt() and 0xFF)
            if (diff != 0) return diff
        }
        return a.size - b.size
    }

    private fun longToBytes(v: Long): ByteArray = ByteArray(8) { i ->
        ((v shr ((7 - i) * 8)) and 0xFF).toByte()
    }

    companion object {
        const val NFC_VERSION          : Byte = 1
        const val NONCE_BYTES          : Int  = 32
        /**
         * Maximum round-trip time for NFC messages. Legitimate NFC completes in 50–200 ms.
         * A relay adding internet latency (~100–500 ms) will exceed this bound.
         *
         * Reduced from 500 ms to 250 ms: at 500 ms a relay with internet latency of
         * 100–200 ms still fit within the window. At 250 ms, legitimate slow devices
         * (200 ms worst-case) have a 50 ms margin while relay attacks requiring ≥ 100 ms
         * of added latency are reliably rejected. Field measurements on older Android
         * devices show 50–180 ms for genuine NFC exchanges.
         */
        const val NFC_MAX_ROUND_TRIP_MS: Long = 250L
        /** Allowed clock skew: the sender's clock may be up to this many ms AHEAD of ours. */
        const val NFC_CLOCK_SKEW_GRACE_MS: Long = 2_000L

        private val NONCE_DOMAIN_B     = "nfc_nonce_b_v1".toByteArray()
        private val RESPONSE_DOMAIN    = "nfc_response_v1".toByteArray()

        /**
         * How long consumed QR nonces are retained before pruning.
         * QR codes are typically valid for a session (minutes). Retaining for 24 hours
         * ensures a photographed QR code cannot be reused even after a device restart.
         * Pruned by [pruneUsedNonces] during periodic maintenance.
         */
        const val NONCE_PRUNE_MS: Long = 24 * 60 * 60 * 1000L  // 24 hours
        private val SESSION_KEY_DOMAIN = "shadowmesh_nfc_session_v1".toByteArray()
    }
}

// ── Wire types ────────────────────────────────────────────────────────────────

/**
 * Sent by the QR scanner (B) to the QR generator (A) over NFC at first contact.
 *
 * Wire format:
 *   [1B version][8B sentAtMs][32B nodeId][32B ed25519PubKey][32B challengeNonce]
 *   [4B sigLen][sig (responseToNonce)][32B respondingToNonce]
 *
 * Total: ~300 bytes (fits comfortably in a single NFC NDEF message or ISO-DEP APDU).
 */
data class NfcChallengeMessage(
    val version:                   Byte,
    val sentAtMs:                  Long,
    val nodeId:                    ByteArray,    // 32 bytes — B's identity
    val ed25519PublicKey:          ByteArray,    // 32 bytes — B's signing key (Ed25519 portion)
    val challengeNonce:            ByteArray,    // 32 bytes — nonce_B (for A to sign)
    val responseToNonce:           ByteArray,    // Sign_B(nonce_A || nodeId_B || sentAtMs)
    val respondingToNonce:         ByteArray,    // 32 bytes — the nonce_A this responds to
    /** Optional: B's hardware attestation evidence, bound to A's QR attestation challenge. */
    val attestationEvidence:       ByteArray? = null,
    /** Optional: B's challenge for A to attest against. A embeds this in its TEE key. */
    val attestationChallengeForPeer: ByteArray? = null
) {
    fun toBytes(): ByteArray {
        val fixed = byteArrayOf(version) +
            longToBytes(sentAtMs) +
            nodeId + ed25519PublicKey + challengeNonce +
            intTo4Bytes(responseToNonce.size) + responseToNonce +
            respondingToNonce
        // Optional attestation evidence: [4B len][bytes] — 0 length = absent
        val attEvBytes   = attestationEvidence ?: ByteArray(0)
        // Optional attestation challenge for peer: [4B len][bytes] — 0 length = absent
        val attChallBytes = attestationChallengeForPeer ?: ByteArray(0)
        return fixed +
               intTo4Bytes(attEvBytes.size)    + attEvBytes +
               intTo4Bytes(attChallBytes.size) + attChallBytes
    }

    companion object {
        fun fromBytes(bytes: ByteArray): NfcChallengeMessage {
            require(bytes.size >= 1 + 8 + 32 + 32 + 32 + 4) { "NfcChallengeMessage too short" }
            var off = 0
            val version  = bytes[off++]
            val sentAtMs = readLong(bytes, off); off += 8
            val nodeId   = bytes.copyOfRange(off, off + 32); off += 32
            val ed25519  = bytes.copyOfRange(off, off + 32); off += 32
            val nonce    = bytes.copyOfRange(off, off + 32); off += 32
            val sigLen   = readInt4(bytes, off); off += 4
            require(off + sigLen + 32 <= bytes.size) { "NfcChallengeMessage: truncated sig" }
            val sig       = bytes.copyOfRange(off, off + sigLen); off += sigLen
            val respNonce = bytes.copyOfRange(off, off + 32); off += 32
            // Optional attestation evidence
            val attestation = if (off + 4 <= bytes.size) {
                val attLen = readInt4(bytes, off); off += 4
                if (attLen > 0 && off + attLen <= bytes.size)
                    bytes.copyOfRange(off, off + attLen).also { off += attLen }
                else null
            } else null
            // Optional attestation challenge for peer
            val attestationChallenge = if (off + 4 <= bytes.size) {
                val challLen = readInt4(bytes, off); off += 4
                if (challLen > 0 && off + challLen <= bytes.size)
                    bytes.copyOfRange(off, off + challLen)
                else null
            } else null
            return NfcChallengeMessage(
                version, sentAtMs, nodeId, ed25519, nonce, sig, respNonce,
                attestation, attestationChallenge
            )
        }
    }

    override fun equals(other: Any?) = other is NfcChallengeMessage &&
        nodeId.contentEquals(other.nodeId) && sentAtMs == other.sentAtMs
    override fun hashCode() = 31 * nodeId.contentHashCode() + sentAtMs.hashCode()
}

/**
 * Sent by the QR generator (A) to the QR scanner (B) over NFC in response.
 *
 * Wire format:
 *   [1B version][8B sentAtMs][32B nodeId][32B ed25519PubKey]
 *   [4B sigLen][sig (responseToNonce)][32B respondingToNonce]
 */
data class NfcResponseMessage(
    val version:             Byte,
    val sentAtMs:            Long,
    val nodeId:              ByteArray,   // 32 bytes — A's identity (matches QR code)
    val ed25519PublicKey:    ByteArray,   // 32 bytes — A's signing key (matches QR code)
    val responseToNonce:     ByteArray,   // Sign_A(nonce_B || nodeId_A || sentAtMs)
    val respondingToNonce:   ByteArray,   // 32 bytes — the nonce_B this responds to
    /** Optional: A's hardware attestation evidence, bound to B's attestationChallengeForPeer. */
    val attestationEvidence: ByteArray? = null
) {
    fun toBytes(): ByteArray {
        val fixed = byteArrayOf(version) +
            longToBytes(sentAtMs) +
            nodeId + ed25519PublicKey +
            intTo4Bytes(responseToNonce.size) + responseToNonce +
            respondingToNonce
        val attBytes = attestationEvidence ?: ByteArray(0)
        return fixed + intTo4Bytes(attBytes.size) + attBytes
    }

    companion object {
        fun fromBytes(bytes: ByteArray): NfcResponseMessage {
            require(bytes.size >= 1 + 8 + 32 + 32 + 4) { "NfcResponseMessage too short" }
            var off = 0
            val version  = bytes[off++]
            val sentAtMs = readLong(bytes, off); off += 8
            val nodeId   = bytes.copyOfRange(off, off + 32); off += 32
            val ed25519  = bytes.copyOfRange(off, off + 32); off += 32
            val sigLen   = readInt4(bytes, off); off += 4
            require(off + sigLen + 32 <= bytes.size) { "NfcResponseMessage: truncated" }
            val sig       = bytes.copyOfRange(off, off + sigLen); off += sigLen
            val respNonce = bytes.copyOfRange(off, off + 32); off += 32
            // Optional attestation evidence
            val attestation = if (off + 4 <= bytes.size) {
                val attLen = readInt4(bytes, off); off += 4
                if (attLen > 0 && off + attLen <= bytes.size)
                    bytes.copyOfRange(off, off + attLen)
                else null
            } else null
            return NfcResponseMessage(version, sentAtMs, nodeId, ed25519, sig, respNonce, attestation)
        }
    }

    override fun equals(other: Any?) = other is NfcResponseMessage &&
        nodeId.contentEquals(other.nodeId) && sentAtMs == other.sentAtMs
    override fun hashCode() = 31 * nodeId.contentHashCode() + sentAtMs.hashCode()
}

/** Discriminated union returned from [NfcHandshake] steps. */
sealed class NfcHandshakeStep {
    /** Returned from [NfcHandshake.verifyAndRespond] — A verified B, here is A's response. */
    data class InitiatorResponse(
        val message:             NfcResponseMessage,
        val verifiedPeerNodeId:  ByteArray,
        val verifiedPeerEd25519Key: ByteArray
    ) : NfcHandshakeStep()

    /** Returned from [NfcHandshake.verifyResponse] — B verified A. Handshake complete. */
    data class HandshakeComplete(
        val verifiedPeerNodeId:     ByteArray,
        val verifiedPeerEd25519Key: ByteArray
    ) : NfcHandshakeStep()
}

/**
 * Trust level earned from a *completed* bootstrap.
 *
 * All four outcomes are reachable:
 *   NFC path (via NfcBootstrapCoordinator.onNfcChallengeReceived / onHceApduReceived):
 *     [TRUST_PHYSICAL_NFC]      — full NFC challenge-response completed
 *     [TRUST_PHYSICAL_ATTESTED] — NFC + hardware attestation verified
 *   Fallback path (via NfcBootstrapCoordinator.completeFallbackAsResponder):
 *     [TRUST_PHYSICAL_BLE]      — BLE proximity signal detected (NFC unavailable)
 *     [TRUST_INTRODUCED_QR_ONLY]— QR-only; NFC and BLE both unavailable
 */
enum class BootstrapTrustLevel {
    /** Full NFC challenge-response completed — strongest TRUST_PHYSICAL. */
    TRUST_PHYSICAL_NFC,
    /** NFC + hardware attestation verified — highest tier. */
    TRUST_PHYSICAL_ATTESTED,
    /**
     * BLE signal-strength proximity verified (NFC unavailable). Grants TRUST_PHYSICAL because
     * the <1m RSSI threshold provides meaningful physical co-location evidence. Lower assurance
     * than NFC (RSSI can be manipulated at moderate cost) but materially stronger than QR-only.
     */
    TRUST_PHYSICAL_BLE,
    /**
     * QR-only exchange — NFC and BLE both unavailable. No physical proximity verification.
     * Grants TRUST_INTRODUCED: the contact is authenticated (we have their public key) but
     * we cannot confirm they were physically present at the exchange. Only the QR scanner
     * (responder) obtains this level; the QR generator (initiator) cannot complete without
     * an NFC or BLE back-channel from the responder.
     */
    TRUST_INTRODUCED_QR_ONLY
}

/** Whether NFC is available and what fallback to use if not. */
enum class NfcFallback {
    /** NFC available — use it. */
    NFC_AVAILABLE,
    /** No NFC hardware — fall back to BLE signal-strength proximity check. */
    BLE_PROXIMITY,
    /** Neither NFC nor BLE — QR-only with explicit UI warning. */
    QR_ONLY_DEGRADED
}

private fun longToBytes(v: Long): ByteArray = ByteArray(8) { i ->
    ((v shr ((7 - i) * 8)) and 0xFF).toByte()
}
private fun readLong(b: ByteArray, off: Int): Long {
    var r = 0L
    for (i in 0..7) r = (r shl 8) or (b[off + i].toLong() and 0xFF)
    return r
}

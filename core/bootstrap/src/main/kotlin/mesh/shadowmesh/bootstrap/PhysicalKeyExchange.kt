package mesh.shadowmesh.bootstrap

import mesh.shadowmesh.crypto.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.crypto.intTo4Bytes
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer

/**
 * Persistent nonce store for bootstrap replay prevention.
 *
 * [PhysicalKeyExchange] calls [isUsed] before accepting a QR code or NFC payload.
 * If [isUsed] returns true, the exchange is rejected — the nonce was already consumed
 * in a previous session. [markUsed] records the nonce so it survives process restart.
 *
 * Provide an implementation backed by [ShadowMeshDao] (core:storage) in production.
 * An in-memory implementation is acceptable in tests where replay across restarts
 * is not the concern under test.
 *
 * Nonce retention: implementations should retain nonces for at least
 * [PhysicalKeyExchange.PAYLOAD_VALIDITY_MS] × 2 (10 minutes) and sweep expired
 * entries periodically.
 */
interface NonceStore {
    /** Returns true if [nonceHex] was already consumed in a prior session. */
    suspend fun isUsed(nonceHex: String): Boolean

    /** Record [nonceHex] as consumed. [seenAtMs] is the acceptance wall-clock time. */
    suspend fun markUsed(nonceHex: String, seenAtMs: Long)
}

/** In-memory [NonceStore] — for use in tests only. Does not survive process restart. */
class InMemoryNonceStore : NonceStore {
    private val seen = java.util.concurrent.ConcurrentHashMap.newKeySet<String>()
    override suspend fun isUsed(nonceHex: String): Boolean = seen.contains(nonceHex)
    override suspend fun markUsed(nonceHex: String, seenAtMs: Long) { seen.add(nonceHex) }
}

/**
 * Physical key exchange — design doc §3.2, Tier A.
 *
 * Bootstraps TRUST_PHYSICAL by physically co-locating two devices and exchanging
 * a signed [ExchangePayload] via QR code, NFC, or Bluetooth.
 *
 * Exchange payload wire format:
 *   [1B version][8B issuedAtMs][NodePublicIdentity bytes][HybridSigner signature]
 *
 * The signature covers everything before it: version + timestamp + identity bytes.
 * This prevents any peer from reusing a captured payload to spoof a different identity.
 *
 * QR vs NFC/BT capacity:
 *   Full payload is ~5 KB (Dilithium public key is large). This exceeds QR capacity.
 *   [buildQrIntroductionCode] produces a compact ~400-byte QR code containing only
 *   the nodeId + Ed25519 public key + a short-lived nonce. The receiving device
 *   then fetches the full [NodePublicIdentity] from the mesh DHT using the nodeId.
 *   NFC/BT can carry the full payload in one transfer.
 *
 * Replay window: payloads are valid for [PAYLOAD_VALIDITY_MS] (5 minutes).
 *   [receivePayload] rejects anything outside this window.
 *   Both devices must have reasonably synchronised clocks (±2 minutes is fine).
 *
 * Thread-safety: all operations dispatched to Dispatchers.IO.
 */
class PhysicalKeyExchange(
    private val signer:     HybridSigner,
    private val hkdf:       Hkdf = Hkdf.instance,
    /**
     * Persisted nonce store for replay prevention.
     *
     * Defaults to [InMemoryNonceStore] so existing callers compile without change.
     * Production code MUST inject a [NonceStore] backed by [ShadowMeshDao] so that
     * a QR code captured before a process restart cannot be replayed within the
     * 5-minute validity window.
     */
    private val nonceStore: NonceStore = InMemoryNonceStore()
) {

    // ── Build ─────────────────────────────────────────────────────────────

    /**
     * Build a signed exchange payload for NFC or Bluetooth transfer (~5 KB).
     * [identity] is the local node's complete identity.
     * [privateKey] is the local node's signing key — used to sign the payload.
     */
    suspend fun buildPayload(
        identity:   NodePublicIdentity,
        privateKey: HybridSigningKey,
        nowMs:      Long = System.currentTimeMillis()
    ): CryptoResult<ExchangePayload> = withContext(Dispatchers.IO) {
        cryptoRunCatching {
            val identityBytes = identity.toBytes()
            val header        = byteArrayOf(VERSION) + longToBytes(nowMs) + identityBytes
            val signature     = signer.sign(header, privateKey).getOrThrow()

            ExchangePayload(
                version       = VERSION,
                issuedAtMs    = nowMs,
                identity      = identity,
                signature     = signature,
                identityBytes = identityBytes
            )
        }
    }

    /**
     * Parse and verify a received exchange payload (NFC/BT full payload).
     *
     * Verifies:
     *   1. Signature is valid for the claimed identity's signing key.
     *   2. nodeId in the payload matches the public keys (tamper check).
     *   3. Payload is within the [PAYLOAD_VALIDITY_MS] replay window.
     *
     * @return [CryptoResult.Success] with the verified [NodePublicIdentity] on success.
     *         [CryptoResult.Failure] with a reason string on any failure.
     */
    suspend fun receivePayload(
        payloadBytes: ByteArray,
        nowMs:        Long = System.currentTimeMillis()
    ): CryptoResult<NodePublicIdentity> = withContext(Dispatchers.IO) {
        cryptoRunCatching {
            val payload = ExchangePayload.fromBytes(payloadBytes, hkdf)

            // Freshness check — reject outside replay window
            val age = nowMs - payload.issuedAtMs
            if (age < -CLOCK_SKEW_TOLERANCE_MS || age > PAYLOAD_VALIDITY_MS) {
                throw SecurityException(
                    "Exchange payload outside validity window: age=${age}ms, " +
                    "limit=${PAYLOAD_VALIDITY_MS}ms"
                )
            }

            // Verify signature — covers version + timestamp + identity bytes
            val header = byteArrayOf(payload.version) +
                         longToBytes(payload.issuedAtMs) +
                         payload.identityBytes
            val valid = signer.verify(
                message   = header,
                signature = payload.signature,
                publicKey = payload.identity.signingPublicKey
            ).getOrThrow()

            if (!valid) throw SecurityException("Exchange payload signature invalid")

            payload.identity
        }
    }

    // ── QR compact code ───────────────────────────────────────────────────

    /**
     * Build a compact QR introduction code (~400 bytes) that fits within QR capacity.
     *
     * Contains:
     *   [1B version][8B issuedAtMs][32B nodeId][32B Ed25519 public key][8B nonce]
     *   [Ed25519 detached signature over all the above — 64 bytes]
     *
     * Total: ~145 bytes binary — fits comfortably in a QR code at error correction L.
     *
     * The receiver uses the nodeId to fetch the full [NodePublicIdentity] (including
     * Kyber/Dilithium keys) from the mesh DHT, then verifies using [receiveQrCode].
     * The Ed25519-only signature here is sufficient for the short-lived QR exchange;
     * the full Dilithium verification happens after DHT fetch.
     */
    suspend fun buildQrIntroductionCode(
        identity:   NodePublicIdentity,
        privateKey: HybridSigningKey,
        nowMs:      Long = System.currentTimeMillis()
    ): CryptoResult<QrIntroductionCode> = withContext(Dispatchers.IO) {
        cryptoRunCatching {
            // SecureRandom nonce rather than HKDF(nowMs + nodeId): the HKDF nonce was
            // deterministic — two QR codes built by the same node at the same millisecond
            // would have identical nonces. Both would be accepted (first use) but one would
            // then block the other (replay detection). More importantly, a deterministic nonce
            // leaks the builder's nodeId to anyone who knows the timestamp, undermining the
            // "who scanned this code" ambiguity property. SecureRandom output is unguessable
            // and unique even if the clock does not advance between calls.
            val nonce = ByteArray(8).also { java.security.SecureRandom().nextBytes(it) }

            // 32-byte attestation challenge for the responder (B) to embed in its TEE key.
            // B's attestation chain will be bound to this value, proving freshness and
            // preventing replay of a previously-captured attestation evidence.
            // Generated with SecureRandom — same source as HardwareAttestation.generateChallenge().
            val attestationChallenge = ByteArray(ATTESTATION_CHALLENGE_BYTES)
                .also { java.security.SecureRandom().nextBytes(it) }

            // Signed payload includes the attestation challenge so it cannot be swapped
            // by an attacker without invalidating the Ed25519 signature.
            val payload = byteArrayOf(QR_VERSION) +
                          longToBytes(nowMs)        +
                          identity.nodeId           +      // 32 bytes
                          identity.signingPublicKey.ed25519PublicKey + // 32 bytes
                          nonce                    +       // 8 bytes
                          attestationChallenge              // 32 bytes — NEW

            // Ed25519-only signature for QR compactness (Dilithium would add ~3 KB).
            // Full hybrid verification occurs after DHT fetch of the complete identity.
            val lazySodiumSig = signEd25519Detached(payload, privateKey.ed25519PrivateKey)

            QrIntroductionCode(
                version              = QR_VERSION,
                issuedAtMs           = nowMs,
                nodeId               = identity.nodeId,
                ed25519PubKey        = identity.signingPublicKey.ed25519PublicKey,
                nonce                = nonce,
                attestationChallenge = attestationChallenge,   // NEW
                signature            = lazySodiumSig,
                rawBytes             = payload + lazySodiumSig
            )
        }
    }

    /**
     * Verify a QR introduction code received from a peer.
     * The returned [QrIntroductionCode] contains the nodeId — use it to fetch
     * the full [NodePublicIdentity] from the DHT, then call [receivePayload] or
     * verify the full identity separately.
     */
    suspend fun receiveQrCode(
        codeBytes: ByteArray,
        nowMs:     Long = System.currentTimeMillis()
    ): CryptoResult<QrIntroductionCode> = withContext(Dispatchers.IO) {
        cryptoRunCatching {
            val code = QrIntroductionCode.fromBytes(codeBytes)

            val age = nowMs - code.issuedAtMs
            if (age < -CLOCK_SKEW_TOLERANCE_MS || age > PAYLOAD_VALIDITY_MS) {
                throw SecurityException("QR code outside validity window: age=${age}ms")
            }

            val payload = codeBytes.copyOfRange(0, codeBytes.size - ED25519_SIG_BYTES)
            val valid   = verifyEd25519Detached(payload, code.signature, code.ed25519PubKey)
            if (!valid) throw SecurityException("QR introduction code signature invalid")

            // Replay check — reject a nonce that was already accepted in a prior session.
            // The timestamp freshness check above only guards against replays within the
            // current process lifetime. Persisting the nonce in NonceStore ensures that
            // a QR code captured just before a crash cannot be replayed after restart
            // while still within the 5-minute validity window.
            val nonceHex = code.nonce.toHex()
            if (nonceStore.isUsed(nonceHex)) {
                throw SecurityException(
                    "QR code nonce already consumed — possible replay attack"
                )
            }
            nonceStore.markUsed(nonceHex, nowMs)

            code
        }
    }

    // ── Ed25519 helpers (pure — no Android dependency) ────────────────────

    private fun signEd25519Detached(message: ByteArray, privateKey: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(privateKey, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    private fun verifyEd25519Detached(
        message:   ByteArray,
        signature: ByteArray,
        publicKey: ByteArray
    ): Boolean {
        return try {
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(publicKey, 0))
            verifier.update(message, 0, message.size)
            verifier.verifySignature(signature)
        } catch (_: Exception) {
            false
        }
    }

    companion object {
        const val VERSION                 : Byte = 1
        const val QR_VERSION              : Byte = 1
        const val PAYLOAD_VALIDITY_MS     : Long = 5 * 60 * 1000L   // 5 minutes
        const val CLOCK_SKEW_TOLERANCE_MS : Long = 2 * 60 * 1000L   // 2 minutes
        const val ED25519_SIG_BYTES       : Int  = 64
        const val ATTESTATION_CHALLENGE_BYTES: Int = 32  // must match HardwareAttestation.CHALLENGE_BYTES
    }
}

// ── Wire types ────────────────────────────────────────────────────────────────

/**
 * Full exchange payload for NFC/BT (~5 KB). Contains complete hybrid public keys.
 */
data class ExchangePayload(
    val version:       Byte,
    val issuedAtMs:    Long,
    val identity:      NodePublicIdentity,
    val signature:     ByteArray,
    val identityBytes: ByteArray          // cached to avoid re-serialisation during verify
) {
    fun toBytes(): ByteArray {
        val header = byteArrayOf(version) + longToBytes(issuedAtMs) + identityBytes
        return header + intTo4Bytes(signature.size) + signature
    }

    companion object {
        fun fromBytes(bytes: ByteArray, hkdf: Hkdf = Hkdf.instance): ExchangePayload {
            require(bytes.size >= 1 + 8 + 4) { "ExchangePayload: too short (${bytes.size})" }
            var off     = 0
            val version = bytes[off++]
            val issuedAtMs = bytesToLong(bytes, off); off += 8

            // Parse NodePublicIdentity: starts at off, variable length
            // We parse it from the remaining bytes minus the trailing signature
            // Signature length is encoded 4 bytes before the signature
            require(bytes.size >= off + 4) { "ExchangePayload: truncated before identity" }
            // Find sig length from end: last 4+sigLen bytes
            // Identity ends where signature length prefix begins.
            // Walk from the end: [4B sigLen][sig]
            // The identity bytes occupy [off .. totalLen - 4 - sigLen)
            val totalLen  = bytes.size
            // Read sigLen from the last chunk — we need to scan from identity start
            // Since identity length is variable, we parse it first to find its end.
            val identityBytes = run {
                // NodePublicIdentity.fromBytes will consume exactly the right bytes
                // We pass the whole remaining slice; it will parse what it needs.
                // The identity is followed by [4B sigLen][sig], so we use the total
                // to reconstruct: sigLen = fourBytesToInt(bytes, identityEnd)
                // We discover identityEnd by parsing: attempt from off onward.
                val remaining = bytes.copyOfRange(off, totalLen)
                // Parse identity to find its byte length
                val tempIdentity = NodePublicIdentity.fromBytes(remaining, hkdf)
                tempIdentity.toBytes()
            }
            val identityLen = identityBytes.size
            val identityEnd = off + identityLen
            require(totalLen >= identityEnd + 4) { "ExchangePayload: truncated before sig length" }
            val sigLen = fourBytesToIntBootstrap(bytes, identityEnd)
            require(totalLen == identityEnd + 4 + sigLen) {
                "ExchangePayload: wrong total length (expected ${identityEnd + 4 + sigLen}, got $totalLen)"
            }
            val signature = bytes.copyOfRange(identityEnd + 4, totalLen)
            val identity  = NodePublicIdentity.fromBytes(identityBytes, hkdf)
            return ExchangePayload(version, issuedAtMs, identity, signature, identityBytes)
        }
    }

    override fun equals(other: Any?) = other is ExchangePayload &&
        identity == other.identity && issuedAtMs == other.issuedAtMs
    override fun hashCode() = 31 * identity.hashCode() + issuedAtMs.hashCode()
}

/**
 * Compact QR introduction code (~177 bytes binary). Contains only Ed25519 key, nodeId,
 * and a 32-byte attestation challenge for the responder to embed in its TEE key.
 * The receiver fetches the full identity from the DHT using [nodeId].
 *
 * Wire format (all fields signed except [rawBytes]):
 *   [1B version][8B issuedAtMs][32B nodeId][32B ed25519PubKey][8B nonce]
 *   [32B attestationChallenge][64B Ed25519 signature]
 *   Total: 177 bytes — fits at QR error correction L.
 */
data class QrIntroductionCode(
    val version:              Byte,
    val issuedAtMs:           Long,
    val nodeId:               ByteArray,       // 32 bytes
    val ed25519PubKey:        ByteArray,       // 32 bytes
    val nonce:                ByteArray,       // 8 bytes
    val attestationChallenge: ByteArray,       // 32 bytes — for responder's TEE key generation
    val signature:            ByteArray,       // 64 bytes Ed25519 detached (covers all above)
    val rawBytes:             ByteArray        // full wire bytes for direct QR encoding
) {
    companion object {
        // 1 + 8 + 32 + 32 + 8 + 32 + 64 = 177 bytes
        private const val HEADER_SIZE = 1 + 8 + 32 + 32 + 8 + 32 + 64

        fun fromBytes(bytes: ByteArray): QrIntroductionCode {
            require(bytes.size == HEADER_SIZE) {
                "QrIntroductionCode: expected $HEADER_SIZE bytes, got ${bytes.size}"
            }
            var off                  = 0
            val version              = bytes[off++]
            val issuedAtMs           = bytesToLong(bytes, off); off += 8
            val nodeId               = bytes.copyOfRange(off, off + 32); off += 32
            val ed25519Pub           = bytes.copyOfRange(off, off + 32); off += 32
            val nonce                = bytes.copyOfRange(off, off + 8);  off += 8
            val attestationChallenge = bytes.copyOfRange(off, off + 32); off += 32   // NEW
            val signature            = bytes.copyOfRange(off, off + 64)
            return QrIntroductionCode(
                version, issuedAtMs, nodeId, ed25519Pub,
                nonce, attestationChallenge, signature, bytes
            )
        }
    }

    override fun equals(other: Any?) = other is QrIntroductionCode &&
        nodeId.contentEquals(other.nodeId) && issuedAtMs == other.issuedAtMs
    override fun hashCode() = 31 * nodeId.contentHashCode() + issuedAtMs.hashCode()
}

// ── Package-private byte helpers ──────────────────────────────────────────────

private fun fourBytesToIntBootstrap(b: ByteArray, off: Int): Int =
    ((b[off].toInt() and 0xFF) shl 24) or
    ((b[off+1].toInt() and 0xFF) shl 16) or
    ((b[off+2].toInt() and 0xFF) shl 8) or
     (b[off+3].toInt() and 0xFF)

// Re-export from crypto package for use in fromBytes
private fun longToBytes(v: Long): ByteArray = ByteArray(8) { i ->
    ((v shr ((7 - i) * 8)) and 0xFF).toByte()
}

private fun bytesToLong(b: ByteArray, off: Int): Long {
    var result = 0L
    for (i in 0..7) result = (result shl 8) or (b[off + i].toLong() and 0xFF)
    return result
}

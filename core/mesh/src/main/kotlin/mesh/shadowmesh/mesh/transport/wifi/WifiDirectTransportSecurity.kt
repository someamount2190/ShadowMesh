package mesh.shadowmesh.mesh.transport.wifi

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.HybridSigner
import mesh.shadowmesh.crypto.NodePrivateIdentity
import mesh.shadowmesh.crypto.NodePublicIdentity
import mesh.shadowmesh.crypto.SymmetricCipher
import mesh.shadowmesh.diagnostics.Diag
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.KeyAgreement

/**
 * Station-to-station (STS) mutual authentication and AEAD frame layer for
 * WiFi Direct TCP fragment exchange.
 *
 * ## Protocol (runs once per TCP connection, before any fragment exchange)
 *
 * ```
 *   Both sides: generate ephemeral P-256 keypair
 *   CLIENT → SERVER: [1B version][32B nodeId][91B ephem_pub_DER][4B sig_len][64B Ed25519 sig]
 *   SERVER → CLIENT: [1B version][32B nodeId][91B ephem_pub_DER][4B sig_len][64B Ed25519 sig]
 *   sig = Ed25519-only sign(nodeId || ephem_pub_DER || DOMAIN_LABEL)
 *   Both sides: (1) look up peer nodeId in trust store; (2) verify Ed25519 sig;
 *               (3) ECDH P-256 → sharedSecret;
 *               (4) K_send/K_recv = HKDF-SHA3-256(sharedSecret, salt=clientPub||serverPub)
 * ```
 *
 * ## After handshake — AEAD frame format
 *
 * All fragment exchange uses XChaCha20-Poly1305:
 * ```
 *   [4B ciphertext_len][24B nonce][ciphertext + 16B Poly1305 tag]
 * ```
 *
 * ## Signing algorithm
 *
 * Ed25519-only (not full Dilithium+Ed25519) is used here. Rationale (from
 * [HybridSigner] KDoc): WiFi Direct is a physically-bounded transport — peers must
 * be within ~200m of each other, and the P2P group is already formed between devices
 * that share TRUST_PHYSICAL from NFC bootstrap. Ed25519 (classical) provides adequate
 * authentication for this threat model; the 64-byte compact signature is also far more
 * practical for a handshake than the ~3.3 KB full hybrid signature.
 *
 * ## Peer lookup
 *
 * [trustedPeerLookup] receives a 32-byte nodeId and must return the peer's
 * [NodePublicIdentity] if that peer is trusted (TRUST_PHYSICAL or better), or null
 * to reject. Supply the gossip engine's identity cache as this function.
 */
class WifiDirectTransportSecurity(
    private val localIdentity:    NodePrivateIdentity,
    private val signer:           HybridSigner,
    private val cipher:           SymmetricCipher,
    private val hkdf:             Hkdf,
    private val trustedPeerLookup: (nodeId: ByteArray) -> NodePublicIdentity?
) {

    /**
     * Perform the STS handshake on an already-connected [socket].
     *
     * Returns an [EstablishedSession] holding directional session keys and the
     * wrapped I/O streams on success. Returns null and closes the socket on any
     * failure (version mismatch, unknown peer, bad signature, ECDH failure).
     *
     * [isGroupOwner] is true when this device is the WiFi Direct group owner (server
     * side). It controls the direction of the two HKDF-derived keys so both sides
     * independently compute the same K_send / K_recv assignment.
     */
    suspend fun handshake(socket: Socket, isGroupOwner: Boolean): EstablishedSession? =
        withContext(Dispatchers.IO) {
            // Bound the handshake so a slow or malicious peer cannot hold the coroutine
            // indefinitely. All DataInputStream.readByte() / readFully() calls block until
            // data arrives; without a socket timeout they never return on a silent peer.
            socket.soTimeout = HANDSHAKE_TIMEOUT_MS.toInt()
            try {
                val input  = DataInputStream(socket.getInputStream())
                val output = DataOutputStream(socket.getOutputStream())

                // ── Step 1: Generate ephemeral P-256 keypair ──────────────
                val kpg = KeyPairGenerator.getInstance("EC")
                kpg.initialize(ECGenParameterSpec("prime256v1"))
                val ephKp      = kpg.generateKeyPair()
                val ephPubDer  = ephKp.public.encoded       // 91-byte X.509 SubjectPublicKeyInfo

                // ── Step 2: Sign nodeId || ephem_pub_DER || domain label ──
                val localToSign = localIdentity.nodeId + ephPubDer + DOMAIN_LABEL
                val localSig    = signer.signEd25519Only(localToSign, localIdentity.signingPrivateKey)
                    .getOrThrow()   // always 64 bytes

                // ── Step 3: Send hello ────────────────────────────────────
                // [1B version][32B nodeId][91B ephem_pub_DER][4B sig_len][64B sig]
                output.writeByte(PROTOCOL_VERSION.toInt())
                output.write(localIdentity.nodeId)
                output.write(ephPubDer)
                output.writeInt(localSig.size)
                output.write(localSig)
                output.flush()

                // ── Step 4: Receive peer hello ────────────────────────────
                val peerVersion = input.readByte()
                if (peerVersion != PROTOCOL_VERSION) {
                    Diag.degraded("wifi-direct-sec", "version-mismatch",
                        "Peer handshake version=$peerVersion expected=$PROTOCOL_VERSION — rejecting")
                    socket.close()
                    return@withContext null
                }
                val peerNodeId  = ByteArray(32).also { input.readFully(it) }
                val peerPubDer  = ByteArray(EC_PUB_DER_BYTES).also { input.readFully(it) }
                val peerSigLen  = input.readInt()
                if (peerSigLen <= 0 || peerSigLen > MAX_SIG_BYTES) {
                    Diag.degraded("wifi-direct-sec", "sig-len-invalid",
                        "Peer sig_len=$peerSigLen is out of bounds — rejecting")
                    socket.close()
                    return@withContext null
                }
                val peerSig = ByteArray(peerSigLen).also { input.readFully(it) }

                // ── Step 5: Peer identity lookup ──────────────────────────
                val peerIdentity = trustedPeerLookup(peerNodeId)
                if (peerIdentity == null) {
                    Diag.degraded("wifi-direct-sec", "untrusted-peer",
                        "Peer nodeId not in trust store — rejecting WiFi Direct connection")
                    socket.close()
                    return@withContext null
                }

                // ── Step 6: Verify peer signature ─────────────────────────
                val peerToVerify = peerNodeId + peerPubDer + DOMAIN_LABEL
                val sigOk = signer.verifyEd25519Only(peerToVerify, peerSig, peerIdentity.signingPublicKey.ed25519PublicKey)
                    .getOrNull() ?: false
                if (!sigOk) {
                    Diag.degraded("wifi-direct-sec", "sig-invalid",
                        "Peer Ed25519 signature invalid — possible impersonation or replay")
                    socket.close()
                    return@withContext null
                }

                // ── Step 7: ECDH P-256 ────────────────────────────────────
                val peerPublicKey = KeyFactory.getInstance("EC")
                    .generatePublic(X509EncodedKeySpec(peerPubDer))
                val ka = KeyAgreement.getInstance("ECDH")
                ka.init(ephKp.private)
                ka.doPhase(peerPublicKey, true)
                val sharedSecret = ka.generateSecret()   // 32 bytes for P-256

                // ── Step 8: Derive directional session keys ───────────────
                // Salt = clientPubDer || serverPubDer || SHA3-256(full handshake transcript).
                // The transcript hash binds the session keys to EVERY field exchanged:
                // both nodeIds, both ephemeral pubkeys, and both signatures. Any in-flight
                // modification (swapped ephem keys, replayed signatures) produces a different
                // transcript hash → different session keys → immediate AEAD authentication
                // failure on the first frame, before any payload is accepted.
                val (clientPubDer, serverPubDer) =
                    if (isGroupOwner) peerPubDer to ephPubDer   // group owner = server
                    else ephPubDer to peerPubDer                // client connects to GO

                // Transcript: ordered concatenation of all sent/received handshake bytes
                // (version + nodeId + ephPubDer + sig for each side, in client-first order).
                val (clientNodeId, serverNodeId) =
                    if (isGroupOwner) peerNodeId to localIdentity.nodeId
                    else localIdentity.nodeId to peerNodeId
                val (clientSig, serverSig) =
                    if (isGroupOwner) peerSig to localSig
                    else localSig to peerSig
                val transcript =
                    byteArrayOf(PROTOCOL_VERSION) + clientNodeId + clientPubDer + clientSig +
                    byteArrayOf(PROTOCOL_VERSION) + serverNodeId + serverPubDer + serverSig
                val transcriptHash = hkdf.sha3_256(transcript)

                val salt = clientPubDer + serverPubDer + transcriptHash

                val kSend = hkdf.derive(sharedSecret, salt, if (isGroupOwner) S2C_INFO else C2S_INFO)
                val kRecv = hkdf.derive(sharedSecret, salt, if (isGroupOwner) C2S_INFO else S2C_INFO)
                sharedSecret.fill(0)

                EstablishedSession(
                    encryptKey = kSend,
                    decryptKey = kRecv,
                    input      = input,
                    output     = output
                )
            } catch (e: Exception) {
                Diag.swallowed("wifi-direct-sec", "handshake-failed", e)
                try { socket.close() } catch (_: Exception) {}
                null
            }
        }

    /**
     * Encrypt [plaintext] and write it as an AEAD frame to [output].
     * Frame format: [4B total_encrypted_len][24B nonce][ciphertext + 16B tag]
     */
    suspend fun writeFrame(output: DataOutputStream, plaintext: ByteArray, key: ByteArray) {
        val encrypted = cipher.encrypt(plaintext, key).getOrThrow()
        output.writeInt(encrypted.size)
        output.write(encrypted)
        output.flush()
    }

    /**
     * Read one AEAD frame from [input] and decrypt it.
     * Returns decrypted plaintext, or null if the frame length is out of bounds
     * (caller should close the connection) or if the MAC check fails.
     * Throws only on unrecoverable I/O errors.
     */
    suspend fun readFrame(input: DataInputStream, key: ByteArray): ByteArray? {
        val len = input.readInt()
        if (len <= SymmetricCipher.NONCE_BYTES + SymmetricCipher.MAC_BYTES || len > MAX_FRAME_BYTES) {
            Diag.degraded("wifi-direct-sec", "frame-size-invalid",
                "AEAD frame length $len is out of bounds — closing connection")
            return null
        }
        val encrypted = ByteArray(len).also { input.readFully(it) }
        return cipher.decrypt(encrypted, key).getOrNull()
    }

    companion object {
        private const val PROTOCOL_VERSION = 1.toByte()
        /** Socket read timeout during the handshake — prevents indefinite block on silent peers. */
        const val HANDSHAKE_TIMEOUT_MS = 30_000L
        /** Domain separation label — prevents cross-protocol signature reuse. */
        private val DOMAIN_LABEL   = "shadowmesh-wifidirect-sts-v1".toByteArray(Charsets.UTF_8)
        private val C2S_INFO       = "shadowmesh-wifidirect-c2s".toByteArray(Charsets.UTF_8)
        private val S2C_INFO       = "shadowmesh-wifidirect-s2c".toByteArray(Charsets.UTF_8)
        /** EC P-256 SubjectPublicKeyInfo DER is always 91 bytes. */
        private const val EC_PUB_DER_BYTES = 91
        /** Ed25519 detached signature is always 64 bytes. */
        private const val MAX_SIG_BYTES    = 64
        /** 4 MB ceiling for encrypted frame payloads (64 KB fragment + generous headroom). */
        private const val MAX_FRAME_BYTES  = 4 * 1024 * 1024
    }
}

/**
 * A successfully authenticated session on one WiFi Direct TCP connection.
 * Holds directional XChaCha20-Poly1305 keys and the wrapped I/O streams.
 */
data class EstablishedSession(
    val encryptKey: ByteArray,
    val decryptKey: ByteArray,
    val input:      DataInputStream,
    val output:     DataOutputStream
) {
    override fun equals(other: Any?) = false
    override fun hashCode() = System.identityHashCode(this)
}

/**
 * Security configuration injected into [WiFiDirectTransport].
 * When null, the transport logs a security degraded event and operates in
 * legacy plaintext mode (accepting unauthenticated connections).
 */
data class WifiDirectSecurityConfig(
    val localIdentity:     NodePrivateIdentity,
    val signer:            HybridSigner,
    val cipher:            SymmetricCipher,
    val hkdf:              Hkdf,
    val trustedPeerLookup: (nodeId: ByteArray) -> NodePublicIdentity?
)

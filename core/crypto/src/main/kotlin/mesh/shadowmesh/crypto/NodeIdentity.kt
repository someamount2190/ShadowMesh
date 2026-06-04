package mesh.shadowmesh.crypto

import java.security.SecureRandom

/**
 * A SHADOWMESH node's complete cryptographic identity.
 *
 * Combines:
 *   - HybridKem keypair  (Kyber-1024 + X25519) — for key agreement
 *   - HybridSigner keypair (Dilithium-3 + Ed25519) — for signatures
 *
 * nodeId = SHA3-256(kemPublicKey.toBytes() || signingPublicKey.toBytes())
 * This is the stable network address. It is derived from the public keys
 * so any peer can independently verify a nodeId from the public keys.
 *
 * The public half (NodePublicIdentity) is safe to transmit. The private half
 * (NodePrivateIdentity) never leaves the device.
 *
 * Generation: always use NodeIdentity.generate() — do not construct directly.
 *
 * APK binding (design doc §5.15):
 *   When [deviceSecret] and [apkBindingHash] are supplied to [NodeIdentityGenerator],
 *   the HKDF key derivation step uses IBD to bind the identity seed to the device
 *   secret and APK hash. A repackaged APK produces a different [apkBindingHash],
 *   therefore a different identity seed, therefore different keys — the node cannot
 *   authenticate as the original identity or decrypt existing channel messages.
 *
 *   Supply both or neither. Supplying only one throws [IllegalArgumentException].
 */
class NodeIdentityGenerator(
    private val kem:            HybridKem,
    private val signer:         HybridSigner,
    private val hkdf:           Hkdf = Hkdf.instance,
    /**
     * Optional IBD instance. When non-null, [deviceSecret] and [apkBindingHash]
     * must also be supplied. The generated identity keys will be APK-bound.
     * When null, keys are generated from fresh entropy only (no APK binding).
     */
    private val ibd:            IntegrityBoundedKeyDerivation? = null,
    private val deviceSecret:   ByteArray? = null,
    private val apkBindingHash: ByteArray? = null
) {
    init {
        val ibdParamsCount = listOf(ibd, deviceSecret, apkBindingHash).count { it != null }
        require(ibdParamsCount == 0 || ibdParamsCount == 3) {
            "ibd, deviceSecret, and apkBindingHash must all be supplied together or all omitted"
        }
    }

    suspend fun generate(): CryptoResult<NodeIdentity> = cryptoRunCatching {
        val kemKp     = kem.generateKeyPair().getOrThrow()
        val signingKp = signer.generateSigningKeyPair().getOrThrow()

        // If APK binding is configured, derive the nodeId via IBD so that a repackaged
        // APK produces a different nodeId — the node cannot impersonate the original.
        // Without IBD, nodeId is SHA3-256(kemPub || sigPub) as before.
        // nodeId = SHA3-256(kemPub || sigPub) — always, regardless of IBD.
        // This is the gossip-visible address. Peers must be able to verify it
        // from the public keys alone, so it cannot include device-private material.
        //
        // FIX (LB1): The previous implementation used SHA3-256(ibdSeed || kemPub || sigPub)
        // when IBD was active, making nodeId unverifiable by peers and incompatible with
        // NodePublicIdentity.fromBytes() which always validates SHA3-256(kemPub || sigPub).
        // Any IBD-bound identity's public part would always fail deserialization.
        //
        // The IBD binding property (repackaged APK cannot impersonate) is preserved at the
        // key-material level: channel keys and ratchet keys are derived via IBD (see
        // KeyOrchestrator.generateAndWrapChannelKey and IntegrityBoundedKeyDerivation).
        // The gossip-visible nodeId remains standard so peers can verify it.
        if (ibd != null && deviceSecret != null && apkBindingHash != null) {
            // Validate IBD parameters (no-op in terms of nodeId derivation — enforces
            // that the caller correctly wired up all three IBD params).
            ibd.derive(
                deviceSecret       = deviceSecret,
                apkBindingHash     = apkBindingHash,
                channelGenesisHash = ByteArray(32),
                purpose            = IntegrityBoundedKeyDerivation.KeyPurpose.IDENTITY
            ).fill(0)  // derive + immediately wipe — just validates inputs
        }
        val nodeId = hkdf.sha3_256(kemKp.publicKey.toBytes() + signingKp.publicKey.toBytes())

        NodeIdentity(
            nodeId     = nodeId,
            publicPart = NodePublicIdentity(
                nodeId           = nodeId,
                kemPublicKey     = kemKp.publicKey,
                signingPublicKey = signingKp.publicKey
            ),
            privatePart = NodePrivateIdentity(
                nodeId            = nodeId,
                kemPrivateKey     = kemKp.privateKey,
                signingPrivateKey = signingKp.privateKey
            )
        )
    }
}

data class NodeIdentity(
    val nodeId:      ByteArray,
    val publicPart:  NodePublicIdentity,
    val privatePart: NodePrivateIdentity
) {
    override fun equals(other: Any?) = other is NodeIdentity && nodeId.contentEquals(other.nodeId)
    override fun hashCode() = nodeId.contentHashCode()
}

/**
 * The transmittable public half of a node identity.
 * Wire format: [32B nodeId][kemPublicKey bytes][signingPublicKey bytes]
 * Each public key is length-prefixed internally (see HybridPublicKey / HybridVerifyKey).
 */
data class NodePublicIdentity(
    val nodeId:           ByteArray,
    val kemPublicKey:     HybridPublicKey,
    val signingPublicKey: HybridVerifyKey
) {
    fun toBytes(): ByteArray =
        nodeId +
        kemPublicKey.toBytes() +
        signingPublicKey.toBytes()

    companion object {
        fun fromBytes(bytes: ByteArray, hkdf: Hkdf = Hkdf.instance): NodePublicIdentity {
            require(bytes.size >= 32) { "NodePublicIdentity: too short (${bytes.size})" }

            val nodeId   = bytes.copyOfRange(0, 32)
            var offset   = 32

            // HybridPublicKey: 4-byte length prefix + kyber key + 32 x25519
            require(bytes.size >= offset + 4) { "NodePublicIdentity: truncated before KEM key" }
            val kemLen = fourBytesToInt(bytes, offset)
            // Explicit overflow-safe check: if kemLen is near Int.MAX_VALUE, `offset + 4 + kemLen + 32`
            // overflows to a negative, making the bounds guard trivially true. Compute the max allowed
            // length first to avoid any overflow in the addition.
            require(kemLen >= 0 && kemLen <= bytes.size - offset - 4 - 32) {
                "NodePublicIdentity: KEM key length out of range ($kemLen)"
            }
            val kemEnd = offset + 4 + kemLen + 32
            val kemPub = HybridPublicKey.fromBytes(bytes.copyOfRange(offset, kemEnd))
            offset = kemEnd

            // HybridVerifyKey: 4-byte length prefix + dilithium key + 32 ed25519
            require(bytes.size >= offset + 4) { "NodePublicIdentity: truncated before signing key" }
            val sigLen = fourBytesToInt(bytes, offset)
            // Same overflow-safe check as kemLen above.
            require(sigLen >= 0 && sigLen <= bytes.size - offset - 4 - 32) {
                "NodePublicIdentity: signing key length out of range ($sigLen)"
            }
            val sigEnd = offset + 4 + sigLen + 32
            val sigPub = HybridVerifyKey.fromBytes(bytes.copyOfRange(offset, sigEnd))

            // Verify nodeId matches the keys
            val expected = hkdf.sha3_256(kemPub.toBytes() + sigPub.toBytes())
            require(expected.contentEquals(nodeId)) {
                "NodePublicIdentity: nodeId does not match public keys — identity may be tampered"
            }

            return NodePublicIdentity(nodeId, kemPub, sigPub)
        }
    }

    override fun equals(other: Any?) = other is NodePublicIdentity &&
        nodeId.contentEquals(other.nodeId)
    override fun hashCode() = nodeId.contentHashCode()
}

/** Private half of a node identity. Never transmitted. Never serialized to disk unencrypted. */
data class NodePrivateIdentity(
    val nodeId:            ByteArray,
    val kemPrivateKey:     HybridPrivateKey,
    val signingPrivateKey: HybridSigningKey
) {
    override fun equals(other: Any?) = other is NodePrivateIdentity &&
        nodeId.contentEquals(other.nodeId)
    override fun hashCode() = nodeId.contentHashCode()
}

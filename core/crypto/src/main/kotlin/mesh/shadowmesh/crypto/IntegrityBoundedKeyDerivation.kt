package mesh.shadowmesh.crypto

/**
 * Integrity-Bound Key Derivation — design doc §5.15.
 *
 * Mesh identity and channel keys are derived from TWO inputs combined:
 *   1. device_secret — from Android Keystore (hardware-backed)
 *   2. apk_binding_hash — SHA3-256(signing_certificate_bytes || SHA3-256(critical_bytecode[]))
 *
 * A modified or repackaged APK produces a different apk_binding_hash.
 * The derived keys change. The node cannot authenticate as the original
 * identity and cannot decrypt existing channel messages.
 *
 * This is architecturally distinct from APK self-verification (§5.12):
 *   - Self-verification: detects tampering and triggers wipe (Android-specific)
 *   - Integrity binding: makes tampered keys cryptographically wrong from derivation
 *     — even if the wipe is patched out, the resulting node cannot function as original.
 *
 * Critical regions hashed (chosen for attack-surface significance):
 *   NSC, gossip engine, DHT client, crypto layer, fragment assembly.
 *   UI layer excluded — UI patches are lower-risk.
 *
 * NOTE: This class is pure JVM — no Android imports. The device_secret and
 * critical_bytecode arrays are provided by the Android layer (BiometricKeyManager
 * and ApkIntegrityVerifier respectively), keeping this class fully testable.
 *
 * IMPORTANT — App update migration:
 *   A legitimate app update produces a new apk_binding_hash → new keys.
 *   Users must re-join channels via key rotation after an update.
 *   This cost is accepted: update security > update convenience.
 */
class IntegrityBoundedKeyDerivation(private val hkdf: Hkdf = Hkdf.instance) {

    /**
     * Derive a 32-byte identity key seed from device secret + APK binding hash.
     *
     * @param deviceSecret         Hardware-backed secret from Android Keystore (≥32 bytes)
     * @param apkBindingHash       SHA3-256(signing_cert || SHA3-256(critical_bytecode[])) — 32 bytes
     * @param channelGenesisHash   Per-channel salt — use channel creation hash or zeros for
     *                             the base identity key
     * @param purpose              Distinguishes identity key from channel key
     */
    fun derive(
        deviceSecret:       ByteArray,
        apkBindingHash:     ByteArray,
        channelGenesisHash: ByteArray = ByteArray(32),
        purpose:            KeyPurpose = KeyPurpose.IDENTITY
    ): ByteArray {
        require(deviceSecret.size >= 32)    { "deviceSecret must be ≥32 bytes, got ${deviceSecret.size}" }
        require(apkBindingHash.size == 32)  { "apkBindingHash must be 32 bytes, got ${apkBindingHash.size}" }
        require(channelGenesisHash.size == 32) { "channelGenesisHash must be 32 bytes" }

        // IKM = device_secret || apk_binding_hash
        // This binding means: different APK → different IKM → different key.
        val ikm = deviceSecret.copyOf(deviceSecret.size) + apkBindingHash

        val result = hkdf.derive(
            ikm       = ikm,
            salt      = channelGenesisHash,
            info      = purpose.info,
            outputLen = 32
        )

        // Wipe IKM immediately — it contains the device secret
        ikm.fill(0)

        return result
    }

    /**
     * Build the APK binding hash from the signing certificate bytes and
     * the bytecode of critical class files.
     *
     * Called by ApkIntegrityVerifier (Android layer) which supplies the raw bytes.
     * Kept here so the hash construction is testable without Android APIs.
     *
     * @param signingCertBytes    Raw DER bytes of the APK signing certificate
     * @param criticalBytecodeList List of class file byte arrays (NSC, gossip, DHT, crypto, assembly)
     */
    fun buildApkBindingHash(
        signingCertBytes:     ByteArray,
        criticalBytecodeList: List<ByteArray>
    ): ByteArray {
        require(signingCertBytes.isNotEmpty()) { "signingCertBytes must not be empty" }
        require(criticalBytecodeList.isNotEmpty()) { "criticalBytecodeList must not be empty" }

        // Hash each critical bytecode independently then combine — order-stable.
        // Use a mutable accumulator and wipe each intermediate concatenation after use
        // so intermediate byte arrays containing concatenated bytecode hashes are not
        // retained in memory until the next GC cycle.
        val hashes = criticalBytecodeList.map { hkdf.sha3_256(it) }
        var acc = ByteArray(0)
        for (h in hashes) {
            val next = acc + h
            acc.fill(0)
            acc = next
        }
        val bytecodeHash = hkdf.sha3_256(acc)
        acc.fill(0)

        return hkdf.sha3_256(signingCertBytes + bytecodeHash)
    }

    enum class KeyPurpose(val info: ByteArray) {
        IDENTITY("shadowmesh_identity_v1".toByteArray()),
        CHANNEL("shadowmesh_channel_v1".toByteArray()),
        RATCHET("shadowmesh_ratchet_v1".toByteArray()),
        FRAGMENT("shadowmesh_fragment_v1".toByteArray())
    }
}

package mesh.shadowmesh.attestation

import android.content.Context
import mesh.shadowmesh.bootstrap.PhysicalKeyExchange
import mesh.shadowmesh.crypto.*

/**
 * Attested physical key exchange — wraps [PhysicalKeyExchange] with hardware attestation.
 *
 * Design doc §3.2 + hardware attestation research finding:
 *
 * The base [PhysicalKeyExchange] establishes TRUST_PHYSICAL based on physical proximity
 * (QR code or NFC exchange) and a signed identity payload. This proves:
 *   - The device was physically present (QR/NFC proximity)
 *   - The identity payload was signed by a key matching the node ID
 *   - The APK signing certificate matches the expected hash (software check)
 *
 * [AttestedPhysicalExchange] additionally proves:
 *   - The node is running on genuine Android hardware with verified boot (hardware check)
 *   - The attestation key was generated in response to a fresh challenge (anti-replay)
 *   - The device's bootloader state (VERIFIED/SELF_SIGNED/UNVERIFIED)
 *
 * This closes the gap identified in the threat model: `ApkIntegrityVerifier`'s software
 * cert-hash check is defeatable by Magisk/Zygisk at the OS level. Hardware attestation
 * has its root of trust in the TEE — the check cannot be bypassed by a rooted OS.
 *
 * ## Exchange flow (augmented)
 *
 * Initiator (node A, generating the QR code):
 *   1. Generate a 32-byte challenge and include it in the QR compact payload.
 *   2. Wait for the responder's full payload.
 *   3. Verify the attestation chain from the responder.
 *
 * Responder (node B, scanning the QR code):
 *   1. Extract the challenge from the QR compact payload.
 *   2. Call [generateLocalAttestation] to embed the challenge in a TEE-generated cert.
 *   3. Build the full [ExchangePayload] via [PhysicalKeyExchange.buildPayload].
 *   4. Embed the [AttestationEvidence] in the payload extension.
 *
 * Both roles verify each other's attestation before issuing [TrustCredential].
 *
 * ## Fallback
 *
 * If the peer's device does not support hardware attestation (emulator, API <26, some
 * low-end devices), [verifyPeerAttestation] returns [VerificationResult.NoAttestationExtension].
 * The caller may choose to:
 *   - Accept the exchange at TRUST_INTRODUCED instead of TRUST_PHYSICAL.
 *   - Reject the exchange entirely (maximum security mode).
 *   - Accept and note the absence in the trust credential (default — interoperability).
 *
 * The design doc does not mandate hardware attestation for TRUST_PHYSICAL (it predates
 * this enhancement). The fallback behaviour is configurable via [requireHardwareAttestation].
 *
 * @param requireHardwareAttestation  When true, exchanges where the peer lacks hardware
 *   attestation result in [ExchangeResult.AttestationUnavailable] rather than accepting
 *   the exchange at a reduced trust level.
 * @param allowCustomOS  When true, peers running GrapheneOS or CalyxOS (SELF_SIGNED boot
 *   state) are accepted. Default: true — GrapheneOS is explicitly in-scope.
 * @param expectedPeerAppIdHash  When non-null, the peer's attestation must embed this
 *   SHA-256 app ID hash. Prevents accepting attestations from a different app using the
 *   same physical exchange mechanism. Leave null in tests.
 */
class AttestedPhysicalExchange(
    private val context:                    Context,
    private val baseExchange:               PhysicalKeyExchange,
    private val requireHardwareAttestation: Boolean    = false,
    private val allowCustomOS:              Boolean    = true,
    private val expectedPeerAppIdHash:      ByteArray? = null,
    /**
     * Keybox revocation cache. When non-null, [verifyPeerAttestation] checks every
     * non-root certificate in the chain against the revocation list before accepting
     * the attestation. Should be the application-scope singleton loaded during init.
     *
     * When null, revocation checking is skipped (acceptable in tests; not in production).
     */
    private val revocationCache:            KeyboxRevocationCache? = null
) {

    /**
     * Generate local attestation evidence for embedding in an outbound exchange payload.
     *
     * @param challenge  32-byte challenge received from the peer (from their QR compact code).
     * @return [AttestationResult.Evidence] on success. Returns [AttestationResult.Error] if
     *         Keystore is unavailable. Returns [AttestationResult.NoHardwareSupport] on emulator.
     */
    fun generateLocalAttestation(challenge: ByteArray): AttestationResult =
        HardwareAttestation.generateAttestationKey(context, challenge)

    /**
     * Generate a fresh 32-byte challenge to send to the peer.
     * Include this in the QR compact payload so the peer embeds it in their attestation key.
     */
    fun generateChallenge(): ByteArray = HardwareAttestation.generateChallenge()

    /**
     * Verify the attestation evidence received from a peer.
     *
     * @param evidence           Extracted from the peer's [ExchangePayload] extension field.
     * @param challengeWeSent    The 32-byte challenge this device included in its QR/NFC payload.
     * @return [ExchangeResult] describing the outcome.
     */
    fun verifyPeerAttestation(
        evidence:        AttestationEvidence,
        challengeWeSent: ByteArray
    ): ExchangeResult {
        val result = HardwareAttestation.verifyAttestationChain(
            evidence          = evidence,
            expectedChallenge = challengeWeSent,
            expectedAppIdHash = expectedPeerAppIdHash,
            allowCustomOS     = allowCustomOS,
            revocationCache   = revocationCache
        )

        return when (result) {
            is VerificationResult.Valid -> {
                // Root certificate check — pin the chain's root public key against the
                // known-good hardware attestation root. This is the last line of defence:
                // a compromised or self-issued root passes chain signature verification
                // but fails here because its public key won't match the embedded constant.
                //
                // Root pinning: all chains — stock Android (VERIFIED) and GrapheneOS (SELF_SIGNED)
                // — root in the Google hardware attestation CA. GrapheneOS has no separate root.
                // Try RSA-4096 first (primary), then EC P-384 (Google rotation root).
                val rootOk =
                    HardwareAttestation.verifyRootCertificate(
                        chain                    = evidence.certificateChain,
                        expectedRootPublicKeyHex = HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA
                    ) || HardwareAttestation.verifyRootCertificate(
                        chain                    = evidence.certificateChain,
                        expectedRootPublicKeyHex = HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_EC
                    )
                if (!rootOk) {
                    return ExchangeResult.AttestationFailed(
                        "Root certificate does not match known hardware attestation root " +
                        "(boot state: ${result.verifiedBootState}). " +
                        "Possible compromised keybox or unrecognised attestation authority."
                    )
                }

                val trustLevel = when (result.verifiedBootState) {
                    // StrongBox is a strictly stronger backing than a plain TEE; surface it
                    // as its own tier. isStrongBox was previously extracted and carried in
                    // the result but never influenced the trust level (latent dead signal).
                    VerifiedBootState.VERIFIED    ->
                        if (result.isStrongBox) AttestationTrustLevel.HARDWARE_STRONGBOX
                        else                    AttestationTrustLevel.HARDWARE_VERIFIED
                    VerifiedBootState.SELF_SIGNED -> AttestationTrustLevel.HARDWARE_CUSTOM_OS
                    else                          -> AttestationTrustLevel.SOFTWARE_ONLY
                }
                ExchangeResult.AttestationVerified(
                    bootState        = result.verifiedBootState,
                    attestationLevel = trustLevel,
                    isStrongBox      = result.isStrongBox
                )
            }

            VerificationResult.NoAttestationExtension -> {
                if (requireHardwareAttestation) {
                    ExchangeResult.AttestationUnavailable(
                        "Peer device does not support hardware key attestation"
                    )
                } else {
                    ExchangeResult.AttestationUnavailable(
                        "No hardware attestation available — accepting at reduced assurance"
                    )
                }
            }

            is VerificationResult.Invalid ->
                ExchangeResult.AttestationFailed(result.reason)
        }
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

enum class AttestationTrustLevel {
    HARDWARE_STRONGBOX,  // VERIFIED boot state + StrongBox-backed key — strongest tier
    HARDWARE_VERIFIED,   // VERIFIED boot state — stock Android, locked bootloader (TEE)
    HARDWARE_CUSTOM_OS,  // SELF_SIGNED — GrapheneOS/CalyxOS with enrolled key
    SOFTWARE_ONLY        // No hardware attestation available
}

/**
 * Map a runtime [AttestationTrustLevel] (lives in core/attestation) down to the durable,
 * crypto-layer [mesh.shadowmesh.crypto.CredentialAttestation] tier that is signed into a
 * [mesh.shadowmesh.crypto.TrustCredential]. This is the bridge that lets the attestation
 * tier verified at bootstrap survive into the persisted credential, rather than collapsing
 * to an undistinguished TRUST_PHYSICAL. Call it at credential-issuance time alongside
 * TrustCredential.physicalAttested(...).
 */
fun AttestationTrustLevel.toCredentialAttestation(): mesh.shadowmesh.crypto.CredentialAttestation =
    when (this) {
        AttestationTrustLevel.HARDWARE_STRONGBOX -> mesh.shadowmesh.crypto.CredentialAttestation.HARDWARE_STRONGBOX
        AttestationTrustLevel.HARDWARE_VERIFIED  -> mesh.shadowmesh.crypto.CredentialAttestation.HARDWARE_VERIFIED
        AttestationTrustLevel.HARDWARE_CUSTOM_OS -> mesh.shadowmesh.crypto.CredentialAttestation.HARDWARE_CUSTOM_OS
        AttestationTrustLevel.SOFTWARE_ONLY      -> mesh.shadowmesh.crypto.CredentialAttestation.NONE
    }

sealed class ExchangeResult {
    /**
     * Attestation verified — hardware root of trust confirmed.
     * The exchange may proceed at TRUST_PHYSICAL.
     */
    data class AttestationVerified(
        val bootState:        VerifiedBootState,
        val attestationLevel: AttestationTrustLevel,
        val isStrongBox:      Boolean
    ) : ExchangeResult()

    /**
     * Hardware attestation was not available on the peer's device.
     * Exchange may proceed at TRUST_INTRODUCED (reduced assurance) unless
     * [AttestedPhysicalExchange.requireHardwareAttestation] is true.
     */
    data class AttestationUnavailable(val reason: String) : ExchangeResult()

    /**
     * Attestation verification failed — do NOT issue TRUST_PHYSICAL.
     * This indicates a tampered device, replay attack, or app identity mismatch.
     */
    data class AttestationFailed(val reason: String) : ExchangeResult()
}

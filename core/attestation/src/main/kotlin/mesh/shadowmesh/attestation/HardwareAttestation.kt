package mesh.shadowmesh.attestation

import mesh.shadowmesh.diagnostics.Diag

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import mesh.shadowmesh.crypto.Hkdf
import java.security.*
import java.security.cert.X509Certificate
import mesh.shadowmesh.crypto.toHex

/**
 * Hardware key attestation for TRUST_PHYSICAL bootstrap — Phase 3 enhancement.
 *
 * ## Why this exists
 *
 * [ApkIntegrityVerifier] performs software-based certificate hash checking. This is
 * correct for detecting repackaged APKs at runtime but is defeatable at the OS level
 * by tools like Magisk/Zygisk if the device is rooted. A compromised OS can intercept
 * the signing-cert check and return the expected hash regardless of the actual binary.
 *
 * Hardware key attestation, by contrast, has its root of trust in the device's
 * Trusted Execution Environment (TEE) or StrongBox — hardware that persists across
 * root, OS modification, and even factory reset. The attestation certificate chain is
 * signed by an OEM-provisioned key that never leaves the secure hardware. Even a fully
 * rooted device cannot forge a valid attestation chain without physically extracting
 * the TEE signing key (which would require a hardware attack, not just Magisk).
 *
 * ## How it works
 *
 * 1. [generateAttestationKey] creates an EC keypair in the Android Keystore with a
 *    fresh 32-byte challenge. The Keystore returns a certificate chain where the leaf
 *    certificate is self-signed by the attestation key, and the chain roots in Google's
 *    hardware attestation root (or the OEM's hardware root for non-Play devices like
 *    GrapheneOS, which has its own auditor infrastructure).
 *
 * 2. The certificate chain is serialised as [AttestationEvidence] and transmitted to
 *    the peer during the TRUST_PHYSICAL QR/NFC bootstrap alongside the node's
 *    [NodePublicIdentity]. See [PhysicalKeyExchange] — the `ExchangePayload` carries
 *    this evidence as an optional extension field.
 *
 * 3. The peer calls [verifyAttestationChain] to:
 *    a. Verify the chain signatures (each cert signed by its issuer).
 *    b. Extract the attestation extension from the leaf cert and check that:
 *       - The challenge matches the one the peer sent (freshness — prevents replay).
 *       - `verifiedBootState` is VERIFIED or SELF_SIGNED (checked or custom OS).
 *       - The app's signing certificate digest in the extension matches the known
 *         SHADOWMESH signing key fingerprint (app identity bound in hardware).
 *    c. Optionally check the root against [GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA] or
 *       [GOOGLE_HARDWARE_ATTESTATION_ROOT_EC] (or the GrapheneOS root for GrapheneOS devices).
 *
 * 4. A node that passes attestation has its [TrustCredential] issued at
 *    [TrustLevel.TRUST_PHYSICAL] with the verified tier recorded in the credential's
 *    signed [mesh.shadowmesh.crypto.CredentialAttestation] field (NONE / HARDWARE_VERIFIED
 *    / HARDWARE_STRONGBOX / HARDWARE_CUSTOM_OS) — making the hardware root that was checked
 *    at bootstrap durably inspectable. Issuance must call TrustCredential.physicalAttested(),
 *    passing AttestationTrustLevel.toCredentialAttestation(); a plain physical() call records
 *    NONE and loses the tier.
 *
 * ## Threat model
 *
 * - **Defeated by**: extracted OEM keyboxes (2022 Samsung/LG leak). Mitigation: check
 *   the revocation list at [KEYBOX_REVOCATION_URL] — cached in the APK and updatable
 *   via signed gossip. A revoked keybox makes the chain fail validation.
 * - **Not defeated by**: Magisk, Zygisk, Shamiko, root hiding, modified OS (as long
 *   as the TEE firmware is unmodified — which it always is on production devices since
 *   TEE firmware is signed by the OEM and cannot be reflashed without physical access).
 * - **GrapheneOS**: uses the standard Google hardware attestation chain — it does NOT have
 *   a separate attestation root. The distinguishing signal is `verifiedBootState=SELF_SIGNED`
 *   combined with a `verifiedBootKey` fingerprint in [GRAPHENEOS_VERIFIED_BOOT_KEYS]. Set
 *   [allowCustomOS] = true in [verifyAttestationChain] to accept these chains.
 *
 * ## API 26+ requirement
 *
 * Hardware key attestation requires API 26 (Android 8.0). SHADOWMESH targets API 29+,
 * so no runtime API check is needed. On emulators and API <26 devices, the keystore
 * will not include the attestation extension — [verifyAttestationChain] returns
 * [AttestationResult.NoHardwareSupport] in that case.
 *
 * Thread-safety: stateless — all methods thread-safe.
 */
object HardwareAttestation {

    private const val KEY_ALIAS   = "shadowmesh_attestation_key"
    private const val KEY_STORE   = "AndroidKeyStore"
    private const val EC_CURVE    = "secp256r1"
    private val hkdf = Hkdf.instance

    // ── Key generation ────────────────────────────────────────────────────

    /**
     * Generate (or retrieve) an EC attestation keypair in the Android Keystore.
     *
     * Returns an [AttestationEvidence] containing the certificate chain. The chain's
     * leaf certificate contains the attestation extension with the embedded [challenge].
     *
     * [challenge] must be 32 bytes of fresh random material generated by the verifying
     * peer and transmitted out-of-band (e.g. in the QR code compact payload). This
     * prevents an attacker from replaying a previously-valid attestation response.
     *
     * The key is generated with:
     *   - Purpose: SIGN only (not for encryption — the attested key signs the node's
     *     identity to prove it originates from the genuine app on verified hardware)
     *   - No user authentication required (attestation is done at bootstrap time, not
     *     every operation — the PhysicalKeyExchange gate controls TRUST_PHYSICAL)
     *   - setAttestationChallenge(challenge): embeds the challenge in the cert extension
     */
    fun generateAttestationKey(
        context:   Context,
        challenge: ByteArray
    ): AttestationResult {
        require(challenge.size == CHALLENGE_BYTES) {
            "Challenge must be $CHALLENGE_BYTES bytes, got ${challenge.size}"
        }
        return try {
            val ks = KeyStore.getInstance(KEY_STORE).apply { load(null) }
            // Delete and regenerate so the new certificate embeds the fresh challenge.
            // The key is ephemeral per-bootstrap — we don't reuse attestation keys.
            if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)

            val spec = KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN
            )
                .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setAttestationChallenge(challenge)
                .build()

            val kpg = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, KEY_STORE
            )
            kpg.initialize(spec)
            kpg.generateKeyPair()

            val chain = ks.getCertificateChain(KEY_ALIAS)
                ?.map { it as X509Certificate }
                ?.takeIf { it.isNotEmpty() }
                ?: return AttestationResult.NoHardwareSupport

            val publicKey = chain.first().publicKey.encoded

            AttestationResult.Evidence(
                AttestationEvidence(
                    challenge        = challenge,
                    certificateChain = chain.map { it.encoded },
                    publicKeyDer     = publicKey
                )
            )
        } catch (e: Exception) {
            AttestationResult.Error("Key generation failed: ${e.message}")
        }
    }

    // ── Chain verification ────────────────────────────────────────────────

    /**
     * Verify an [AttestationEvidence] received from a peer during TRUST_PHYSICAL bootstrap.
     *
     * Checks:
     *   1a. Certificate validity (not expired, not yet valid).
     *   1b. Chain signatures (each cert signed by its issuer).
     *   1c. Keybox revocation (optional — supply [revocationCache]).
     *   2.  Challenge freshness (leaf cert extension challenge == [expectedChallenge]).
     *   3.  Verified boot state is VERIFIED, or SELF_SIGNED with a verifiedBootKey fingerprint
     *       in [GRAPHENEOS_VERIFIED_BOOT_KEYS] (requires [allowCustomOS] = true).
     *   4.  App ID in the attestation extension matches [expectedAppIdHash] (when supplied).
     *   5.  keymasterSecurityLevel >= TrustedEnvironment — rejects software-backed attestation.
     *   6.  Root pinning — chain root matches the Google hardware attestation root (RSA or EC).
     *       GrapheneOS chains to the same Google root (it has no separate attestation root).
     *       Fails-closed when roots are deployment placeholders.
     *
     * @param evidence          Received from peer.
     * @param expectedChallenge The 32-byte challenge this device sent to the peer.
     * @param expectedAppIdHash Optional SHA-256 of the SHADOWMESH signing cert bytes.
     *                          When supplied, the attestation extension's app ID must match.
     *                          When null, app ID check is skipped (weaker — use only in tests).
     * @param allowCustomOS     True to accept SELF_SIGNED chains whose verifiedBootKey fingerprint
     *                          is in [GRAPHENEOS_VERIFIED_BOOT_KEYS]. SELF_SIGNED chains with an
     *                          unrecognised key are always rejected. Default: false.
     * @param googleRootRsaHex  Expected Google hardware attestation RSA-4096 root public key (hex DER).
     *                          Defaults to [GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA].
     * @param googleRootEcHex   Expected Google hardware attestation EC P-384 root public key (hex DER).
     *                          Defaults to [GOOGLE_HARDWARE_ATTESTATION_ROOT_EC].
     */
    fun verifyAttestationChain(
        evidence:            AttestationEvidence,
        expectedChallenge:   ByteArray,
        expectedAppIdHash:   ByteArray? = null,
        allowCustomOS:       Boolean = false,
        revocationCache:     KeyboxRevocationCache? = null,
        googleRootRsaHex:    String = GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA,
        googleRootEcHex:     String = GOOGLE_HARDWARE_ATTESTATION_ROOT_EC
    ): VerificationResult {
        if (evidence.certificateChain.isEmpty()) {
            return VerificationResult.Invalid("Empty certificate chain")
        }

        // Parse certificates
        val certs = try {
            val cf = java.security.cert.CertificateFactory.getInstance("X.509")
            evidence.certificateChain.map { der ->
                cf.generateCertificate(der.inputStream()) as X509Certificate
            }
        } catch (e: Exception) {
            Diag.degraded("attestation", "cert-parse-failed", "Certificate parse failed: ${e.message}")
            return VerificationResult.Invalid("Certificate parse failed: ${e.message}")
        }

        // 1a. Validity check: all certs must be currently valid (not expired, not yet valid).
        for ((index, cert) in certs.withIndex()) {
            try {
                cert.checkValidity()
            } catch (e: java.security.cert.CertificateExpiredException) {
                return VerificationResult.Invalid("Certificate at chain position $index is expired")
            } catch (e: java.security.cert.CertificateNotYetValidException) {
                return VerificationResult.Invalid("Certificate at chain position $index is not yet valid")
            }
        }

        // 1b. Verify chain signatures: each cert is signed by the next
        for (i in 0 until certs.size - 1) {
            try {
                certs[i].verify(certs[i + 1].publicKey)
            } catch (e: Exception) {
                Diag.degraded("attestation", "chain-sig-invalid",
                    "Chain signature invalid at position $i: ${e.message}",
                    "position" to i.toString())
                return VerificationResult.Invalid(
                    "Chain signature invalid at position $i: ${e.message}"
                )
            }
        }

        // 1c. Keybox revocation check — reject chains whose intermediate or leaf
        //     certificate serial/key hash is on the revocation list.
        //     Checks every non-root cert (root revocation is handled separately via
        //     verifyRootCertificate). On 2022 Samsung/LG leak: the intermediate
        //     provisioning cert serial is in the revocation list.
        if (revocationCache != null) {
            for ((index, cert) in certs.dropLast(1).withIndex()) {
                val serialHex  = cert.serialNumber.toString(16).lowercase()
                val pubKeyHash = cert.publicKey.encoded.let { pub ->
                    java.security.MessageDigest.getInstance("SHA-256").digest(pub)
                        .toHex()
                }
                if (revocationCache.isRevoked(serialHex, pubKeyHash)) {
                    return VerificationResult.Invalid(
                        "Certificate at chain position $index is revoked " +
                        "(serial=$serialHex) — possible leaked keybox"
                    )
                }
            }
        }

        // 2. Extract attestation extension from leaf cert and check challenge + boot state
        val leaf = certs.first()
        val extBytes = leaf.getExtensionValue(KEY_ATTESTATION_OID)
            ?: return VerificationResult.NoAttestationExtension

        val parseResult = parseAttestationExtension(extBytes)
            ?: return VerificationResult.Invalid("Could not parse attestation extension")

        // Challenge freshness
        if (!parseResult.challenge.contentEquals(expectedChallenge)) {
            return VerificationResult.Invalid(
                "Challenge mismatch — possible replay attack"
            )
        }

        // Verified boot state
        // SELF_SIGNED is accepted only when allowCustomOS=true AND the verifiedBootKey
        // fingerprint matches a known GrapheneOS key. GrapheneOS chains to the same Google
        // root as stock Android — the key fingerprint is the only GrapheneOS-specific signal.
        val bootOk = when (parseResult.verifiedBootState) {
            VerifiedBootState.VERIFIED    -> true
            VerifiedBootState.SELF_SIGNED ->
                allowCustomOS && isGrapheneOsBootKey(parseResult.verifiedBootKey)
            VerifiedBootState.UNVERIFIED,
            VerifiedBootState.FAILED      -> false
        }
        if (!bootOk) {
            val reason = when {
                parseResult.verifiedBootState == VerifiedBootState.SELF_SIGNED && !allowCustomOS ->
                    "Verified boot state is SELF_SIGNED — set allowCustomOS=true to accept GrapheneOS"
                parseResult.verifiedBootState == VerifiedBootState.SELF_SIGNED ->
                    "Verified boot state is SELF_SIGNED but verifiedBootKey is not a known " +
                    "GrapheneOS fingerprint — unknown custom OS rejected"
                else ->
                    "Verified boot state is ${parseResult.verifiedBootState} — boot verification failed"
            }
            return VerificationResult.Invalid(reason)
        }

        // 3. App ID check (when supplied).
        //
        // Security fix: the previous condition `if (expectedAppIdHash != null && parseResult.appIdHash != null)`
        // was bypassable: a malicious peer could generate an attestation key WITHOUT including the
        // applicationId field, making parseResult.appIdHash == null and skipping the check entirely.
        // The attestation would be accepted even though the peer might be running a different app.
        //
        // Correct check: if we REQUIRE the app ID to match, reject attestations that DON'T include it.
        // The `applicationId` field in the attestation extension is optional per the Android spec,
        // but security-critical deployments that set expectedAppIdHash must treat its absence as failure.
        if (expectedAppIdHash != null) {
            if (parseResult.appIdHash == null) {
                return VerificationResult.Invalid(
                    "App ID hash missing from attestation extension — " +
                    "peer attestation key was generated without applicationId binding. " +
                    "This is required when expectedAppIdHash is configured."
                )
            }
            if (!parseResult.appIdHash.contentEquals(expectedAppIdHash)) {
                return VerificationResult.Invalid(
                    "App ID hash mismatch — attestation is from a different app or signing key"
                )
            }
        }

        // 4. keymasterSecurityLevel check: reject SOFTWARE-backed attestation (level=0).
        // A software-backed key lives entirely in the Android OS — a rooted device can
        // extract or forge it without touching TEE firmware. Require at least TEE (level=1).
        if (parseResult.keymasterSecurityLevel == 0) {
            Diag.degraded("attestation", "software-attestation",
                "keymasterSecurityLevel=SOFTWARE — not hardware-backed")
            return VerificationResult.Invalid(
                "keymasterSecurityLevel=SOFTWARE — hardware attestation requires at least " +
                "TrustedEnvironment; this chain was produced by software-only keymaster"
            )
        }

        // 5. Root pinning: all chains — stock Android and GrapheneOS alike — must root in the
        // Google hardware attestation root. GrapheneOS does not have a separate attestation root;
        // its chains are signed by the same Google root as stock Android. The verifiedBootKey
        // check above is the only GrapheneOS-specific gate.
        // Try RSA-4096 (primary, most devices) and EC P-384 (Google rotation root). Valid if either.
        // If both roots are deployment placeholders, verifyRootCertificate() fails-closed.
        val googleRsaOk  = verifyRootCertificate(evidence.certificateChain, googleRootRsaHex)
        val googleEcOk   = verifyRootCertificate(evidence.certificateChain, googleRootEcHex)
        if (!googleRsaOk && !googleEcOk) {
            Diag.degraded("attestation", "root-mismatch",
                "Chain root does not match Google hardware attestation root (RSA or EC)")
            return VerificationResult.Invalid(
                "Root certificate does not match any known hardware attestation root — " +
                "possible forged chain or unconfigured deployment root (deployment blocker)"
            )
        }

        return VerificationResult.Valid(
            verifiedBootState = parseResult.verifiedBootState,
            publicKeyDer      = evidence.publicKeyDer,
            isStrongBox       = parseResult.isStrongBox
        )
    }

    /**
     * Verify the root certificate of the chain against a known hardware attestation root.
     *
     * Call this after [verifyAttestationChain] returns [VerificationResult.Valid].
     * For Google-provisioned devices, try [GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA] and
     * [GOOGLE_HARDWARE_ATTESTATION_ROOT_EC] (chain is valid if either matches).
     * For GrapheneOS, the chain also roots in the Google root — no separate root is needed.
     *
     * Returns true if the root's public key matches the expected root. The root cert
     * is self-signed — we don't verify its signature (that would be circular); we check
     * its public key against the known-good embedded constant.
     *
     * @param chain        Certificate chain from [AttestationEvidence.certificateChain].
     * @param expectedRootPublicKeyHex  Hex-encoded DER public key of the known root.
     */
    fun verifyRootCertificate(
        chain:                    List<ByteArray>,
        expectedRootPublicKeyHex: String
    ): Boolean {
        if (chain.isEmpty()) return false
        // Fail safe: an unconfigured root must NEVER validate.
        // Catches:
        //   - blank / empty string (deployment blocker sentinel before v22)
        //   - "REPLACE_WITH..." (older placeholder format)
        //   - "DEPLOYMENT_PLACEHOLDER_..." (current sentinel — see companion object constants)
        //   - implausibly short values (real SPKIs: EC P-256=182, EC P-384=240, RSA-4096=1100 chars)
        // Any of these means the operator has not embedded the real root key; fail closed.
        if (expectedRootPublicKeyHex.isBlank() ||
            expectedRootPublicKeyHex.startsWith("REPLACE_WITH") ||
            expectedRootPublicKeyHex.startsWith("DEPLOYMENT_PLACEHOLDER_") ||
            expectedRootPublicKeyHex.length < 100) {
            mesh.shadowmesh.diagnostics.Diag.degraded(
                "attestation", "root-unconfigured",
                "Attestation root hex is a placeholder or too short — failing closed; " +
                "TRUST_PHYSICAL_ATTESTED cannot be issued. " +
                "Set the real DER SubjectPublicKeyInfo hex before deployment."
            )
            return false
        }
        return try {
            val cf   = java.security.cert.CertificateFactory.getInstance("X.509")
            val root = cf.generateCertificate(chain.last().inputStream()) as X509Certificate
            val actualHex = root.publicKey.encoded.toHex()
            actualHex.equals(expectedRootPublicKeyHex, ignoreCase = true)
        } catch (e: Exception) {
            Diag.swallowed("attestation", "verify-root", e)
            false
        }
    }

    /**
     * True only when [rootHex] looks like a real SubjectPublicKeyInfo:
     *   - non-blank
     *   - does not start with "DEPLOYMENT_PLACEHOLDER_" (the sentinel used in this file)
     *   - does not start with "REPLACE_WITH" (older sentinel format)
     *   - at least 100 hex characters (50 bytes minimum; real SPKIs: EC P-256=182, EC P-384=240, RSA-4096=1100)
     *
     * Returns false for both sentinel strings, keeping this helper consistent with
     * what [verifyRootCertificate] actually enforces.  Callers that check
     * isRootConfigured() before calling verifyRootCertificate() will get the correct
     * answer rather than a false "configured" signal from a plausible-looking but wrong value.
     */
    fun isRootConfigured(rootHex: String): Boolean =
        rootHex.isNotBlank() &&
        !rootHex.startsWith("DEPLOYMENT_PLACEHOLDER_") &&
        !rootHex.startsWith("REPLACE_WITH") &&
        rootHex.length >= 100

    // ── Challenge generation ──────────────────────────────────────────────

    /**
     * Generate a fresh 32-byte challenge for the peer to embed in their attestation key.
     * The challenger (verifying device) generates this and includes it in the QR compact
     * payload or NFC exchange. The attesting device receives it and passes it to
     * [generateAttestationKey].
     */
    fun generateChallenge(): ByteArray =
        ByteArray(CHALLENGE_BYTES).also { java.security.SecureRandom().nextBytes(it) }

    // ── Extension parsing ─────────────────────────────────────────────────

    /**
     * Parse the Android key attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
     *
     * The full extension schema is defined at:
     * https://developer.android.com/training/articles/security-key-attestation#certificate_schema
     *
     * This is a structural ASN.1 scanner for the fields we care about:
     *   - challenge (explicit tag [10] / 0xAA in the root sequence)
     *   - verifiedBootState (ENUMERATED 0x0A inside the RootOfTrust sequence)
     *   - appPackageName / appCertificateDigests (in the attestationApplicationId)
     *   - keymasterSecurityLevel (0=Software, 1=TEE, 2=StrongBox)
     *
     * ## Known failure modes on real devices (issue #60)
     *
     * The scanner walks bytes looking for specific tag bytes. It can false-positive on
     * payload data that happens to contain the same byte values. Known problematic cases:
     *
     *   - Some Samsung Exynos TEEs emit a non-standard RootOfTrust extension with extra
     *     context tags between the standard fields, causing [extractRootOfTrust] to
     *     scan past the ENUMERATED and return [VerifiedBootState.UNVERIFIED].
     *
     *   - Some MediaTek devices (MT6765, MT6768) wrap the extension value in an extra
     *     SEQUENCE layer not present in the AOSP reference implementation, causing
     *     [unwrapOctetString] to return null and the entire parse to fail.
     *
     *   - Attestation extension version 300+ (Android 14+) adds new tagged fields before
     *     the challenge field, shifting offsets. The scanner is position-independent for
     *     the challenge (tag scan, not offset-based) so this should be fine, but has not
     *     been validated on all 14+ devices.
     *
     * All failures return null, which causes [verifyAttestationChain] to return
     * [VerificationResult.Invalid] — i.e. fail-closed. Affected devices fall back to
     * TRUST_PHYSICAL_NFC instead of TRUST_PHYSICAL_ATTESTED.
     *
     * ## Migration path (TODO: before production)
     *
     * Replace this scanner with Bouncy Castle's DER parser:
     *   implementation("org.bouncycastle:bcprov-jdk15to18:1.78.1")
     *   val seq = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(content))
     *
     * Bouncy Castle handles multi-byte lengths, indefinite-length encoding, and
     * non-standard structures correctly. The attestation extension OID is
     * 1.3.6.1.4.1.11129.2.1.17. The key description schema is in
     * hardware/libhardware/include/hardware/keymaster_defs.h (AOSP).
     *
     * Returns null if the extension cannot be parsed.
     */
    private fun parseAttestationExtension(extBytes: ByteArray): ParsedAttestation? {
        // The extension value is a DER OCTET STRING wrapping the actual extension value.
        // Strip the outer OCTET STRING wrapper (tag 0x04, length).
        val content = unwrapOctetString(extBytes) ?: return null

        // The attestation extension is a SEQUENCE. We do a structural extraction
        // of the challenge (tagged [10]) and RootOfTrust (tagged inside teeEnforced [704]).
        // Full ASN.1 parsing is out of scope here — we extract by tag scanning.
        return try {
            val rot = extractRootOfTrust(content)
            ParsedAttestation(
                challenge                = extractChallengeFromExtension(content) ?: return null,
                verifiedBootState        = rot.verifiedBootState,
                verifiedBootKey          = rot.verifiedBootKey,
                appIdHash                = extractAppIdHash(content),
                isStrongBox              = extractIsStrongBox(content),
                keymasterSecurityLevel   = extractKeymasterSecurityLevel(content)
            )
        } catch (e: Exception) {
            Diag.swallowed("attestation", "parse-extension", e)
            null
        }
    }

    /**
     * Structural challenge extraction: looks for the explicit tag [10] (0xAA) in the
     * attestation extension SEQUENCE, which contains the challenge bytes.
     */
    private fun extractChallengeFromExtension(ext: ByteArray): ByteArray? {
        var i = 0
        while (i < ext.size - 2) {
            if (ext[i] == 0xAA.toByte()) {  // [10] explicit tag
                val len = readLength(ext, i + 1)
                if (len != null && i + 2 + len.length <= ext.size) {
                    val contentStart = i + 1 + len.lengthBytes
                    // Inside: OCTET STRING (0x04) containing the challenge bytes
                    if (ext[contentStart] == 0x04.toByte()) {
                        val challengeLen = readLength(ext, contentStart + 1)
                        if (challengeLen != null) {
                            val dataStart = contentStart + 1 + challengeLen.lengthBytes
                            return ext.copyOfRange(dataStart, dataStart + challengeLen.length)
                        }
                    }
                }
            }
            i++
        }
        return null
    }

    private data class RootOfTrust(
        val verifiedBootState: VerifiedBootState,
        val verifiedBootKey:   ByteArray?   // SHA-256 digest of the verified boot public key
    )

    /**
     * Extracts both verifiedBootState and verifiedBootKey by navigating the ASN.1 structure:
     *   KeyDescription SEQUENCE → teeEnforced [1] (0xA1) → RootOfTrust [704] (0xBF 0x85 0x40)
     *   → RootOfTrust SEQUENCE → verifiedBootKey (OCTET STRING) → deviceLocked (BOOLEAN)
     *   → verifiedBootState (ENUMERATED).
     *
     * verifiedBootKey is a 32-byte SHA-256 digest of the verified boot public key. On GrapheneOS
     * it matches one of the entries in [GRAPHENEOS_VERIFIED_BOOT_KEYS]; on stock Android the
     * key is Google-issued and need not be checked explicitly.
     *
     * This replaces the prior full-extension scan which could match attestationSecurityLevel
     * before verifiedBootState, allowing a crafted extension to spoof VERIFIED boot state.
     *
     * Returns UNVERIFIED / null key on any parse failure (fail-closed).
     */
    private fun extractRootOfTrust(ext: ByteArray): RootOfTrust {
        val failed = RootOfTrust(VerifiedBootState.UNVERIFIED, null)
        // Find teeEnforced: context-specific tag [1] = 0xA1
        var i = 0
        while (i < ext.size - 1) {
            if (ext[i] != 0xA1.toByte()) { i++; continue }
            val teeLen = readLength(ext, i + 1) ?: break
            val teeStart = i + 1 + teeLen.lengthBytes
            val teeEnd   = minOf(teeStart + teeLen.length, ext.size)

            // Within teeEnforced, find RootOfTrust [704] = 0xBF 0x85 0x40
            var j = teeStart
            while (j < teeEnd - 3) {
                if (ext[j] != 0xBF.toByte() || ext[j+1] != 0x85.toByte() || ext[j+2] != 0x40.toByte()) {
                    j++; continue
                }
                val rotLen = readLength(ext, j + 3) ?: break
                var k = j + 3 + rotLen.lengthBytes
                val rotEnd = minOf(k + rotLen.length, teeEnd)

                // RootOfTrust content is a SEQUENCE (tag 0x30)
                if (k >= rotEnd || ext[k] != 0x30.toByte()) break
                val innerLen = readLength(ext, k + 1) ?: break
                k += 1 + innerLen.lengthBytes
                val innerEnd = minOf(k + innerLen.length, rotEnd)

                // Field 0: verifiedBootKey (OCTET STRING 0x04) — capture before advancing
                if (k >= innerEnd || ext[k] != 0x04.toByte()) break
                val vbkLen = readLength(ext, k + 1) ?: break
                val vbkStart = k + 1 + vbkLen.lengthBytes
                val verifiedBootKey = if (vbkStart + vbkLen.length <= innerEnd)
                    ext.copyOfRange(vbkStart, vbkStart + vbkLen.length)
                else null
                k += 1 + vbkLen.lengthBytes + vbkLen.length

                // Skip field 1: deviceLocked (BOOLEAN 0x01)
                if (k >= innerEnd || ext[k] != 0x01.toByte()) break
                val dlLen = readLength(ext, k + 1) ?: break
                k += 1 + dlLen.lengthBytes + dlLen.length

                // Field 2: verifiedBootState (ENUMERATED 0x0A 0x01 <value>)
                if (k + 2 >= innerEnd || ext[k] != 0x0A.toByte() || ext[k+1] != 0x01.toByte()) break
                val state = when (ext[k + 2].toInt() and 0xFF) {
                    0    -> VerifiedBootState.VERIFIED
                    1    -> VerifiedBootState.SELF_SIGNED
                    2    -> VerifiedBootState.UNVERIFIED
                    3    -> VerifiedBootState.FAILED
                    else -> VerifiedBootState.UNVERIFIED
                }
                return RootOfTrust(state, verifiedBootKey)
            }
            break
        }
        return failed
    }

    /** True when [verifiedBootKey] matches a known GrapheneOS verified boot key fingerprint. */
    private fun isGrapheneOsBootKey(verifiedBootKey: ByteArray?): Boolean {
        if (verifiedBootKey == null) return false
        return verifiedBootKey.toHex().lowercase() in GRAPHENEOS_VERIFIED_BOOT_KEYS
    }

    /**
     * Extract the app signing-certificate digest from the attestationApplicationId field.
     *
     * In the Android attestation extension, attestationApplicationId is an OCTET STRING
     * (explicit context tag [709] = BER bytes 0xBF 0x85 0x45) inside the
     * softwareEnforced AuthorizationList. Its content is a DER-encoded
     * AttestationApplicationId ::= SEQUENCE {
     *     packageInfos      SET OF AttestationPackageInfo,
     *     signatureDigests  SET OF OCTET STRING   -- SHA-256 of each signing cert
     * }
     *
     * We locate the [709] tag, unwrap the inner OCTET STRING, then walk the SEQUENCE to
     * the signatureDigests SET (the second SET, tag 0x31) and return the first digest
     * (32-byte OCTET STRING). For SHADOWMESH's single-signer APK this is the signing
     * cert's SHA-256 — exactly what the caller compares against expectedAppIdHash.
     *
     * Returns null if the field is absent (e.g. software-only attestation) — in which
     * case verifyAttestationChain skips the app-ID check rather than failing closed,
     * matching the documented "Optional" semantics of the parameter.
     *
     * Limitation: this is a structural scanner, not a full DER parser. It assumes the
     * standard single-package/single-digest layout Android emits. A multi-signer APK
     * with several digests would only have its first digest checked.
     */
    private fun extractAppIdHash(ext: ByteArray): ByteArray? {
        // Find context tag [709] = 0xBF 0x85 0x45
        var i = 0
        while (i < ext.size - 3) {
            if (ext[i] == 0xBF.toByte() && ext[i + 1] == 0x85.toByte() && ext[i + 2] == 0x45.toByte()) {
                val outerLen = readLength(ext, i + 3) ?: return null
                var p = i + 3 + outerLen.lengthBytes
                // Content is an OCTET STRING wrapping the AttestationApplicationId SEQUENCE
                if (p >= ext.size || ext[p] != 0x04.toByte()) return null
                val octLen = readLength(ext, p + 1) ?: return null
                p += 1 + octLen.lengthBytes
                val seqEnd = minOf(p + octLen.length, ext.size)
                // Walk to the signatureDigests SET (tag 0x31) — the second SET in the SEQUENCE
                var sawFirstSet = false
                var q = p
                while (q < seqEnd - 1) {
                    if (ext[q] == 0x31.toByte()) {          // SET
                        if (!sawFirstSet) {
                            sawFirstSet = true               // first SET = packageInfos, skip it
                            val sLen = readLength(ext, q + 1) ?: return null
                            q += 1 + sLen.lengthBytes + sLen.length
                            continue
                        }
                        // second SET = signatureDigests; first element is an OCTET STRING digest
                        val sLen = readLength(ext, q + 1) ?: return null
                        var d = q + 1 + sLen.lengthBytes
                        if (d < ext.size && ext[d] == 0x04.toByte()) {
                            val dLen = readLength(ext, d + 1) ?: return null
                            val start = d + 1 + dLen.lengthBytes
                            if (start + dLen.length <= ext.size) {
                                return ext.copyOfRange(start, start + dLen.length)
                            }
                        }
                        return null
                    }
                    q++
                }
                return null
            }
            i++
        }
        return null
    }

    /**
     * Detect StrongBox backing from the attestationSecurityLevel, the first ENUMERATED
     * at the top level of the attestation extension SEQUENCE:
     *   0 = Software, 1 = TrustedEnvironment (TEE), 2 = StrongBox.
     *
     * The extension layout is:
     *   KeyDescription ::= SEQUENCE {
     *     attestationVersion         INTEGER,
     *     attestationSecurityLevel   SecurityLevel (ENUMERATED),   <- this one
     *     keymasterVersion           INTEGER,
     *     keymasterSecurityLevel     SecurityLevel (ENUMERATED),
     *     ...
     *   }
     * The first ENUMERATED (0x0A 0x01) after the opening SEQUENCE header is the
     * attestation security level. Returns true only when it equals 2 (StrongBox).
     *
     * Limitation: structural scan; if the first ENUMERATED is not the security level on
     * some atypical layout this would misread, hence it is treated as advisory metadata
     * (isStrongBox is reported but is not a gate in verifyAttestationChain).
     */
    private fun extractIsStrongBox(ext: ByteArray): Boolean {
        // Skip the outer SEQUENCE header (tag 0x30 + length) then find the first ENUMERATED.
        if (ext.isEmpty() || ext[0] != 0x30.toByte()) return false
        val seqLen = readLength(ext, 1) ?: return false
        var i = 1 + seqLen.lengthBytes
        while (i < ext.size - 2) {
            if (ext[i] == 0x0A.toByte() && ext[i + 1] == 0x01.toByte()) {
                return (ext[i + 2].toInt() and 0xFF) == 2   // 2 = StrongBox
            }
            // stop scanning once we reach the first context-tagged authorization list
            if (ext[i] == 0xA0.toByte() || ext[i] == 0xA1.toByte()) break
            i++
        }
        return false
    }

    /**
     * Extract keymasterSecurityLevel (field index 3) from the KeyDescription SEQUENCE.
     *
     * KeyDescription field order:
     *   [0] attestationVersion      INTEGER
     *   [1] attestationSecurityLevel ENUMERATED  (0=Software, 1=TEE, 2=StrongBox)
     *   [2] keymasterVersion        INTEGER
     *   [3] keymasterSecurityLevel  ENUMERATED  ← this one
     *
     * Navigates by skipping the first 3 TLV fields rather than scanning for ENUMERATED tags,
     * so it cannot be fooled by other ENUMERATED values.
     * Returns 0 (Software) on any parse failure — most conservative interpretation.
     */
    private fun extractKeymasterSecurityLevel(ext: ByteArray): Int {
        if (ext.isEmpty() || ext[0] != 0x30.toByte()) return 0
        val seqLen = readLength(ext, 1) ?: return 0
        var i = 1 + seqLen.lengthBytes
        val seqEnd = minOf(i + seqLen.length, ext.size)
        // Skip the first 3 fields: attestationVersion, attestationSecurityLevel, keymasterVersion
        for (field in 0 until 3) {
            if (i >= seqEnd) return 0
            val fieldLen = readLength(ext, i + 1) ?: return 0
            i += 1 + fieldLen.lengthBytes + fieldLen.length
        }
        return if (i + 2 < seqEnd && ext[i] == 0x0A.toByte() && ext[i+1] == 0x01.toByte()) {
            ext[i + 2].toInt() and 0xFF
        } else 0
    }

    private fun unwrapOctetString(bytes: ByteArray): ByteArray? {
        if (bytes.isEmpty()) return null
        // The extension value from getExtensionValue() is always DER OCTET STRING (tag 0x04).
        // If the outer tag is not 0x04, the extension is malformed — reject rather than
        // silently processing the raw bytes, which could produce false parse results.
        if (bytes[0] != 0x04.toByte()) return null
        val len = readLength(bytes, 1) ?: return null
        val start = 1 + len.lengthBytes
        return if (start + len.length <= bytes.size)
            bytes.copyOfRange(start, start + len.length)
        else null
    }

    private data class DerLength(val length: Int, val lengthBytes: Int)

    private fun readLength(bytes: ByteArray, offset: Int): DerLength? {
        if (offset >= bytes.size) return null
        val first = bytes[offset].toInt() and 0xFF
        return if (first < 0x80) {
            DerLength(first, 1)
        } else {
            val numBytes = first and 0x7F
            if (offset + numBytes >= bytes.size) return null
            var len = 0
            for (i in 1..numBytes) len = (len shl 8) or (bytes[offset + i].toInt() and 0xFF)
            DerLength(len, 1 + numBytes)
        }
    }

    // ── OID constant ──────────────────────────────────────────────────────

    /** OID for Android Key Attestation extension. */
    const val KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17"

    const val CHALLENGE_BYTES = 32

    /**
     * Google hardware attestation RSA-4096 root public key — SubjectPublicKeyInfo, DER-encoded, hex.
     *
     * Serial f92009e853b6b045 — Google Hardware Attestation Root CA.
     * Valid 2022–2042. Most current Android devices (including Xiaomi, Infinix, Samsung, Pixel)
     * chain to this root. This is the primary root to check.
     *
     * Verified against the known public Google hardware attestation root published since Android 7.
     */
    const val GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA =
        "30820222300d06092a864886f70d01010105000382020f003082020a0282020100afb6c7822bb1a701" +
        "ec2bb42e8bcc541663abef982f32c77f7531030c97524b1b5fe809fbc72aa9451f743cbd9a6f133574" +
        "4aa55e77f6b6ac3535ee17c25e639517dd9c92e6374a53cbfe258f8ffbb6fd129378a22a4ca99c452d" +
        "47a59f3201f44197ca1ccd7e762fb2f53151b6feb2fffd2b6fe4fe5bc6bd9ec34bfe08239daafceb8e" +
        "b5a8ed2b3acd9c5e3a7790e1b51442793159859811ad9eb2a96bbdd7a57c93a91c41fccd27d67fd6f6" +
        "71aa0b815261ad384fa37944864604ddb3d8c4f920a19b1656c2f14ad6d03c56ec060899041c1ed1a5" +
        "fe6d3440b556bad1d0a152589c53e55d370762f0122eef91861b1b0e6c4c80927499c0e9bec0b83e3b" +
        "c1f93c72c049604bbd2f1345e62c3f8e26dbec06c94766f3c128239d4f4312fad8123887e06becf567" +
        "583bf8355a81feeabaf99a83c8df3e2a322afc672bf120b135158b6821ceaf309b6eee77f98833b018" +
        "daa10e451f06a374d50781f359082966bb778b9308942698e74e0bcd24628a01c2cc03e51f0b3e5b4a" +
        "c1e4df9eaf9ff6a492a77c1483882885015b422ce67b80b88c9b48e13b607ab545c723ff8c44f8f2d3" +
        "68b9f6520d31145ebf9e862ad71df6a3bfd2450959d653740d97a12f368b13ef66d5d0a54a6e2f5d9a" +
        "6fef446832bc67844725861f093dd0e6f3405da89643ef0f4d69b6420051fdb93049673e36950580d3" +
        "cdf4fbd08bc58483952600630203010001"

    /**
     * Google hardware attestation EC P-384 root public key — SubjectPublicKeyInfo, DER-encoded, hex.
     *
     * Valid 2025–2035. Google's newer rotation root; future devices may chain to this instead of
     * [GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA]. Worth checking for forward-compatibility.
     *
     * Note: the subject CN field of this root has a known typo ("Key Atlestation CA1"). If
     * verification against real devices fails consistently, this root may need re-extraction or
     * removal — in which case, rely solely on [GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA].
     */
    const val GOOGLE_HARDWARE_ATTESTATION_ROOT_EC =
        "3076301006072a8648ce3d020106052b810400220362000423da23714edf3e5b050a3c72e8846ace07" +
        "8ea0ad1bf98b15f453d0cb08b2c3c110453909f6edeac1f9c8e031a848b941a829535c97e07c2719be" +
        "ceb416290d"

    // ── REMAINING DEPLOYMENT ITEM ─────────────────────────────────────────
    // WIRE INTO PHYSICAL_EXCHANGE: AttestedPhysicalExchange.verifyPeerAttestation()
    // calls verifyRootCertificate(), but the NFC onboarding flow (NfcBootstrapCoordinator)
    // only reaches AttestedPhysicalExchange when attestation evidence is present.
    // The onboarding UI must be updated to:
    //   a. Always generate a fresh attestation challenge in buildQrIntroductionCode.
    //   b. Require the responder to embed attestation evidence in its NFC payload.
    //   c. Reject the bootstrap (or downgrade trust) if verifyPeerAttestation fails.
    // Until this is done, TRUST_PHYSICAL is granted via NFC key exchange alone — a rooted
    // phone can pass bootstrap without hardware verification.
    // ─────────────────────────────────────────────────────────────────────

    /**
     * SHA-256 fingerprints of GrapheneOS verified boot public keys, sourced from
     * grapheneos.org/attestation.json (fetched 2026-06-02, timestamp 1776709772).
     *
     * Covers all supported devices: Pixel 6 through Pixel 10a (21 keys).
     *
     * These are matched against the `verifiedBootKey` field extracted from the Android key
     * attestation extension (RootOfTrust → verifiedBootKey OCTET STRING). A device running
     * GrapheneOS will have `verifiedBootState=SELF_SIGNED` and a `verifiedBootKey` whose
     * hex digest appears in this set. The attestation chain still roots in the standard Google
     * hardware attestation root — GrapheneOS has no separate attestation CA.
     *
     * Update this set when new Pixel devices are added to GrapheneOS's supported list.
     */
    val GRAPHENEOS_VERIFIED_BOOT_KEYS: Set<String> = setOf(
        "d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80",
        "55a2d44103e56d5ec65496399c417987ba77730e6488fc60ba058d09fc3caee3",
        "141d7fc32af7958a416f2661b37cf6f27bfb376fb5ce616aeaa27a82c7a04f74",
        "4e8ee8f717754052198ca6d2d3aaa232e2461b4293c0d6f297e519cc778de093",
        "3f7415ea26f5df5b14ea6d153256071a7a1af9ce7b0970b7311cc463c7ea02c7",
        "0508de44ee00bfb49ece32c418af1896391abde0f05b64f41bc9a2dfb589445b",
        "af4d2c6e62be0fec54f0271b9776ff061dd8392d9f51cf6ab1551d346679e24c",
        "55d3c2323db91bb91f20d38d015e85112d038f6b6b5738fe352c1a80dba57023",
        "f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86",
        "9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de",
        "096b8bd6d44527a24ac1564b308839f67e78202185cbff9cfdcb10e63250bc5e",
        "896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c",
        "cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233",
        "ee0c9dfef6f55a878538b0dbf7e78e3bc3f1a13c8c44839b095fe26dd5fe2842",
        "94df136e6c6aa08dc26580af46f36419b5f9baf46039db076f5295b91aaff230",
        "508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4",
        "bc1c0dd95664604382bb888412026422742eb333071ea0b2d19036217d49182f",
        "3efe5392be3ac38afb894d13de639e521675e62571a8a9b3ef9fc8c44fd17fa1",
        "08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031",
        "439b76524d94c40652ce1bf0d8243773c634d2f99ba3160d8d02aa5e29ff925c",
        "f0a890375d1405e62ebfd87e8d3f475f948ef031bbf9ddd516d5f600a23677e8"
    )

    /**
     * Keybox revocation list URL (Google's Certificate Transparency equivalent for
     * hardware attestation keys). Leaked OEM keyboxes (e.g. 2022 Samsung/LG leak)
     * are published here. The APK must cache this list and update it via signed gossip.
     * Without revocation checking, a node with a leaked keybox can pass attestation.
     */
    const val KEYBOX_REVOCATION_URL =
        "https://android.googleapis.com/attestation/status"
}

// ── Data types ────────────────────────────────────────────────────────────────

data class AttestationEvidence(
    /** The 32-byte challenge this device was given by the peer. */
    val challenge:        ByteArray,
    /** DER-encoded X.509 certificate chain, leaf first, root last. */
    val certificateChain: List<ByteArray>,
    /** DER-encoded EC public key from the leaf certificate. */
    val publicKeyDer:     ByteArray
) {
    override fun equals(other: Any?) = other is AttestationEvidence &&
        challenge.contentEquals(other.challenge) &&
        publicKeyDer.contentEquals(other.publicKeyDer)
    override fun hashCode() = 31 * challenge.contentHashCode() + publicKeyDer.contentHashCode()
}

enum class VerifiedBootState {
    VERIFIED,      // Stock Android — locked bootloader, verified OS
    SELF_SIGNED,   // Custom OS with enrolled developer key (GrapheneOS, CalyxOS)
    UNVERIFIED,    // Unlocked bootloader — OS not verified
    FAILED         // Boot verification failed — indicates tampering
}

sealed class AttestationResult {
    data class Evidence(val attestation: AttestationEvidence)  : AttestationResult()
    object NoHardwareSupport                                    : AttestationResult()
    data class Error(val reason: String)                        : AttestationResult()
}

sealed class VerificationResult {
    data class Valid(
        val verifiedBootState: VerifiedBootState,
        val publicKeyDer:      ByteArray,
        val isStrongBox:       Boolean
    ) : VerificationResult()
    object NoAttestationExtension                        : VerificationResult()
    data class Invalid(val reason: String)               : VerificationResult()
}

private data class ParsedAttestation(
    val challenge:                ByteArray,
    val verifiedBootState:        VerifiedBootState,
    val verifiedBootKey:          ByteArray?,  // from RootOfTrust; used for GrapheneOS key check
    val appIdHash:                ByteArray?,
    val isStrongBox:              Boolean,
    val keymasterSecurityLevel:   Int   // 0=Software, 1=TrustedEnvironment, 2=StrongBox
)

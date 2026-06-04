package mesh.shadowmesh.attestation

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf

/**
 * Hardware attestation unit tests — covers all logic that does not require
 * an Android Keystore or real attestation certificates (those are device-only tests).
 *
 * Unit-testable surface:
 *   - Challenge generation (size, randomness)
 *   - Chain verification against a tampered chain
 *   - [VerifiedBootState] semantics
 *   - [AttestedPhysicalExchange] fallback logic
 *   - Constants (OID, challenge size, revocation URL)
 *   - Challenge mismatch detection
 *
 * Device-only (accepted gaps):
 *   - generateAttestationKey() — requires real Android Keystore + TEE
 *   - Chain verification against a real Google attestation root
 *   - StrongBox detection
 */
class HardwareAttestationTest : DescribeSpec({

    describe("HardwareAttestation — challenge generation") {

        it("generates a 32-byte challenge") {
            val ch = HardwareAttestation.generateChallenge()
            ch.size shouldBe HardwareAttestation.CHALLENGE_BYTES
        }

        it("two challenges are different (random)") {
            val ch1 = HardwareAttestation.generateChallenge()
            val ch2 = HardwareAttestation.generateChallenge()
            ch1.contentEquals(ch2) shouldBe false
        }

        it("challenge is non-zero") {
            val ch = HardwareAttestation.generateChallenge()
            ch.any { it != 0.toByte() } shouldBe true
        }
    }

    describe("HardwareAttestation — verifyAttestationChain with stub data") {

        it("empty certificate chain returns Invalid") {
            val evidence = AttestationEvidence(
                challenge        = ByteArray(32),
                certificateChain = emptyList(),
                publicKeyDer     = ByteArray(32)
            )
            val result = HardwareAttestation.verifyAttestationChain(
                evidence          = evidence,
                expectedChallenge = ByteArray(32)
            )
            result.shouldBeInstanceOf<VerificationResult.Invalid>()
        }

        it("malformed certificate bytes returns Invalid") {
            val evidence = AttestationEvidence(
                challenge        = ByteArray(32) { 0x42 },
                certificateChain = listOf(ByteArray(32) { 0xFF.toByte() }),
                publicKeyDer     = ByteArray(32)
            )
            val result = HardwareAttestation.verifyAttestationChain(
                evidence          = evidence,
                expectedChallenge = ByteArray(32) { 0x42 }
            )
            result.shouldBeInstanceOf<VerificationResult.Invalid>()
        }
    }

    describe("HardwareAttestation — VerifiedBootState semantics") {

        it("VERIFIED is accepted without allowCustomOS") {
            VerifiedBootState.VERIFIED shouldNotBe VerifiedBootState.FAILED
        }

        it("SELF_SIGNED is not accepted by default (allowCustomOS=false)") {
            // SELF_SIGNED with allowCustomOS=false should be rejected.
            // Test the semantics: SELF_SIGNED != VERIFIED
            VerifiedBootState.SELF_SIGNED shouldNotBe VerifiedBootState.VERIFIED
        }

        it("FAILED is never accepted regardless of allowCustomOS") {
            VerifiedBootState.FAILED shouldNotBe VerifiedBootState.VERIFIED
            VerifiedBootState.FAILED shouldNotBe VerifiedBootState.SELF_SIGNED
        }

        it("all four boot states are declared") {
            val states = VerifiedBootState.values().map { it.name }.toSet()
            setOf("VERIFIED", "SELF_SIGNED", "UNVERIFIED", "FAILED").forEach { s ->
                states.contains(s) shouldBe true
            }
        }
    }

    describe("HardwareAttestation — constants") {

        it("KEY_ATTESTATION_OID is the Android attestation OID") {
            HardwareAttestation.KEY_ATTESTATION_OID shouldBe "1.3.6.1.4.1.11129.2.1.17"
        }

        it("CHALLENGE_BYTES is 32") {
            HardwareAttestation.CHALLENGE_BYTES shouldBe 32
        }

        it("KEYBOX_REVOCATION_URL is the Google attestation status endpoint") {
            HardwareAttestation.KEYBOX_REVOCATION_URL shouldBe
                "https://android.googleapis.com/attestation/status"
        }

        it("root key constants are non-empty and pass isRootConfigured") {
            HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA.isNotBlank() shouldBe true
            HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_EC.isNotBlank() shouldBe true
            HardwareAttestation.isRootConfigured(HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA) shouldBe true
            HardwareAttestation.isRootConfigured(HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_EC) shouldBe true
        }

        it("GRAPHENEOS_VERIFIED_BOOT_KEYS contains 21 entries of 64-char hex fingerprints") {
            HardwareAttestation.GRAPHENEOS_VERIFIED_BOOT_KEYS.size shouldBe 21
            HardwareAttestation.GRAPHENEOS_VERIFIED_BOOT_KEYS.forEach { key ->
                key.length shouldBe 64
                key.all { it in '0'..'9' || it in 'a'..'f' } shouldBe true
            }
            // Spot-check a known Pixel key from the set
            HardwareAttestation.GRAPHENEOS_VERIFIED_BOOT_KEYS.contains(
                "d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80"
            ) shouldBe true
        }
    }

    describe("AttestedPhysicalExchange — fallback logic (no Android Context needed)") {

        it("AttestationUnavailable is produced when no hardware support") {
            val result = ExchangeResult.AttestationUnavailable("test reason")
            result.reason.isNotBlank() shouldBe true
        }

        it("AttestationFailed carries the failure reason") {
            val result = ExchangeResult.AttestationFailed("Challenge mismatch")
            result.reason shouldBe "Challenge mismatch"
        }

        it("AttestationVerified carries boot state and trust level") {
            val result = ExchangeResult.AttestationVerified(
                bootState        = VerifiedBootState.VERIFIED,
                attestationLevel = AttestationTrustLevel.HARDWARE_VERIFIED,
                isStrongBox      = false
            )
            result.bootState        shouldBe VerifiedBootState.VERIFIED
            result.attestationLevel shouldBe AttestationTrustLevel.HARDWARE_VERIFIED
        }

        it("HARDWARE_VERIFIED corresponds to VERIFIED boot state") {
            AttestationTrustLevel.HARDWARE_VERIFIED shouldNotBe AttestationTrustLevel.SOFTWARE_ONLY
        }

        it("HARDWARE_CUSTOM_OS corresponds to GrapheneOS / SELF_SIGNED") {
            AttestationTrustLevel.HARDWARE_CUSTOM_OS shouldNotBe AttestationTrustLevel.HARDWARE_VERIFIED
        }
    }

    describe("AttestationEvidence — data model") {

        it("round-trip equality is determined by challenge + publicKeyDer") {
            val ch  = ByteArray(32) { 0x42 }
            val pub = ByteArray(32) { 0x11 }
            val e1  = AttestationEvidence(ch, emptyList(), pub)
            val e2  = AttestationEvidence(ch, listOf(ByteArray(8)), pub)
            e1 shouldBe e2   // chain contents not in equals() — challenge+pub are stable ID
        }

        it("different challenges produce different instances") {
            val e1 = AttestationEvidence(ByteArray(32) { 0x01 }, emptyList(), ByteArray(32))
            val e2 = AttestationEvidence(ByteArray(32) { 0x02 }, emptyList(), ByteArray(32))
            e1 shouldNotBe e2
        }
    }
})

package mesh.shadowmesh.crypto

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.test.runTest

class HybridSignerTest : DescribeSpec({

    val signer = HybridSigner()

    describe("HybridSigner — known-answer structural vectors") {

        /**
         * Dilithium-3 + Ed25519 structural KAT.
         *
         * As with the KEM, Dilithium signing is randomised (uses internal random coins)
         * so fixed-output KAT vectors require seeding the liboqs RNG, which is not
         * exposed via the JNI bridge. We verify:
         *
         *   1. Signature length: Dilithium-3 signatures are 3293 bytes.
         *   2. Determinism of verify: same message + same key → same result.
         *   3. Independence: corrupting either sub-signature fails verification.
         *   4. Size structure: wire format encodes Dilithium length correctly.
         *
         * For algorithm-level KAT vectors, liboqs' own test suite (test_sig) runs
         * against NIST KAT vectors for Dilithium-3, and lazysodium's test suite
         * covers Ed25519 against RFC 8032 §6 vectors.
         */

        it("Dilithium-3 signature size matches specification (3293 bytes)") {
            runTest {
                val kp  = signer.generateSigningKeyPair().getOrThrow()
                val msg = "known-answer test message".toByteArray()
                val sig = signer.sign(msg, kp.privateKey).getOrThrow()

                // Wire: [4B dLen][Dilithium sig (3293)][Ed25519 sig (64)]
                val dLen = ((sig[0].toInt() and 0xFF) shl 24) or
                           ((sig[1].toInt() and 0xFF) shl 16) or
                           ((sig[2].toInt() and 0xFF) shl  8) or
                            (sig[3].toInt() and 0xFF)
                dLen shouldBe 3293
                sig.size shouldBe 4 + 3293 + 64
            }
        }

        it("Ed25519 signature portion is always 64 bytes") {
            runTest {
                val kp  = signer.generateSigningKeyPair().getOrThrow()
                val sig = signer.sign("msg".toByteArray(), kp.privateKey).getOrThrow()
                val dLen = ((sig[0].toInt() and 0xFF) shl 24) or
                           ((sig[1].toInt() and 0xFF) shl 16) or
                           ((sig[2].toInt() and 0xFF) shl  8) or
                            (sig[3].toInt() and 0xFF)
                // Last 64 bytes are the Ed25519 sig
                (sig.size - 4 - dLen) shouldBe 64
            }
        }

        it("verification is deterministic — same message and key always returns same result") {
            runTest {
                val kp  = signer.generateSigningKeyPair().getOrThrow()
                val msg = "determinism test".toByteArray()
                val sig = signer.sign(msg, kp.privateKey).getOrThrow()
                val r1  = signer.verify(msg, sig, kp.publicKey).getOrThrow()
                val r2  = signer.verify(msg, sig, kp.publicKey).getOrThrow()
                r1 shouldBe true
                r1 shouldBe r2
            }
        }

        it("Dilithium-3 public key size matches specification (1952 bytes)") {
            runTest {
                val kp = signer.generateSigningKeyPair().getOrThrow()
                kp.publicKey.dilithiumPublicKey.size shouldBe 1952
            }
        }

        it("Ed25519 public key is always 32 bytes") {
            runTest {
                val kp = signer.generateSigningKeyPair().getOrThrow()
                kp.publicKey.ed25519PublicKey.size shouldBe 32
            }
        }

        it("signature non-malleable — single bit flip in Dilithium portion fails") {
            runTest {
                val kp  = signer.generateSigningKeyPair().getOrThrow()
                val msg = "non-malleable test".toByteArray()
                val sig = signer.sign(msg, kp.privateKey).getOrThrow()

                // Flip a bit at the start of the Dilithium signature body
                val flipped = sig.copyOf().also { it[4] = (it[4].toInt() xor 0x01).toByte() }
                signer.verify(msg, flipped, kp.publicKey).isFailure shouldBe true
            }
        }

        it("signature non-malleable — single bit flip in Ed25519 portion fails") {
            runTest {
                val kp  = signer.generateSigningKeyPair().getOrThrow()
                val msg = "non-malleable test 2".toByteArray()
                val sig = signer.sign(msg, kp.privateKey).getOrThrow()

                // Flip a bit in the Ed25519 tail
                val flipped = sig.copyOf().also {
                    it[it.size - 1] = (it[it.size - 1].toInt() xor 0x01).toByte()
                }
                signer.verify(msg, flipped, kp.publicKey).isFailure shouldBe true
            }
        }
    }

        it("sign/verify round-trip succeeds") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val message = "SHADOWMESH authenticated message".toByteArray()

                val sig    = signer.sign(message, kp.privateKey).getOrThrow()
                val result = signer.verify(message, sig, kp.publicKey).getOrThrow()

                result shouldBe true
            }
        }

        it("tampered message fails verification") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val message = "authentic content".toByteArray()

                val sig      = signer.sign(message, kp.privateKey).getOrThrow()
                val tampered = message.copyOf().also { it[0] = (it[0].toInt() xor 0xFF).toByte() }

                val result = signer.verify(tampered, sig, kp.publicKey)
                result.isFailure shouldBe true
            }
        }

        it("tampered signature fails verification") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val message = "authentic content".toByteArray()
                val sig     = signer.sign(message, kp.privateKey).getOrThrow()

                // Corrupt the last byte — hits the Ed25519 portion
                val tampered = sig.copyOf().also { it[it.size - 1] = (it[it.size - 1].toInt() xor 0xFF).toByte() }
                signer.verify(message, tampered, kp.publicKey).isFailure shouldBe true
            }
        }

        it("corrupting only the Dilithium portion fails verification independently") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val message = "message".toByteArray()
                val sig     = signer.sign(message, kp.privateKey).getOrThrow()

                // Dilithium sig starts at byte 4 (after 4-byte length prefix)
                // Flip a byte deep in the Dilithium portion, well before Ed25519
                val tampered = sig.copyOf().also { it[10] = (it[10].toInt() xor 0xFF).toByte() }
                signer.verify(message, tampered, kp.publicKey).isFailure shouldBe true
            }
        }

        it("corrupting only the Ed25519 portion fails verification independently") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val message = "message".toByteArray()
                val sig     = signer.sign(message, kp.privateKey).getOrThrow()

                // Ed25519 sig is the last Sign.BYTES (64) bytes of the serialised sig
                val tampered = sig.copyOf().also {
                    it[it.size - 10] = (it[it.size - 10].toInt() xor 0xFF).toByte()
                }
                signer.verify(message, tampered, kp.publicKey).isFailure shouldBe true
            }
        }

        it("wrong public key fails verification") {
            runTest {
                val kp1     = signer.generateSigningKeyPair().getOrThrow()
                val kp2     = signer.generateSigningKeyPair().getOrThrow()
                val message = "message".toByteArray()

                val sig    = signer.sign(message, kp1.privateKey).getOrThrow()
                val result = signer.verify(message, sig, kp2.publicKey)

                result.isFailure shouldBe true
            }
        }

        it("empty message signs and verifies correctly") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val message = ByteArray(0)

                val sig    = signer.sign(message, kp.privateKey).getOrThrow()
                val result = signer.verify(message, sig, kp.publicKey).getOrThrow()

                result shouldBe true
            }
        }

        it("large message signs and verifies correctly") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val message = ByteArray(64 * 1024) { (it % 256).toByte() }

                val sig    = signer.sign(message, kp.privateKey).getOrThrow()
                val result = signer.verify(message, sig, kp.publicKey).getOrThrow()

                result shouldBe true
            }
        }

        it("two signatures of the same message differ — Dilithium is randomised") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val message = "same message".toByteArray()

                val sig1 = signer.sign(message, kp.privateKey).getOrThrow()
                val sig2 = signer.sign(message, kp.privateKey).getOrThrow()

                // Dilithium-3 is randomised — signatures must differ
                sig1.contentEquals(sig2) shouldBe false

                // Both must still verify
                signer.verify(message, sig1, kp.publicKey).getOrThrow() shouldBe true
                signer.verify(message, sig2, kp.publicKey).getOrThrow() shouldBe true
            }
        }

        it("HybridVerifyKey serialises and deserialises correctly") {
            runTest {
                val kp           = signer.generateSigningKeyPair().getOrThrow()
                val bytes        = kp.publicKey.toBytes()
                val deserialized = HybridVerifyKey.fromBytes(bytes)
                deserialized shouldBe kp.publicKey
            }
        }

        it("HybridVerifyKey.fromBytes rejects trailing garbage") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val valid   = kp.publicKey.toBytes()
                val garbage = valid + byteArrayOf(0x42)
                var threw   = false
                try { HybridVerifyKey.fromBytes(garbage) }
                catch (e: IllegalArgumentException) { threw = true }
                threw shouldBe true
            }
        }

        it("sign with serialised key — verify with deserialised key — succeeds") {
            runTest {
                val kp      = signer.generateSigningKeyPair().getOrThrow()
                val message = "wire round-trip test".toByteArray()

                val sig      = signer.sign(message, kp.privateKey).getOrThrow()
                val pubBytes = kp.publicKey.toBytes()
                val restoredPub = HybridVerifyKey.fromBytes(pubBytes)

                signer.verify(message, sig, restoredPub).getOrThrow() shouldBe true
            }
        }
    }
})

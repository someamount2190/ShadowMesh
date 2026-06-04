package mesh.shadowmesh.crypto

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.test.runTest

class TrustCredentialTest : DescribeSpec({

    val hkdf         = Hkdf()
    val kem          = HybridKem(hkdf)
    val signer       = HybridSigner()
    val gen          = NodeIdentityGenerator(kem, signer, hkdf)
    val credSigner   = TrustCredentialSigner(signer)

    describe("TrustCredential — issuance and verification") {

        it("physical credential verifies correctly") {
            runTest {
                val introducer = gen.generate().getOrThrow()
                val node       = gen.generate().getOrThrow()

                val unsigned = TrustCredential.physical(node.nodeId, introducer.nodeId)
                val cred     = credSigner.sign(unsigned, introducer.privatePart.signingPrivateKey).getOrThrow()

                cred.trustLevel shouldBe TrustLevel.TRUST_PHYSICAL
                val valid = credSigner.verify(cred, introducer.publicPart.signingPublicKey).getOrThrow()
                valid shouldBe true
            }
        }

        it("introduced credential verifies correctly") {
            runTest {
                val introducer = gen.generate().getOrThrow()
                val node       = gen.generate().getOrThrow()

                val unsigned = TrustCredential.introduced(node.nodeId, introducer.nodeId)
                val cred     = credSigner.sign(unsigned, introducer.privatePart.signingPrivateKey).getOrThrow()

                cred.trustLevel shouldBe TrustLevel.TRUST_INTRODUCED
                credSigner.verify(cred, introducer.publicPart.signingPublicKey).getOrThrow() shouldBe true
            }
        }

        it("verification fails with wrong verify key") {
            runTest {
                val introducer = gen.generate().getOrThrow()
                val attacker   = gen.generate().getOrThrow()
                val node       = gen.generate().getOrThrow()

                val cred = credSigner.sign(
                    TrustCredential.physical(node.nodeId, introducer.nodeId),
                    introducer.privatePart.signingPrivateKey
                ).getOrThrow()

                val result = credSigner.verify(cred, attacker.publicPart.signingPublicKey)
                result.isSuccess shouldBe false
            }
        }

        it("credential round-trips through toBytes / fromBytes") {
            runTest {
                val introducer = gen.generate().getOrThrow()
                val node       = gen.generate().getOrThrow()
                val cred       = credSigner.sign(
                    TrustCredential.physical(node.nodeId, introducer.nodeId),
                    introducer.privatePart.signingPrivateKey
                ).getOrThrow()

                val bytes      = cred.toBytes()
                val deserialized = TrustCredential.fromBytes(bytes)

                deserialized.trustLevel shouldBe cred.trustLevel
                deserialized.nodeId.contentEquals(cred.nodeId) shouldBe true
                deserialized.issuedAtMs shouldBe cred.issuedAtMs
                deserialized.signature.contentEquals(cred.signature) shouldBe true
            }
        }
    }

    describe("TrustCredential — transitivity cap") {

        it("TRUST_PHYSICAL grants TRUST_PHYSICAL on physical introduction") {
            runTest {
                val introducer = gen.generate().getOrThrow()
                val cred       = credSigner.sign(
                    TrustCredential.physical(ByteArray(32), introducer.nodeId),
                    introducer.privatePart.signingPrivateKey
                ).getOrThrow()

                cred.grantableTrustLevel(IntroductionMethod.PHYSICAL) shouldBe TrustLevel.TRUST_PHYSICAL
            }
        }

        it("TRUST_PHYSICAL grants only TRUST_INTRODUCED on remote introduction") {
            runTest {
                val introducer = gen.generate().getOrThrow()
                val cred       = credSigner.sign(
                    TrustCredential.physical(ByteArray(32), introducer.nodeId),
                    introducer.privatePart.signingPrivateKey
                ).getOrThrow()

                cred.grantableTrustLevel(IntroductionMethod.REMOTE) shouldBe TrustLevel.TRUST_INTRODUCED
            }
        }

        it("TRUST_INTRODUCED can only grant TRUST_PUBLIC — chain capped") {
            runTest {
                val introducer = gen.generate().getOrThrow()
                val cred       = credSigner.sign(
                    TrustCredential.introduced(ByteArray(32), introducer.nodeId),
                    introducer.privatePart.signingPrivateKey
                ).getOrThrow()

                cred.grantableTrustLevel(IntroductionMethod.PHYSICAL) shouldBe TrustLevel.TRUST_PUBLIC
                cred.grantableTrustLevel(IntroductionMethod.REMOTE)   shouldBe TrustLevel.TRUST_PUBLIC
            }
        }

        it("TRUST_PUBLIC can only grant TRUST_PUBLIC") {
            runTest {
                val node = gen.generate().getOrThrow()
                val cred = credSigner.sign(
                    TrustCredential.selfIssued(node.nodeId),
                    node.privatePart.signingPrivateKey
                ).getOrThrow()

                cred.grantableTrustLevel(IntroductionMethod.PHYSICAL) shouldBe TrustLevel.TRUST_PUBLIC
                cred.grantableTrustLevel(IntroductionMethod.REMOTE)   shouldBe TrustLevel.TRUST_PUBLIC
            }
        }
    }
})

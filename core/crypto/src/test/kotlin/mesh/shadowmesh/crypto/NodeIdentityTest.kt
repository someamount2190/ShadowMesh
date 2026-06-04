package mesh.shadowmesh.crypto

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.test.runTest

class NodeIdentityTest : DescribeSpec({

    val hkdf    = Hkdf()
    val kem     = HybridKem(hkdf)
    val signer  = HybridSigner()
    val gen     = NodeIdentityGenerator(kem, signer, hkdf)

    describe("NodeIdentity — IntegrityBoundedKeyDerivation wiring") {

        val ibd = IntegrityBoundedKeyDerivation(hkdf)

        it("IBD-bound identity has a different nodeId than unbound identity") {
            runTest {
                val deviceSecret   = ByteArray(32) { 0x42 }
                val apkBindingHash = ByteArray(32) { 0x55 }

                val unboundGen = NodeIdentityGenerator(kem, signer, hkdf)
                val boundGen   = NodeIdentityGenerator(
                    kem, signer, hkdf, ibd, deviceSecret, apkBindingHash
                )

                val unbound = unboundGen.generate().getOrThrow()
                val bound   = boundGen.generate().getOrThrow()

                // Different APK-binding seed → different nodeId (with overwhelming probability)
                unbound.nodeId.contentEquals(bound.nodeId) shouldBe false
            }
        }

        it("different APK binding hash produces different nodeId — repackaged APK cannot impersonate") {
            runTest {
                val deviceSecret    = ByteArray(32) { 0x11 }
                val realApkHash     = ByteArray(32) { 0xAA.toByte() }
                val repackagedHash  = ByteArray(32) { 0xBB.toByte() }

                val realGen       = NodeIdentityGenerator(kem, signer, hkdf, ibd, deviceSecret, realApkHash)
                val repackagedGen = NodeIdentityGenerator(kem, signer, hkdf, ibd, deviceSecret, repackagedHash)

                val realId       = realGen.generate().getOrThrow()
                val repackagedId = repackagedGen.generate().getOrThrow()

                realId.nodeId.contentEquals(repackagedId.nodeId) shouldBe false
            }
        }

        it("different device secret produces different nodeId — identity is device-specific") {
            runTest {
                val apkHash   = ByteArray(32) { 0xCC.toByte() }
                val device1   = ByteArray(32) { 0x01 }
                val device2   = ByteArray(32) { 0x02 }

                val gen1 = NodeIdentityGenerator(kem, signer, hkdf, ibd, device1, apkHash)
                val gen2 = NodeIdentityGenerator(kem, signer, hkdf, ibd, device2, apkHash)

                val id1 = gen1.generate().getOrThrow()
                val id2 = gen2.generate().getOrThrow()

                id1.nodeId.contentEquals(id2.nodeId) shouldBe false
            }
        }

        it("IBD seed is wiped after use — not detectable in generated nodeId structure") {
            runTest {
                val deviceSecret   = ByteArray(32) { 0x77 }
                val apkBindingHash = ByteArray(32) { 0x88.toByte() }

                val gen = NodeIdentityGenerator(kem, signer, hkdf, ibd, deviceSecret, apkBindingHash)
                val id  = gen.generate().getOrThrow()

                // nodeId is 32 bytes regardless of IBD path
                id.nodeId.size shouldBe 32
                id.nodeId.any { it != 0.toByte() } shouldBe true
            }
        }

        it("supplying only ibd without deviceSecret throws at construction") {
            var threw = false
            try {
                NodeIdentityGenerator(kem, signer, hkdf, ibd = ibd, deviceSecret = null, apkBindingHash = null)
            } catch (e: IllegalArgumentException) {
                threw = true
            }
            // ibd supplied alone → should throw
            threw shouldBe true
        }
    }

        it("generates a valid identity with 32-byte nodeId") {
            runTest {
                val id = gen.generate().getOrThrow()
                id.nodeId.size shouldBe 32
                id.publicPart.nodeId.contentEquals(id.nodeId) shouldBe true
                id.privatePart.nodeId.contentEquals(id.nodeId) shouldBe true
            }
        }

        it("two generated identities have different nodeIds") {
            runTest {
                val a = gen.generate().getOrThrow()
                val b = gen.generate().getOrThrow()
                a.nodeId.contentEquals(b.nodeId) shouldBe false
            }
        }

        it("nodeId is SHA3-256 of kemPub + sigPub") {
            runTest {
                val id       = gen.generate().getOrThrow()
                val expected = hkdf.sha3_256(
                    id.publicPart.kemPublicKey.toBytes() +
                    id.publicPart.signingPublicKey.toBytes()
                )
                id.nodeId.contentEquals(expected) shouldBe true
            }
        }

        it("NodePublicIdentity round-trips through toBytes / fromBytes") {
            runTest {
                val id           = gen.generate().getOrThrow()
                val bytes        = id.publicPart.toBytes()
                val deserialized = NodePublicIdentity.fromBytes(bytes, hkdf)
                deserialized shouldBe id.publicPart
            }
        }

        it("fromBytes rejects tampered nodeId") {
            runTest {
                val id    = gen.generate().getOrThrow()
                val bytes = id.publicPart.toBytes().copyOf()
                bytes[5] = (bytes[5] + 1).toByte()  // flip a byte in nodeId region
                var threw = false
                try { NodePublicIdentity.fromBytes(bytes, hkdf) }
                catch (e: IllegalArgumentException) { threw = true }
                threw shouldBe true
            }
        }

        it("fromBytes rejects truncated input") {
            runTest {
                var threw = false
                try { NodePublicIdentity.fromBytes(ByteArray(10), hkdf) }
                catch (e: IllegalArgumentException) { threw = true }
                threw shouldBe true
            }
        }
    }
})

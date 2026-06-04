package mesh.shadowmesh.crypto

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import kotlinx.coroutines.test.runTest

class NodeCallsignTest : DescribeSpec({

    val hkdf    = Hkdf()
    val kem     = HybridKem(hkdf)
    val signer  = HybridSigner()
    val gen     = NodeIdentityGenerator(kem, signer, hkdf)
    val mgr     = NodeCallsignManager(signer)

    describe("NodeCallsign — issuance and verification") {

        it("issues a valid callsign for a node identity") {
            runTest {
                val identity = gen.generate().getOrThrow()
                val cs = mgr.issueCallsign(identity, "ALPHA-1").getOrThrow()
                cs.callsign shouldBe "ALPHA-1"
                cs.nodeId.contentEquals(identity.nodeId) shouldBe true
            }
        }

        it("normalises callsign to uppercase") {
            runTest {
                val identity = gen.generate().getOrThrow()
                val cs = mgr.issueCallsign(identity, "bravo-2").getOrThrow()
                cs.callsign shouldBe "BRAVO-2"
            }
        }

        it("rejects callsign longer than 16 chars") {
            runTest {
                val identity = gen.generate().getOrThrow()
                var threw = false
                try { mgr.issueCallsign(identity, "TOOLONGCALLSIGNXYZ").getOrThrow() }
                catch (e: Exception) { threw = true }
                threw shouldBe true
            }
        }

        it("rejects callsign with invalid characters") {
            runTest {
                val identity = gen.generate().getOrThrow()
                var threw = false
                try { mgr.issueCallsign(identity, "alpha_1").getOrThrow() }
                catch (e: Exception) { threw = true }
                threw shouldBe true
            }
        }

        it("round-trips through toBytes / fromBytes") {
            runTest {
                val identity = gen.generate().getOrThrow()
                val cs       = mgr.issueCallsign(identity, "DELTA-3").getOrThrow()
                val bytes    = cs.toBytes()
                val parsed   = NodeCallsign.fromBytes(bytes)
                parsed.callsign shouldBe cs.callsign
                parsed.nodeId.contentEquals(cs.nodeId) shouldBe true
                parsed.issuedAtMs shouldBe cs.issuedAtMs
                parsed.signature.contentEquals(cs.signature) shouldBe true
            }
        }

        it("verifies a valid peer callsign") {
            runTest {
                val alice   = gen.generate().getOrThrow()
                val cs      = mgr.issueCallsign(alice, "ECHO-5").getOrThrow()
                val result  = mgr.receiveAndVerify(cs, alice.publicPart)
                result shouldNotBe null
                result!!.callsign shouldBe "ECHO-5"
            }
        }

        it("rejects a callsign with wrong nodeId") {
            runTest {
                val alice = gen.generate().getOrThrow()
                val bob   = gen.generate().getOrThrow()
                val cs    = mgr.issueCallsign(alice, "FOXTROT-6").getOrThrow()
                // Present Alice's callsign but claim it belongs to Bob
                val result = mgr.receiveAndVerify(cs, bob.publicPart)
                result shouldBe null
            }
        }

        it("rejects a tampered callsign") {
            runTest {
                val alice  = gen.generate().getOrThrow()
                val cs     = mgr.issueCallsign(alice, "GOLF-7").getOrThrow()
                val bytes  = cs.toBytes().copyOf()
                bytes[10]  = (bytes[10] + 1).toByte()  // tamper payload
                val parsed = NodeCallsign.fromBytes(bytes)
                val result = mgr.receiveAndVerify(parsed, alice.publicPart)
                result shouldBe null
            }
        }
    }

    describe("NodeCallsignManager — display name resolution") {

        it("returns callsign display form when verified") {
            runTest {
                val alice   = gen.generate().getOrThrow()
                val cs      = mgr.issueCallsign(alice, "HOTEL-8").getOrThrow()
                mgr.receiveAndVerify(cs, alice.publicPart)
                val nodeIdHex = alice.nodeId.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                mgr.displayName(nodeIdHex) shouldBe cs.displayName()
            }
        }

        it("local nickname overrides callsign") {
            runTest {
                val alice     = gen.generate().getOrThrow()
                val cs        = mgr.issueCallsign(alice, "INDIA-9").getOrThrow()
                mgr.receiveAndVerify(cs, alice.publicPart)
                val nodeIdHex = alice.nodeId.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                mgr.setLocalNickname(nodeIdHex, "Reyes")
                mgr.displayName(nodeIdHex) shouldBe "Reyes"
            }
        }

        it("falls back to Unknown when no callsign and no nickname") {
            val unknownHex = "0".repeat(64)
            mgr.displayName(unknownHex) shouldBe "Unknown (00000000…)"
        }

        it("clearing local nickname reverts to callsign") {
            runTest {
                val alice     = gen.generate().getOrThrow()
                val cs        = mgr.issueCallsign(alice, "JULIET-10").getOrThrow()
                mgr.receiveAndVerify(cs, alice.publicPart)
                val nodeIdHex = alice.nodeId.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                mgr.setLocalNickname(nodeIdHex, "Santos")
                mgr.displayName(nodeIdHex) shouldBe "Santos"
                mgr.clearLocalNickname(nodeIdHex)
                mgr.displayName(nodeIdHex) shouldBe cs.displayName()
            }
        }
    }
})

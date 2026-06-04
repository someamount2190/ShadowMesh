package mesh.shadowmesh.crypto

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

/**
 * Unit tests for [SignedContact], [VerifyResult], and [ContactSeqCounter].
 * Pure JVM — no Android, no core/mesh dependencies.
 *
 * [addressBytes] is passed as a raw ByteArray; [PeerAddress.toWireBytes] and
 * [RoutingTable] seq replay tests live in core/mesh (RoutingTableSeqTest.kt).
 */
class SignedContactTest : DescribeSpec({

    val signer = HybridSigner()
    val hkdf   = Hkdf.instance

    // 7-byte mock address bytes (IPv4 wire format: version + 4B IP + 2B port)
    val addressBytes = byteArrayOf(0x04, 192.toByte(), 168.toByte(), 1, 42, 0x1C, 0xF8.toByte())

    suspend fun makeIdentity(): Triple<NodePublicIdentity, HybridSigningKey, ByteArray> {
        val kemKp  = HybridKem(hkdf).generateKeyPair().getOrThrow()
        val sigKp  = signer.generateSigningKeyPair().getOrThrow()
        val nodeId = hkdf.sha3_256(kemKp.publicKey.toBytes() + sigKp.publicKey.toBytes())
        val pub    = NodePublicIdentity(nodeId, kemKp.publicKey, sigKp.publicKey)
        return Triple(pub, sigKp.privateKey, nodeId)
    }

    // ── ContactSeqCounter ─────────────────────────────────────────────────

    describe("ContactSeqCounter") {

        it("starts at 0") {
            ContactSeqCounter().current() shouldBe 0L
        }

        it("increments monotonically") {
            val c = ContactSeqCounter()
            c.increment() shouldBe 1L
            c.increment() shouldBe 2L
            c.increment() shouldBe 3L
        }
    }

    // ── SignedContact.sign + verifyIdentityAndSignature ───────────────────

    describe("SignedContact — self-signed contact") {

        it("verifies a freshly signed contact") {
            val (pub, priv, _) = makeIdentity()
            SignedContact.sign(pub, priv, addressBytes, seq = 0L, signer)
                .verifyIdentityAndSignature()
                .shouldBeInstanceOf<VerifyResult.Ok>()
        }

        it("Ok result contains the correct nodeId") {
            val (pub, priv, nodeId) = makeIdentity()
            val result = SignedContact.sign(pub, priv, addressBytes, seq = 0L, signer)
                .verifyIdentityAndSignature() as VerifyResult.Ok
            result.nodeId.contentEquals(nodeId) shouldBe true
        }

        it("rejects a contact with tampered addressBytes") {
            val (pub, priv, _) = makeIdentity()
            val sc       = SignedContact.sign(pub, priv, addressBytes, seq = 0L, signer)
            val tampered = sc.addressBytes.copyOf().also { it[3] = (it[3].toInt() xor 0xFF).toByte() }
            sc.copy(addressBytes = tampered)
                .verifyIdentityAndSignature()
                .shouldBeInstanceOf<VerifyResult.InvalidSignature>()
        }

        it("rejects a contact with tampered seq (signature was over original seq)") {
            val (pub, priv, _) = makeIdentity()
            val sc = SignedContact.sign(pub, priv, addressBytes, seq = 5L, signer)
            sc.copy(seq = 6L)
                .verifyIdentityAndSignature()
                .shouldBeInstanceOf<VerifyResult.InvalidSignature>()
        }

        it("rejects when nodeId is replaced with random bytes") {
            val (pub, priv, _) = makeIdentity()
            val sc        = SignedContact.sign(pub, priv, addressBytes, seq = 0L, signer)
            val badNodeId = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
            sc.copy(nodeId = badNodeId)
                .verifyIdentityAndSignature()
                .shouldBeInstanceOf<VerifyResult.IdentityMismatch>()
        }

        it("rejects when public keys are replaced with a different identity's keys") {
            val (pub1, priv1, _) = makeIdentity()
            val (pub2, _,    _)  = makeIdentity()
            // nodeId was committed to pub1's keys; replacing keys with pub2 breaks the binding
            SignedContact.sign(pub1, priv1, addressBytes, seq = 0L, signer)
                .copy(kemPublicKey = pub2.kemPublicKey, signingPublicKey = pub2.signingPublicKey)
                .verifyIdentityAndSignature()
                .shouldBeInstanceOf<VerifyResult.IdentityMismatch>()
        }

        it("different seq values produce different signed payloads") {
            val (pub, priv, _) = makeIdentity()
            val sc0 = SignedContact.sign(pub, priv, addressBytes, seq = 0L, signer)
            val sc1 = SignedContact.sign(pub, priv, addressBytes, seq = 1L, signer)
            // signedPayload() must differ (seq is part of the payload)
            sc0.signedPayload().contentEquals(sc1.signedPayload()) shouldBe false
            // Both must verify independently
            sc0.verifyIdentityAndSignature().shouldBeInstanceOf<VerifyResult.Ok>()
            sc1.verifyIdentityAndSignature().shouldBeInstanceOf<VerifyResult.Ok>()
        }
    }

    // ── Serialization round-trip ──────────────────────────────────────────

    describe("SignedContact serialization") {

        it("round-trips via toBytes / fromBytes and re-verifies") {
            val (pub, priv, nodeId) = makeIdentity()
            val sc   = SignedContact.sign(pub, priv, addressBytes, seq = 7L, signer)
            val back = SignedContact.fromBytes(sc.toBytes())

            back.nodeId.contentEquals(nodeId) shouldBe true
            back.seq shouldBe 7L
            back.addressBytes.contentEquals(addressBytes) shouldBe true
            back.verifyIdentityAndSignature().shouldBeInstanceOf<VerifyResult.Ok>()
        }

        it("fromBytes throws on truncated input") {
            val (pub, priv, _) = makeIdentity()
            val bytes = SignedContact.sign(pub, priv, addressBytes, seq = 0L, signer).toBytes()
            runCatching { SignedContact.fromBytes(bytes.copyOfRange(0, bytes.size / 2)) }
                .isFailure shouldBe true
        }

        it("corrupted key data: fromBytes succeeds but signature verification fails") {
            // Byte[10] is inside the Kyber key payload (after the 4-byte kemLen prefix).
            // The length field is intact so fromBytes parses successfully, but derives
            // a different nodeId from the corrupted key. The original signature was
            // computed over the original nodeId, so verifyIdentityAndSignature fails.
            val (pub, priv, _) = makeIdentity()
            val original = SignedContact.sign(pub, priv, addressBytes, seq = 0L, signer)
            val bytes    = original.toBytes().copyOf()
            bytes[10]    = (bytes[10].toInt() xor 0x01).toByte()
            val corrupted = SignedContact.fromBytes(bytes)  // parse succeeds
            val result    = corrupted.verifyIdentityAndSignature()
            (result is VerifyResult.InvalidSignature || result is VerifyResult.IdentityMismatch) shouldBe true
        }

        it("corrupted length prefix: fromBytes throws") {
            val (pub, priv, _) = makeIdentity()
            val bytes = SignedContact.sign(pub, priv, addressBytes, seq = 0L, signer).toBytes().copyOf()
            bytes[0] = 0x7F; bytes[1] = 0xFF.toByte(); bytes[2] = 0xFF.toByte(); bytes[3] = 0xFF.toByte()
            runCatching { SignedContact.fromBytes(bytes) }.isFailure shouldBe true
        }

        it("seq = Long.MAX_VALUE round-trips correctly") {
            val (pub, priv, _) = makeIdentity()
            val sc   = SignedContact.sign(pub, priv, addressBytes, seq = Long.MAX_VALUE, signer)
            val back = SignedContact.fromBytes(sc.toBytes())
            back.seq shouldBe Long.MAX_VALUE
            back.verifyIdentityAndSignature().shouldBeInstanceOf<VerifyResult.Ok>()
        }
    }

    // ── HybridSigner sync wrappers ────────────────────────────────────────

    describe("HybridSigner.signSync / verifySync") {

        it("signSync produces a signature that verifySync accepts") {
            val sigKp   = signer.generateSigningKeyPair().getOrThrow()
            val message = "hello signed world".toByteArray()
            val sig     = signer.signSync(message, sigKp.privateKey)
            signer.verifySync(message, sig, sigKp.publicKey) shouldBe true
        }

        it("verifySync rejects a tampered message") {
            val sigKp   = signer.generateSigningKeyPair().getOrThrow()
            val message = "hello".toByteArray()
            val sig     = signer.signSync(message, sigKp.privateKey)
            val bad     = "world".toByteArray()
            signer.verifySync(bad, sig, sigKp.publicKey) shouldBe false
        }

        it("verifySync rejects a truncated signature") {
            val sigKp   = signer.generateSigningKeyPair().getOrThrow()
            val message = "hello".toByteArray()
            val sig     = signer.signSync(message, sigKp.privateKey)
            signer.verifySync(message, sig.copyOfRange(0, 4), sigKp.publicKey) shouldBe false
        }
    }
})

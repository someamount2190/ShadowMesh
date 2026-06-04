package mesh.shadowmesh.bootstrap

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import mesh.shadowmesh.crypto.*

class PhysicalKeyExchangeTest : DescribeSpec({

    val hkdf    = Hkdf()
    val signer  = HybridSigner()
    val kem     = HybridKem(hkdf)
    val exchange = PhysicalKeyExchange(signer, hkdf)

    suspend fun generateIdentity(): Pair<NodePublicIdentity, HybridSigningKey> {
        val generator  = NodeIdentityGenerator(kem, signer, hkdf)
        val identity   = generator.generate().getOrThrow()
        return identity.publicPart to identity.privatePart.signingPrivateKey
    }

    describe("PhysicalKeyExchange — NFC/BT full payload") {

        it("round-trip: build then receive returns the same identity") {
            val (pubIdentity, signingKey) = generateIdentity()
            val nowMs   = System.currentTimeMillis()

            val payload = exchange.buildPayload(pubIdentity, signingKey, nowMs).getOrThrow()
            val received = exchange.receivePayload(payload.toBytes(), nowMs).getOrThrow()

            received.nodeId.contentEquals(pubIdentity.nodeId) shouldBe true
            received shouldBe pubIdentity
        }

        it("rejects tampered identity bytes") {
            val (pubIdentity, signingKey) = generateIdentity()
            val nowMs   = System.currentTimeMillis()

            val payload  = exchange.buildPayload(pubIdentity, signingKey, nowMs).getOrThrow()
            val bytes    = payload.toBytes().copyOf()
            // Flip a byte in the middle of the identity section
            bytes[20] = bytes[20].xor(0xFF.toByte())

            val result = exchange.receivePayload(bytes, nowMs)
            result.shouldBeInstanceOf<CryptoResult.Failure>()
        }

        it("rejects payload signed by wrong key") {
            val (pubIdentity, _)          = generateIdentity()
            val (_, wrongSigningKey)      = generateIdentity()
            val nowMs = System.currentTimeMillis()

            val payload  = exchange.buildPayload(pubIdentity, wrongSigningKey, nowMs).getOrThrow()
            val result   = exchange.receivePayload(payload.toBytes(), nowMs)

            // signature is by wrong key — verification against pubIdentity's key must fail
            result.shouldBeInstanceOf<CryptoResult.Failure>()
        }

        it("rejects payload outside replay window — too old") {
            val (pubIdentity, signingKey) = generateIdentity()
            val tooOldMs = System.currentTimeMillis() - PhysicalKeyExchange.PAYLOAD_VALIDITY_MS - 1_000

            val payload = exchange.buildPayload(pubIdentity, signingKey, tooOldMs).getOrThrow()
            val result  = exchange.receivePayload(payload.toBytes())

            result.shouldBeInstanceOf<CryptoResult.Failure>()
        }

        it("rejects payload from far future — clock skew exceeded") {
            val (pubIdentity, signingKey) = generateIdentity()
            val futureMs = System.currentTimeMillis() + PhysicalKeyExchange.CLOCK_SKEW_TOLERANCE_MS + 60_000

            val payload = exchange.buildPayload(pubIdentity, signingKey, futureMs).getOrThrow()
            val result  = exchange.receivePayload(payload.toBytes())

            result.shouldBeInstanceOf<CryptoResult.Failure>()
        }

        it("accepts payload within clock skew tolerance") {
            val (pubIdentity, signingKey) = generateIdentity()
            val slightFutureMs = System.currentTimeMillis() + 30_000  // 30s ahead — within tolerance

            val payload  = exchange.buildPayload(pubIdentity, signingKey, slightFutureMs).getOrThrow()
            val result   = exchange.receivePayload(payload.toBytes())

            result.shouldBeInstanceOf<CryptoResult.Success<NodePublicIdentity>>()
        }
    }

    describe("PhysicalKeyExchange — QR compact code") {

        it("QR code round-trip: build then receive returns matching nodeId") {
            val (pubIdentity, signingKey) = generateIdentity()
            val nowMs = System.currentTimeMillis()

            val code     = exchange.buildQrIntroductionCode(pubIdentity, signingKey, nowMs).getOrThrow()
            val received = exchange.receiveQrCode(code.rawBytes, nowMs).getOrThrow()

            received.nodeId.contentEquals(pubIdentity.nodeId) shouldBe true
        }

        it("QR code is exactly the expected fixed size") {
            val (pubIdentity, signingKey) = generateIdentity()
            val code = exchange.buildQrIntroductionCode(pubIdentity, signingKey).getOrThrow()
            // Wire layout (from QrIntroductionCode.HEADER_SIZE):
            //   1B version + 8B issuedAtMs + 32B nodeId + 32B ed25519PubKey +
            //   8B nonce + 32B attestationChallenge + 64B Ed25519 signature = 177 bytes.
            // Previous assertion of 145 missed the 32-byte attestationChallenge field
            // that was added in the attestation bootstrap enhancement.
            code.rawBytes.size shouldBe 177
        }

        it("QR code rejects tampered bytes") {
            val (pubIdentity, signingKey) = generateIdentity()
            val code  = exchange.buildQrIntroductionCode(pubIdentity, signingKey).getOrThrow()
            val bytes = code.rawBytes.copyOf()
            bytes[10] = bytes[10].xor(0xAB.toByte())

            val result = exchange.receiveQrCode(bytes)
            result.shouldBeInstanceOf<CryptoResult.Failure>()
        }

        it("QR code rejects expired code") {
            val (pubIdentity, signingKey) = generateIdentity()
            val expiredMs = System.currentTimeMillis() - PhysicalKeyExchange.PAYLOAD_VALIDITY_MS - 1_000

            val code   = exchange.buildQrIntroductionCode(pubIdentity, signingKey, expiredMs).getOrThrow()
            val result = exchange.receiveQrCode(code.rawBytes)

            result.shouldBeInstanceOf<CryptoResult.Failure>()
        }

        it("two codes from same identity at different times differ") {
            val (pubIdentity, signingKey) = generateIdentity()
            val nowMs = System.currentTimeMillis()

            val code1 = exchange.buildQrIntroductionCode(pubIdentity, signingKey, nowMs).getOrThrow()
            val code2 = exchange.buildQrIntroductionCode(pubIdentity, signingKey, nowMs + 1000).getOrThrow()

            code1.rawBytes.contentEquals(code2.rawBytes) shouldBe false
        }
    }

    describe("PhysicalKeyExchange — different identities") {

        it("two nodes produce non-overlapping payloads") {
            val (pub1, sig1) = generateIdentity()
            val (pub2, sig2) = generateIdentity()
            val nowMs = System.currentTimeMillis()

            val p1 = exchange.buildPayload(pub1, sig1, nowMs).getOrThrow()
            val p2 = exchange.buildPayload(pub2, sig2, nowMs).getOrThrow()

            // Cross-check: payload from node 1 should fail verification with node 2's key
            // (the identity bytes contain node 1's signing key, so verify uses node 1's key)
            val received1 = exchange.receivePayload(p1.toBytes(), nowMs).getOrThrow()
            val received2 = exchange.receivePayload(p2.toBytes(), nowMs).getOrThrow()

            received1.nodeId.contentEquals(pub1.nodeId) shouldBe true
            received2.nodeId.contentEquals(pub2.nodeId) shouldBe true
            received1.nodeId.contentEquals(received2.nodeId) shouldBe false
        }
    }
})

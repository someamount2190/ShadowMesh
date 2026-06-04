package mesh.shadowmesh.bootstrap.nfc

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import kotlinx.coroutines.test.runTest
import mesh.shadowmesh.bootstrap.QrIntroductionCode
import mesh.shadowmesh.crypto.*

/**
 * NFC handshake unit tests — full protocol verified without NFC hardware.
 *
 * All tests use two simulated devices (A = initiator, B = responder) with
 * independently generated keypairs. The [NfcHandshake] is stateless and
 * pure-JVM so every step is exercisable in a unit test.
 *
 * Coverage:
 *   - Full happy path (all 6 steps complete, session key derived)
 *   - Challenge mismatch rejection (relay attack simulation)
 *   - Timing window enforcement
 *   - NodeId cross-check (different device trying to respond)
 *   - Wrong signing key detection
 *   - Wire format round-trips (NfcChallengeMessage, NfcResponseMessage)
 *   - Session key is symmetric (both sides derive the same key)
 *   - BootstrapTrustLevel semantics
 */
class NfcHandshakeTest : DescribeSpec({

    val hkdf    = Hkdf()
    val kem     = HybridKem(hkdf)
    val signer  = HybridSigner()
    val handshake = NfcHandshake(signer, hkdf)

    // Build two device identities
    suspend fun makeIdentity() = NodeIdentityGenerator(kem, signer, hkdf).generate().getOrThrow()

    fun makeQrCode(identity: NodePublicIdentity, nonce: ByteArray): QrIntroductionCode {
        val ed25519Priv = ByteArray(64) { it.toByte() }   // fake — not used in these tests
        return QrIntroductionCode(
            version      = 1,
            issuedAtMs   = System.currentTimeMillis(),
            nodeId       = identity.nodeId,
            ed25519PubKey = identity.signingPublicKey.ed25519PublicKey,
            nonce        = nonce,
            signature    = ByteArray(64),
            rawBytes     = ByteArray(145)
        )
    }

    // ── Full happy path ────────────────────────────────────────────────────

    describe("NFC handshake — full 6-step happy path") {

        it("completes mutual authentication and both sides get HandshakeComplete") {
            runTest {
                val idA = makeIdentity()
                val idB = makeIdentity()

                // Step 1: A generates QR with nonce_A
                val nonce_A = ByteArray(32) { 0x42 }
                val qrFromA = makeQrCode(idA.publicPart, nonce_A)

                val now = System.currentTimeMillis()

                // Step 4b: B builds its challenge message
                val challengeMsg = handshake.buildChallengeMessage(
                    localIdentity   = idB.publicPart,
                    localPrivateKey = idB.privatePart.signingPrivateKey,
                    qrCode          = qrFromA,
                    nowMs           = now
                ).getOrThrow()

                // Verify structure
                challengeMsg.nodeId.contentEquals(idB.publicPart.nodeId) shouldBe true
                challengeMsg.challengeNonce.size shouldBe NfcHandshake.NONCE_BYTES
                challengeMsg.respondingToNonce.contentEquals(nonce_A) shouldBe true

                // Step 5a: A verifies B's message and builds its response
                val stepA = handshake.verifyAndRespond(
                    localIdentity   = idA.publicPart,
                    localPrivateKey = idA.privatePart.signingPrivateKey,
                    localQrNonce    = nonce_A,
                    peerMessage     = challengeMsg,
                    nowMs           = now
                ).getOrThrow()

                stepA.shouldBeInstanceOf<NfcHandshakeStep.InitiatorResponse>()
                val responseMsg = (stepA as NfcHandshakeStep.InitiatorResponse).message

                // A's response nodeId must match A's identity
                responseMsg.nodeId.contentEquals(idA.publicPart.nodeId) shouldBe true
                // A's response should be responding to B's nonce
                responseMsg.respondingToNonce.contentEquals(challengeMsg.challengeNonce) shouldBe true

                // Step 6b: B verifies A's response
                val stepB = handshake.verifyResponse(
                    localChallengeNonce = challengeMsg.challengeNonce,
                    peerResponse        = responseMsg,
                    qrCode              = qrFromA,
                    nowMs               = now
                ).getOrThrow()

                stepB.shouldBeInstanceOf<NfcHandshakeStep.HandshakeComplete>()
                val complete = stepB as NfcHandshakeStep.HandshakeComplete

                complete.verifiedPeerNodeId.contentEquals(idA.publicPart.nodeId) shouldBe true
            }
        }

        it("both sides derive the same session key") {
            runTest {
                val idA = makeIdentity()
                val idB = makeIdentity()
                val nonce_A = ByteArray(32) { 0x11 }
                val qrFromA = makeQrCode(idA.publicPart, nonce_A)
                val now = System.currentTimeMillis()

                val challengeMsg = handshake.buildChallengeMessage(
                    idB.publicPart, idB.privatePart.signingPrivateKey, qrFromA, now
                ).getOrThrow()

                val sessionKeyA = handshake.buildSessionKey(
                    nonceA      = nonce_A,
                    nonceB      = challengeMsg.challengeNonce,
                    localNodeId = idA.publicPart.nodeId,
                    peerNodeId  = idB.publicPart.nodeId
                )
                val sessionKeyB = handshake.buildSessionKey(
                    nonceA      = nonce_A,
                    nonceB      = challengeMsg.challengeNonce,
                    localNodeId = idB.publicPart.nodeId,
                    peerNodeId  = idA.publicPart.nodeId
                )

                // Both sides must derive the same 32-byte key
                sessionKeyA.size shouldBe 32
                sessionKeyA shouldBe sessionKeyB
            }
        }
    }

    // ── Relay attack rejection ─────────────────────────────────────────────

    describe("NFC handshake — relay attack rejection") {

        it("rejects challenge message where nonce_A does not match QR") {
            runTest {
                val idA = makeIdentity()
                val idB = makeIdentity()

                val realNonce  = ByteArray(32) { 0x42 }
                val wrongNonce = ByteArray(32) { 0x99.toByte() }

                // B signs the wrong nonce (attacker relayed a different QR's nonce)
                val qrFromA = makeQrCode(idA.publicPart, realNonce)
                val attackerQr = makeQrCode(idA.publicPart, wrongNonce)

                val now = System.currentTimeMillis()

                // B builds challenge using the attacker's QR (wrong nonce)
                val challengeMsg = handshake.buildChallengeMessage(
                    idB.publicPart, idB.privatePart.signingPrivateKey, attackerQr, now
                ).getOrThrow()

                // A expects its real nonce to be signed — verification should fail
                val result = handshake.verifyAndRespond(
                    localIdentity   = idA.publicPart,
                    localPrivateKey = idA.privatePart.signingPrivateKey,
                    localQrNonce    = realNonce,   // A's actual nonce
                    peerMessage     = challengeMsg,
                    nowMs           = now
                )

                result.isFailure shouldBe true
            }
        }

        it("rejects response where nodeId does not match QR code") {
            runTest {
                val idA     = makeIdentity()
                val idB     = makeIdentity()
                val idRogue = makeIdentity()   // attacker

                val nonce_A = ByteArray(32) { 0x42 }
                val qrFromA = makeQrCode(idA.publicPart, nonce_A)
                val now     = System.currentTimeMillis()

                val challengeMsg = handshake.buildChallengeMessage(
                    idB.publicPart, idB.privatePart.signingPrivateKey, qrFromA, now
                ).getOrThrow()

                val stepA = handshake.verifyAndRespond(
                    idA.publicPart, idA.privatePart.signingPrivateKey, nonce_A, challengeMsg, now
                ).getOrThrow() as NfcHandshakeStep.InitiatorResponse

                // Rogue device modifies the response to use its own nodeId
                val spoofedResponse = NfcResponseMessage(
                    version          = stepA.message.version,
                    sentAtMs         = stepA.message.sentAtMs,
                    nodeId           = idRogue.publicPart.nodeId,   // ← spoofed
                    ed25519PublicKey = idRogue.publicPart.signingPublicKey.ed25519PublicKey,
                    responseToNonce  = stepA.message.responseToNonce,
                    respondingToNonce = stepA.message.respondingToNonce
                )

                val result = handshake.verifyResponse(
                    localChallengeNonce = challengeMsg.challengeNonce,
                    peerResponse        = spoofedResponse,
                    qrCode              = qrFromA,
                    nowMs               = now
                )
                result.isFailure shouldBe true
            }
        }
    }

    // ── Timing window enforcement ──────────────────────────────────────────

    describe("NFC handshake — timing window") {

        it("rejects challenge message older than NFC_MAX_ROUND_TRIP_MS") {
            runTest {
                val idA = makeIdentity()
                val idB = makeIdentity()
                val nonce_A = ByteArray(32) { 0x42 }
                val qrFromA = makeQrCode(idA.publicPart, nonce_A)

                val sentAt = 1_000L    // sent at t=1s
                val nowAt  = 1_000L + NfcHandshake.NFC_MAX_ROUND_TRIP_MS + 1  // t=1.501s

                val challengeMsg = handshake.buildChallengeMessage(
                    idB.publicPart, idB.privatePart.signingPrivateKey, qrFromA, sentAt
                ).getOrThrow()

                val result = handshake.verifyAndRespond(
                    idA.publicPart, idA.privatePart.signingPrivateKey, nonce_A,
                    challengeMsg, nowAt   // now is past the window
                )
                result.isFailure shouldBe true
            }
        }

        it("accepts challenge message within NFC_MAX_ROUND_TRIP_MS") {
            runTest {
                val idA = makeIdentity()
                val idB = makeIdentity()
                val nonce_A = ByteArray(32) { 0x42 }
                val qrFromA = makeQrCode(idA.publicPart, nonce_A)
                val now = System.currentTimeMillis()

                val challengeMsg = handshake.buildChallengeMessage(
                    idB.publicPart, idB.privatePart.signingPrivateKey, qrFromA, now
                ).getOrThrow()

                // Verify immediately
                val result = handshake.verifyAndRespond(
                    idA.publicPart, idA.privatePart.signingPrivateKey, nonce_A, challengeMsg, now
                )
                result.isSuccess shouldBe true
            }
        }

        it("NFC_MAX_ROUND_TRIP_MS is 500ms") {
            NfcHandshake.NFC_MAX_ROUND_TRIP_MS shouldBe 500L
        }
    }

    // ── Wire format round-trips ────────────────────────────────────────────

    describe("Wire format — NfcChallengeMessage serialisation") {

        it("toBytes / fromBytes round-trip") {
            val msg = NfcChallengeMessage(
                version           = 1,
                sentAtMs          = 1_700_000_000_000L,
                nodeId            = ByteArray(32) { it.toByte() },
                ed25519PublicKey  = ByteArray(32) { (it + 1).toByte() },
                challengeNonce    = ByteArray(32) { (it + 2).toByte() },
                responseToNonce   = ByteArray(64) { it.toByte() },
                respondingToNonce = ByteArray(32) { (it + 3).toByte() },
                attestationEvidence = null
            )
            val recovered = NfcChallengeMessage.fromBytes(msg.toBytes())
            recovered.nodeId.contentEquals(msg.nodeId) shouldBe true
            recovered.challengeNonce.contentEquals(msg.challengeNonce) shouldBe true
            recovered.respondingToNonce.contentEquals(msg.respondingToNonce) shouldBe true
            recovered.sentAtMs shouldBe msg.sentAtMs
        }

        it("round-trip preserves optional attestationEvidence") {
            val att = ByteArray(48) { 0x55 }
            val msg = NfcChallengeMessage(
                version = 1, sentAtMs = 0L,
                nodeId = ByteArray(32), ed25519PublicKey = ByteArray(32),
                challengeNonce = ByteArray(32), responseToNonce = ByteArray(64),
                respondingToNonce = ByteArray(32), attestationEvidence = att
            )
            val recovered = NfcChallengeMessage.fromBytes(msg.toBytes())
            recovered.attestationEvidence.shouldBeInstanceOf<ByteArray>()
            recovered.attestationEvidence!!.contentEquals(att) shouldBe true
        }
    }

    describe("Wire format — NfcResponseMessage serialisation") {

        it("toBytes / fromBytes round-trip") {
            val msg = NfcResponseMessage(
                version          = 1,
                sentAtMs         = 1_700_000_000_001L,
                nodeId           = ByteArray(32) { it.toByte() },
                ed25519PublicKey = ByteArray(32) { (it + 10).toByte() },
                responseToNonce  = ByteArray(64) { it.toByte() },
                respondingToNonce = ByteArray(32) { (it + 20).toByte() }
            )
            val recovered = NfcResponseMessage.fromBytes(msg.toBytes())
            recovered.nodeId.contentEquals(msg.nodeId) shouldBe true
            recovered.sentAtMs shouldBe msg.sentAtMs
            recovered.respondingToNonce.contentEquals(msg.respondingToNonce) shouldBe true
        }
    }

    // ── Trust level semantics ──────────────────────────────────────────────

    describe("BootstrapTrustLevel semantics") {

        it("only the two reachable NFC trust levels are defined") {
            // The BLE-proximity and QR-only fallback completion exchanges are not
            // implemented, so their trust levels were removed rather than left as
            // unreachable enum states the UI pretends to render. Re-add them with their
            // production path when those fallbacks are actually wired.
            val levels = BootstrapTrustLevel.values().map { it.name }.toSet()
            levels shouldBe setOf("TRUST_PHYSICAL_NFC", "TRUST_PHYSICAL_ATTESTED")
        }

        it("NFC fallback enum still advertises all three detection variants") {
            // Detection is real even though only NFC completes a bootstrap.
            NfcFallback.values().map { it.name }.toSet() shouldBe
                setOf("NFC_AVAILABLE", "BLE_PROXIMITY", "QR_ONLY_DEGRADED")
        }
    }

    // ── APDU framing (NfcTransport — no Android context needed) ─────────────

    describe("NfcTransport — APDU framing") {

        it("wrapPayloadApdu / unwrapPayloadApdu round-trip") {
            val payload = "hello NFC".toByteArray()
            val apdu    = NfcTransport.wrapPayloadApdu(payload)
            val recovered = NfcTransport.unwrapPayloadApdu(apdu)
            recovered?.contentEquals(payload) shouldBe true
        }

        it("unwrapPayloadApdu returns null for wrong CLA") {
            val badApdu = byteArrayOf(0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x03) +
                          "abc".toByteArray()
            NfcTransport.unwrapPayloadApdu(badApdu) shouldBe null
        }

        it("SHADOWMESH_AID is 9 bytes") {
            NfcTransport.SHADOWMESH_AID.size shouldBe 9
        }

        it("SW_OK is 90 00") {
            NfcTransport.SW_OK.toList() shouldBe listOf(0x90.toByte(), 0x00.toByte())
        }

        it("buildSelectAidApdu produces correct SELECT APDU structure") {
            val apdu = NfcTransport.buildSelectAidApdu(NfcTransport.SHADOWMESH_AID)
            apdu[0] shouldBe 0x00       // CLA
            apdu[1] shouldBe 0xA4.toByte() // INS: SELECT
            apdu[2] shouldBe 0x04       // P1: select by AID
            apdu[4] shouldBe NfcTransport.SHADOWMESH_AID.size.toByte()
        }

        it("userPrompt returns non-blank string for all fallback modes") {
            NfcFallback.values().forEach { fallback ->
                NfcTransport.userPrompt(fallback).isNotBlank() shouldBe true
            }
        }

        it("QR_ONLY_DEGRADED prompt contains a warning symbol") {
            NfcTransport.userPrompt(NfcFallback.QR_ONLY_DEGRADED) shouldNotBe null
            NfcTransport.userPrompt(NfcFallback.QR_ONLY_DEGRADED).contains("⚠") shouldBe true
        }
    }
})

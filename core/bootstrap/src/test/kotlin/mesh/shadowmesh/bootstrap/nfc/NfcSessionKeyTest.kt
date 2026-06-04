package mesh.shadowmesh.bootstrap.nfc

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe

/**
 * Stub-audit regression: the NFC session key must be derived from the *verified* peer
 * node id, never an all-zero placeholder. NfcHandshake.buildSessionKey folds peerNodeId
 * into the HKDF salt, so a placeholder would weaken the binding and risk a key mismatch.
 *
 * This guards the contract directly on NfcHandshake.buildSessionKey: two distinct peer
 * ids must yield distinct keys, and the coordinator-level guard (require non-zero id)
 * is exercised separately in instrumentation since it needs Android NFC types.
 */
class NfcSessionKeyTest : DescribeSpec({

    val handshake = NfcHandshake(mesh.shadowmesh.crypto.HybridSigner(), mesh.shadowmesh.crypto.Hkdf.instance)
    val nonceA = ByteArray(32) { it.toByte() }
    val nonceB = ByteArray(32) { (it + 1).toByte() }
    val localId = ByteArray(32) { 0x11 }

    describe("session key binds to peer identity") {
        it("differs when the peer node id differs") {
            val peer1 = ByteArray(32) { 0x22 }
            val peer2 = ByteArray(32) { 0x33 }
            val k1 = handshake.buildSessionKey(nonceA, nonceB, localId, peer1)
            val k2 = handshake.buildSessionKey(nonceA, nonceB, localId, peer2)
            (k1.contentEquals(k2)) shouldBe false
        }

        it("a zero peer id produces a different key than a real one (placeholder is not equivalent)") {
            val realPeer = ByteArray(32) { 0x44 }
            val zeroPeer = ByteArray(32)   // the old placeholder
            val kReal = handshake.buildSessionKey(nonceA, nonceB, localId, realPeer)
            val kZero = handshake.buildSessionKey(nonceA, nonceB, localId, zeroPeer)
            (kReal.contentEquals(kZero)) shouldBe false
        }

        it("is symmetric: both peers derive the same key regardless of arg order") {
            val a = ByteArray(32) { 0x55 }
            val b = ByteArray(32) { 0x66 }
            // Device A sees (localId=a, peer=b); Device B sees (localId=b, peer=a).
            val fromA = handshake.buildSessionKey(nonceA, nonceB, a, b)
            val fromB = handshake.buildSessionKey(nonceA, nonceB, b, a)
            fromA.contentEquals(fromB) shouldBe true
        }
    }
})

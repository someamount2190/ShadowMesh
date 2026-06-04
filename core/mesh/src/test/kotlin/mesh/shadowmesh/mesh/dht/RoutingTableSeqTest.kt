package mesh.shadowmesh.mesh.dht

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf

/**
 * Tests for:
 *   1. [PeerAddress.toWireBytes] / [PeerAddress.fromWireBytes] — deterministic wire encoding
 *      used as the [addressBytes] field in [mesh.shadowmesh.crypto.SignedContact].
 *   2. [RoutingTable] seq replay protection — the seqTable logic added alongside
 *      [DhtContact.seq].
 *
 * These tests live in core/mesh (not core/crypto) because both [PeerAddress] and
 * [RoutingTable] are defined in core/mesh, which core/crypto tests cannot import.
 */
class RoutingTableSeqTest : DescribeSpec({

    // ── PeerAddress wire encoding ─────────────────────────────────────────

    describe("PeerAddress.toWireBytes / fromWireBytes") {

        it("round-trips a typical LAN address") {
            val addr  = PeerAddress("192.168.1.42", 7400)
            val back  = PeerAddress.fromWireBytes(addr.toWireBytes())
            back?.ip   shouldBe "192.168.1.42"
            back?.port shouldBe 7400
        }

        it("round-trips loopback") {
            val addr = PeerAddress("127.0.0.1", 9000)
            val back = PeerAddress.fromWireBytes(addr.toWireBytes())
            back?.ip   shouldBe "127.0.0.1"
            back?.port shouldBe 9000
        }

        it("round-trips port 1 (minimum)") {
            val back = PeerAddress.fromWireBytes(PeerAddress("10.0.0.1", 1).toWireBytes())
            back?.port shouldBe 1
        }

        it("round-trips port 65535 (maximum)") {
            val back = PeerAddress.fromWireBytes(PeerAddress("10.0.0.1", 65535).toWireBytes())
            back?.port shouldBe 65535
        }

        it("encodes IPv4 as exactly 7 bytes") {
            PeerAddress("10.0.0.1", 7400).toWireBytes().size shouldBe 7
        }

        it("produces stable bytes for the same address — required for signed payloads") {
            val addr = PeerAddress("172.16.5.3", 7400)
            val b1   = addr.toWireBytes()
            val b2   = addr.toWireBytes()
            b1.contentEquals(b2) shouldBe true
        }

        it("returns null for an empty byte array") {
            PeerAddress.fromWireBytes(ByteArray(0)) shouldBe null
        }

        it("returns null for an unknown version byte") {
            PeerAddress.fromWireBytes(byteArrayOf(0x05, 1, 2, 3, 4, 0, 80)) shouldBe null
        }

        it("returns null when IPv4 payload is truncated") {
            // Version byte = 4, but only 5 bytes follow (need 6 more: 4B IP + 2B port)
            PeerAddress.fromWireBytes(byteArrayOf(0x04, 192.toByte(), 168.toByte(), 1)) shouldBe null
        }

        it("different addresses produce different wire bytes") {
            val b1 = PeerAddress("10.0.0.1", 7400).toWireBytes()
            val b2 = PeerAddress("10.0.0.2", 7400).toWireBytes()
            b1.contentEquals(b2) shouldBe false
        }

        it("different ports produce different wire bytes") {
            val b1 = PeerAddress("10.0.0.1", 7400).toWireBytes()
            val b2 = PeerAddress("10.0.0.1", 7401).toWireBytes()
            b1.contentEquals(b2) shouldBe false
        }
    }

    // ── RoutingTable seq replay protection ────────────────────────────────

    describe("RoutingTable seq replay protection") {

        fun localId() = NodeId.random()

        fun contact(nodeId: NodeId, seq: Long, ip: String = "10.0.0.1"): DhtContact = DhtContact(
            nodeId   = nodeId,
            address  = PeerAddress(ip, 7400),
            tier     = NodeTier.TIER_1,
            isAnchor = true,
            seq      = seq
        )

        it("accepts a new contact with seq=0") {
            val table  = RoutingTable(localId())
            val peerId = NodeId.random()
            table.insert(contact(peerId, seq = 0L)) shouldBe InsertResult.Inserted
        }

        it("accepts seq=0 from multiple distinct peers independently") {
            val table = RoutingTable(localId())
            val a = NodeId.random()
            val b = NodeId.random()
            table.insert(contact(a, seq = 0L)) shouldBe InsertResult.Inserted
            table.insert(contact(b, seq = 0L)) shouldBe InsertResult.Inserted
        }

        it("accepts a contact with a higher seq than the stored one") {
            val table  = RoutingTable(localId())
            val peerId = NodeId.random()
            table.insert(contact(peerId, seq = 3L))
            table.insert(contact(peerId, seq = 4L)) shouldBe InsertResult.Inserted
        }

        it("accepts seq increment by more than 1") {
            val table  = RoutingTable(localId())
            val peerId = NodeId.random()
            table.insert(contact(peerId, seq = 0L))
            table.insert(contact(peerId, seq = 100L)) shouldBe InsertResult.Inserted
        }

        it("rejects exact seq replay") {
            val table  = RoutingTable(localId())
            val peerId = NodeId.random()
            table.insert(contact(peerId, seq = 5L))
            table.insert(contact(peerId, seq = 5L))
                .shouldBeInstanceOf<InsertResult.Rejected>()
        }

        it("rejects seq lower than stored (old-address replay)") {
            val table  = RoutingTable(localId())
            val peerId = NodeId.random()
            table.insert(contact(peerId, seq = 10L))
            table.insert(contact(peerId, seq = 3L))
                .shouldBeInstanceOf<InsertResult.Rejected>()
        }

        it("rejected message mentions seq values") {
            val table  = RoutingTable(localId())
            val peerId = NodeId.random()
            table.insert(contact(peerId, seq = 7L))
            val result = table.insert(contact(peerId, seq = 2L)) as InsertResult.Rejected
            // Confirm reason string contains the seq numbers for diagnosability
            result.reason.contains("2") shouldBe true
            result.reason.contains("7") shouldBe true
        }

        it("seqTable is cleared on remove — fresh seq=0 accepted after eviction") {
            val table  = RoutingTable(localId())
            val peerId = NodeId.random()
            table.insert(contact(peerId, seq = 5L))
            table.remove(peerId)
            // After removal, a contact with seq=0 should be accepted as a new introduction
            table.insert(contact(peerId, seq = 0L)) shouldBe InsertResult.Inserted
        }

        it("seqTable tracks each peer independently") {
            val table = RoutingTable(localId())
            val a     = NodeId.random()
            val b     = NodeId.random()
            table.insert(contact(a, seq = 10L))
            table.insert(contact(b, seq = 1L))
            // Peer A with lower seq rejected; peer B with higher seq accepted independently
            table.insert(contact(a, seq = 3L)).shouldBeInstanceOf<InsertResult.Rejected>()
            table.insert(contact(b, seq = 2L)) shouldBe InsertResult.Inserted
        }

        it("address change with incremented seq is accepted") {
            val table  = RoutingTable(localId())
            val peerId = NodeId.random()
            table.insert(contact(peerId, seq = 0L, ip = "10.0.0.1"))
            // Node moved to a new address — increments seq
            table.insert(contact(peerId, seq = 1L, ip = "10.0.0.2")) shouldBe InsertResult.Inserted
        }
    }
})

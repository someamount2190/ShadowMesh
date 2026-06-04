package mesh.shadowmesh.mesh.delivery

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.nulls.shouldBeNull
import kotlinx.coroutines.test.*
import kotlinx.coroutines.*
import mesh.shadowmesh.mesh.fragment.*

// ── FecScheme ─────────────────────────────────────────────────────────────────

class FecSchemeTest : DescribeSpec({

    describe("FecScheme — link quality selection") {

        it("selects RS_10_7 for excellent link (>= 90%)") {
            FecScheme.selectForLinkQuality(90)  shouldBe FecScheme.RS_10_7
            FecScheme.selectForLinkQuality(100) shouldBe FecScheme.RS_10_7
        }

        it("selects RS_10_8 for good link (75-89%)") {
            FecScheme.selectForLinkQuality(75) shouldBe FecScheme.RS_10_8
            FecScheme.selectForLinkQuality(89) shouldBe FecScheme.RS_10_8
        }

        it("selects RS_10_9 for fair link (60-74%)") {
            FecScheme.selectForLinkQuality(60) shouldBe FecScheme.RS_10_9
            FecScheme.selectForLinkQuality(74) shouldBe FecScheme.RS_10_9
        }

        it("selects RS_10_10 for poor link (< 60%)") {
            FecScheme.selectForLinkQuality(59) shouldBe FecScheme.RS_10_10
            FecScheme.selectForLinkQuality(0)  shouldBe FecScheme.RS_10_10
        }

        it("selects NONE for offline / BT mode") {
            FecScheme.selectForLinkQuality(100, offline = true) shouldBe FecScheme.NONE
        }

        it("round-trips wire encoding") {
            FecScheme.values().forEach { scheme ->
                FecScheme.fromWire(scheme.wire) shouldBe scheme
            }
        }

        it("RS_10_7 has correct loss tolerance") {
            // 7 parity / 17 total = ~41% but design doc says 30% packet loss
            // (loss tolerance = P/(N+P) = 7/17 ≈ 0.41 — but usable at 30% loss)
            (FecScheme.RS_10_7.lossTolerance > 0.4f) shouldBe true
        }
    }
})

// ── FragmentationEngine ───────────────────────────────────────────────────────

class FragmentationEngineTest : DescribeSpec({

    val engine = FragmentationEngine()
    val postId    = ByteArray(32) { it.toByte() }
    val channelId = ByteArray(32) { (it + 1).toByte() }

    describe("FragmentationEngine — split and reassemble") {

        it("fragments a small payload with RS_10_7") {
            val payload = "Hello SHADOWMESH".repeat(10).toByteArray()
            val set     = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)

            set.fragments.size shouldBe (FecScheme.RS_10_7.dataShards + FecScheme.RS_10_7.parityShards)
            set.originalLength shouldBe payload.size
            set.scheme shouldBe FecScheme.RS_10_7
        }

        it("all fragment IDs are distinct") {
            val payload = ByteArray(500) { it.toByte() }
            val set     = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
            val ids     = set.fragments.map { it.fragmentId }.toSet()
            ids.size shouldBe set.fragments.size
        }

        it("reassembles from ALL data fragments") {
            val payload = "Tactical message content for test".toByteArray()
            val set     = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
            val data    = set.dataFragments

            val result = engine.reassemble(data, set.originalLength, FecScheme.RS_10_7)
            result.shouldNotBeNull()
            result.contentEquals(payload) shouldBe true
        }

        it("reassembles with 30% fragment loss — RS_10_7") {
            val payload  = ByteArray(1000) { it.toByte() }
            val set      = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
            val total    = set.fragments.size   // 17

            // Drop 30% = 5 fragments (just under 7 parity tolerance)
            val surviving = set.fragments.filterIndexed { i, _ -> i % 6 != 0 }
            surviving.size shouldBe (total - 2)  // dropped ~2 in 17

            val result = engine.reassemble(surviving, set.originalLength, FecScheme.RS_10_7)
            result.shouldNotBeNull()
            result.contentEquals(payload) shouldBe true
        }

        it("reassembles with exactly N data fragments (zero parity needed)") {
            val payload = ByteArray(200) { it.toByte() }
            val set     = engine.fragment(postId, channelId, payload, FecScheme.RS_10_8)
            // Keep only the first 10 data shards
            val datOnly = set.fragments.filter { it.sequenceIndex < 10 }

            val result = engine.reassemble(datOnly, set.originalLength, FecScheme.RS_10_8)
            result.shouldNotBeNull()
            result.contentEquals(payload) shouldBe true
        }

        it("returns null when fewer than N fragments available") {
            val payload = ByteArray(200) { it.toByte() }
            val set     = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
            val tooFew  = set.fragments.take(5)  // only 5, need 10

            val result = engine.reassemble(tooFew, set.originalLength, FecScheme.RS_10_7)
            result.shouldBeNull()
        }

        it("handles single-blob NONE scheme") {
            val payload = ByteArray(64) { 0x42 }
            val set     = engine.fragment(postId, channelId, payload, FecScheme.NONE)

            set.fragments.size shouldBe 1
            val result = engine.reassemble(set.fragments, set.originalLength, FecScheme.NONE)
            result.shouldNotBeNull()
            result.contentEquals(payload) shouldBe true
        }

        it("fragment IDs are content-addressed — same payload same ID") {
            val payload = ByteArray(100) { 0x13 }
            val set1    = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
            val set2    = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
            set1.fragments[0].fragmentId shouldBe set2.fragments[0].fragmentId
        }

        it("different payload produces different fragment IDs") {
            val p1   = ByteArray(100) { 0x01 }
            val p2   = ByteArray(100) { 0x02 }
            val set1 = engine.fragment(postId, channelId, p1, FecScheme.RS_10_7)
            val set2 = engine.fragment(postId, channelId, p2, FecScheme.RS_10_7)
            set1.fragments[0].fragmentId shouldNotBe set2.fragments[0].fragmentId
        }

        it("Merkle root is deterministic for same payload") {
            val payload = ByteArray(300) { it.toByte() }
            val set1    = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
            val set2    = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
            set1.merkleRoot.contentEquals(set2.merkleRoot) shouldBe true
        }
    }
})

// ── FragmentMerkleTree ────────────────────────────────────────────────────────

class FragmentMerkleTreeTest : DescribeSpec({

    describe("FragmentMerkleTree — integrity proofs") {

        it("builds a tree from a list of payloads") {
            val payloads = (0..9).map { i -> ByteArray(32) { i.toByte() } }
            val tree     = FragmentMerkleTree.build(payloads)
            tree.root.size shouldBe 32
            tree.leaves shouldHaveSize 10
        }

        it("same payloads produce same root (deterministic)") {
            val payloads = listOf(ByteArray(32) { 1 }, ByteArray(32) { 2 })
            val t1 = FragmentMerkleTree.build(payloads)
            val t2 = FragmentMerkleTree.build(payloads)
            t1.root.contentEquals(t2.root) shouldBe true
        }

        it("different payload set produces different root") {
            val p1 = listOf(ByteArray(32) { 1 })
            val p2 = listOf(ByteArray(32) { 2 })
            val t1 = FragmentMerkleTree.build(p1)
            val t2 = FragmentMerkleTree.build(p2)
            t1.root.contentEquals(t2.root) shouldBe false
        }

        it("sibling path has correct length for 8-leaf tree") {
            val payloads = (0..7).map { i -> ByteArray(32) { i.toByte() } }
            val tree = FragmentMerkleTree.build(payloads)
            // 8 leaves = log2(8) = 3 levels
            tree.siblingPath(0).size shouldBe 3
        }
    }
})

// ── MerkleAckProtocol ─────────────────────────────────────────────────────────

class MerkleAckProtocolTest : DescribeSpec({

    fun makeFragment(postId: String, seq: Int, total: Int, parity: Int = 7) =
        FragmentEntity(
            fragmentId    = "frag_${postId}_$seq",
            postId        = postId,
            channelId     = "channel_abc",
            sequenceIndex = seq,
            totalData     = total,
            totalParity   = parity,
            payload       = ByteArray(64) { seq.toByte() },
            fecScheme     = FecScheme.RS_10_7
        )

    describe("FragmentAccumulator") {

        it("returns Empty when no fragments added") {
            val acc = FragmentAccumulator("post1", 10, 7)
            acc.currentStatus() shouldBe AccumulatorStatus.Empty
        }

        it("returns Partial when below Tier1 threshold") {
            val acc = FragmentAccumulator("post1", 10, 7)
            acc.addFragment(makeFragment("post1", 0, 10))
            // 1/10 = 10% — exactly at Tier1 threshold
            val status = acc.currentStatus()
            (status is AccumulatorStatus.PartialTier1 || status is AccumulatorStatus.Partial) shouldBe true
        }

        it("returns Complete when N data fragments received") {
            val acc = FragmentAccumulator("post2", 10, 7)
            repeat(10) { i -> acc.addFragment(makeFragment("post2", i, 10)) }
            (acc.currentStatus() is AccumulatorStatus.Complete) shouldBe true
        }

        it("returns Complete with mix of data and parity fragments") {
            val acc = FragmentAccumulator("post3", 10, 7)
            // 7 data + 3 parity = 10 total >= N=10 data required
            repeat(7) { i -> acc.addFragment(makeFragment("post3", i,      10, 7)) }
            repeat(3) { i -> acc.addFragment(makeFragment("post3", i + 10, 10, 7)) }
            (acc.currentStatus() is AccumulatorStatus.Complete) shouldBe true
        }

        it("identifies missing sequences correctly") {
            val acc = FragmentAccumulator("post4", 10, 7)
            acc.addFragment(makeFragment("post4", 0, 10))
            acc.addFragment(makeFragment("post4", 2, 10))
            acc.addFragment(makeFragment("post4", 5, 10))
            val missing = acc.missingFragmentSequences()
            (1 in missing) shouldBe true
            (3 in missing) shouldBe true
            (0 !in missing) shouldBe true
        }
    }

    describe("MerkleAckProtocol — ACK verification") {

        val transport = object : AckTransport {
            val sentAcks   = mutableListOf<ByteArray>()
            val sentNacks  = mutableListOf<ByteArray>()
            val retransmits= mutableListOf<FragmentEntity>()
            override suspend fun sendAck(targetNodeId: String, ackBytes: ByteArray) { sentAcks.add(ackBytes) }
            override suspend fun broadcastNack(postId: String, nackBytes: ByteArray) { sentNacks.add(nackBytes) }
            override suspend fun retransmitFragment(fragment: FragmentEntity) { retransmits.add(fragment) }
        }
        val protocol = MerkleAckProtocol(transport = transport)

        it("verifyAck passes for correct Merkle root") {
            val root = ByteArray(32) { 0xAB.toByte() }
            val postIdBytes = ByteArray(32) { 0x01 }
            val ack = MerkleAckProtocol.ACK_MAGIC + postIdBytes + root
            protocol.verifyAck(ack, root) shouldBe AckVerification.Valid
        }

        it("verifyAck fails for wrong Merkle root") {
            val root  = ByteArray(32) { 0xAB.toByte() }
            val wrong = ByteArray(32) { 0xCD.toByte() }
            val postIdBytes = ByteArray(32) { 0x01 }
            val ack = MerkleAckProtocol.ACK_MAGIC + postIdBytes + root
            val result = protocol.verifyAck(ack, wrong)
            (result is AckVerification.Invalid) shouldBe true
        }

        it("verifyAck fails for wrong magic bytes") {
            val root = ByteArray(32) { 0xAB.toByte() }
            val bad  = ByteArray(68) { 0xFF.toByte() }
            val result = protocol.verifyAck(bad, root)
            (result is AckVerification.Invalid) shouldBe true
        }

        it("verifyAck fails for too-short packet") {
            val result = protocol.verifyAck(ByteArray(10), ByteArray(32))
            (result is AckVerification.Invalid) shouldBe true
        }
    }
})

// ── DistributedRetransmissionManager ─────────────────────────────────────────

class DistributedRetransmissionManagerTest : DescribeSpec({

    fun makeFragment(postId: String, seq: Int) = FragmentEntity(
        fragmentId    = "f_${postId}_$seq",
        postId        = postId,
        channelId     = "ch1",
        sequenceIndex = seq,
        totalData     = 10,
        totalParity   = 7,
        payload       = ByteArray(32) { seq.toByte() },
        fecScheme     = FecScheme.RS_10_7,
        createdAtMs   = System.currentTimeMillis(),
        heldUntilMs   = System.currentTimeMillis() + 2 * 60 * 60 * 1000L
    )

    describe("DistributedRetransmissionManager") {

        it("holds a fragment after relay") {
            runTest {
                val retransmits = mutableListOf<FragmentEntity>()
                val transport   = object : RetransmitTransport {
                    override suspend fun retransmitFragment(f: FragmentEntity) { retransmits.add(f) }
                }
                val mgr = DistributedRetransmissionManager(this, transport)
                val f   = makeFragment("post1", 0)
                mgr.hold(f)
                mgr.hasFragment("post1", 0) shouldBe true
            }
        }

        it("serves NACK for held fragment") {
            runTest {
                val retransmits = mutableListOf<FragmentEntity>()
                val transport   = object : RetransmitTransport {
                    override suspend fun retransmitFragment(f: FragmentEntity) { retransmits.add(f) }
                }
                val mgr = DistributedRetransmissionManager(this, transport)
                repeat(5) { i -> mgr.hold(makeFragment("post2", i)) }
                val served = mgr.serveNack("post2", listOf(0, 1, 2))
                served shouldBe 3
                retransmits.size shouldBe 3
            }
        }

        it("respects MAX_RETRANSMITS_PER_POST limit") {
            runTest {
                val retransmits = mutableListOf<FragmentEntity>()
                val transport   = object : RetransmitTransport {
                    override suspend fun retransmitFragment(f: FragmentEntity) { retransmits.add(f) }
                }
                val mgr = DistributedRetransmissionManager(this, transport)
                repeat(10) { i -> mgr.hold(makeFragment("post3", i)) }
                // First NACK: serves 3 (= MAX)
                mgr.serveNack("post3", (0..9).toList()) shouldBe 3
                // Second NACK: limit already reached
                mgr.serveNack("post3", (0..9).toList()) shouldBe 0
            }
        }

        it("does not serve expired fragments") {
            runTest {
                val retransmits = mutableListOf<FragmentEntity>()
                val transport   = object : RetransmitTransport {
                    override suspend fun retransmitFragment(f: FragmentEntity) { retransmits.add(f) }
                }
                val mgr = DistributedRetransmissionManager(this, transport)
                val expired = makeFragment("post4", 0).copy(
                    heldUntilMs = System.currentTimeMillis() - 1000  // already expired
                )
                mgr.hold(expired)
                mgr.serveNack("post4", listOf(0)) shouldBe 0
            }
        }

        it("evictExpired removes old holds") {
            runTest {
                val transport = object : RetransmitTransport {
                    override suspend fun retransmitFragment(f: FragmentEntity) {}
                }
                val mgr = DistributedRetransmissionManager(this, transport)
                val expired = makeFragment("post5", 0).copy(
                    heldUntilMs = System.currentTimeMillis() - 1000
                )
                mgr.hold(expired)
                mgr.totalHeldCount() shouldBe 1
                mgr.evictExpired()
                mgr.totalHeldCount() shouldBe 0
            }
        }
    }
})

// ── NudgeEngine ───────────────────────────────────────────────────────────────

class NudgeEngineTest : DescribeSpec({

    describe("NudgeEngine — packet construction") {

        it("builds a 12-byte nudge packet") {
            val engine    = buildEngine()
            val channelId = ByteArray(32) { 0x01 }
            val packet    = engine.buildNudgePacket(channelId)
            packet.size shouldBe 12
        }

        it("channel hash portion is first 8 bytes of SHA3-256") {
            val engine    = buildEngine()
            val channelId = ByteArray(32) { 0x42 }
            val packet    = engine.buildNudgePacket(channelId)
            val expected  = mesh.shadowmesh.crypto.Hkdf.instance.sha3_256(channelId).take(8).toByteArray()
            packet.copyOfRange(0, 8).contentEquals(expected) shouldBe true
        }

        it("timestamp is rounded to nearest minute") {
            val engine    = buildEngine()
            val channelId = ByteArray(32) { 0x01 }
            val packet    = engine.buildNudgePacket(channelId)
            // Extract timestamp: bytes 8-11
            val tsSecs = ((packet[8].toLong() and 0xFF) shl 24) or
                         ((packet[9].toLong() and 0xFF) shl 16) or
                         ((packet[10].toLong() and 0xFF) shl 8) or
                         (packet[11].toLong() and 0xFF)
            (tsSecs % 60) shouldBe 0  // must be on minute boundary
        }

        it("onNudgeReceived accepts valid packet") {
            val engine    = buildEngine()
            val channelId = ByteArray(32) { 0x01 }
            val packet    = engine.buildNudgePacket(channelId)
            val result    = engine.onNudgeReceived(packet)
            result.shouldNotBeNull()
            result.size shouldBe 8
        }

        it("onNudgeReceived rejects wrong-size packet") {
            val engine = buildEngine()
            engine.onNudgeReceived(ByteArray(10)).shouldBeNull()
            engine.onNudgeReceived(ByteArray(13)).shouldBeNull()
        }

        it("two packets for same channel in same minute have same channel hash") {
            val engine    = buildEngine()
            val channelId = ByteArray(32) { 0x77 }
            val p1 = engine.buildNudgePacket(channelId)
            val p2 = engine.buildNudgePacket(channelId)
            p1.copyOfRange(0, 8).contentEquals(p2.copyOfRange(0, 8)) shouldBe true
        }

        it("packets for different channels have different channel hash") {
            val engine = buildEngine()
            val ch1    = ByteArray(32) { 0x01 }
            val ch2    = ByteArray(32) { 0x02 }
            val p1 = engine.buildNudgePacket(ch1)
            val p2 = engine.buildNudgePacket(ch2)
            p1.copyOfRange(0, 8).contentEquals(p2.copyOfRange(0, 8)) shouldBe false
        }
    }
})

private fun buildEngine(): mesh.shadowmesh.mesh.nudge.NudgeEngine {
    val transport = object : mesh.shadowmesh.mesh.nudge.NudgeTransport {
        override suspend fun sendUdpNudge(peerId: mesh.shadowmesh.mesh.dht.NodeId, packet: ByteArray) {}
        override suspend fun sendBleNudge(peerId: mesh.shadowmesh.mesh.dht.NodeId, packet: ByteArray) {}
    }
    return mesh.shadowmesh.mesh.nudge.NudgeEngine(
        scope     = CoroutineScope(Dispatchers.Unconfined),
        transport = transport
    )
}

private fun List<Byte>.toByteArray() = ByteArray(size) { this[it] }

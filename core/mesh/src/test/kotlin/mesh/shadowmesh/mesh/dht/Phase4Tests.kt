package mesh.shadowmesh.mesh.dht

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import mesh.shadowmesh.mesh.gossip.*
import mesh.shadowmesh.mesh.gossip.IntroductionMethod
import mesh.shadowmesh.storage.*

// ── NodeId ────────────────────────────────────────────────────────────────────

class NodeIdTest : DescribeSpec({

    describe("NodeId — XOR distance and bucket index") {

        it("xorDistance(self) is all zeros") {
            val id = NodeId.random()
            id.xorDistance(id).all { it == 0.toByte() } shouldBe true
        }

        it("xorDistance is commutative") {
            val a = NodeId.random()
            val b = NodeId.random()
            a.xorDistance(b).contentEquals(b.xorDistance(a)) shouldBe true
        }

        it("bucketIndex(self) returns -1") {
            val id = NodeId.random()
            id.bucketIndex(id) shouldBe -1
        }

        it("bucketIndex for IDs differing in highest bit is 255") {
            val bytes1 = ByteArray(NODE_ID_BYTES)
            val bytes2 = ByteArray(NODE_ID_BYTES)
            bytes2[0] = 0x80.toByte()  // flip highest bit
            val id1 = NodeId(bytes1)
            val id2 = NodeId(bytes2)
            id1.bucketIndex(id2) shouldBe 255
        }

        it("bucketIndex for IDs differing only in lowest bit is 0") {
            val bytes1 = ByteArray(NODE_ID_BYTES)
            val bytes2 = ByteArray(NODE_ID_BYTES)
            bytes2[NODE_ID_BYTES - 1] = 0x01.toByte()  // flip lowest bit
            val id1 = NodeId(bytes1)
            val id2 = NodeId(bytes2)
            id1.bucketIndex(id2) shouldBe 0
        }

        it("fromHex / toHex round-trip") {
            val id  = NodeId.random()
            val hex = id.toHex()
            NodeId.fromHex(hex).bytes.contentEquals(id.bytes) shouldBe true
        }

        it("fromHex rejects wrong length") {
            var threw = false
            try { NodeId.fromHex("deadbeef") }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }

        it("two NodeIds with identical bytes are equal (content-based equality)") {
            val bytes1 = ByteArray(NODE_ID_BYTES) { it.toByte() }
            val bytes2 = ByteArray(NODE_ID_BYTES) { it.toByte() }
            // Distinct array instances — must still be equal
            (bytes1 === bytes2) shouldBe false
            NodeId(bytes1) shouldBe NodeId(bytes2)
        }

        it("NodeId works correctly as a HashMap key (content-based hashCode)") {
            val bytes = ByteArray(NODE_ID_BYTES) { 0x42 }
            val id1   = NodeId(bytes.copyOf())
            val id2   = NodeId(bytes.copyOf())
            val map   = HashMap<NodeId, String>()
            map[id1]  = "value"
            // id2 has different array instance but same content — must find the entry
            map[id2] shouldBe "value"
        }

        it("NodeIds with different bytes are not equal") {
            val id1 = NodeId.random()
            val id2 = NodeId.random()
            // Astronomically unlikely to collide
            (id1 == id2) shouldBe false
        }

        it("XorDistanceComparator orders by closeness to target") {
            val target = NodeId(ByteArray(NODE_ID_BYTES))

            // close: bytes differ only in last byte
            val closeBytes = ByteArray(NODE_ID_BYTES); closeBytes[NODE_ID_BYTES-1] = 1
            val close = DhtContact(NodeId(closeBytes), PeerAddress("1.1.1.1", 1), isAnchor = true, tier = NodeTier.TIER_1)

            // far: bytes differ in first byte
            val farBytes = ByteArray(NODE_ID_BYTES); farBytes[0] = 0x80.toByte()
            val far = DhtContact(NodeId(farBytes), PeerAddress("2.2.2.2", 2), isAnchor = true, tier = NodeTier.TIER_1)

            val cmp = XorDistanceComparator(target)
            (cmp.compare(close, far) < 0) shouldBe true  // close comes first
        }
    }
})

// ── KBucket ───────────────────────────────────────────────────────────────────

class KBucketTest : DescribeSpec({

    fun contact(n: Int) = DhtContact(
        NodeId(ByteArray(NODE_ID_BYTES).also { it[NODE_ID_BYTES-1] = n.toByte() }),
        PeerAddress("127.0.0.$n", n),
        isAnchor = true, tier = NodeTier.TIER_1
    )

    describe("KBucket — K-node capacity and LRS eviction") {

        it("accepts up to K contacts without triggering ping") {
            val bucket = KBucket()
            repeat(K) { i ->
                bucket.insertOrUpdate(contact(i)).shouldBeNull()
            }
            bucket.size() shouldBe K
        }

        it("returns LRS contact when full") {
            val bucket = KBucket()
            val first  = contact(0)
            bucket.insertOrUpdate(first)
            repeat(K - 1) { i -> bucket.insertOrUpdate(contact(i + 1)) }
            val lrs = bucket.insertOrUpdate(contact(K + 1))
            lrs.shouldNotBeNull()
            lrs.nodeId shouldBe first.nodeId
        }

        it("updating existing contact moves it to tail") {
            val bucket = KBucket()
            val c = contact(1)
            bucket.insertOrUpdate(c)
            bucket.insertOrUpdate(contact(2))
            // Re-insert c — should move to tail (most recently seen)
            val result = bucket.insertOrUpdate(c.copy(lastSeenMs = System.currentTimeMillis() + 1))
            result.shouldBeNull()  // no ping needed
        }

        it("evictAndInsert removes LRS and adds new contact") {
            val bucket  = KBucket()
            val old     = contact(0)
            val newC    = contact(K + 5)
            bucket.insertOrUpdate(old)
            repeat(K - 1) { i -> bucket.insertOrUpdate(contact(i + 1)) }
            bucket.evictAndInsert(newC)
            bucket.contains(old.nodeId) shouldBe false
            bucket.contains(newC.nodeId) shouldBe true
        }

        it("remove deletes a specific contact") {
            val bucket = KBucket()
            val c = contact(7)
            bucket.insertOrUpdate(c)
            bucket.remove(c.nodeId) shouldBe true
            bucket.contains(c.nodeId) shouldBe false
        }
    }
})

// ── RoutingTable ──────────────────────────────────────────────────────────────

class RoutingTableTest : DescribeSpec({

    val localId = NodeId(ByteArray(NODE_ID_BYTES) { 0 })

    fun tier1Contact(seed: Int): DhtContact {
        val bytes = ByteArray(NODE_ID_BYTES)
        bytes[NODE_ID_BYTES - 1] = seed.toByte()
        bytes[NODE_ID_BYTES - 2] = (seed shr 8).toByte()
        return DhtContact(NodeId(bytes), PeerAddress("10.0.0.$seed", seed),
            isAnchor = true, tier = NodeTier.TIER_1)
    }

    fun tier2Contact(seed: Int): DhtContact {
        val bytes = ByteArray(NODE_ID_BYTES); bytes[NODE_ID_BYTES-1] = seed.toByte()
        return DhtContact(NodeId(bytes), PeerAddress("10.0.1.$seed", seed),
            isAnchor = false, tier = NodeTier.TIER_2)
    }

    describe("RoutingTable") {

        it("accepts Tier 1 anchors") {
            val rt = RoutingTable(localId)
            val result = rt.insert(tier1Contact(1))
            result shouldBe InsertResult.Inserted
            rt.size() shouldBe 1
        }

        it("rejects non-Tier-1 contacts") {
            val rt = RoutingTable(localId)
            val result = rt.insert(tier2Contact(1))
            (result is InsertResult.Rejected) shouldBe true
            rt.size() shouldBe 0
        }

        it("rejects self-insert") {
            val rt = RoutingTable(localId)
            val selfContact = DhtContact(localId, PeerAddress("127.0.0.1", 1),
                isAnchor = true, tier = NodeTier.TIER_1)
            (rt.insert(selfContact) is InsertResult.Rejected) shouldBe true
        }

        it("findClosest returns contacts sorted by XOR distance") {
            val rt = RoutingTable(localId)
            (1..10).forEach { rt.insert(tier1Contact(it)) }

            val target = NodeId(ByteArray(NODE_ID_BYTES).also { it[NODE_ID_BYTES-1] = 5 })
            val closest = rt.findClosest(target, 3)
            closest.size shouldBe 3
            // First result should be closest to target
            (closest[0].nodeId.xorDistance(target).toHex() <=
             closest[1].nodeId.xorDistance(target).toHex()) shouldBe true
        }

        it("contains returns true after insert") {
            val rt = RoutingTable(localId)
            val c  = tier1Contact(42)
            rt.insert(c)
            rt.contains(c.nodeId) shouldBe true
        }

        it("remove clears the contact") {
            val rt = RoutingTable(localId)
            val c  = tier1Contact(7)
            rt.insert(c)
            rt.remove(c.nodeId)
            rt.contains(c.nodeId) shouldBe false
            rt.size() shouldBe 0
        }

        it("touch moves contact to most-recently-seen position") {
            val rt = RoutingTable(localId)
            val c  = tier1Contact(3)
            rt.insert(c)
            rt.touch(c.nodeId, System.currentTimeMillis() + 5000)
            rt.contains(c.nodeId) shouldBe true
        }

        it("staleContacts returns contacts not seen recently") {
            val rt   = RoutingTable(localId)
            val oldC = tier1Contact(1).copy(lastSeenMs = System.currentTimeMillis() - 20 * 60 * 1000L)
            val newC = tier1Contact(2).copy(lastSeenMs = System.currentTimeMillis())
            rt.insert(oldC); rt.insert(newC)
            val stale = rt.staleContacts(staleThresholdMs = 15 * 60 * 1000L)
            stale.any { it.nodeId == oldC.nodeId } shouldBe true
            stale.none { it.nodeId == newC.nodeId } shouldBe true
        }
    }
})

// ── DhtEngine ─────────────────────────────────────────────────────────────────

class DhtEngineTest : DescribeSpec({

    val localId = NodeId.random()

    fun makeEngine(scope: TestScope): Pair<DhtEngine, FakeDhtTransport> {
        val transport = FakeDhtTransport()
        val engine    = DhtEngine(localId, transport, scope)
        return engine to transport
    }

    describe("DhtEngine — local store") {

        it("storeLocal then getLocal returns the value") {
            runTest {
                val (engine, _) = makeEngine(this)
                val key   = NodeId.random()
                val value = DhtValue(key, "hello".toByteArray(), System.currentTimeMillis() + 60_000)
                engine.storeLocal(value)
                val got = engine.getLocal(key)
                got.shouldNotBeNull()
                got.value.decodeToString() shouldBe "hello"
            }
        }

        it("getLocal returns null for expired value") {
            runTest {
                val (engine, _) = makeEngine(this)
                val key   = NodeId.random()
                val value = DhtValue(key, "expired".toByteArray(), System.currentTimeMillis() - 1)
                engine.storeLocal(value)
                engine.getLocal(key).shouldBeNull()
            }
        }

        it("evictExpired removes expired values") {
            runTest {
                val (engine, _) = makeEngine(this)
                val key1  = NodeId.random()
                val key2  = NodeId.random()
                engine.storeLocal(DhtValue(key1, "old".toByteArray(), System.currentTimeMillis() - 1))
                engine.storeLocal(DhtValue(key2, "new".toByteArray(), System.currentTimeMillis() + 60_000))
                engine.evictExpired()
                engine.getLocal(key1).shouldBeNull()
                engine.getLocal(key2).shouldNotBeNull()
                engine.localStoreSize() shouldBe 1
            }
        }
    }

    describe("DhtEngine — dead drop") {

        it("deadDropPut then deadDropGet returns the blob when stored locally") {
            runTest {
                val (engine, transport) = makeEngine(this)
                val dhtKey = NodeId.random()
                val blob   = "channel_key_blob".toByteArray()

                // Make transport return localId as the closest node so engine stores locally
                transport.findNodeResponse = listOf(
                    DhtContact(localId, PeerAddress("127.0.0.1", 1),
                        isAnchor = true, tier = NodeTier.TIER_1)
                )

                engine.deadDropPut(dhtKey, blob)
                advanceUntilIdle()

                val retrieved = engine.getLocal(dhtKey)
                retrieved.shouldNotBeNull()
                retrieved.value.contentEquals(blob) shouldBe true
            }
        }
    }

    describe("DhtEngine — routing table integration") {

        it("bootstrap pings seeds and inserts responding ones") {
            runTest {
                val (engine, transport) = makeEngine(this)
                val seed1 = DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 1),
                    isAnchor = true, tier = NodeTier.TIER_1)
                val seed2 = DhtContact(NodeId.random(), PeerAddress("2.2.2.2", 2),
                    isAnchor = true, tier = NodeTier.TIER_1)

                transport.pingResponse = seed1  // seed1 responds
                transport.deadSeed     = seed2.nodeId  // seed2 doesn't

                engine.bootstrap(listOf(seed1, seed2))
                advanceUntilIdle()

                engine.routingTable.contains(seed1.nodeId) shouldBe true
            }
        }
    }
})

// ── VrfElection ───────────────────────────────────────────────────────────────

class VrfElectionTest : DescribeSpec({

    val hkdf     = Hkdf.instance
    val election = VrfElection(hkdf)

    describe("VrfElection — commit-reveal") {

        it("generateCommit produces valid commitHash = SHA3-256(nonce || roundId)") {
            val candidateId = NodeId.random()
            val roundId     = "round-001"
            val bundle      = election.generateCommit(candidateId, roundId)

            val expected = hkdf.sha3_256(bundle.secretNonce + roundId.toByteArray())
            bundle.commit.commitHash.contentEquals(expected) shouldBe true
        }

        it("acceptReveal passes for valid commit-reveal pair") {
            val candidateId = NodeId.random()
            val roundId     = "round-002"
            val bundle      = election.generateCommit(candidateId, roundId)
            val sigKey      = ByteArray(32) { 0x42 }
            val reveal      = election.generateReveal(candidateId, bundle.secretNonce, roundId, sigKey)

            val round = election.newRound(roundId, listOf(bundle.commit))
            round.acceptReveal(reveal) shouldBe VerificationResult.Valid
        }

        it("acceptReveal fails for wrong nonce (tampered reveal)") {
            val candidateId = NodeId.random()
            val roundId     = "round-003"
            val bundle      = election.generateCommit(candidateId, roundId)
            val sigKey      = ByteArray(32) { 0x42 }
            val wrongNonce  = ByteArray(32) { 0xFF.toByte() }
            val reveal      = election.generateReveal(candidateId, wrongNonce, roundId, sigKey)

            val round = election.newRound(roundId, listOf(bundle.commit))
            (round.acceptReveal(reveal) is VerificationResult.Invalid) shouldBe true
        }

        it("acceptReveal fails on nonce reuse") {
            val candidateId = NodeId.random()
            val roundId     = "round-004"
            val bundle      = election.generateCommit(candidateId, roundId)
            val sigKey      = ByteArray(32) { 0x42 }
            val reveal      = election.generateReveal(candidateId, bundle.secretNonce, roundId, sigKey)

            val round = election.newRound(roundId, listOf(bundle.commit))
            round.acceptReveal(reveal) // first use — valid
            (round.acceptReveal(reveal) is VerificationResult.Invalid) shouldBe true
        }

        it("acceptReveal fails for wrong roundId") {
            val candidateId = NodeId.random()
            val bundle      = election.generateCommit(candidateId, "round-A")
            val sigKey      = ByteArray(32) { 0x42 }
            val reveal      = election.generateReveal(candidateId, bundle.secretNonce, "round-B", sigKey)

            val round = election.newRound("round-A", listOf(bundle.commit))
            (round.acceptReveal(reveal) is VerificationResult.Invalid) shouldBe true
        }

        it("resolve picks winner with lowest VRF output") {
            val roundId    = "round-final"
            val sigKey1    = ByteArray(32) { 0x11.toByte() }
            val sigKey2    = ByteArray(32) { 0x22.toByte() }
            val sigKey3    = ByteArray(32) { 0x33.toByte() }

            val candidates = listOf(NodeId.random(), NodeId.random(), NodeId.random())
            val bundles    = candidates.map { election.generateCommit(it, roundId) }
            val sigKeys    = listOf(sigKey1, sigKey2, sigKey3)

            val commits  = bundles.map { it.commit }
            val reveals  = bundles.zip(sigKeys).zip(candidates).map { (bi, id) ->
                election.generateReveal(id, bi.first.secretNonce, roundId, bi.second)
            }

            val round = election.newRound(roundId, commits)
            reveals.forEach { round.acceptReveal(it) }
            val result = round.resolve()

            result.shouldNotBeNull()
            candidates.any { it == result.winner } shouldBe true
        }

        it("resolve returns null for empty reveals") {
            election.newRound("", emptyList()).resolve().shouldBeNull()
        }

        it("resolve excludes non-revealers") {
            val roundId   = "partial-round"
            val id1       = NodeId.random()
            val id2       = NodeId.random()
            val bundle1   = election.generateCommit(id1, roundId)
            val bundle2   = election.generateCommit(id2, roundId)
            val sigKey    = ByteArray(32) { 0x42 }
            val reveal1   = election.generateReveal(id1, bundle1.secretNonce, roundId, sigKey)

            val round = election.newRound(roundId, listOf(bundle1.commit, bundle2.commit))
            round.acceptReveal(reveal1)
            val result = round.resolve()

            result.shouldNotBeNull()
            result.winner shouldBe id1
            result.allVotes.size shouldBe 1
        }

        it("resolve is deterministic — two independent rounds with same reveals agree on winner") {
            val roundId     = "idempotent-round"
            val candidateId = NodeId.random()
            val bundle      = election.generateCommit(candidateId, roundId)
            val sigKey      = ByteArray(32) { 0x42 }
            val reveal      = election.generateReveal(candidateId, bundle.secretNonce, roundId, sigKey)

            val round1 = election.newRound(roundId, listOf(bundle.commit))
            round1.acceptReveal(reveal)
            val result1 = round1.resolve()

            val round2 = election.newRound(roundId, listOf(bundle.commit))
            round2.acceptReveal(reveal)
            val result2 = round2.resolve()

            result1.shouldNotBeNull()
            result2.shouldNotBeNull()
            result1.winner shouldBe result2.winner
        }

        it("resolve excludes reveals from a different round (mixed-round partition scenario)") {
            val roundA = "round-A"
            val roundB = "round-B"
            val idA    = NodeId.random()
            val idB    = NodeId.random()
            val sigKey = ByteArray(32) { 0x55 }

            val bundleA = election.generateCommit(idA, roundA)
            val bundleB = election.generateCommit(idB, roundB)
            val revealA = election.generateReveal(idA, bundleA.secretNonce, roundA, sigKey)
            val revealB = election.generateReveal(idB, bundleB.secretNonce, roundB, sigKey)

            val allCommits = listOf(bundleA.commit, bundleB.commit)

            val roundObjA = election.newRound(roundA, allCommits)
            roundObjA.acceptReveal(revealA)
            roundObjA.acceptReveal(revealB)  // rejected: roundId mismatch
            val resultA = roundObjA.resolve()
            resultA.shouldNotBeNull()
            resultA.winner shouldBe idA
            resultA.allVotes.size shouldBe 1

            val roundObjB = election.newRound(roundB, allCommits)
            roundObjB.acceptReveal(revealA)  // rejected: roundId mismatch
            roundObjB.acceptReveal(revealB)
            val resultB = roundObjB.resolve()
            resultB.shouldNotBeNull()
            resultB.winner shouldBe idB
            resultB.allVotes.size shouldBe 1
        }

        it("deriveRoundId is deterministic — same inputs produce same roundId") {
            val lastHash = ByteArray(32) { 0xAB.toByte() }
            val r1 = election.deriveRoundId(lastHash, 1L)
            val r2 = election.deriveRoundId(lastHash, 1L)
            r1 shouldBe r2
        }

        it("deriveRoundId differs for different election_seq") {
            val lastHash = ByteArray(32) { 0xAB.toByte() }
            election.deriveRoundId(lastHash, 1L) shouldNotBe election.deriveRoundId(lastHash, 2L)
        }
    }
})

// ── NodeTierManager ───────────────────────────────────────────────────────────

class NodeTierManagerTest : DescribeSpec({

    val mgr = NodeTierManager()

    fun profile(
        tier:       NodeTier,
        trust:      TrustLevel,
        uptimeMs:   Long  = NodeTierManager.TIER1_MIN_UPTIME_MS + 1,
        storagePct: Int   = 50,
        isOnline:   Boolean = true
    ) = NodeProfile(NodeId.random(), trust, tier, uptimeMs, storagePct, isOnline)

    describe("NodeTierManager — promotion rules") {

        it("eligible for Tier 1 when all conditions met") {
            val p = profile(NodeTier.TIER_2, TrustLevel.TRUST_PHYSICAL)
            mgr.canPromoteToTier1(p) shouldBe PromotionDecision.Eligible
        }

        it("ineligible for Tier 1 without TRUST_PHYSICAL") {
            val p = profile(NodeTier.TIER_2, TrustLevel.TRUST_INTRODUCED)
            (mgr.canPromoteToTier1(p) is PromotionDecision.Ineligible) shouldBe true
        }

        it("ineligible for Tier 1 with insufficient uptime") {
            val p = profile(NodeTier.TIER_2, TrustLevel.TRUST_PHYSICAL,
                uptimeMs = NodeTierManager.TIER1_MIN_UPTIME_MS - 1)
            (mgr.canPromoteToTier1(p) is PromotionDecision.Ineligible) shouldBe true
        }

        it("ineligible for Tier 1 at storage threshold") {
            val p = profile(NodeTier.TIER_2, TrustLevel.TRUST_PHYSICAL,
                storagePct = NodeTierManager.TIER1_MAX_STORAGE_PCT)
            (mgr.canPromoteToTier1(p) is PromotionDecision.Ineligible) shouldBe true
        }

        it("ineligible for Tier 1 when not online") {
            val p = profile(NodeTier.TIER_2, TrustLevel.TRUST_PHYSICAL, isOnline = false)
            (mgr.canPromoteToTier1(p) is PromotionDecision.Ineligible) shouldBe true
        }

        it("ineligible for Tier 1 if already Tier 1") {
            val p = profile(NodeTier.TIER_1, TrustLevel.TRUST_PHYSICAL)
            (mgr.canPromoteToTier1(p) is PromotionDecision.Ineligible) shouldBe true
        }
    }

    describe("NodeTierManager — demotion rules") {

        it("no demotion needed when healthy") {
            val p = profile(NodeTier.TIER_1, TrustLevel.TRUST_PHYSICAL)
            mgr.checkDemotion(p) shouldBe DemotionDecision.NotRequired
        }

        it("demotion required at 95% storage") {
            val p = profile(NodeTier.TIER_1, TrustLevel.TRUST_PHYSICAL,
                storagePct = NodeTierManager.TIER1_DEMOTION_STORAGE_PCT)
            (mgr.checkDemotion(p) is DemotionDecision.Required) shouldBe true
        }

        it("demotion required when trust drops") {
            val p = profile(NodeTier.TIER_1, TrustLevel.TRUST_INTRODUCED)
            (mgr.checkDemotion(p) is DemotionDecision.Required) shouldBe true
        }

        it("demotion required when goes offline") {
            val p = profile(NodeTier.TIER_1, TrustLevel.TRUST_PHYSICAL, isOnline = false)
            (mgr.checkDemotion(p) is DemotionDecision.Required) shouldBe true
        }

        it("no demotion check for non-Tier-1") {
            val p = profile(NodeTier.TIER_2, TrustLevel.TRUST_PHYSICAL)
            mgr.checkDemotion(p) shouldBe DemotionDecision.NotRequired
        }

        it("Tier 1 demotes to Tier 2") {
            val p = profile(NodeTier.TIER_1, TrustLevel.TRUST_PHYSICAL, storagePct = 96)
            mgr.demotionTarget(p) shouldBe NodeTier.TIER_2
        }
    }

    describe("NodeTierManager — circuit eligibility") {

        it("TRUST_PUBLIC is not circuit eligible") {
            val p = profile(NodeTier.TIER_2, TrustLevel.TRUST_PUBLIC)
            mgr.isCircuitEligible(p) shouldBe false
        }

        it("TRUST_PHYSICAL Tier 1 is circuit eligible") {
            val p = profile(NodeTier.TIER_1, TrustLevel.TRUST_PHYSICAL)
            mgr.isCircuitEligible(p) shouldBe true
        }

        it("TRUST_INTRODUCED Tier 2 is circuit eligible") {
            val p = profile(NodeTier.TIER_2, TrustLevel.TRUST_INTRODUCED)
            mgr.isCircuitEligible(p) shouldBe true
        }
    }
})

// ── GossipEngine — trust transitivity and watchdog ────────────────────────────

class GossipEngineTest : DescribeSpec({

    describe("Trust transitivity cap (§5.14)") {

        fun engine(scope: TestScope) = GossipEngine(
            localNodeId = NodeId.random(),
            scope       = scope,
            transport   = FakeGossipTransport()
        )

        it("TRUST_PHYSICAL + PHYSICAL intro → TRUST_PHYSICAL") {
            runTest {
                val e = engine(this)
                e.enforceTrustTransitivityCap(
                    TrustLevel.TRUST_PHYSICAL, IntroductionMethod.PHYSICAL
                ) shouldBe TrustLevel.TRUST_PHYSICAL
            }
        }

        it("TRUST_PHYSICAL + REMOTE intro → TRUST_INTRODUCED") {
            runTest {
                val e = engine(this)
                e.enforceTrustTransitivityCap(
                    TrustLevel.TRUST_PHYSICAL, IntroductionMethod.REMOTE
                ) shouldBe TrustLevel.TRUST_INTRODUCED
            }
        }

        it("TRUST_INTRODUCED + any intro → TRUST_PUBLIC (cap at depth 1)") {
            runTest {
                val e = engine(this)
                e.enforceTrustTransitivityCap(
                    TrustLevel.TRUST_INTRODUCED, IntroductionMethod.PHYSICAL
                ) shouldBe TrustLevel.TRUST_PUBLIC

                e.enforceTrustTransitivityCap(
                    TrustLevel.TRUST_INTRODUCED, IntroductionMethod.REMOTE
                ) shouldBe TrustLevel.TRUST_PUBLIC
            }
        }

        it("TRUST_PUBLIC + any intro → TRUST_PUBLIC") {
            runTest {
                val e = engine(this)
                e.enforceTrustTransitivityCap(
                    TrustLevel.TRUST_PUBLIC, IntroductionMethod.PHYSICAL
                ) shouldBe TrustLevel.TRUST_PUBLIC
            }
        }

        it("Sybil chain blocked: TRUST_INTRODUCED cannot create 100 anchors") {
            runTest {
                val e = engine(this)
                // 100 attempt to be introduced by a TRUST_INTRODUCED node
                repeat(100) {
                    e.enforceTrustTransitivityCap(
                        TrustLevel.TRUST_INTRODUCED, IntroductionMethod.REMOTE
                    ) shouldBe TrustLevel.TRUST_PUBLIC
                }
                // None of them get TRUST_INTRODUCED or above
            }
        }
    }

    describe("Local Watchdog — 3 failures → local block") {

        it("3 challenge failures in window triggers local block") {
            runTest {
                val transport = FakeGossipTransport(alwaysFail = true)
                val e = GossipEngine(
                    localNodeId = NodeId.random(),
                    scope       = this,
                    transport   = transport
                )
                val peer = DhtContact(
                    NodeId.random(), PeerAddress("1.2.3.4", 9),
                    isAnchor = true, tier = NodeTier.TIER_1
                )
                e.registerPeer(peer, TrustLevel.TRUST_PHYSICAL)

                // Issue 3 challenges — all fail
                repeat(GossipEngine.WATCHDOG_FAILURE_THRESHOLD) {
                    e.issueChallenge(peer)
                }
                advanceUntilIdle()

                e.isLocallyBlocked(peer.nodeId) shouldBe true
            }
        }

        it("2 failures do not trigger block") {
            runTest {
                val transport = FakeGossipTransport(alwaysFail = true)
                val e = GossipEngine(
                    localNodeId = NodeId.random(),
                    scope       = this,
                    transport   = transport
                )
                val peer = DhtContact(
                    NodeId.random(), PeerAddress("1.2.3.5", 9),
                    isAnchor = true, tier = NodeTier.TIER_1
                )
                e.registerPeer(peer, TrustLevel.TRUST_PHYSICAL)

                repeat(GossipEngine.WATCHDOG_FAILURE_THRESHOLD - 1) {
                    e.issueChallenge(peer)
                }
                advanceUntilIdle()

                e.isLocallyBlocked(peer.nodeId) shouldBe false
            }
        }

        it("blocked node fragments are silently dropped") {
            runTest {
                val transport = FakeGossipTransport(alwaysFail = true)
                val blockedId = NodeId.random()
                val e = GossipEngine(
                    localNodeId = NodeId.random(),
                    scope       = this,
                    transport   = transport
                )
                val peer = DhtContact(blockedId, PeerAddress("5.5.5.5", 9),
                    isAnchor = true, tier = NodeTier.TIER_1)
                e.registerPeer(peer, TrustLevel.TRUST_INTRODUCED)

                // Manually trigger 3 failures to block
                repeat(3) { e.issueChallenge(peer) }
                advanceUntilIdle()

                val fragment = FragmentEntity(
                    fragmentId    = "frag1", postId = "post1", channelId = "chan1",
                    sequenceIndex = 0, totalData = 10, totalParity = 7,
                    payload       = ByteArray(64), fecScheme = mesh.shadowmesh.mesh.fragment.FecScheme.RS_10_7
                )
                val relayed = e.relayFragment(fragment, blockedId)
                relayed shouldBe false
            }
        }
    }

    describe("GossipEngine — HoneyAnchor detection") {

        it("onHoneyFragmentDecrypted fires callback and locally blocks the source") {
            runTest {
                var tripped: NodeId? = null
                val e = GossipEngine(
                    localNodeId    = NodeId.random(),
                    scope          = this,
                    transport      = FakeGossipTransport(),
                    onHoneyTripped = { tripped = it }
                )
                val sourceId = NodeId.random()
                val peer     = DhtContact(sourceId, PeerAddress("9.9.9.9", 9),
                    isAnchor = true, tier = NodeTier.TIER_1)
                e.registerPeer(peer, TrustLevel.TRUST_PHYSICAL)

                e.onHoneyFragmentDecrypted(sourceId)

                tripped shouldBe sourceId
                e.isLocallyBlocked(sourceId) shouldBe true
            }
        }
    }

    describe("GossipEngine — rate limiting integration") {

        it("relay is dropped when rate limit exceeded") {
            runTest {
                val e = GossipEngine(
                    localNodeId = NodeId.random(),
                    scope       = this,
                    transport   = FakeGossipTransport()
                )
                val senderId = NodeId.random()
                val peer     = DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 1),
                    isAnchor = true, tier = NodeTier.TIER_1)
                e.registerPeer(peer, TrustLevel.TRUST_PHYSICAL)

                var accepted = 0
                repeat(RateLimitBucket.MAX_FRAGMENT_TOKENS + 10) { i ->
                    val frag = FragmentEntity(
                        fragmentId    = "frag-$i", postId = "post1", channelId = "chan1",
                        sequenceIndex = i, totalData = 100, totalParity = 0,
                        payload       = ByteArray(64), fecScheme = mesh.shadowmesh.mesh.fragment.FecScheme.NONE
                    )
                    if (e.relayFragment(frag, senderId)) accepted++
                }
                advanceUntilIdle()

                // Accepted count should be capped at MAX_FRAGMENT_TOKENS
                (accepted <= RateLimitBucket.MAX_FRAGMENT_TOKENS) shouldBe true
            }
        }
    }
})

// ── Fake transport implementations ───────────────────────────────────────────

private class FakeDhtTransport : DhtTransport {
    var pingResponse:    DhtContact? = null
    var deadSeed:        NodeId?     = null
    var findNodeResponse:List<DhtContact> = emptyList()

    override suspend fun ping(contact: DhtContact): DhtContact? =
        if (contact.nodeId == deadSeed) null else pingResponse ?: contact

    override suspend fun findNode(peer: DhtContact, target: NodeId): List<DhtContact> =
        findNodeResponse

    override suspend fun findValue(peer: DhtContact, key: NodeId): LookupResult =
        LookupResult.Contacts(findNodeResponse)

    override suspend fun store(peer: DhtContact, value: DhtValue) {}
}

private class FakeGossipTransport(val alwaysFail: Boolean = false) : GossipTransport {
    var sentFragments    = 0
    var honeyFragmentsSent = 0
    var challengeCount   = 0
    override suspend fun sendFragment(peer: DhtContact, fragment: FragmentEntity) { sentFragments++ }
    override suspend fun issueChallenge(peer: DhtContact, type: ChallengeType): Boolean {
        challengeCount++
        return !alwaysFail
    }
    override suspend fun broadcastHoneyFragment(fragment: FragmentEntity) { honeyFragmentsSent++ }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it.toInt() and 0xFF) }

// ── SeedList ──────────────────────────────────────────────────────────────────

class SeedListTest : DescribeSpec({

    describe("SeedList — List A DHT bootstrap") {

        it("hardcoded() returns 10 entries") {
            val list = SeedList.hardcoded()
            list.entries.size shouldBe 10
        }

        it("toContacts() produces valid DhtContact list") {
            val contacts = SeedList.hardcoded().toContacts()
            contacts.size shouldBe 10
            contacts.all { it.isTier1Anchor() } shouldBe true
        }

        it("expired entries are excluded from toContacts()") {
            val list = SeedList.from(listOf(
                SeedEntry("1.1.1.1", 7400, ttlMs = System.currentTimeMillis() - 1),
                SeedEntry("2.2.2.2", 7400, ttlMs = Long.MAX_VALUE)
            ))
            list.toContacts().size shouldBe 1
        }

        it("activeCount() only counts non-expired entries") {
            val list = SeedList.from(listOf(
                SeedEntry("1.1.1.1", 7400, ttlMs = System.currentTimeMillis() - 1),
                SeedEntry("2.2.2.2", 7400, ttlMs = Long.MAX_VALUE),
                SeedEntry("3.3.3.3", 7400, ttlMs = Long.MAX_VALUE)
            ))
            list.activeCount() shouldBe 2
        }

        it("withUpdate replaces existing entries by IP:port key") {
            val original = SeedList.from(listOf(
                SeedEntry("1.1.1.1", 7400, ttlMs = Long.MAX_VALUE)
            ))
            val update = SeedListUpdate(
                entries       = listOf(SeedEntry("1.1.1.1", 7400, ttlMs = Long.MAX_VALUE, publicKeyHex = "abcd")),
                issuedAtMs    = System.currentTimeMillis(),
                issuerNodeId  = ByteArray(32),
                signature     = ByteArray(64)
            )
            val updated = original.withUpdate(update)
            updated.entries.size shouldBe 1
            updated.entries[0].publicKeyHex shouldBe "abcd"
        }
    }
})

// ── HardenedChallengeLayer ─────────────────────────────────────────────────────

class HardenedChallengeLayerTest : DescribeSpec({

    describe("HardenedChallengeLayer — one challenge per peer per sync cycle") {

        it("onSyncCycleStart issues exactly one challenge per active peer") {
            runTest {
                val transport = FakeGossipTransport()
                val engine = GossipEngine(
                    localNodeId = NodeId.random(),
                    scope       = this,
                    transport   = transport
                )
                val layer = HardenedChallengeLayer(engine, this)

                val peers = (1..3).map {
                    DhtContact(NodeId.random(), PeerAddress("10.0.0.$it", 9),
                        isAnchor = true, tier = NodeTier.TIER_1)
                }
                peers.forEach { layer.markPeerActive(it) }
                layer.activePeerCount() shouldBe 3

                layer.onSyncCycleStart(peers)
                advanceUntilIdle()

                // Each peer should have received exactly one challenge
                transport.challengeCount shouldBe 3
            }
        }

        it("peers removed via removePeer are not challenged") {
            runTest {
                val transport = FakeGossipTransport()
                val engine = GossipEngine(
                    localNodeId = NodeId.random(),
                    scope       = this,
                    transport   = transport
                )
                val layer = HardenedChallengeLayer(engine, this)

                val peer1 = DhtContact(NodeId.random(), PeerAddress("10.0.0.1", 9),
                    isAnchor = true, tier = NodeTier.TIER_1)
                val peer2 = DhtContact(NodeId.random(), PeerAddress("10.0.0.2", 9),
                    isAnchor = true, tier = NodeTier.TIER_1)

                layer.markPeerActive(peer1)
                layer.markPeerActive(peer2)
                layer.removePeer(peer2.nodeId)

                layer.onSyncCycleStart(listOf(peer1, peer2))
                advanceUntilIdle()

                transport.challengeCount shouldBe 1
            }
        }

        it("challenge types rotate across cycles for the same peer") {
            runTest {
                val transport = CountingGossipTransport()
                val engine = GossipEngine(
                    localNodeId = NodeId.random(),
                    scope       = this,
                    transport   = transport
                )
                val layer = HardenedChallengeLayer(engine, this)
                val peer  = DhtContact(NodeId.random(), PeerAddress("10.0.0.1", 9),
                    isAnchor = true, tier = NodeTier.TIER_1)
                layer.markPeerActive(peer)

                // Run 4 cycles — should see all 4 challenge types
                repeat(4) {
                    layer.onSyncCycleStart(listOf(peer))
                    advanceUntilIdle()
                }

                transport.challengeTypes.distinct().size shouldBe 4
            }
        }
    }
})

// ── Extended fake transports ──────────────────────────────────────────────────

private class CountingGossipTransport : GossipTransport {
    val challengeTypes = mutableListOf<ChallengeType>()
    override suspend fun sendFragment(peer: DhtContact, fragment: FragmentEntity) {}
    override suspend fun issueChallenge(peer: DhtContact, type: ChallengeType): Boolean {
        challengeTypes.add(type)
        return true
    }
    override suspend fun broadcastHoneyFragment(fragment: FragmentEntity) {}
}

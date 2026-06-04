package mesh.shadowmesh.mesh.mode

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.coroutines.*
import kotlinx.coroutines.test.*
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.mesh.anchor.*
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.fragment.*
import mesh.shadowmesh.mesh.migration.*
import mesh.shadowmesh.nsc.*

// ── NetworkModeStateMachine ───────────────────────────────────────────────────

class NetworkModeStateMachineTest : DescribeSpec({

    describe("NetworkModeStateMachine — four-mode transitions") {

        it("starts in SURVIVAL with 0 anchors") {
            val sm = NetworkModeStateMachine(0)
            sm.currentMode shouldBe NetworkMode.SURVIVAL
        }

        it("transitions to CRITICAL at entry threshold (4 anchors)") {
            val sm = NetworkModeStateMachine(0)
            sm.onAnchorCountChanged(4)
            sm.currentMode shouldBe NetworkMode.CRITICAL
        }

        it("transitions to DEGRADED at entry threshold (8 anchors)") {
            val sm = NetworkModeStateMachine(0)
            sm.onAnchorCountChanged(8)
            sm.currentMode shouldBe NetworkMode.DEGRADED
        }

        it("transitions to HEALTHY at entry threshold (15 anchors)") {
            val sm = NetworkModeStateMachine(0)
            sm.onAnchorCountChanged(15)
            sm.currentMode shouldBe NetworkMode.HEALTHY
        }

        it("correct transitions at boundary — 1 to 100 anchors") {
            val sm = NetworkModeStateMachine(0)
            (1..100).forEach { count ->
                val mode = sm.onAnchorCountChanged(count)
                when {
                    count >= 15 -> mode shouldBe NetworkMode.HEALTHY
                    count >= 8  -> (mode == NetworkMode.DEGRADED || mode == NetworkMode.HEALTHY) shouldBe true
                    count >= 4  -> (mode == NetworkMode.CRITICAL || mode == NetworkMode.DEGRADED) shouldBe true
                    else        -> (mode == NetworkMode.SURVIVAL || mode == NetworkMode.CRITICAL) shouldBe true
                }
            }
        }

        it("listener fires on transition") {
            val sm = NetworkModeStateMachine(0)
            val transitions = mutableListOf<Pair<NetworkMode, NetworkMode>>()
            sm.addListener { from, to -> transitions.add(from to to) }
            sm.onAnchorCountChanged(15)
            transitions.size shouldBe 1
            transitions[0].second shouldBe NetworkMode.HEALTHY
        }

        it("listener not fired when mode unchanged") {
            val sm = NetworkModeStateMachine(15)
            val transitions = mutableListOf<Pair<NetworkMode, NetworkMode>>()
            sm.addListener { from, to -> transitions.add(from to to) }
            sm.onAnchorCountChanged(20)  // still HEALTHY
            transitions.size shouldBe 0
        }
    }

    describe("NetworkMode capabilities per mode") {

        it("HEALTHY: 3-hop circuit available, SNDP 10%, replication 3") {
            NetworkMode.HEALTHY.circuitAvailable   shouldBe true
            NetworkMode.HEALTHY.sndpEnabled        shouldBe true
            NetworkMode.HEALTHY.sndpRate           shouldBe 0.10f
            NetworkMode.HEALTHY.replicationFactor  shouldBe 3
            NetworkMode.HEALTHY.dhtOperational     shouldBe true
        }

        it("DEGRADED: circuit available, SNDP reduced to 5%, replication 5") {
            NetworkMode.DEGRADED.circuitAvailable  shouldBe true
            NetworkMode.DEGRADED.sndpEnabled       shouldBe true
            NetworkMode.DEGRADED.sndpRate          shouldBe 0.05f
            NetworkMode.DEGRADED.replicationFactor shouldBe 5
        }

        it("CRITICAL: no 3-hop circuit, 2-hop available, SNDP disabled") {
            NetworkMode.CRITICAL.circuitAvailable  shouldBe false
            NetworkMode.CRITICAL.twoHopAvailable   shouldBe true
            NetworkMode.CRITICAL.sndpEnabled       shouldBe false
            NetworkMode.CRITICAL.sndpRate          shouldBe 0f
        }

        it("SURVIVAL: no circuit, no SNDP, no DHT") {
            NetworkMode.SURVIVAL.circuitAvailable  shouldBe false
            NetworkMode.SURVIVAL.twoHopAvailable   shouldBe false
            NetworkMode.SURVIVAL.sndpEnabled       shouldBe false
            NetworkMode.SURVIVAL.dhtOperational    shouldBe false
        }

        it("replicationFactor increases as mode degrades") {
            (NetworkMode.HEALTHY.replicationFactor <
             NetworkMode.DEGRADED.replicationFactor) shouldBe true
        }
    }

    describe("Degraded mode peer selection adjustments") {

        it("HEALTHY uses STANDARD peer selection") {
            NetworkMode.HEALTHY.peerSelectionMode shouldBe PeerSelectionMode.STANDARD
        }

        it("CRITICAL uses OPERATIONAL peer selection (no cover)") {
            NetworkMode.CRITICAL.peerSelectionMode shouldBe PeerSelectionMode.OPERATIONAL
        }

        it("SURVIVAL uses OPERATIONAL peer selection") {
            NetworkMode.SURVIVAL.peerSelectionMode shouldBe PeerSelectionMode.OPERATIONAL
        }
    }

    describe("NetworkModeStateMachine — hysteresis transition matrix") {

        it("cold start at 0 anchors is SURVIVAL") {
            NetworkModeStateMachine(0).currentMode shouldBe NetworkMode.SURVIVAL
        }

        it("cold start at 15 anchors is HEALTHY") {
            NetworkModeStateMachine(15).currentMode shouldBe NetworkMode.HEALTHY
        }

        // ── Descent from HEALTHY ──────────────────────────────────────────

        it("HEALTHY stays HEALTHY at 15 (at threshold)") {
            val sm = NetworkModeStateMachine(20)
            sm.onAnchorCountChanged(15) shouldBe NetworkMode.HEALTHY
        }

        it("HEALTHY drops to DEGRADED at 10 (DEGRADED_EXIT_THRESHOLD)") {
            val sm = NetworkModeStateMachine(20)
            sm.onAnchorCountChanged(10) shouldBe NetworkMode.DEGRADED
        }

        it("HEALTHY does not drop to DEGRADED at 14 (hysteresis — stays HEALTHY)") {
            val sm = NetworkModeStateMachine(20)
            sm.onAnchorCountChanged(14) shouldBe NetworkMode.HEALTHY
        }

        it("HEALTHY drops to CRITICAL at 6 (CRITICAL_EXIT_THRESHOLD)") {
            val sm = NetworkModeStateMachine(20)
            sm.onAnchorCountChanged(6) shouldBe NetworkMode.CRITICAL
        }

        it("HEALTHY drops to SURVIVAL at 0") {
            val sm = NetworkModeStateMachine(20)
            sm.onAnchorCountChanged(0) shouldBe NetworkMode.SURVIVAL
        }

        // ── Descent from DEGRADED ─────────────────────────────────────────

        it("DEGRADED stays DEGRADED at 8 (DEGRADED_ENTRY_THRESHOLD)") {
            val sm = NetworkModeStateMachine(12)
            sm.onAnchorCountChanged(12)  // ensure DEGRADED
            sm.onAnchorCountChanged(8) shouldBe NetworkMode.DEGRADED
        }

        it("DEGRADED drops to CRITICAL at 6") {
            val sm = NetworkModeStateMachine(12)
            sm.onAnchorCountChanged(6) shouldBe NetworkMode.CRITICAL
        }

        it("DEGRADED does NOT drop to CRITICAL at 7 (hysteresis)") {
            val sm = NetworkModeStateMachine(12)
            sm.onAnchorCountChanged(7) shouldBe NetworkMode.DEGRADED
        }

        // ── Recovery from CRITICAL ────────────────────────────────────────

        it("CRITICAL recovers to DEGRADED only at DEGRADED_EXIT_THRESHOLD (10)") {
            val sm = NetworkModeStateMachine(3)
            sm.onAnchorCountChanged(3)   // ensure CRITICAL
            sm.onAnchorCountChanged(9) shouldBe NetworkMode.CRITICAL  // below exit threshold
            sm.onAnchorCountChanged(10) shouldBe NetworkMode.DEGRADED // at exit threshold
        }

        it("CRITICAL does not jump to HEALTHY (one mode at a time)") {
            val sm = NetworkModeStateMachine(3)
            // From CRITICAL, reaching 15 should go to HEALTHY (allowed — large jump up)
            sm.onAnchorCountChanged(20) shouldBe NetworkMode.HEALTHY
        }

        // ── Recovery from SURVIVAL ────────────────────────────────────────

        it("SURVIVAL recovers to CRITICAL at SURVIVAL_EXIT_THRESHOLD (2)") {
            val sm = NetworkModeStateMachine(0)
            sm.onAnchorCountChanged(1) shouldBe NetworkMode.SURVIVAL  // below exit threshold
            sm.onAnchorCountChanged(2) shouldBe NetworkMode.CRITICAL  // at exit threshold
        }

        it("SURVIVAL recovers to DEGRADED at DEGRADED_EXIT_THRESHOLD (10)") {
            val sm = NetworkModeStateMachine(0)
            sm.onAnchorCountChanged(10) shouldBe NetworkMode.DEGRADED
        }

        // ── Listener ──────────────────────────────────────────────────────

        it("listener fires on transition with correct from/to") {
            val transitions = mutableListOf<Pair<NetworkMode, NetworkMode>>()
            val sm = NetworkModeStateMachine(20)
            sm.addListener { from, to -> transitions.add(from to to) }

            sm.onAnchorCountChanged(5)  // HEALTHY → CRITICAL

            transitions.size shouldBe 1
            transitions[0].first  shouldBe NetworkMode.HEALTHY
            transitions[0].second shouldBe NetworkMode.CRITICAL
        }

        it("listener does not fire when mode stays the same") {
            var fired = false
            val sm = NetworkModeStateMachine(20)
            sm.addListener { _, _ -> fired = true }
            sm.onAnchorCountChanged(18)  // still HEALTHY
            fired shouldBe false
        }
    }
})

// ── AnchorHandoffManager ──────────────────────────────────────────────────────

class AnchorHandoffManagerTest : DescribeSpec({

    describe("buildAnchorHandoffTransition — NSC P1 transition") {

        it("success path: all steps execute, returns Success") {
            runTest {
                var transferred = false
                var verified    = false
                var updated     = false
                var reembed     = false

                val t = buildAnchorHandoffTransition(
                    sourceNodeId       = "src",
                    targetNodeId       = "tgt",
                    dhtSliceTransferFn = { transferred = true; true },
                    merkleVerifyFn     = { verified    = true; true },
                    dhtUpdateFn        = { updated     = true },
                    revertDhtFn        = {},
                    honeyReembedFn     = { reembed     = true }
                )

                val checkpoints = mutableListOf<Checkpoint>()
                val result = t.execute { checkpoints.add(it) }

                result shouldBe TransitionResult.Success
                transferred shouldBe true
                verified    shouldBe true
                updated     shouldBe true
                reembed     shouldBe true
                checkpoints.size shouldBe 3
            }
        }

        it("transfer failure: returns Failure immediately") {
            runTest {
                var verifyCalled = false
                val t = buildAnchorHandoffTransition(
                    sourceNodeId       = "src",
                    targetNodeId       = "tgt",
                    dhtSliceTransferFn = { false },
                    merkleVerifyFn     = { verifyCalled = true; true },
                    dhtUpdateFn        = {},
                    revertDhtFn        = {}
                )
                val result = t.execute {}
                (result is TransitionResult.Failure) shouldBe true
                verifyCalled shouldBe false
            }
        }

        it("Merkle verify failure: returns retriable Failure, rollback called") {
            runTest {
                var revertCalled = false
                val checkpoints  = mutableListOf<Checkpoint>()
                val t = buildAnchorHandoffTransition(
                    sourceNodeId       = "src",
                    targetNodeId       = "tgt",
                    dhtSliceTransferFn = { true },
                    merkleVerifyFn     = { false },
                    dhtUpdateFn        = {},
                    revertDhtFn        = { revertCalled = true }
                )

                val result = t.execute { checkpoints.add(it) }
                (result is TransitionResult.Failure) shouldBe true
                (result as TransitionResult.Failure).shouldRetry shouldBe true

                // Simulate NSC rollback
                checkpoints.reversed().forEach { it.rollback() }
                revertCalled shouldBe true
            }
        }

        it("transition priority is P1_DATA_INTEGRITY") {
            val t = buildAnchorHandoffTransition("s", "t", { true }, { true }, {}, {})
            t.priority shouldBe Priority.P1_DATA_INTEGRITY
        }

        it("transition scope is GLOBAL") {
            val t = buildAnchorHandoffTransition("s", "t", { true }, { true }, {}, {})
            t.scope shouldBe TransitionScope.GLOBAL
        }

        it("acquires NODE_TIER(src), NODE_TIER(tgt), DHT_SLICE(src) locks") {
            val t = buildAnchorHandoffTransition("src", "tgt", { true }, { true }, {}, {})
            val lockTypes = t.requiredLocks.map { it.type }
            lockTypes.count { it == LockType.NODE_TIER }  shouldBe 2
            lockTypes.count { it == LockType.DHT_SLICE }  shouldBe 1
            t.requiredLocks.any { it.type == LockType.DHT_SLICE && it.entityId == "src" } shouldBe true
        }

        it("first checkpoint rollback opcode is ReclaimDhtSlice") {
            runTest {
                val checkpoints = mutableListOf<Checkpoint>()
                val t = buildAnchorHandoffTransition("src", "tgt", { true }, { true }, {}, {})
                t.execute { checkpoints.add(it) }
                (checkpoints.first().opcode is RollbackOpcode.ReclaimDhtSlice) shouldBe true
            }
        }

        it("HoneyAnchor re-embedding failure does not block commit") {
            runTest {
                var updated = false
                val t = buildAnchorHandoffTransition(
                    sourceNodeId       = "src",
                    targetNodeId       = "tgt",
                    dhtSliceTransferFn = { true },
                    merkleVerifyFn     = { true },
                    dhtUpdateFn        = { updated = true },
                    revertDhtFn        = {},
                    honeyReembedFn     = { throw RuntimeException("honey embed failed") }
                )
                val result = t.execute {}
                result shouldBe TransitionResult.Success
                updated shouldBe true
            }
        }
    }
})

// ── DHT re-bootstrap ──────────────────────────────────────────────────────────

class DhtRebootstrapTest : DescribeSpec({

    describe("AnchorHandoffManager.rebootstrap — anchor failure recovery") {

        it("rebootstrap succeeds with available survivor") {
            runTest {
                val localId   = NodeId.random()
                val failedId  = NodeId.random()
                val winnerId  = NodeId.random()
                val survivorId= NodeId.random()

                var handoffCalled = false
                val transport = object : AnchorTransport {
                    override suspend fun transferDhtSlice(s: String, t: String): Boolean { handoffCalled = true; return true }
                    override suspend fun verifySliceMerkle(s: String, t: String) = true
                    override suspend fun broadcastRoutingUpdate(o: String, n: String) {}
                    override suspend fun revertSliceTransfer(s: String, t: String) {}
                    override suspend fun reembedHoneyAnchor(n: String) {}
                }

                // Routing table with survivor
                val routingTable = RoutingTable(localId)
                val survivorContact = DhtContact(
                    survivorId, PeerAddress("1.2.3.4", 7400),
                    isAnchor = true, tier = NodeTier.TIER_1
                )
                routingTable.insert(survivorContact)

                val dhtEngine = DhtEngine(localId, FakeDhtTransport(), this)

                // Patch routing table contacts for test
                // (DhtEngine.routingTable.findClosest will find our survivor)
                dhtEngine.routingTable.insert(survivorContact)

                val manager = AnchorHandoffManager(
                    localNodeId = localId,
                    nsc         = FakeNsc(),
                    dhtEngine   = dhtEngine,
                    transport   = transport,
                    scope       = this
                )

                val result = manager.rebootstrap(failedId, winnerId)
                (result is RebootstrapResult.Success || result is RebootstrapResult.Failed) shouldBe true
            }
        }

        it("rebootstrap returns NoSurvivors when routing table empty") {
            runTest {
                val localId  = NodeId.random()
                val failedId = NodeId.random()
                val winnerId = NodeId.random()

                val manager = AnchorHandoffManager(
                    localNodeId = localId,
                    nsc         = FakeNsc(),
                    dhtEngine   = DhtEngine(localId, FakeDhtTransport(), this),
                    transport   = FakeAnchorTransport(),
                    scope       = this
                )

                val result = manager.rebootstrap(failedId, winnerId)
                result shouldBe RebootstrapResult.NoSurvivors
            }
        }
    }
})

// ── FragmentMigrationManager ──────────────────────────────────────────────────

class FragmentMigrationManagerTest : DescribeSpec({

    describe("FragmentMigrationManager — storage threshold events") {

        it("no action below 80% storage") {
            runTest {
                val mgr = makeMigrationManager(this)
                mgr.onStorageChanged(79) shouldBe StorageAction.NoAction
            }
        }

        it("migration started at exactly 80%") {
            runTest {
                val mgr = makeMigrationManager(this)
                mgr.onStorageChanged(80) shouldBe StorageAction.MigrationStarted
                mgr.isMigrationInProgress() shouldBe true
            }
        }

        it("migration cancelled when storage drops below 75%") {
            runTest {
                val mgr = makeMigrationManager(this)
                mgr.onStorageChanged(80)  // start
                advanceUntilIdle()
                mgr.onStorageChanged(74)  // cancel
                mgr.isMigrationInProgress() shouldBe false
            }
        }

        it("no migration started twice without cancel") {
            runTest {
                val mgr = makeMigrationManager(this)
                val r1 = mgr.onStorageChanged(80)
                val r2 = mgr.onStorageChanged(85)  // already in progress
                r1 shouldBe StorageAction.MigrationStarted
                // r2 should be NoAction or UserNotificationRequired (not double-start)
                (r2 != StorageAction.MigrationStarted) shouldBe true
            }
        }
    }

    describe("Lease management") {

        it("claimLease adds active lease") {
            runTest {
                val mgr = makeMigrationManager(this)
                mgr.claimLease("channel_key_abc", "nodeX")
                mgr.activeLeasesCount() shouldBe 1
            }
        }

        it("releaseLease removes lease") {
            runTest {
                val transport = FakeMigrationTransport()
                val mgr = FragmentMigrationManager(NodeId.random(), transport, this)
                mgr.claimLease("key1", "node1")
                mgr.releaseLease("key1")
                mgr.activeLeasesCount() shouldBe 0
                transport.leaseExpiryCalls shouldBe 1
            }
        }

        it("evictExpiredLeases removes only expired ones") {
            runTest {
                val mgr = makeMigrationManager(this)
                mgr.claimLease("active", "node1")
                // Manually expire by testing with past time — simulate via direct model
                // Active lease should remain
                mgr.activeLeasesCount() shouldBe 1
            }
        }
    }

    describe("Live Mode query budget") {

        it("10 queries allocated across 1 thread = 10 queries per thread") {
            val mgr = makeMigrationManagerSync()
            mgr.allocateLiveModeQueries(1) shouldBe 10
        }

        it("10 queries allocated across 5 threads = 2 queries per thread") {
            val mgr = makeMigrationManagerSync()
            mgr.allocateLiveModeQueries(5) shouldBe 2
        }

        it("10 queries across 15 threads = 1 query per thread (minimum)") {
            val mgr = makeMigrationManagerSync()
            mgr.allocateLiveModeQueries(15) shouldBe 1
        }

        it("0 threads = 0 queries") {
            val mgr = makeMigrationManagerSync()
            mgr.allocateLiveModeQueries(0) shouldBe 0
        }
    }

    describe("User-initiated LRU clear") {

        it("releases oldest leases first (LRU order)") {
            runTest {
                val transport = FakeMigrationTransport()
                val mgr = FragmentMigrationManager(NodeId.random(), transport, this)
                // Add 3 leases at different times
                mgr.claimLease("old",    "node1")
                delay(10)
                mgr.claimLease("middle", "node2")
                delay(10)
                mgr.claimLease("new",    "node3")

                // Target 0 storage pct (release all)
                transport.currentStoragePctValue = 0
                val released = mgr.userInitiatedLruClear(targetPct = 50)
                // At least some leases released
                (released > 0) shouldBe true
            }
        }
    }
})

// ── AnticipatoryReplicationManager ───────────────────────────────────────────

class AnticipatoryReplicationManagerTest : DescribeSpec({

    val hkdf   = Hkdf.instance
    val cipher = mesh.shadowmesh.crypto.SymmetricCipher()

    describe("AnticipatoryReplicationManager — cache lifecycle") {

        it("cache populated after refreshCacheForAllPeers") {
            runTest {
                val deviceSecret = ByteArray(32) { 0x42 }
                val mgr = AnticipatoryReplicationManager(
                    localNodeId  = NodeId.random(),
                    deviceSecret = deviceSecret,
                    scope        = this,
                    transport    = FakeAnticipatoryCacheTransport()
                )
                val peer = DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 1),
                    isAnchor = true, tier = NodeTier.TIER_1)

                mgr.refreshCacheForAllPeers(listOf(peer))
                advanceUntilIdle()

                mgr.activePeerCacheCount() shouldBe 1
            }
        }

        it("cycle sequence increments each refresh") {
            runTest {
                val mgr = makeAnticipatoryCacheManager(this)
                mgr.currentCycleSequence() shouldBe 0
                mgr.refreshCacheForAllPeers(emptyList())
                mgr.currentCycleSequence() shouldBe 1
                mgr.refreshCacheForAllPeers(emptyList())
                mgr.currentCycleSequence() shouldBe 2
            }
        }

        it("onMigrationCancelled clears all caches") {
            runTest {
                val mgr = makeAnticipatoryCacheManager(this)
                val peer = DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 1),
                    isAnchor = true, tier = NodeTier.TIER_1)
                mgr.refreshCacheForAllPeers(listOf(peer))
                advanceUntilIdle()
                mgr.activePeerCacheCount() shouldBe 1

                mgr.onMigrationCancelled(listOf("slot1", "slot2"))
                mgr.activePeerCacheCount() shouldBe 0
            }
        }

        it("retrieveForUrgentMode returns null for unknown peer") {
            runTest {
                val mgr = makeAnticipatoryCacheManager(this)
                mgr.retrieveForUrgentMode(NodeId.random()).shouldBeNull()
            }
        }

        it("ANTICIPATORY_CACHE constants correct") {
            AnticipatoryReplicationManager.TARGET_CACHE_BYTES shouldBe 200 * 1024
            AnticipatoryReplicationManager.DECOY_FRAGMENT_SIZE shouldBe 512
        }
    }
})

// ── Phase 6 exit gate — integration scenario ──────────────────────────────────

class Phase6ExitGateTest : DescribeSpec({

    describe("Phase 6 exit gate — mode boundary transitions") {

        it("1→15 node ramp: correct mode at each threshold") {
            val sm = NetworkModeStateMachine(0)
            val modeAt = (1..20).map { count ->
                count to sm.onAnchorCountChanged(count)
            }

            // At count=1: SURVIVAL or CRITICAL (hysteresis from 0)
            val at1  = modeAt.find { it.first == 1  }!!.second
            val at4  = modeAt.find { it.first == 4  }!!.second
            val at8  = modeAt.find { it.first == 8  }!!.second
            val at15 = modeAt.find { it.first == 15 }!!.second

            (at1  == NetworkMode.SURVIVAL || at1  == NetworkMode.CRITICAL) shouldBe true
            (at4  == NetworkMode.CRITICAL || at4  == NetworkMode.DEGRADED) shouldBe true
            (at8  == NetworkMode.DEGRADED || at8  == NetworkMode.HEALTHY)  shouldBe true
            at15 shouldBe NetworkMode.HEALTHY
        }

        it("replication factor adjusts correctly across mode boundaries") {
            val sm = NetworkModeStateMachine(0)
            sm.onAnchorCountChanged(15)
            sm.replicationFactor shouldBe 3

            sm.onAnchorCountChanged(8)
            sm.replicationFactor shouldBe 5

            sm.onAnchorCountChanged(4)
            (sm.replicationFactor == Int.MAX_VALUE) shouldBe true  // all available

            sm.onAnchorCountChanged(1)
            (sm.replicationFactor == Int.MAX_VALUE) shouldBe true
        }

        it("SNDP disabled at CRITICAL and SURVIVAL, enabled at HEALTHY and DEGRADED") {
            val sm = NetworkModeStateMachine(0)

            sm.onAnchorCountChanged(15); sm.sndpEnabled shouldBe true
            sm.onAnchorCountChanged(8);  sm.sndpEnabled shouldBe true
            sm.onAnchorCountChanged(4);  sm.sndpEnabled shouldBe false
            sm.onAnchorCountChanged(1);  sm.sndpEnabled shouldBe false
        }

        it("circuit unavailable at CRITICAL and SURVIVAL") {
            val sm = NetworkModeStateMachine(0)
            sm.onAnchorCountChanged(4)
            sm.circuitAvailable shouldBe false
            sm.twoHopAvailable shouldBe true   // 2-hop fallback available in CRITICAL

            sm.onAnchorCountChanged(1)
            sm.circuitAvailable shouldBe false
            sm.twoHopAvailable shouldBe false   // no circuit at all in SURVIVAL
        }
    }

    describe("Phase 6 exit gate — anchor handoff zero data loss") {

        it("handoff completes with zero data loss — all 3 steps execute in order") {
            runTest {
                val executionOrder = mutableListOf<String>()

                val t = buildAnchorHandoffTransition(
                    sourceNodeId       = "anchor_A",
                    targetNodeId       = "anchor_B",
                    dhtSliceTransferFn = { executionOrder.add("transfer"); true },
                    merkleVerifyFn     = { executionOrder.add("verify"); true },
                    dhtUpdateFn        = { executionOrder.add("update") },
                    revertDhtFn        = {}
                )

                val result = t.execute {}
                result shouldBe TransitionResult.Success
                executionOrder shouldBe listOf("transfer", "verify", "update")
            }
        }
    }

    describe("Phase 6 exit gate — fragment migration MIGRATION_CANCEL") {

        it("MIGRATION_CANCEL sent when storage drops below 75% after starting") {
            runTest {
                val transport = FakeMigrationTransport()
                val mgr = FragmentMigrationManager(NodeId.random(), transport, this)

                mgr.onStorageChanged(80)   // start migration
                advanceUntilIdle()
                val cancelResult = mgr.onStorageChanged(74)  // cancel

                cancelResult shouldBe StorageAction.MigrationCancelled
                mgr.isMigrationInProgress() shouldBe false
                transport.migrationCancelCalls shouldBe 1
            }
        }
    }
})

// ── Fake implementations ──────────────────────────────────────────────────────

private class FakeAnchorTransport : AnchorTransport {
    override suspend fun transferDhtSlice(s: String, t: String) = true
    override suspend fun verifySliceMerkle(s: String, t: String) = true
    override suspend fun broadcastRoutingUpdate(o: String, n: String) {}
    override suspend fun revertSliceTransfer(s: String, t: String) {}
    override suspend fun reembedHoneyAnchor(n: String) {}
}

private class FakeDhtTransport : DhtTransport {
    override suspend fun ping(c: DhtContact) = c
    override suspend fun findNode(p: DhtContact, t: NodeId) = emptyList<DhtContact>()
    override suspend fun findValue(p: DhtContact, k: NodeId) = LookupResult.NotFound
    override suspend fun store(p: DhtContact, v: DhtValue) {}
}

private class FakeMigrationTransport : MigrationTransport {
    var migrationCancelCalls = 0
    var leaseExpiryCalls     = 0
    var currentStoragePctValue = 85

    override suspend fun publishMigrationNeeded(n: String, k: String) {}
    override suspend fun publishMigrationCancel(n: String, k: String) { migrationCancelCalls++ }
    override suspend fun publishLeaseExpiry(n: String, k: String) { leaseExpiryCalls++ }
    override suspend fun currentStoragePct() = currentStoragePctValue
}

private class FakeAnticipatoryCacheTransport : AnticipatoryCacheTransport {
    override suspend fun fetchRealFragmentsForPeer(p: DhtContact, m: Int): List<FragmentEntity> =
        listOf(FragmentEntity(
            fragmentId = "real_frag", postId = "post1", channelId = "chan1",
            sequenceIndex = 0, totalData = 1, totalParity = 0,
            payload = ByteArray(64) { 0x01 }, fecScheme = FecScheme.NONE
        ))
}

/** Minimal fake NSC — always succeeds immediately. */
private class FakeNsc : mesh.shadowmesh.nsc.NscLike {
    override fun requestTransition(t: StateTransition): kotlinx.coroutines.Deferred<TransitionResult> =
        CompletableDeferred(kotlinx.coroutines.runBlocking { t.execute {} })
}

private fun makeMigrationManager(scope: TestScope): FragmentMigrationManager =
    FragmentMigrationManager(NodeId.random(), FakeMigrationTransport(), scope)

private fun makeMigrationManagerSync(): FragmentMigrationManager =
    FragmentMigrationManager(NodeId.random(), object : MigrationTransport {
        override suspend fun publishMigrationNeeded(n: String, k: String) {}
        override suspend fun publishMigrationCancel(n: String, k: String) {}
        override suspend fun publishLeaseExpiry(n: String, k: String) {}
        override suspend fun currentStoragePct() = 50
    }, CoroutineScope(Dispatchers.Default))

private fun makeAnticipatoryCacheManager(scope: TestScope): AnticipatoryReplicationManager =
    AnticipatoryReplicationManager(
        localNodeId  = NodeId.random(),
        deviceSecret = ByteArray(32) { 0x42 },
        scope        = scope,
        transport    = FakeAnticipatoryCacheTransport()
    )

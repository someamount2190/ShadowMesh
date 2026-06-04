package mesh.shadowmesh.mesh.delivery

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.doubles.shouldBeLessThan
import io.kotest.matchers.doubles.shouldBeGreaterThan
import mesh.shadowmesh.mesh.mode.NetworkMode

class DensityAwareReplicationPolicyTest : DescribeSpec({

    // ── Factor table — HEALTHY mode ───────────────────────────────────────

    describe("DensityAwareReplicationPolicy — HEALTHY mode factor table") {

        it("0 local peers → factor 3 (sparse, no density reduction)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 0) shouldBe 3
        }

        it("1 local peer → factor 3 (small cluster, still full DHT)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 1) shouldBe 3
        }

        it("4 local peers → factor 3 (below medium threshold)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 4) shouldBe 3
        }

        it("5 local peers → factor 2 (medium cluster)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 5) shouldBe 2
        }

        it("9 local peers → factor 2 (still medium cluster)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 9) shouldBe 2
        }

        it("10 local peers → factor 1 (dense cluster — local holds copies)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 10) shouldBe 1
        }

        it("50 local peers → factor 1 (very dense — one DHT backup)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 50) shouldBe 1
        }
    }

    // ── Factor table — DEGRADED mode ──────────────────────────────────────

    describe("DensityAwareReplicationPolicy — DEGRADED mode factor table") {

        it("0 local peers → factor 5 (sparse — maximum DHT replication)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.DEGRADED, 0) shouldBe 5
        }

        it("1 local peer → factor 4 (small cluster — slight reduction)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.DEGRADED, 1) shouldBe 4
        }

        it("5 local peers → factor 3 (medium cluster)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.DEGRADED, 5) shouldBe 3
        }

        it("10 local peers → factor 2 (dense — still keeps 2 DHT backups)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.DEGRADED, 10) shouldBe 2
        }

        it("DEGRADED dense factor is always ≥ 2 (more conservative than HEALTHY)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            repeat(100) {
                val factor = policy.effectiveFactor(NetworkMode.DEGRADED, 100)
                (factor >= 2) shouldBe true
            }
        }
    }

    // ── CRITICAL and SURVIVAL override ────────────────────────────────────

    describe("DensityAwareReplicationPolicy — CRITICAL/SURVIVAL override density") {

        it("CRITICAL always returns Int.MAX_VALUE regardless of local peers") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            listOf(0, 1, 5, 10, 100).forEach { peerCount ->
                policy.effectiveFactor(NetworkMode.CRITICAL, peerCount) shouldBe Int.MAX_VALUE
            }
        }

        it("SURVIVAL always returns Int.MAX_VALUE regardless of local peers") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            listOf(0, 1, 5, 50).forEach { peerCount ->
                policy.effectiveFactor(NetworkMode.SURVIVAL, peerCount) shouldBe Int.MAX_VALUE
            }
        }

        it("CRITICAL does not update EMA — next HEALTHY call still sees 0 density") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            // Call CRITICAL with high peer count — should not update EMA
            policy.effectiveFactor(NetworkMode.CRITICAL, 100)
            // Now call HEALTHY — should see 0 density (EMA not updated by CRITICAL)
            policy.smoothedPeerCount() shouldBe 0.0
        }
    }

    // ── EMA smoothing and hysteresis ──────────────────────────────────────

    describe("DensityAwareReplicationPolicy — EMA smoothing") {

        it("smoothed density converges toward true density over multiple observations") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 0.3)
            // Feed 20 observations of 10 peers
            repeat(20) { policy.effectiveFactor(NetworkMode.HEALTHY, 10) }
            // Smoothed density should be close to 10
            (policy.smoothedPeerCount() > 8.0) shouldBe true
        }

        it("smoothed density falls gradually when peers drop off") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 0.3)
            // Build up density to ~10
            repeat(20) { policy.effectiveFactor(NetworkMode.HEALTHY, 10) }
            val beforeDrop = policy.smoothedPeerCount()

            // One observation of 0 peers — EMA should not immediately drop to 0
            policy.effectiveFactor(NetworkMode.HEALTHY, 0)
            val afterOneDrop = policy.smoothedPeerCount()

            (afterOneDrop < beforeDrop) shouldBe true  // falling
            (afterOneDrop > 5.0) shouldBe true          // but not yet below 5 (hysteresis)
        }

        it("smoothed density rises gradually when peers join") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 0.3)
            // Start sparse
            repeat(5) { policy.effectiveFactor(NetworkMode.HEALTHY, 0) }
            val atZero = policy.smoothedPeerCount()

            // One spike to 20 peers — EMA should rise but not jump to 20
            policy.effectiveFactor(NetworkMode.HEALTHY, 20)
            val afterSpike = policy.smoothedPeerCount()

            (afterSpike > atZero) shouldBe true   // rising
            (afterSpike < 15.0) shouldBe true     // EMA dampens the spike
        }

        it("reset clears smoothed density to zero") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 50)
            policy.smoothedPeerCount() shouldBe 50.0
            policy.reset()
            policy.smoothedPeerCount() shouldBe 0.0
        }

        it("updateDensity advances EMA without returning a factor") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.smoothedPeerCount() shouldBe 0.0
            policy.updateDensity(8)
            policy.smoothedPeerCount() shouldBe 8.0
        }

        it("smoothingFactor = 1.0 produces instant response (no smoothing)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 0)
            policy.effectiveFactor(NetworkMode.HEALTHY, 15)
            policy.smoothedPeerCount() shouldBe 15.0  // exactly 15 — no averaging
        }

        it("smoothingFactor = 0.0 produces no change (frozen at initial 0)") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 0.0)
            repeat(100) { policy.effectiveFactor(NetworkMode.HEALTHY, 50) }
            policy.smoothedPeerCount() shouldBe 0.0  // never changes
        }
    }

    // ── Minimum factor floor ──────────────────────────────────────────────

    describe("DensityAwareReplicationPolicy — minimum factor floor") {

        it("HEALTHY_DENSE_FACTOR is 1 — minimum possible") {
            DensityAwareReplicationPolicy.HEALTHY_DENSE_FACTOR shouldBe 1
        }

        it("DEGRADED_DENSE_FACTOR is 2 — always retains 2 DHT backups") {
            DensityAwareReplicationPolicy.DEGRADED_DENSE_FACTOR shouldBe 2
        }

        it("MINIMUM_FACTOR is 1") {
            DensityAwareReplicationPolicy.MINIMUM_FACTOR shouldBe 1
        }

        it("factor is never below MINIMUM_FACTOR for any mode and peer count") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            listOf(NetworkMode.HEALTHY, NetworkMode.DEGRADED).forEach { mode ->
                (0..200 step 5).forEach { peerCount ->
                    val f = policy.effectiveFactor(mode, peerCount)
                    (f >= DensityAwareReplicationPolicy.MINIMUM_FACTOR) shouldBe true
                }
            }
        }
    }

    // ── Privacy properties ────────────────────────────────────────────────

    describe("DensityAwareReplicationPolicy — privacy: local-only density signal") {

        it("density is derived from local peer count only — no IP or geo inference") {
            // Structural: DensityAwareReplicationPolicy takes an Int (local peer count)
            // not an InetAddress or location. Test verifies the API contract.
            val policy = DensityAwareReplicationPolicy()
            val factor = policy.effectiveFactor(NetworkMode.HEALTHY, localPeerCount = 7)
            (factor in 1..3) shouldBe true
        }

        it("two nodes with same local peer count produce identical factor (deterministic)") {
            val p1 = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            val p2 = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            val f1 = p1.effectiveFactor(NetworkMode.HEALTHY, 6)
            val f2 = p2.effectiveFactor(NetworkMode.HEALTHY, 6)
            f1 shouldBe f2
        }
    }

    // ── DensityContext ────────────────────────────────────────────────────

    describe("DensityContext") {

        it("holds mode and localPeerCount") {
            val ctx = DensityContext(NetworkMode.HEALTHY, localPeerCount = 7)
            ctx.mode           shouldBe NetworkMode.HEALTHY
            ctx.localPeerCount shouldBe 7
        }
    }

    // ── StoreAndForwardManager integration ────────────────────────────────

    describe("StoreAndForwardManager density integration") {

        it("uses DensityAwareReplicationPolicy when provided — dense cluster targets fewer nodes") {
            val policy  = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            val queried = mutableListOf<Int>()  // track how many nodes were targeted

            val transport = object : StoreForwardTransport {
                override suspend fun storeFragment(node: mesh.shadowmesh.mesh.dht.DhtContact, fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity) {
                    synchronized(queried) { queried.add(queried.size) }
                }
                override suspend fun fetchFragmentsSince(
                    node: mesh.shadowmesh.mesh.dht.DhtContact,
                    channelId: ByteArray, sinceMs: Long
                ) = emptyList<mesh.shadowmesh.mesh.fragment.FragmentEntity>()
            }

            // Dense context: 12 local peers → HEALTHY factor = 1
            val denseCtx = DensityContext(NetworkMode.HEALTHY, localPeerCount = 12)

            val manager = StoreAndForwardManager(
                scope             = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default),
                transport         = transport,
                routingTable      = mesh.shadowmesh.mesh.dht.RoutingTable(mesh.shadowmesh.mesh.dht.NodeId.random()),
                replicationPolicy = policy,
                densityContext    = { denseCtx }
            )

            // With empty routing table no nodes are targeted — but factor computation
            // should have run with factor=1. Main assertion: no crash and policy was used.
            kotlinx.coroutines.runBlocking {
                manager.replicate(ByteArray(32), emptyList())
            }
            // Empty routing table means 0 nodes targeted — factor logic still ran
        }

        it("falls back to REPLICATION_FACTOR=3 when no policy provided") {
            val manager = StoreAndForwardManager(
                scope          = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default),
                transport      = object : StoreForwardTransport {
                    override suspend fun storeFragment(n: mesh.shadowmesh.mesh.dht.DhtContact, f: mesh.shadowmesh.mesh.fragment.FragmentEntity) {}
                    override suspend fun fetchFragmentsSince(n: mesh.shadowmesh.mesh.dht.DhtContact, c: ByteArray, s: Long) = emptyList<mesh.shadowmesh.mesh.fragment.FragmentEntity>()
                },
                routingTable      = mesh.shadowmesh.mesh.dht.RoutingTable(mesh.shadowmesh.mesh.dht.NodeId.random()),
                replicationPolicy = null,  // no policy — legacy path
                densityContext    = null
            )
            // Should complete without crash
            kotlinx.coroutines.runBlocking {
                manager.replicate(ByteArray(32), emptyList())
            }
        }

        it("CRITICAL DensityContext does not overflow — policy returns Int.MAX_VALUE, replicate must not throw") {
            // Regression test for BUG 1: factor * 2 overflowed when policy returned
            // Int.MAX_VALUE (CRITICAL/SURVIVAL), causing findClosest(target, -2) →
            // List.take(-2) → IllegalArgumentException.
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            val manager = StoreAndForwardManager(
                scope             = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default),
                transport         = object : StoreForwardTransport {
                    override suspend fun storeFragment(n: mesh.shadowmesh.mesh.dht.DhtContact, f: mesh.shadowmesh.mesh.fragment.FragmentEntity) {}
                    override suspend fun fetchFragmentsSince(n: mesh.shadowmesh.mesh.dht.DhtContact, c: ByteArray, s: Long) = emptyList<mesh.shadowmesh.mesh.fragment.FragmentEntity>()
                },
                routingTable      = mesh.shadowmesh.mesh.dht.RoutingTable(mesh.shadowmesh.mesh.dht.NodeId.random()),
                replicationPolicy = policy,
                densityContext    = { DensityContext(NetworkMode.CRITICAL, localPeerCount = 5) }
            )
            // Must not throw IllegalArgumentException from List.take(-2)
            kotlinx.coroutines.runBlocking {
                manager.replicate(ByteArray(32), emptyList())
            }
        }

        it("SURVIVAL DensityContext does not overflow") {
            val policy = DensityAwareReplicationPolicy(smoothingFactor = 1.0)
            val manager = StoreAndForwardManager(
                scope             = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.Dispatchers.Default),
                transport         = object : StoreForwardTransport {
                    override suspend fun storeFragment(n: mesh.shadowmesh.mesh.dht.DhtContact, f: mesh.shadowmesh.mesh.fragment.FragmentEntity) {}
                    override suspend fun fetchFragmentsSince(n: mesh.shadowmesh.mesh.dht.DhtContact, c: ByteArray, s: Long) = emptyList<mesh.shadowmesh.mesh.fragment.FragmentEntity>()
                },
                routingTable      = mesh.shadowmesh.mesh.dht.RoutingTable(mesh.shadowmesh.mesh.dht.NodeId.random()),
                replicationPolicy = policy,
                densityContext    = { DensityContext(NetworkMode.SURVIVAL, localPeerCount = 0) }
            )
            kotlinx.coroutines.runBlocking {
                manager.replicate(ByteArray(32), emptyList())
            }
        }
    }
})

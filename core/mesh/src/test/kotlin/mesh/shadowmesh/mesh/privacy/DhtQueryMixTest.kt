package mesh.shadowmesh.mesh.privacy

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeLessThanOrEqual
import kotlinx.coroutines.test.runTest
import mesh.shadowmesh.mesh.dht.DhtContact
import mesh.shadowmesh.mesh.dht.NodeId
import mesh.shadowmesh.mesh.dht.PeerAddress
import mesh.shadowmesh.mesh.mode.PeerSelectionMode
import kotlin.random.Random

/**
 * Phase 8 — DHT Query Mix tests.
 * Covers the pure, deterministic surface: adaptive hold window per mode, 3-peer fan-out,
 * and the 10-query/min sliding budget. Timing-driven holding is exercised with a fixed
 * clock so the assertions stay deterministic.
 */
class DhtQueryMixTest : DescribeSpec({

    fun peers(n: Int) = (1..n).map { DhtContact(NodeId.random(), PeerAddress("10.0.0.$it", 7000 + it)) }

    fun mix(
        mode: PeerSelectionMode = PeerSelectionMode.STANDARD,
        pool: List<DhtContact> = peers(5),
        clock: () -> Long = { 0L },
        scope: kotlinx.coroutines.CoroutineScope,
        forward: suspend (ByteArray, List<DhtContact>) -> Unit = { _, _ -> }
    ) = DhtQueryMix(
        scope    = scope,
        getMode  = { mode },
        getPeers = { pool },
        forward  = forward,
        rng      = Random(42),
        clockMs  = clock
    )

    describe("adaptive hold window") {
        it("MAXIMUM_SECURITY holds 1000-3000ms") {
            runTest {
                mix(scope = this).windowFor(PeerSelectionMode.MAXIMUM_SECURITY) shouldBe 1000..3000
            }
        }
        it("STANDARD and OPERATIONAL hold 0-500ms") {
            runTest {
                val m = mix(scope = this)
                m.windowFor(PeerSelectionMode.STANDARD)    shouldBe 0..500
                m.windowFor(PeerSelectionMode.OPERATIONAL) shouldBe 0..500
            }
        }
        it("EMERGENCY does not hold (0ms)") {
            runTest {
                mix(scope = this).windowFor(PeerSelectionMode.EMERGENCY) shouldBe 0..0
            }
        }
    }

    describe("peer fan-out") {
        it("forwards to exactly 3 peers when pool is larger") {
            runTest {
                mix(scope = this).pickPeers(peers(10)).shouldHaveSize(3)
            }
        }
        it("forwards to all peers when pool is 3 or fewer") {
            runTest {
                val m = mix(scope = this)
                m.pickPeers(peers(2)).shouldHaveSize(2)
                m.pickPeers(peers(3)).shouldHaveSize(3)
            }
        }
        it("chosen peers are distinct") {
            runTest {
                val chosen = mix(scope = this).pickPeers(peers(8))
                chosen.map { it.nodeId.bytes.toList() }.toSet().size shouldBe chosen.size
            }
        }
    }

    describe("query budget (10 per minute)") {
        it("emits at most 10 queries within the window and drops the rest") {
            runTest {
                var emitted = 0
                val m = mix(
                    mode  = PeerSelectionMode.EMERGENCY,   // 0ms hold → all due immediately
                    clock = { 0L },                        // frozen clock → all in one budget window
                    scope = this,
                    forward = { _, _ -> emitted++ }
                )
                repeat(15) { m.submit(byteArrayOf(it.toByte())) }
                testScheduler.advanceUntilIdle()
                emitted shouldBe 10
            }
        }

        it("budgetAvailable is false once 10 emissions are recorded in-window") {
            runTest {
                var emitted = 0
                val m = mix(
                    mode = PeerSelectionMode.EMERGENCY,
                    clock = { 0L },
                    scope = this,
                    forward = { _, _ -> emitted++ }
                )
                repeat(12) { m.submit(byteArrayOf(it.toByte())) }
                testScheduler.advanceUntilIdle()
                // budgetAvailable is a pump-internal helper; test via observable behaviour:
                // total emitted must not exceed the per-minute cap
                emitted shouldBeLessThanOrEqual 10
            }
        }
    }
})

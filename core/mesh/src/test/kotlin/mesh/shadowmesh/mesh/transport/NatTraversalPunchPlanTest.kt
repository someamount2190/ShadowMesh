package mesh.shadowmesh.mesh.transport

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.comparables.shouldBeGreaterThanOrEqualTo
import io.kotest.matchers.comparables.shouldBeLessThanOrEqualTo
import io.kotest.matchers.doubles.shouldBeGreaterThan
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import mesh.shadowmesh.mesh.dht.NodeId

class NatTraversalPunchPlanTest : DescribeSpec({

    fun engine() = NatTraversalEngine(
        localNodeId   = NodeId(ByteArray(32)),
        socketAdapter = NoOpUdpSocketAdapter,
        scope         = CoroutineScope(Dispatchers.Unconfined)
    )

    describe("adaptive punch plan — latency vs success") {

        it("low RTT (LAN) uses the base window and the full attempt budget") {
            val plan = engine().estimateAdaptivePunchPlan(coordinationRttMs = 20)
            plan.firstWindowMs shouldBe NatTraversalEngine.BASE_PROBE_WINDOW_MS
            // With small windows, many attempts fit under the budget ceiling.
            plan.attempts shouldBeGreaterThanOrEqualTo 4
            plan.predictedSuccess shouldBeGreaterThan 0.99
        }

        it("first window always covers ~2x the coordination skew") {
            // The old fixed 200ms first window would miss whenever skew > 200ms.
            val rtt = 700L
            val plan = engine().estimateAdaptivePunchPlan(rtt)
            plan.firstWindowMs shouldBeGreaterThanOrEqualTo (rtt * NatTraversalEngine.SKEW_COVER_FACTOR)
                .coerceAtMost(NatTraversalEngine.MAX_FIRST_WINDOW_MS)
        }

        it("high RTT widens windows but stays under the budget ceiling and never stalls") {
            val plan = engine().estimateAdaptivePunchPlan(coordinationRttMs = 3_000)
            plan.firstWindowMs shouldBeLessThanOrEqualTo NatTraversalEngine.MAX_FIRST_WINDOW_MS
            plan.totalBudgetMs shouldBeLessThanOrEqualTo NatTraversalEngine.PUNCH_BUDGET_CEIL_MS
            // Fewer attempts fit when each window is large — but at least one always runs.
            plan.attempts shouldBeGreaterThanOrEqualTo 1
        }

        it("predicted success is monotonically non-increasing as RTT grows") {
            val e = engine()
            val low  = e.estimateAdaptivePunchPlan(50).predictedSuccess
            val mid  = e.estimateAdaptivePunchPlan(800).predictedSuccess
            val high = e.estimateAdaptivePunchPlan(5_000).predictedSuccess
            (low >= mid) shouldBe true
            (mid >= high) shouldBe true
        }
    }
})

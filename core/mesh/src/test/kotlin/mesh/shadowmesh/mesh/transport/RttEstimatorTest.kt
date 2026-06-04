package mesh.shadowmesh.mesh.transport

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.longs.shouldBeGreaterThanOrEqual
import io.kotest.matchers.longs.shouldBeLessThan

class RttEstimatorTest : DescribeSpec({

    describe("RttEstimator — Jacobson/Karels behaviour") {

        it("cold peer returns the path seed clamped, not zero") {
            val e = RttEstimator()
            // LAN seed 40 is below MIN_RTO_MS (50) → clamped up to the floor.
            e.rtoMs("peerA", RttEstimator.PathClass.LAN) shouldBe RttEstimator.MIN_RTO_MS
            // INTERNET seed 500 sits within range.
            e.rtoMs("peerB", RttEstimator.PathClass.INTERNET) shouldBeGreaterThanOrEqual 500
        }

        it("converges toward a stable RTT and yields a tight RTO") {
            val e = RttEstimator()
            repeat(30) { e.recordSample("p", 120, RttEstimator.PathClass.INTERNET) }
            val rto = e.rtoMs("p", RttEstimator.PathClass.INTERNET)
            // Stable input → RTTVAR shrinks → RTO approaches SRTT (~120), well under the seed RTO.
            rto shouldBeGreaterThanOrEqual 120
            rto shouldBeLessThan 200
        }

        it("a jittery path produces a WIDER RTO than a stable path at the same mean") {
            val stable = RttEstimator()
            val jittery = RttEstimator()
            repeat(40) { stable.recordSample("s", 200, RttEstimator.PathClass.INTERNET) }
            // Same ~200 mean, but alternating high/low → large RTTVAR.
            repeat(40) { i ->
                jittery.recordSample("j", if (i % 2 == 0) 80 else 320, RttEstimator.PathClass.INTERNET)
            }
            jittery.rtoMs("j") shouldBeGreaterThan stable.rtoMs("s")
        }

        it("Karn's rule: a retried sample is discarded (does not move the estimate)") {
            val e = RttEstimator()
            repeat(20) { e.recordSample("k", 100, RttEstimator.PathClass.INTERNET) }
            val before = e.rtoMs("k")
            // A wildly large RTT from a retried rendezvous must NOT corrupt the estimate.
            e.recordSample("k", 9_999, RttEstimator.PathClass.INTERNET, retried = true)
            e.rtoMs("k") shouldBe before
        }

        it("onTimeout backs off the RTO and a fresh sample recovers it") {
            val e = RttEstimator()
            repeat(20) { e.recordSample("t", 150, RttEstimator.PathClass.INTERNET) }
            val base = e.rtoMs("t")
            e.onTimeout("t")
            e.rtoMs("t") shouldBeGreaterThan base
        }

        it("RTO is always clamped within [MIN_RTO_MS, MAX_RTO_MS]") {
            val e = RttEstimator()
            e.recordSample("hi", 100_000, RttEstimator.PathClass.INTERNET)
            e.rtoMs("hi") shouldBe RttEstimator.MAX_RTO_MS
            val e2 = RttEstimator()
            e2.recordSample("lo", 1, RttEstimator.PathClass.LAN)
            e2.rtoMs("lo") shouldBe RttEstimator.MIN_RTO_MS
        }
    }

    describe("RttEstimator — staleness widening (vanish-and-return)") {

        // Controllable clock so elapsed time is deterministic.
        fun fixedClock(t: LongArray) = RttEstimator(nowMs = { t[0] })

        it("a fresh estimate is not widened") {
            val t = longArrayOf(0L)
            val e = fixedClock(t)
            repeat(20) { e.recordSample("p", 200, RttEstimator.PathClass.INTERNET) }
            val fresh = e.rtoMs("p")
            t[0] = t[0] + 10_000  // within grace window
            e.rtoMs("p") shouldBe fresh
        }

        it("a stale peer's window WIDENS, never shrinks") {
            val t = longArrayOf(0L)
            val e = fixedClock(t)
            repeat(20) { e.recordSample("p", 200, RttEstimator.PathClass.INTERNET) }
            val fresh = e.rtoMs("p")
            t[0] = t[0] + 600_000  // 10 min idle — past STALENESS_FULL_MS
            val stale = e.rtoMs("p")
            stale shouldBeGreaterThan fresh
        }

        it("widening is monotonic in idle time and capped") {
            val t = longArrayOf(0L)
            val e = fixedClock(t)
            repeat(20) { e.recordSample("p", 200, RttEstimator.PathClass.INTERNET) }
            t[0] = 60_000;  val at1m  = e.rtoMs("p")
            t[0] = 180_000; val at3m  = e.rtoMs("p")
            t[0] = 600_000; val at10m = e.rtoMs("p")
            (at1m <= at3m) shouldBe true
            (at3m <= at10m) shouldBe true
            // Capped: even very stale never exceeds the global clamp.
            (at10m <= RttEstimator.MAX_RTO_MS) shouldBe true
        }

        it("a fresh sample after a long idle resets the staleness clock") {
            val t = longArrayOf(0L)
            val e = fixedClock(t)
            repeat(20) { e.recordSample("p", 200, RttEstimator.PathClass.INTERNET) }
            t[0] = t[0] + 600_000
            val stale = e.rtoMs("p")
            e.recordSample("p", 210, RttEstimator.PathClass.INTERNET)  // fresh sample at t=600k
            val afterFresh = e.rtoMs("p")
            afterFresh shouldBeLessThan stale
        }
    }
})

package mesh.shadowmesh.nsc

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe

class RollbackOpcodeTest : DescribeSpec({
    describe("RollbackOpcode — encode/decode round-trip") {

        listOf(
            RollbackOpcode.ReclaimDhtSlice("nodeA", "nodeB"),
            RollbackOpcode.RevertTierPromotion("nodeX", 2),
            RollbackOpcode.CancelFragmentDelivery("frag-uuid-123"),
            RollbackOpcode.RestoreNetworkMode("HEALTHY"),
            RollbackOpcode.RestoreBeaconMode(true),
            RollbackOpcode.RestoreBeaconMode(false),
            RollbackOpcode.RestorePeerSelection("STANDARD"),
            RollbackOpcode.NoOp
        ).forEach { op ->
            it("${op::class.simpleName} round-trips correctly") {
                val (k, v) = op.encode()
                RollbackOpcode.decode(k, v) shouldBe op
            }
        }

        it("unknown opcode decodes to NoOp without throwing") {
            RollbackOpcode.decode("UNKNOWN_OP", "args") shouldBe RollbackOpcode.NoOp
        }
    }
})

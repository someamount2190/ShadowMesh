package mesh.shadowmesh.mesh.anchor

import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.nsc.*
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag

/**
 * Anchor handoff manager — design doc Phase 6.
 *
 * Handles the full anchor handoff lifecycle:
 *   1. Transfer: source anchor streams DHT slice to target anchor
 *   2. Verify: target computes Merkle root over received slice; source verifies
 *   3. Update: DHT routing table entries updated on all nodes via gossip
 *   4. HoneyAnchor: honey fragments re-embedded on the new anchor
 *   5. Rollback: if Merkle verification fails, ReclaimDhtSlice NSC opcode reverts
 *
 * This is a P1_DATA_INTEGRITY transition — holds the highest NSC priority.
 * Zero data loss is the exit gate. Merkle root must match before transfer
 * is committed. Rollback is tested in Phase 6 integration tests.
 *
 * DHT re-bootstrap after anchor failure:
 *   When an anchor fails without a planned handoff, [rebootstrap()] is called.
 *   It uses the VRF election winner as the new anchor and performs an emergency
 *   slice transfer from the closest surviving peer.
 *   Target: re-bootstrap complete within 2 sync cycles.
 *
 * Thread-safety: handoff state uses ConcurrentHashMap. NSC ensures only one
 * P1 transition runs at a time.
 */
class AnchorHandoffManager(
    private val localNodeId: NodeId,
    private val nsc:         mesh.shadowmesh.nsc.NscLike,
    private val dhtEngine:   DhtEngine,
    private val hkdf:        Hkdf = Hkdf.instance,
    private val transport:   AnchorTransport,
    private val scope:       CoroutineScope
) {
    // Active handoffs: sourceNodeId → HandoffState
    private val activeHandoffs = ConcurrentHashMap<String, HandoffState>()

    // ── Planned handoff ────────────────────────────────────────────────────

    /**
     * Initiate a planned anchor handoff from [sourceNodeId] to [targetNodeId].
     *
     * Submits a P1_DATA_INTEGRITY NSC transition. The transition:
     *   1. Calls [transport.transferSlice] to stream DHT entries to target
     *   2. Verifies Merkle root of transferred slice against expected root
     *   3. Updates DHT routing table entries
     *   4. Re-embeds HoneyAnchor fragments on new anchor
     *
     * On Merkle verification failure: ReclaimDhtSlice rollback opcode reverts
     * the transfer. The transition is marked retriable.
     *
     * @return The NSC [TransitionResult] — callers wait for COMMITTED status.
     */
    suspend fun initiateHandoff(
        sourceNodeId: String,
        targetNodeId: String
    ): TransitionResult {
        val transition = buildAnchorHandoffTransition(
            sourceNodeId        = sourceNodeId,
            targetNodeId        = targetNodeId,
            dhtSliceTransferFn  = { transferSlice(sourceNodeId, targetNodeId) },
            merkleVerifyFn      = { verifySliceMerkle(sourceNodeId, targetNodeId) },
            dhtUpdateFn         = { updateRoutingAfterHandoff(sourceNodeId, targetNodeId) },
            revertDhtFn         = { revertSliceTransfer(sourceNodeId, targetNodeId) },
            honeyReembedFn      = { reembedHoneyAnchor(targetNodeId) }
        )

        activeHandoffs[sourceNodeId] = HandoffState(sourceNodeId, targetNodeId,
            HandoffPhase.TRANSFERRING)

        return nsc.requestTransition(transition).await()
    }

    // ── Anchor failure recovery ────────────────────────────────────────────

    /**
     * Emergency re-bootstrap after anchor failure.
     *
     * Called when an anchor becomes unreachable (watchdog timeout + DHT routing
     * failure). Uses the VRF election winner as the new anchor.
     *
     * Recovery steps:
     *   1. Identify the VRF election winner for the failed anchor's slot
     *   2. Find surviving peers closest to the failed anchor's DHT region
     *   3. Perform emergency slice transfer from the best surviving peer
     *   4. Verify and commit; update routing table
     *
     * Design doc exit gate: complete within 2 sync cycles (2 × 15s = 30s).
     *
     * @param failedAnchorId  The nodeId of the failed anchor.
     * @param electionWinner  VRF-elected replacement anchor.
     */
    suspend fun rebootstrap(
        failedAnchorId: NodeId,
        electionWinner: NodeId
    ): RebootstrapResult {
        // Find surviving peers who held copies of the failed anchor's slice
        val survivors = dhtEngine.routingTable
            .findClosest(failedAnchorId, 5)
            .filter { it.nodeId != failedAnchorId }

        if (survivors.isEmpty()) return RebootstrapResult.NoSurvivors

        // Attempt emergency transfer from best surviving peer
        for (survivor in survivors) {
            try {
                val result = initiateHandoff(
                    sourceNodeId = survivor.nodeId.bytes.toHex(),
                    targetNodeId = electionWinner.toHex()
                )
                if (result is TransitionResult.Success) {
                    return RebootstrapResult.Success(electionWinner, survivor.nodeId)
                }
            } catch (e: Exception) {
                Diag.swallowed("anchor-handoff", "rebootstrap-survivor", e,
                    "survivor" to survivor.nodeId.bytes.toHex())
                continue
            }
        }

        return RebootstrapResult.Failed("All survivors unreachable")
    }

    // ── Internal transfer operations ───────────────────────────────────────

    private suspend fun transferSlice(
        sourceNodeId: String,
        targetNodeId: String
    ): Boolean {
        activeHandoffs[sourceNodeId]?.let {
            activeHandoffs[sourceNodeId] = it.copy(phase = HandoffPhase.TRANSFERRING)
        }
        return transport.transferDhtSlice(sourceNodeId, targetNodeId)
    }

    private suspend fun verifySliceMerkle(
        sourceNodeId: String,
        targetNodeId: String
    ): Boolean {
        activeHandoffs[sourceNodeId]?.let {
            activeHandoffs[sourceNodeId] = it.copy(phase = HandoffPhase.VERIFYING)
        }
        return transport.verifySliceMerkle(sourceNodeId, targetNodeId)
    }

    private suspend fun updateRoutingAfterHandoff(
        sourceNodeId: String,
        targetNodeId: String
    ) {
        activeHandoffs[sourceNodeId]?.let {
            activeHandoffs[sourceNodeId] = it.copy(phase = HandoffPhase.UPDATING_ROUTING)
        }
        transport.broadcastRoutingUpdate(sourceNodeId, targetNodeId)
        activeHandoffs.remove(sourceNodeId)
    }

    private suspend fun revertSliceTransfer(sourceNodeId: String, targetNodeId: String) {
        transport.revertSliceTransfer(sourceNodeId, targetNodeId)
        activeHandoffs.remove(sourceNodeId)
    }

    private suspend fun reembedHoneyAnchor(targetNodeId: String) {
        // HoneyAnchor re-embedding: inject new honey fragments into the new anchor's
        // gossip stream. The honey key registry is managed by the security layer (Phase 8).
        // Here we signal the transport to perform the re-embedding.
        transport.reembedHoneyAnchor(targetNodeId)
    }

    // ── Queries ───────────────────────────────────────────────────────────

    fun activeHandoffCount(): Int = activeHandoffs.size
    fun handoffState(sourceNodeId: String): HandoffState? = activeHandoffs[sourceNodeId]
}

// ── NSC transition builder ────────────────────────────────────────────────────

/**
 * Build the P1_DATA_INTEGRITY NSC transition for anchor handoff.
 * Extracted as a top-level function so it can be tested independently of [AnchorHandoffManager].
 */
fun buildAnchorHandoffTransition(
    sourceNodeId:       String,
    targetNodeId:       String,
    dhtSliceTransferFn: suspend () -> Boolean,
    merkleVerifyFn:     suspend () -> Boolean,
    dhtUpdateFn:        suspend () -> Unit,
    revertDhtFn:        suspend () -> Unit,
    honeyReembedFn:     suspend () -> Unit = {}
): StateTransition = StateTransition(
    id           = "anchor_handoff_${sourceNodeId}_to_$targetNodeId",
    description  = "Anchor handoff: $sourceNodeId → $targetNodeId",
    priority     = Priority.P1_DATA_INTEGRITY,
    scope        = TransitionScope.GLOBAL,
    requiredLocks = listOf(
        LockKey(LockType.NODE_TIER, sourceNodeId),
        LockKey(LockType.NODE_TIER, targetNodeId),
        LockKey(LockType.DHT_SLICE, sourceNodeId)
    ),
    deadlineMs   = System.currentTimeMillis() + HANDOFF_DEADLINE_MS,
    execute      = { log ->
        // Step 1: Transfer DHT slice
        log(Checkpoint(
            description = "DHT slice transfer $sourceNodeId → $targetNodeId",
            opcode      = RollbackOpcode.ReclaimDhtSlice(sourceNodeId, targetNodeId),
            rollback    = { revertDhtFn() }
        ))
        if (!dhtSliceTransferFn()) {
            return@StateTransition TransitionResult.Failure("DHT slice transfer failed")
        }

        // Step 2: Merkle root verification
        log(Checkpoint(
            description = "Merkle root verification",
            opcode      = RollbackOpcode.ReclaimDhtSlice(sourceNodeId, targetNodeId),
            rollback    = { revertDhtFn() }
        ))
        if (!merkleVerifyFn()) {
            return@StateTransition TransitionResult.Failure(
                "Merkle root mismatch after slice transfer — rolling back",
                shouldRetry = true
            )
        }

        // Step 3: Update routing table
        log(Checkpoint(
            description = "DHT routing table update",
            opcode      = RollbackOpcode.ReclaimDhtSlice(sourceNodeId, targetNodeId),
            rollback    = { revertDhtFn() }
        ))
        dhtUpdateFn()

        // Step 4: Re-embed HoneyAnchor (best-effort — does not block commit)
        try { honeyReembedFn() } catch (e: Exception) { Diag.swallowed("anchor-handoff", "honey-reembed", e) }

        TransitionResult.Success
    }
)

private const val HANDOFF_DEADLINE_MS = 2L * 15_000  // 2 sync cycles

// ── Supporting types ──────────────────────────────────────────────────────────

data class HandoffState(
    val sourceNodeId: String,
    val targetNodeId: String,
    val phase:        HandoffPhase
)

enum class HandoffPhase { TRANSFERRING, VERIFYING, UPDATING_ROUTING, COMPLETE, FAILED }

sealed class RebootstrapResult {
    data class Success(val newAnchor: NodeId, val dataSource: NodeId) : RebootstrapResult()
    object NoSurvivors                                                 : RebootstrapResult()
    data class Failed(val reason: String)                             : RebootstrapResult()
}

// ── Transport interface ────────────────────────────────────────────────────────

interface AnchorTransport {
    suspend fun transferDhtSlice(sourceNodeId: String, targetNodeId: String): Boolean
    suspend fun verifySliceMerkle(sourceNodeId: String, targetNodeId: String): Boolean
    suspend fun broadcastRoutingUpdate(oldAnchorId: String, newAnchorId: String)
    suspend fun revertSliceTransfer(sourceNodeId: String, targetNodeId: String)
    suspend fun reembedHoneyAnchor(newAnchorId: String)
}

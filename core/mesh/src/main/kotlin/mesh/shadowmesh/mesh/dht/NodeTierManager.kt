package mesh.shadowmesh.mesh.dht

import mesh.shadowmesh.crypto.TrustLevel
import mesh.shadowmesh.storage.ChannelType

/**
 * Node tier promotion and demotion rules — design doc §4.
 *
 * Three tiers:
 *   Tier 1 (Anchor)  — participates in DHT routing; runs circuit guard/middle/exit;
 *                       requires TRUST_PHYSICAL, ≥72h uptime, <80% storage, online mode.
 *   Tier 2 (Relay)   — relays fragments and stores posts; cannot anchor DHT.
 *   Tier 3 (Client)  — read-only; contributes nothing to the mesh.
 *
 * Demotion thresholds (design doc):
 *   Storage ≥95%      → forced demotion from Tier 1
 *   Trust < PHYSICAL  → cannot be Tier 1 anchor
 *   Mode ≠ online     → cannot hold Tier 1
 *   Uptime < 72h      → cannot promote to Tier 1
 *
 * Promotion to Tier 2 from Tier 3:
 *   Storage <80%, trust ≥ TRUST_INTRODUCED, device has been online ≥ 1h.
 *
 * Thread-safety: stateless — thread-safe by construction.
 */
class NodeTierManager {

    // ── Promotion eligibility ─────────────────────────────────────────────

    /**
     * Evaluate whether [candidate] is eligible for Tier 1 anchor promotion.
     *
     * All conditions must be met simultaneously:
     *   - Trust level: TRUST_PHYSICAL
     *   - Uptime: ≥ [TIER1_MIN_UPTIME_MS] (72 hours)
     *   - Storage: < [TIER1_MAX_STORAGE_PCT] (80%)
     *   - Mode: online (not POLLING, DEGRADED, CRITICAL, or SURVIVAL)
     *   - Current tier: Tier 2 (cannot skip tiers)
     */
    fun canPromoteToTier1(candidate: NodeProfile): PromotionDecision {
        if (candidate.trustLevel != TrustLevel.TRUST_PHYSICAL)
            return PromotionDecision.Ineligible("Requires TRUST_PHYSICAL; node has ${candidate.trustLevel}")
        if (candidate.uptimeMs < TIER1_MIN_UPTIME_MS)
            return PromotionDecision.Ineligible("Uptime ${candidate.uptimeMs}ms < required ${TIER1_MIN_UPTIME_MS}ms (72h)")
        if (candidate.storagePct >= TIER1_MAX_STORAGE_PCT)
            return PromotionDecision.Ineligible("Storage ${candidate.storagePct}% ≥ ${TIER1_MAX_STORAGE_PCT}% limit")
        if (!candidate.isOnline)
            return PromotionDecision.Ineligible("Node is not in online mode")
        if (candidate.currentTier != NodeTier.TIER_2)
            return PromotionDecision.Ineligible("Can only promote from Tier 2; node is ${candidate.currentTier}")
        return PromotionDecision.Eligible
    }

    /**
     * Evaluate whether [candidate] is eligible for Tier 2 relay promotion.
     */
    fun canPromoteToTier2(candidate: NodeProfile): PromotionDecision {
        if (candidate.trustLevel == TrustLevel.TRUST_PUBLIC && candidate.uptimeMs < TIER2_MIN_UPTIME_MS)
            return PromotionDecision.Ineligible("TRUST_PUBLIC node must be online ≥ 1h for Tier 2")
        if (candidate.storagePct >= TIER2_MAX_STORAGE_PCT)
            return PromotionDecision.Ineligible("Storage ${candidate.storagePct}% ≥ ${TIER2_MAX_STORAGE_PCT}% limit")
        if (candidate.currentTier != NodeTier.TIER_3)
            return PromotionDecision.Ineligible("Already at Tier 2 or above")
        return PromotionDecision.Eligible
    }

    // ── Demotion checks ───────────────────────────────────────────────────

    /**
     * Check if a Tier 1 node must be demoted.
     * Returns [DemotionDecision.Required] with the reason if demotion is mandatory.
     */
    fun checkDemotion(node: NodeProfile): DemotionDecision {
        if (node.currentTier != NodeTier.TIER_1) return DemotionDecision.NotRequired

        if (node.storagePct >= TIER1_DEMOTION_STORAGE_PCT)
            return DemotionDecision.Required("Storage ${node.storagePct}% ≥ demotion threshold ${TIER1_DEMOTION_STORAGE_PCT}%")
        if (node.trustLevel != TrustLevel.TRUST_PHYSICAL)
            return DemotionDecision.Required("Trust level dropped to ${node.trustLevel}; Tier 1 requires TRUST_PHYSICAL")
        if (!node.isOnline)
            return DemotionDecision.Required("Node entered non-online mode")
        return DemotionDecision.NotRequired
    }

    /**
     * Determine the target tier after demotion.
     * Tier 1 → Tier 2 (retains relay capability).
     * Tier 2 → Tier 3 only on extreme conditions (storage >95%, trust dropped to PUBLIC).
     */
    fun demotionTarget(node: NodeProfile): NodeTier = when {
        node.currentTier == NodeTier.TIER_1                       -> NodeTier.TIER_2
        node.storagePct >= TIER2_DEMOTION_STORAGE_PCT             -> NodeTier.TIER_3
        node.trustLevel == TrustLevel.TRUST_PUBLIC                -> NodeTier.TIER_3
        else                                                       -> NodeTier.TIER_3
    }

    // ── Circuit role eligibility ──────────────────────────────────────────

    /**
     * TRUST_PUBLIC nodes are excluded from all circuit roles (Guard/Middle/Exit).
     * Only TRUST_PHYSICAL and TRUST_INTRODUCED nodes may hold circuit roles.
     */
    fun isCircuitEligible(node: NodeProfile): Boolean =
        node.trustLevel != TrustLevel.TRUST_PUBLIC && node.currentTier != NodeTier.TIER_3

    companion object {
        const val TIER1_MIN_UPTIME_MS        = 72L * 60 * 60 * 1000  // 72 hours
        const val TIER2_MIN_UPTIME_MS        = 1L  * 60 * 60 * 1000  // 1 hour
        const val TIER1_MAX_STORAGE_PCT      = 80
        const val TIER2_MAX_STORAGE_PCT      = 90
        const val TIER1_DEMOTION_STORAGE_PCT = 95
        const val TIER2_DEMOTION_STORAGE_PCT = 98
    }
}

// ── Profile and decision types ────────────────────────────────────────────────

data class NodeProfile(
    val nodeId:      NodeId,
    val trustLevel:  TrustLevel,
    val currentTier: NodeTier,
    val uptimeMs:    Long,
    val storagePct:  Int,       // 0–100
    val isOnline:    Boolean    // true = not in POLLING/SURVIVAL mode
)

sealed class PromotionDecision {
    object Eligible                             : PromotionDecision()
    data class Ineligible(val reason: String)  : PromotionDecision()
}

sealed class DemotionDecision {
    object NotRequired                          : DemotionDecision()
    data class Required(val reason: String)    : DemotionDecision()
}

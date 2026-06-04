package mesh.shadowmesh.mesh.circuit

import mesh.shadowmesh.mesh.dht.*
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.crypto.toHex

/**
 * Circuit role rotation — design doc §13c.3, Phase 8 (Entry Node Split).
 *
 * Four-hop circuit topology:
 *   Sender → Entry → Guard → Middle → Exit → Destination
 *
 * Roles and trust requirements:
 *   Entry  — TRUST_PHYSICAL only. Sender-chosen from a ranked preference list.
 *            Receives the sender's real IP. Injects the sender into the mesh
 *            without exposing their IP to Guard, Middle, or Exit. The sender
 *            explicitly chooses who sees their IP; this is not randomly assigned.
 *   Guard  — TRUST_PHYSICAL or TRUST_INTRODUCED (full mesh minus PUBLIC).
 *            Randomly selected. Sees Entry's IP only — NOT the sender's real IP.
 *            Guard pool drawn from the full mesh, so anonymity set scales with
 *            total mesh size, not just the TRUST_PHYSICAL count.
 *   Middle — TRUST_PHYSICAL or TRUST_INTRODUCED. Pure random. Sees Guard IP only.
 *   Exit   — TRUST_PHYSICAL or TRUST_INTRODUCED. Pure random. Sees destination IP only.
 *
 * Why this separation matters:
 *   In the original 3-hop design, Guard was required to be TRUST_PHYSICAL because
 *   it saw the sender's real IP. This confined the Guard anonymity set to the
 *   TRUST_PHYSICAL pool, which in hub-and-spoke deployments is far smaller than
 *   total mesh size. The P=(c/n)² formula was optimistic: n_physical << n_total.
 *   By separating IP-exposure (Entry, chosen) from anonymizing relay (Guard, random),
 *   the Guard pool expands to the full mesh and the quadratic formula holds accurately.
 *
 * Entry selection — ranked preferences with fallback chain:
 *   1. Walk [entryPreferences] in order (caller-supplied ranked list).
 *      Skip any node that is blocked, offline, or the local node.
 *   2. If preferences exhausted: any unblocked TRUST_PHYSICAL peer in candidates
 *      that has not served as Entry in the immediately previous circuit.
 *   3. If still none: any unblocked TRUST_PHYSICAL peer in candidates.
 *   4. If truly none: return null — circuit cannot be built without a trusted Entry.
 *
 * Guard/Middle/Exit selection:
 *   - Entry node excluded from all three pools.
 *   - No node serves the same role in two consecutive circuits (no-repeat rule).
 *   - No-repeat fallback: if all eligible nodes have served the role recently,
 *     relax the constraint rather than failing entirely.
 *
 * Degraded mode fallbacks:
 *   HEALTHY  — Entry + Guard + Middle + Exit (4-hop, full circuit)
 *   DEGRADED — Entry + Guard + Exit (3-hop, middle absent)
 *   CRITICAL — Entry + Exit (2-hop, guard absent — extreme fallback)
 *              Guard is null in CircuitSelection when only 1 non-entry eligible node.
 *
 * Thread-safety: [lastRoles] uses ConcurrentHashMap. Role selection is
 * stateless otherwise — thread-safe by construction.
 */
class CircuitRoleRotator(
    private val localNodeId: NodeId,
    private val rng:         SecureRandom = SecureRandom()
) {
    // Last role each node served — enforces no-consecutive-same-role
    private val lastRoles = ConcurrentHashMap<String, CircuitRole>()

    enum class CircuitRole { ENTRY, GUARD, MIDDLE, EXIT }

    data class CircuitSelection(
        val entry:  DhtContact,
        val guard:  DhtContact?,  // null = Entry+Exit 2-hop extreme fallback
        val middle: DhtContact?,  // null = Entry+Guard+Exit 3-hop degraded fallback
        val exit:   DhtContact
    )

    /**
     * Select Entry, Guard, Middle, and Exit for the next circuit.
     *
     * @param candidates        All known peers with trust levels and uptime scores.
     * @param entryPreferences  Caller's ranked list of preferred Entry nodes.
     * @param forceNoGuard      When true (CRITICAL mode), always produce guard=null.
     *                          This enforces a 2-hop Entry+Exit circuit regardless of
     *                          how many eligible peers are available. Without this,
     *                          the rotator would produce a 4-hop circuit whenever the
     *                          peer pool is large enough, violating the mode contract.
     * @param forceNoMiddle     When true, always produce middle=null (3-hop Entry+Guard+Exit).
     *                          Not currently used but available for DEGRADED enforcement
     *                          if the design doc requires strict 3-hop in DEGRADED.
     *
     * Returns null only if no TRUST_PHYSICAL Entry node is available at all.
     * Guard and Middle may be null per the fallback chain or [forceNoGuard]/[forceNoMiddle].
     */
    fun selectNextCircuit(
        candidates:       List<CircuitCandidate>,
        entryPreferences: List<CircuitCandidate>,
        forceNoGuard:     Boolean = false,
        forceNoMiddle:    Boolean = false
    ): CircuitSelection? {
        val eligible = candidates.filter { it.nodeId != localNodeId && !it.isBlocked }

        // Evict lastRoles entries for nodes no longer in the candidate pool.
        // Prevents unbounded growth when nodes churn. Cost: O(|lastRoles|) per
        // rotation — negligible at a 10-minute rotation interval.
        val candidateHexIds = candidates.map { it.nodeId.bytes.toHex() }.toHashSet()
        lastRoles.keys.removeIf { it !in candidateHexIds }

        // ── Entry selection: ranked preferences with fallback chain ───────
        val entry = selectEntry(eligible, entryPreferences) ?: return null

        // ── Guard selection: full mesh minus Entry, minus PUBLIC ──────────
        // Guard no longer requires TRUST_PHYSICAL — it no longer sees sender IP.
        // Entry is excluded. TRUST_PUBLIC excluded (no circuit role).
        // No-repeat rule applied with fallback.
        val guardEligible = eligible.filter {
            it.nodeId != entry.nodeId &&
            it.trustLevel != TrustLevelForCircuit.PUBLIC
        }

        val guard = if (!forceNoGuard && guardEligible.isNotEmpty()) {
            val guardPool = guardEligible.filter {
                lastRoles[it.nodeId.bytes.toHex()] != CircuitRole.GUARD
            }.takeIf { it.isNotEmpty() } ?: guardEligible
            weightedRandomSelect(guardPool)
        } else null
        // null = forceNoGuard (CRITICAL mode 2-hop) or no eligible peers

        // ── Exit selection: not Entry, not Guard ──────────────────────────
        // Entry is always excluded from exitEligible — Entry == Exit is structurally
        // impossible. In CRITICAL mode (forceNoGuard=true, guard=null), if the only
        // remaining eligible peer IS the Entry node, exitEligible will be empty and
        // selectNextCircuit returns null (no circuit) rather than building a degenerate
        // 1-node circuit. This is the correct fail-closed behaviour: better no circuit
        // than a "2-hop" circuit where Entry and Exit are the same node, which would give
        // that single node visibility into both sender identity and destination.
        val exitEligible = eligible.filter {
            it.nodeId != entry.nodeId &&
            it.nodeId != guard?.nodeId &&
            it.trustLevel != TrustLevelForCircuit.PUBLIC
        }
        if (exitEligible.isEmpty()) return null  // cannot build any circuit without a distinct Exit

        val exitPool = exitEligible.filter {
            lastRoles[it.nodeId.bytes.toHex()] != CircuitRole.EXIT
        }.takeIf { it.isNotEmpty() } ?: exitEligible
        val exit = exitPool.random(rng)

        // ── Middle selection: not Entry, Guard, or Exit ───────────────────
        val middlePool = eligible.filter {
            it.nodeId != entry.nodeId &&
            it.nodeId != guard?.nodeId &&
            it.nodeId != exit.nodeId &&
            it.trustLevel != TrustLevelForCircuit.PUBLIC &&
            lastRoles[it.nodeId.bytes.toHex()] != CircuitRole.MIDDLE
        }
        val middle = if (!forceNoMiddle && middlePool.isNotEmpty()) middlePool.random(rng) else null
        // null = forceNoMiddle, or 3-hop degraded fallback (Entry+Guard+Exit)

        // Record roles for next rotation
        recordRole(entry.nodeId, CircuitRole.ENTRY)
        guard?.let { recordRole(it.nodeId, CircuitRole.GUARD) }
        middle?.let { recordRole(it.nodeId, CircuitRole.MIDDLE) }
        recordRole(exit.nodeId, CircuitRole.EXIT)

        return CircuitSelection(
            entry  = entry.contact,
            guard  = guard?.contact,
            middle = middle?.contact,
            exit   = exit.contact
        )
    }

    // ── Entry selection ───────────────────────────────────────────────────

    /**
     * Select an Entry node using the ranked preference fallback chain.
     *
     * Step 1: preferred and available — walk [entryPreferences] in order.
     *         An entry preference is available if it appears in [eligible]
     *         (online, not blocked, not the local node).
     * Step 2: preferred but recently used — walk [entryPreferences] ignoring
     *         the no-repeat constraint. Prefer rotating, but don't fail over it.
     * Step 3: any unblocked TRUST_PHYSICAL peer from [eligible] not recently Entry.
     * Step 4: any unblocked TRUST_PHYSICAL peer from [eligible] — last resort.
     *
     * Returns null only if no TRUST_PHYSICAL peer exists in the mesh at all.
     */
    private fun selectEntry(
        eligible:         List<CircuitCandidate>,
        entryPreferences: List<CircuitCandidate>
    ): CircuitCandidate? {
        val eligibleIds = eligible.associateBy { it.nodeId.bytes.toHex() }

        // Step 1: preferred, available, not recently Entry
        for (pref in entryPreferences) {
            val candidate = eligibleIds[pref.nodeId.bytes.toHex()] ?: continue
            if (lastRoles[candidate.nodeId.bytes.toHex()] == CircuitRole.ENTRY) continue
            return candidate
        }

        // Step 2: preferred, available, ignoring no-repeat (all preferred nodes
        // have served as Entry recently — small preference list)
        for (pref in entryPreferences) {
            val candidate = eligibleIds[pref.nodeId.bytes.toHex()] ?: continue
            return candidate
        }

        // Step 3: any TRUST_PHYSICAL peer from eligible, not recently Entry
        val physicalEligible = eligible.filter { it.trustLevel == TrustLevelForCircuit.PHYSICAL }
        physicalEligible.firstOrNull {
            lastRoles[it.nodeId.bytes.toHex()] != CircuitRole.ENTRY
        }?.let { return it }

        // Step 4: any TRUST_PHYSICAL peer — absolute last resort
        return physicalEligible.firstOrNull()
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun recordRole(nodeId: NodeId, role: CircuitRole) {
        lastRoles[nodeId.bytes.toHex()] = role
    }

    /**
     * Weighted random selection: probability proportional to [CircuitCandidate.uptimeScore].
     * Pure highest-score selection is avoided — it makes Guard identity predictable.
     */
    private fun weightedRandomSelect(pool: List<CircuitCandidate>): CircuitCandidate? {
        if (pool.isEmpty()) return null
        val totalWeight = pool.sumOf { it.uptimeScore.coerceAtLeast(1) }.toDouble()
        var remaining   = rng.nextDouble() * totalWeight
        for (candidate in pool) {
            remaining -= candidate.uptimeScore.coerceAtLeast(1)
            if (remaining <= 0) return candidate
        }
        return pool.last()
    }

    private fun List<CircuitCandidate>.random(rng: SecureRandom) =
        this[rng.nextInt(size)]
}

// ── Supporting types ──────────────────────────────────────────────────────────

enum class TrustLevelForCircuit { PHYSICAL, INTRODUCED, PUBLIC }

data class CircuitCandidate(
    val nodeId:      NodeId,
    val contact:     DhtContact,
    val trustLevel:  TrustLevelForCircuit,
    val uptimeScore: Int,        // 0–100; used for weighted Guard selection
    val isBlocked:   Boolean = false
)

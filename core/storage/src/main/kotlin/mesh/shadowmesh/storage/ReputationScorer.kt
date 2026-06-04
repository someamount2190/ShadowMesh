package mesh.shadowmesh.storage

import mesh.shadowmesh.crypto.TrustLevel

/**
 * Local reputation scoring — design doc Phase 3.
 *
 * Computes a [ReputationTier] from local observations only:
 *   - Key age (older = more established)
 *   - Relay reliability (success / (success + failure) ratio)
 *   - Vouching depth (how deep in the trust graph)
 *   - Trust level from TrustCredential
 *   - Behavioral coherence signal from [BehavioralCoherenceScorer]
 *
 * The behavioral signal is a NEW fourth dimension that can downgrade a node's
 * reputation tier regardless of trust level. A TRUST_PHYSICAL node exhibiting
 * machine-like behavior patterns is still suspicious — physical contact proves
 * hardware but not that the device is human-operated.
 *
 * Scores are NEVER transmitted. This is strictly local intelligence.
 * The UI MUST display a mandatory warning when reputation data is shown,
 * because it is a heuristic — not a cryptographic guarantee.
 *
 * Tier definitions:
 *   ESTABLISHED  — long key age, high relay reliability, TRUST_PHYSICAL, coherent behavior
 *   KNOWN        — moderate age/reliability, TRUST_INTRODUCED or vouched
 *   NEW          — recently seen, limited relay history
 *   UNVERIFIED   — no relay history, TRUST_PUBLIC, very new key, or suspicious behavior
 *
 * Thread-safety: stateless — thread-safe by construction.
 */
class ReputationScorer {

    private val behavioralScorer = BehavioralCoherenceScorer()

    /**
     * Compute a reputation tier from the given observations.
     *
     * @param keyAgeMs          Age of the node's identity key in milliseconds.
     * @param relaySuccessCount Number of successfully relayed fragments.
     * @param relayFailureCount Number of failed relay attempts.
     * @param vouchingDepth     0 = no vouching, 1 = TRUST_PHYSICAL vouched, etc.
     * @param trustLevel        Trust level from the node's TrustCredential.
     * @param behaviorWindow    Optional behavioral observation window. When provided,
     *                          the behavioral signal can downgrade the reputation tier.
     *                          Pass null to skip behavioral scoring (backward-compatible).
     */
    fun score(
        keyAgeMs:          Long,
        relaySuccessCount: Int,
        relayFailureCount: Int,
        vouchingDepth:     Int,
        trustLevel:        TrustLevel,
        behaviorWindow:    NodeBehaviorWindow? = null
    ): ReputationTier {
        val totalRelays   = relaySuccessCount + relayFailureCount
        val reliability   = if (totalRelays > 0) relaySuccessCount.toFloat() / totalRelays else 0f

        val ageScore      = ageScore(keyAgeMs)
        val reliabilityOk = totalRelays >= MIN_RELAY_OBSERVATIONS && reliability >= MIN_RELIABILITY
        val wellVouched   = vouchingDepth >= 1

        // Behavioral signal — can cap or downgrade but never upgrade
        val behavioralSignal = behaviorWindow?.let { behavioralScorer.score(it) }
        val behaviorallyCompromised = behavioralSignal is BehavioralSignal.HighlySuspicious

        // A HighlySuspicious behavioral signal caps the tier at UNVERIFIED regardless
        // of trust level. This reflects that physical contact proves hardware, not
        // human operation — an AI agent that obtained one physical bootstrap is still
        // an AI agent.
        if (behaviorallyCompromised) {
            return ReputationTier.UNVERIFIED
        }

        // A Suspicious (not highly) behavioral signal prevents ESTABLISHED
        val behaviorallySuspicious = behavioralSignal is BehavioralSignal.Suspicious

        val baselineTier = when {
            trustLevel == TrustLevel.TRUST_PHYSICAL && ageScore >= AGE_SCORE_ESTABLISHED && reliabilityOk ->
                ReputationTier.ESTABLISHED

            (trustLevel == TrustLevel.TRUST_PHYSICAL || trustLevel == TrustLevel.TRUST_INTRODUCED) &&
            (ageScore >= AGE_SCORE_KNOWN || wellVouched) ->
                ReputationTier.KNOWN

            totalRelays >= MIN_RELAY_OBSERVATIONS || ageScore >= AGE_SCORE_NEW ->
                ReputationTier.NEW

            else ->
                ReputationTier.UNVERIFIED
        }

        // Apply behavioral downgrade: Suspicious → cannot be ESTABLISHED
        return if (behaviorallySuspicious && baselineTier == ReputationTier.ESTABLISHED) {
            ReputationTier.KNOWN
        } else {
            baselineTier
        }
    }

    /**
     * Recompute and update a [ReputationEntry] given updated observations.
     * Returns a new entry with the recalculated tier and timestamps.
     */
    fun update(
        existing:       ReputationEntry,
        trustLevel:     TrustLevel,
        behaviorWindow: NodeBehaviorWindow? = null,
        nowMs:          Long = System.currentTimeMillis()
    ): ReputationEntry {
        val tier = score(
            keyAgeMs          = existing.keyAgeMs,
            relaySuccessCount = existing.relaySuccessCount,
            relayFailureCount = existing.relayFailureCount,
            vouchingDepth     = existing.vouchingDepth,
            trustLevel        = trustLevel,
            behaviorWindow    = behaviorWindow
        )
        return existing.copy(tier = tier, updatedAtMs = nowMs)
    }

    // ── Internal scoring ──────────────────────────────────────────────────

    private fun ageScore(keyAgeMs: Long): Int = when {
        keyAgeMs >= AGE_MS_30_DAYS -> AGE_SCORE_ESTABLISHED
        keyAgeMs >= AGE_MS_7_DAYS  -> AGE_SCORE_KNOWN
        keyAgeMs >= AGE_MS_1_DAY   -> AGE_SCORE_NEW
        else                       -> 0
    }

    companion object {
        private const val MIN_RELAY_OBSERVATIONS = 10
        private const val MIN_RELIABILITY        = 0.8f

        private const val AGE_SCORE_ESTABLISHED  = 3
        private const val AGE_SCORE_KNOWN        = 2
        private const val AGE_SCORE_NEW          = 1

        private const val AGE_MS_30_DAYS = 30L * 24 * 60 * 60 * 1000
        private const val AGE_MS_7_DAYS  =  7L * 24 * 60 * 60 * 1000
        private const val AGE_MS_1_DAY   =  1L * 24 * 60 * 60 * 1000

        /** Mandatory UI warning text — must be shown whenever reputation data is displayed. */
        const val MANDATORY_UI_WARNING =
            "Reputation scores are local estimates only. They are not cryptographic guarantees " +
            "and may be inaccurate. Do not rely on reputation alone for operational security decisions."
    }
}


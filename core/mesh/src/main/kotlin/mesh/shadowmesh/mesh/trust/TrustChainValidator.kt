package mesh.shadowmesh.mesh.trust

import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.mesh.dht.NodeId
import mesh.shadowmesh.diagnostics.Diag

/**
 * Trust chain validation — design doc §5.2, §5.14.
 *
 * Validates that a node's trust credential is:
 *   1. Cryptographically valid (signature verifiable with introducer's key).
 *   2. Consistent with the transitivity cap (depth limit at 1 remote hop).
 *   3. Not self-claimed above TRUST_PUBLIC (self-issued credentials are always PUBLIC).
 *   4. Within the sponsor's introduction rate/lifetime limits ([SponsorshipLedger]).
 *
 * This class consolidates the trust enforcement that was previously spread
 * across GossipEngine.enforceTrustTransitivityCap() and TrustCredential.grantableTrustLevel().
 * Those remain for in-line use; this class is the authoritative validator used
 * at node admission time (bootstrap, DHT insert, peer registration).
 *
 * Trust transitivity cap (design doc §5.14):
 *   TRUST_PHYSICAL  + physical intro  → TRUST_PHYSICAL   (depth 0)
 *   TRUST_PHYSICAL  + remote intro    → TRUST_INTRODUCED  (depth 1)
 *   TRUST_INTRODUCED + any intro      → TRUST_PUBLIC      (cap — depth 1 enforced)
 *   TRUST_PUBLIC    + any intro       → TRUST_PUBLIC      (no introduction rights)
 *
 * Sybil breadth cap (SponsorshipLedger):
 *   Even a valid TRUST_PHYSICAL introducer is rate-limited to [SponsorshipLedger.MAX_INTRODUCTIONS_PER_WINDOW]
 *   TRUST_INTRODUCED issuances per rolling window. Exceeding the limit downgrades the new
 *   credential to TRUST_PUBLIC. This prevents a single compromised physical contact from
 *   spinning up an unlimited TRUST_INTRODUCED Sybil swarm.
 *
 * Thread-safety: stateless — thread-safe by construction. [SponsorshipLedger] is @Synchronized.
 *
 * @param ledger  Optional [SponsorshipLedger] for Sybil breadth limiting. When null,
 *                rate limiting is skipped (e.g., in unit tests that don't need it).
 */
class TrustChainValidator(
    private val signer: HybridSigner,
    private val ledger: SponsorshipLedger? = null
) {

    /**
     * Validate a [TrustCredential] presented by [claimedNodeId].
     *
     * Checks:
     *   1. Credential's nodeId matches [claimedNodeId].
     *   2. Credential's signature is valid (signed by [introducerVerifyKey]).
     *   3. The granted trust level respects the transitivity cap given
     *      [introducerTrustLevel] and [method].
     *   4. If the effective level would be TRUST_INTRODUCED, consult the
     *      [SponsorshipLedger] to enforce the Sybil breadth cap.
     *
     * @param credential           The credential to validate.
     * @param claimedNodeId        The node presenting this credential.
     * @param introducerVerifyKey  The introducer's public signing key.
     * @param introducerNodeId     The introducer's node ID (for ledger tracking).
     * @param introducerTrustLevel The introducer's own verified trust level.
     * @param method               How the introduction was performed.
     *
     * @return [ValidationResult.Valid] with the effective trust level on success.
     *         [ValidationResult.Invalid] with a reason on any failure.
     */
    suspend fun validate(
        credential:            TrustCredential,
        claimedNodeId:         NodeId,
        introducerVerifyKey:   HybridVerifyKey,
        introducerNodeId:      NodeId,
        introducerTrustLevel:  TrustLevel,
        method:                IntroductionMethod
    ): ValidationResult {
        // 0. Credential timestamp sanity + age check.
        //
        // TrustCredential has no expiresAtMs wire field (v2 format). Until v3 is added, we
        // enforce a 90-day lifetime heuristic to prevent indefinite replay of stale credentials.
        //
        // Two sub-checks required — checking only "age > 90 days" is insufficient:
        //
        // (a) Reject future-dated credentials: if issuedAtMs > now + clock-skew, the credential
        //     was issued with a far-future timestamp to permanently bypass the age check below.
        //     Example: issuedAtMs = Long.MAX_VALUE → credentialAgeMs = currentTime - Long.MAX_VALUE
        //     which is a very large NEGATIVE number → (negative) > 90 days = false → bypass.
        //
        // (b) Reject over-age credentials: if credentialAgeMs > 90 days the credential has expired.
        val now = System.currentTimeMillis()
        val CLOCK_SKEW_TOLERANCE_MS = 5L * 60 * 1000          // ±5 minutes
        val CREDENTIAL_MAX_AGE_MS   = 90L * 24 * 60 * 60 * 1000  // 90 days
        if (credential.issuedAtMs > now + CLOCK_SKEW_TOLERANCE_MS) {
            return ValidationResult.Invalid(
                "Credential has a future issuedAtMs (${credential.issuedAtMs}) that exceeds " +
                "now + ${CLOCK_SKEW_TOLERANCE_MS / 60_000}min clock-skew tolerance. " +
                "Possible forgery or severe clock skew — rejecting."
            )
        }
        val credentialAgeMs = now - credential.issuedAtMs
        // Add CLOCK_SKEW_TOLERANCE_MS to the age check for consistency: a credential
        // issued by a device whose clock is up to 5 minutes behind appears 5 minutes
        // older than it actually is. Adding the same tolerance used for the future-dated
        // check prevents valid credentials from being rejected near the 90-day boundary.
        if (credentialAgeMs > CREDENTIAL_MAX_AGE_MS + CLOCK_SKEW_TOLERANCE_MS) {
            return ValidationResult.Invalid(
                "Credential is older than the 90-day maximum lifetime " +
                "(issued ${credentialAgeMs / (24 * 60 * 60 * 1000)}d ago). " +
                "Re-bootstrap with this node to obtain a fresh credential."
            )
        }

        // 1. Node ID match
        if (!credential.nodeId.contentEquals(claimedNodeId.bytes)) {
            return ValidationResult.Invalid("Credential nodeId does not match presenting node")
        }

        // 2. Signature verification
        val sigValid = try {
            signer.verify(
                message   = credential.signedPayload(),
                signature = credential.signature,
                publicKey = introducerVerifyKey
            ).getOrThrow()
        } catch (e: Exception) {
            Diag.swallowed("trust-chain", "sig-verify", e,
                "nodeId" to claimedNodeId.bytes.toHex().take(8))
            return ValidationResult.Invalid("Credential signature invalid: ${e.message}")
        }
        if (!sigValid) {
            return ValidationResult.Invalid("Credential signature did not verify")
        }

        // 3. Transitivity cap — compute the maximum grantable trust level
        val maxGrantable = computeGrantable(introducerTrustLevel, method)

        // The claimed trust level must not exceed what the introducer can grant
        if (!isLevelAtMost(credential.trustLevel, maxGrantable)) {
            return ValidationResult.Invalid(
                "Trust level ${credential.trustLevel} exceeds what introducer " +
                "(${introducerTrustLevel}) can grant via $method: max is $maxGrantable"
            )
        }

        // Effective level is min(claimed, maxGrantable) — always apply the cap
        var effective = minLevel(credential.trustLevel, maxGrantable)

        // 4. Sybil breadth cap — consult the ledger before issuing TRUST_INTRODUCED.
        //    A single compromised TRUST_PHYSICAL node cannot issue unlimited TRUST_INTRODUCED
        //    credentials: the ledger enforces per-sponsor rate and lifetime caps.
        //    On violation, downgrade to TRUST_PUBLIC rather than rejecting outright —
        //    the candidate is legitimate, just the sponsor is saturated.
        if (effective == TrustLevel.TRUST_INTRODUCED && ledger != null) {
            val decision = ledger.checkIntroduction(introducerNodeId, claimedNodeId)
            effective = when (decision) {
                is IntroductionDecision.Allowed   -> TrustLevel.TRUST_INTRODUCED
                is IntroductionDecision.Downgraded -> TrustLevel.TRUST_PUBLIC  // sponsor rate-limited
                is IntroductionDecision.MeshBurst  -> TrustLevel.TRUST_PUBLIC  // mesh-wide burst
            }
        }

        return ValidationResult.Valid(effective)
    }

    /**
     * Validate a self-issued credential (no introducer — first contact / public beacon).
     * Self-issued credentials are always capped at TRUST_PUBLIC regardless of what
     * the credential claims.
     *
     * No signature verification is performed here, by design:
     *   - A self-issued credential is signed by the node's own key.
     *   - At first contact (public beacon), we do not yet have the node's verified
     *     public key — we are in the process of receiving it.
     *   - Verifying the signature with the key embedded in the same credential would
     *     be trivially forgeable (any node could generate a matching keypair).
     *   - The trust level (TRUST_PUBLIC) grants only read-only access, so the security
     *     property we care about is not the signature but the level cap.
     *   - Full signature verification is performed later, after the node's key has been
     *     independently confirmed via the DHT (Phase 4, nodeId = SHA3-256(kemPub || sigPub)).
     */
    fun validateSelfIssued(credential: TrustCredential, claimedNodeId: NodeId): ValidationResult {
        if (!credential.nodeId.contentEquals(claimedNodeId.bytes)) {
            return ValidationResult.Invalid("Self-issued credential nodeId mismatch")
        }
        if (credential.trustLevel != TrustLevel.TRUST_PUBLIC) {
            return ValidationResult.Invalid(
                "Self-issued credentials must be TRUST_PUBLIC; got ${credential.trustLevel}"
            )
        }
        return ValidationResult.Valid(TrustLevel.TRUST_PUBLIC)
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun computeGrantable(
        introducerLevel: TrustLevel,
        method:          IntroductionMethod
    ): TrustLevel = when (introducerLevel) {
        TrustLevel.TRUST_PHYSICAL -> when (method) {
            IntroductionMethod.PHYSICAL -> TrustLevel.TRUST_PHYSICAL
            IntroductionMethod.REMOTE   -> TrustLevel.TRUST_INTRODUCED
        }
        TrustLevel.TRUST_INTRODUCED,
        TrustLevel.TRUST_PUBLIC -> TrustLevel.TRUST_PUBLIC
    }

    /** Returns true if [level] is at most [max] in the trust ordering. */
    private fun isLevelAtMost(level: TrustLevel, max: TrustLevel): Boolean =
        trustOrdinal(level) >= trustOrdinal(max)  // higher ordinal = lower trust

    private fun minLevel(a: TrustLevel, b: TrustLevel): TrustLevel =
        if (trustOrdinal(a) >= trustOrdinal(b)) a else b

    // Ordinal: PHYSICAL=0 (highest), INTRODUCED=1, PUBLIC=2 (lowest)
    private fun trustOrdinal(level: TrustLevel): Int = when (level) {
        TrustLevel.TRUST_PHYSICAL    -> 0
        TrustLevel.TRUST_INTRODUCED  -> 1
        TrustLevel.TRUST_PUBLIC      -> 2
    }
}

sealed class ValidationResult {
    data class Valid(val effectiveTrustLevel: TrustLevel) : ValidationResult()
    data class Invalid(val reason: String)                : ValidationResult()
}

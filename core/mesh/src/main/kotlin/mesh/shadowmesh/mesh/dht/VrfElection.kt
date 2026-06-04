package mesh.shadowmesh.mesh.dht

import mesh.shadowmesh.crypto.Hkdf
import java.security.SecureRandom
import mesh.shadowmesh.crypto.toHex

/**
 * VRF commit-reveal anchor election — design doc §4.
 *
 * Two-phase election to select the next anchor node deterministically
 * and unpredictably (no node can predict the winner before reveal phase).
 *
 * Round ID: SHA3-256(last_post_hash || election_seq). Binds the election
 * to the current mesh state; stale election_seq values are rejected by callers.
 *
 * Phase 1 — COMMIT:
 *   Each candidate generates a random nonce (32 bytes) and gossips
 *   commitHash = SHA3-256(nonce || roundId). The nonce is kept secret.
 *
 * Phase 2 — REVEAL:
 *   Each candidate reveals its nonce. Non-revealers are excluded.
 *   The commitHash is verified: SHA3-256(revealedNonce || roundId) must match.
 *   VRF output = HKDF(IKM = signingKey || roundId.bytes,
 *                     salt = nonce, info = "vrf_election_v1", len = 32)
 *   Winner: candidate with lexicographically lowest VRF output.
 *
 * Partition heal tie-break: if two candidates have identical VRF output
 * (astronomically unlikely), the one with the lower nodeId wins.
 *
 * ── Nonce anti-replay design ────────────────────────────────────────────────
 *
 * Each [VrfElectionRound] owns its nonce set internally. The caller constructs
 * a [VrfElectionRound] via [VrfElection.newRound], feeds reveals into it via
 * [VrfElectionRound.acceptReveal], then calls [VrfElectionRound.resolve].
 * The round object is then discarded — there is no shared mutable set for
 * callers to accidentally reuse across rounds.
 *
 * Previous design passed a MutableSet<String> from the caller. That was a
 * footgun: nothing prevented a caller from reusing the same set across two
 * elections, causing valid nonces from round N+1 to be falsely rejected as
 * replays of round N. The typed [VrfElectionRound] object makes this impossible
 * by construction — the set is private and scoped to one round lifetime.
 *
 * Thread-safety: [VrfElection] is stateless — thread-safe by construction.
 *               [VrfElectionRound] is NOT thread-safe; use one per goroutine or
 *               synchronize externally if reveals arrive concurrently.
 */
class VrfElection(private val hkdf: Hkdf = Hkdf.instance) {

    private val rng = SecureRandom()

    // ── Phase 1: Commit ────────────────────────────────────────────────────

    fun generateCommit(candidateNodeId: NodeId, roundId: String): CommitBundle {
        val nonce      = ByteArray(32).also { rng.nextBytes(it) }
        val commitHash = hkdf.sha3_256(nonce + roundId.toByteArray())
        return CommitBundle(
            commit      = VrfCommit(candidateNodeId, commitHash, roundId),
            secretNonce = nonce
        )
    }

    // ── Phase 2: Reveal ────────────────────────────────────────────────────

    fun generateReveal(
        candidateNodeId: NodeId,
        secretNonce:     ByteArray,
        roundId:         String,
        signingKeyBytes: ByteArray
    ): VrfReveal {
        require(secretNonce.size == 32)       { "nonce must be 32 bytes" }
        require(signingKeyBytes.size >= 32)   { "signing key must be at least 32 bytes; copyOf(32) would zero-pad a shorter key, reducing VRF output entropy" }

        // FIX (Bug 8): bind the output to candidateNodeId via the HKDF info tag, so two
        // candidates sharing a signing key (shouldn't happen, but defensive) cannot produce
        // identical outputs, and the output is domain-separated per candidate identity.
        //
        // IMPORTANT — this is NOT a publicly-verifiable VRF. It is a keyed PRF used in a
        // commit-reveal: a verifier can only check the output AFTER the reveal exposes
        // secretNonce + signingKeyBytes, by recomputing this HKDF. It does NOT provide
        // VRF-style proof-without-secret verifiability, and it does NOT prevent a candidate
        // from grinding outputs across many (nonce, key) pairs BEFORE committing. If the
        // election must resist a malicious candidate biasing its own output, replace this
        // with a real VRF (e.g. ECVRF / RFC 9381). The commit hash binds the candidate to a
        // single nonce, which is the property the current scheme actually relies on.
        // info = VRF_INFO || candidateNodeId.bytes (32 bytes) — stable byte sequence.
        val vrfOutput = hkdf.derive(
            ikm       = signingKeyBytes.copyOf(32) + roundId.toByteArray(),
            salt      = secretNonce,
            info      = VRF_INFO + candidateNodeId.bytes,
            outputLen = 32
        )
        return VrfReveal(candidateNodeId, secretNonce, roundId, vrfOutput)
    }

    // ── Election round factory ─────────────────────────────────────────────

    /**
     * Create a new [VrfElectionRound] for [roundId].
     *
     * Feed reveals into the round via [VrfElectionRound.acceptReveal], then call
     * [VrfElectionRound.resolve] to determine the winner. Discard the round object
     * afterwards — never reuse it for a subsequent election.
     */
    fun newRound(roundId: String, commits: List<VrfCommit>): VrfElectionRound =
        VrfElectionRound(roundId, commits, hkdf)

    // ── Round ID derivation ────────────────────────────────────────────────

    /**
     * Derive a round ID from the last post hash and election sequence.
     * roundId = hex(SHA3-256(last_post_hash || election_seq_bytes))
     *
     * election_seq must be monotonically increasing and never reused.
     * Callers must persist the current seq and increment before each election.
     */
    fun deriveRoundId(lastPostHash: ByteArray, electionSeq: Long): String {
        val seqBytes = ByteArray(8) { i -> ((electionSeq shr ((7 - i) * 8)) and 0xFF).toByte() }
        return hkdf.sha3_256(lastPostHash + seqBytes).toHex()
    }

    companion object {
        private val VRF_INFO = "vrf_election_v1".toByteArray()
    }
}

/**
 * A single VRF election round. Owns the anti-replay nonce set internally —
 * callers cannot accidentally share it across rounds.
 *
 * Construct via [VrfElection.newRound]. Discard after [resolve] returns.
 *
 * NOT thread-safe: if reveals arrive concurrently, synchronize [acceptReveal]
 * externally or collect all reveals before calling [resolve].
 */
class VrfElectionRound internal constructor(
    private val expectedRoundId: String,
    commits:                     List<VrfCommit>,
    private val hkdf:            Hkdf
) {
    private val commitMap    = commits.associateBy { it.candidateNodeId }
    // Nonce set is private and scoped to this round — callers cannot misuse it.
    private val seenNonces   = mutableSetOf<String>()
    private val validReveals = mutableListOf<VrfReveal>()

    /**
     * Validate [reveal] against its commit and the round's accumulated nonce set.
     * Accepted reveals are stored for [resolve].
     *
     * Returns the [VerificationResult] — callers may log rejections but should
     * not act on them beyond that (a rejected reveal simply excludes the candidate).
     */
    fun acceptReveal(reveal: VrfReveal): VerificationResult {
        if (reveal.roundId != expectedRoundId)
            return VerificationResult.Invalid("Round ID mismatch: expected=$expectedRoundId got=${reveal.roundId}")

        val commit = commitMap[reveal.candidateNodeId]
            ?: return VerificationResult.Invalid("No commit for ${reveal.candidateNodeId.toHex().take(8)}")

        val nonceKey = reveal.nonce.toHex()
        if (!seenNonces.add(nonceKey))
            return VerificationResult.Invalid("Nonce reuse detected in round $expectedRoundId")

        val expected = hkdf.sha3_256(reveal.nonce + reveal.roundId.toByteArray())
        if (!expected.contentEquals(commit.commitHash))
            return VerificationResult.Invalid("Commit hash mismatch — nonce does not match commitment")

        validReveals.add(reveal)
        return VerificationResult.Valid
    }

    /**
     * Resolve the election from all accepted reveals.
     * Winner = candidate with lexicographically lowest VRF output.
     * Tie-break = lexicographically lowest nodeId (for partition heal).
     *
     * Returns null if no valid reveals were accepted.
     */
    fun resolve(): ElectionResult? {
        if (validReveals.isEmpty()) return null

        val winner = validReveals.minWithOrNull(
            compareBy<VrfReveal> { it.vrfOutput.toHex() }
                .thenBy { it.candidateNodeId.toHex() }
        ) ?: return null

        return ElectionResult(
            winner   = winner.candidateNodeId,
            roundId  = expectedRoundId,
            allVotes = validReveals.toList()
        )
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

data class CommitBundle(
    val commit:      VrfCommit,
    val secretNonce: ByteArray   // keep locally until reveal — never gossip
)

sealed class VerificationResult {
    object Valid                            : VerificationResult()
    data class Invalid(val reason: String) : VerificationResult()
}

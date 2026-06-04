package mesh.shadowmesh.mesh.dht

/**
 * Routing table diversity guard — XOR key-space density enforcement.
 *
 * ## The problem: eclipse attacks via XOR clustering
 *
 * In a Kademlia DHT, an attacker mounts an eclipse attack by generating node IDs
 * that cluster tightly in XOR space near a target key. Because Kademlia routing
 * always forwards to the closest known node, a dense cluster of adversarial nodes
 * in a narrow XOR region intercepts all traffic destined for that region. With as
 * few as 8 strategically placed nodes, an attacker can eclipse a target completely
 * (Cerri et al., 2009; IPFS Sybil attack, ARES 2024).
 *
 * SHADOWMESH's existing routing table (RoutingTable.kt) admits only TRUST_PHYSICAL
 * Tier 1 anchors — which is the correct first line of defence. But trust level alone
 * is not sufficient: a compromised or coerced TRUST_PHYSICAL cluster could still
 * produce a locally dense routing table region.
 *
 * ## What this does
 *
 * Applies the same Poisson density model used by DensityAwareReplicationPolicy
 * (fragment replication) to routing table topology. Before inserting a new contact
 * into a bucket, this guard checks whether the insertion would create a density
 * spike in the bucket's XOR prefix region that exceeds what is statistically
 * expected for a uniformly distributed routing table of the current size.
 *
 * A spike is defined as: observed contacts in the suspicious region > expected
 * contacts + [SIGMA_THRESHOLD] standard deviations under a Poisson(λ) model,
 * where λ = (total routing table size) * (region size / total key-space size).
 *
 * ## S/Kademlia disjoint path integration
 *
 * The S/Kademlia paper (Baumgart & Mies, 2007) shows that even with 20% adversarial
 * nodes, lookup success stays at 99% when using d=4 disjoint lookup paths. The
 * diversity guard supports this by annotating rejected contacts as
 * [DiversityVerdict.Probationary] rather than hard-rejecting them — the routing
 * table can still use them as disjoint path candidates while excluding them from
 * primary routing. Hard rejection ([DiversityVerdict.Rejected]) is reserved for
 * extreme density (> [HARD_REJECT_SIGMA] sigma) which indicates active attack.
 *
 * ## What this does NOT do
 *
 * Does not prevent an attacker from distributing adversarial nodes uniformly across
 * key-space (a global Sybil attack) — only clustering is detected. Global Sybil
 * resistance requires the trust layer (TRUST_PHYSICAL gate + SponsorshipLedger).
 *
 * Thread-safety: all methods are pure (stateless) — the routing table passes
 * its current state as parameters. Thread safety is the routing table's concern.
 */
object RoutingTableDiversityGuard {

    /**
     * Check whether inserting [candidate] into the routing table with [currentContacts]
     * would create a suspicious XOR density spike.
     *
     * @param localNodeId     This node's ID (used as the XOR origin).
     * @param candidate       The new contact being considered for insertion.
     * @param currentContacts All contacts currently in the routing table.
     * @param bucketDepth     The bit-depth of the bucket [candidate] falls into.
     *                        Pass [NodeId.bucketIndex] output (0–255).
     *
     * @return [DiversityVerdict.OK] if insertion is safe.
     *         [DiversityVerdict.Probationary] if insertion creates a soft density spike —
     *           admit but flag; exclude from primary routing preference.
     *         [DiversityVerdict.Rejected] if insertion creates an extreme density spike —
     *           hard reject; log and consider escalating to HardenedChallengeLayer.
     */
    fun check(
        localNodeId:     NodeId,
        candidate:       DhtContact,
        currentContacts: List<DhtContact>,
        bucketDepth:     Int
    ): DiversityVerdict {

        if (currentContacts.size < MIN_CONTACTS_FOR_ANALYSIS) {
            // Too few contacts to compute a meaningful baseline — admit freely
            return DiversityVerdict.OK
        }

        // Count contacts that share the same XOR prefix region as the candidate.
        // The region is defined by the top [bucketDepth] bits of the XOR distance.
        // Two nodes are in the same region if their XOR distances to localNodeId
        // share the same [PREFIX_ANALYSIS_BITS]-bit prefix.
        val candidateDistance   = localNodeId.xorDistance(candidate.nodeId)
        val prefixBits          = minOf(PREFIX_ANALYSIS_BITS, bucketDepth)
        val regionCount         = currentContacts.count { contact ->
            val d = localNodeId.xorDistance(contact.nodeId)
            sharedPrefixBits(candidateDistance, d) >= prefixBits
        }

        // Poisson model: λ = n * (1 / 2^prefixBits)
        // In a uniformly distributed routing table of size n, the expected number
        // of nodes in a region covering 1/2^prefixBits of key-space is n / 2^prefixBits.
        val n      = currentContacts.size.toDouble()
        val lambda = n / (1L shl prefixBits).toDouble()   // expected count

        // Poisson standard deviation = sqrt(λ)
        val sigma  = Math.sqrt(lambda)

        // Observed = regionCount + 1 (including the candidate we're checking)
        val observed = (regionCount + 1).toDouble()

        return when {
            sigma < SIGMA_MIN_MEANINGFUL -> DiversityVerdict.OK   // too few to be meaningful
            observed > lambda + HARD_REJECT_SIGMA * sigma ->
                DiversityVerdict.Rejected(
                    prefixBits   = prefixBits,
                    observed     = regionCount + 1,
                    expected     = lambda,
                    sigmasAbove  = (observed - lambda) / sigma
                )
            observed > lambda + SOFT_REJECT_SIGMA * sigma ->
                DiversityVerdict.Probationary(
                    prefixBits   = prefixBits,
                    observed     = regionCount + 1,
                    expected     = lambda,
                    sigmasAbove  = (observed - lambda) / sigma
                )
            else -> DiversityVerdict.OK
        }
    }

    /**
     * Convenience overload that takes a [RoutingTable] directly.
     * Extracts the current contacts and computes the bucket index internally.
     */
    fun check(
        table:     RoutingTable,
        candidate: DhtContact
    ): DiversityVerdict {
        val bucketDepth = table.localNodeId.bucketIndex(candidate.nodeId)
        // bucketDepth < 0 means candidate == localNodeId (self-insert).
        // RoutingTable.insert already guards this before calling here, so this
        // branch is dead code in practice. Return OK rather than Rejected to avoid
        // spuriously firing onEclipseAlert if the call order ever changes.
        // A self-insert attempt is not an eclipse attack.
        if (bucketDepth < 0) return DiversityVerdict.OK
        return check(
            localNodeId     = table.localNodeId,
            candidate       = candidate,
            currentContacts = table.allContacts(),
            bucketDepth     = bucketDepth
        )
    }

    /**
     * Count how many leading bits two XOR distances share.
     * Used to determine whether two distances fall in the same prefix region.
     */
    private fun sharedPrefixBits(a: ByteArray, b: ByteArray): Int {
        var count = 0
        for (i in a.indices) {
            val xor = (a[i].toInt() and 0xFF) xor (b[i].toInt() and 0xFF)
            if (xor == 0) {
                count += 8
            } else {
                count += Integer.numberOfLeadingZeros(xor) - 24  // normalise for 8-bit byte
                break
            }
        }
        return count
    }

    // ── Tuning constants ──────────────────────────────────────────────────

    /**
     * Number of leading XOR prefix bits used to define the density analysis region.
     * Smaller = coarser regions (catches broad clustering); larger = finer regions
     * (catches tight clustering). 8 bits = 1/256 of key-space per region — fine
     * enough to catch targeted eclipse clusters without penalising natural variation.
     */
    const val PREFIX_ANALYSIS_BITS = 8

    /**
     * Soft rejection threshold in standard deviations above Poisson expected.
     * Contacts above this threshold are admitted as Probationary — they can be
     * used for disjoint path lookups but are deprioritised in primary routing.
     * 2.0 sigma ≈ 97.7th percentile of Poisson — rare enough to be suspicious.
     */
    const val SOFT_REJECT_SIGMA = 2.0

    /**
     * Hard rejection threshold. Contacts above this are refused entirely and
     * the event is escalated. 3.5 sigma ≈ 99.98th percentile — almost certainly
     * an active eclipse attack in progress.
     */
    const val HARD_REJECT_SIGMA = 3.5

    /**
     * Minimum Poisson sigma for the analysis to be meaningful. If lambda is
     * very small (sparse region), sigma is tiny and the test is noisy. Skip
     * analysis if sigma < this threshold.
     */
    const val SIGMA_MIN_MEANINGFUL = 1.0

    /**
     * Minimum routing table size before density analysis is applied.
     * With fewer contacts, the Poisson baseline is unreliable.
     */
    const val MIN_CONTACTS_FOR_ANALYSIS = 20
}

// ── Result types ──────────────────────────────────────────────────────────────

sealed class DiversityVerdict {
    /** Insertion is within expected density — proceed normally. */
    object OK : DiversityVerdict()

    /**
     * Soft density spike detected. Insert the contact but mark as probationary:
     * - Exclude from primary bucket selection in [RoutingTable.findClosest].
     * - Use only as a disjoint path fallback (S/Kademlia lookup strategy).
     * - Re-evaluate on next routing table refresh.
     *
     * @param prefixBits  The XOR prefix length used for the density region.
     * @param observed    Number of contacts in the region (including candidate).
     * @param expected    Poisson-expected contacts in this region.
     * @param sigmasAbove How many standard deviations above expected.
     */
    data class Probationary(
        val prefixBits:  Int,
        val observed:    Int,
        val expected:    Double,
        val sigmasAbove: Double
    ) : DiversityVerdict()

    /**
     * Extreme density spike — hard reject.
     * Do NOT insert this contact. Log the event and consider flagging the
     * contact's sponsor via [SponsorshipLedger] and HardenedChallengeLayer.
     */
    data class Rejected(
        val prefixBits:  Int,
        val observed:    Int,
        val expected:    Double,
        val sigmasAbove: Double
    ) : DiversityVerdict()
}

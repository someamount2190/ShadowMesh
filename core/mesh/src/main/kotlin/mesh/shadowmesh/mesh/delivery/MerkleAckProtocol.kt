package mesh.shadowmesh.mesh.delivery

import kotlinx.coroutines.CompletableDeferred
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.hexToBytes
import mesh.shadowmesh.mesh.fragment.*
import java.util.concurrent.ConcurrentHashMap

/**
 * Merkle ACK protocol — design doc §8.
 *
 * Single ACK = Merkle root only (32 bytes) — not per-fragment.
 * NACK = list of missing fragment IDs that relay nodes should retransmit.
 *
 * Protocol (recipient side):
 *   1. Fragments arrive via gossip — collected in [FragmentAccumulator]
 *   2. When threshold reached (data or RS-reconstructible set):
 *      → build Merkle tree from all received payloads
 *      → send ACK = Merkle root to sender + relay nodes
 *   3. If 30s timeout without full set:
 *      → identify missing fragment IDs
 *      → send NACK listing missing IDs
 *      → relay nodes serve the missing fragments (sender not required)
 *
 * Protocol (relay side):
 *   1. Relay holds all fragments for [FragmentEntity.RELAY_HOLD_MS] (2 hours)
 *   2. On receiving NACK: serve requested fragment IDs if still held
 *   3. Rate-limited retransmit: max [MAX_NACK_RETRANSMITS] per post per relay
 *
 * Wire formats:
 *   ACK:  [4B "ACK\0"][32B postId][32B merkleRoot]                    = 68 bytes
 *   NACK: [4B "NACK"][32B postId][2B count N][N × 2B sequenceIndex (big-endian)]   = 38 + N*2 bytes
 *
 * Thread-safety: [FragmentAccumulator] uses ConcurrentHashMap.
 * Timeout jobs are managed by the caller (WorkManager or coroutine).
 */
class MerkleAckProtocol(
    private val hkdf:      Hkdf = Hkdf.instance,
    private val transport: AckTransport
) {
    // Per-post accumulator — maps postId hex → accumulator
    private val accumulators = ConcurrentHashMap<String, FragmentAccumulator>()

    // Per-post HMAC keys for authenticated ACKs. Keys are 32-byte values derived from encTier2.
    // Recipient registers before sendAck (uses and removes). Sender registers before awaitAck
    // (used by verifyAck, removed by AckRouter.handleAck or removeAckListener).
    private val ackHmacKeys = ConcurrentHashMap<String, ByteArray>()

    /** Register a per-post HMAC key so ACKs are authenticated with a channel-bound MAC. */
    fun registerAckHmacKey(postId: String, hmacKey: ByteArray) {
        ackHmacKeys[postId] = hmacKey.copyOf()
    }

    /** Remove and zero the registered HMAC key for [postId]. */
    fun clearAckHmacKey(postId: String) {
        ackHmacKeys.remove(postId)?.fill(0)
    }

    /**
     * Synchronously register a [CompletableDeferred] in [awaitingAck] for [postId] BEFORE
     * fragment dispatch begins.
     *
     * Problem: the old approach called `scope.launch { awaitAck(...) }` which schedules
     * the coroutine but does NOT execute it immediately — there is a window between fragment
     * dispatch and the moment the scheduled coroutine runs and registers the deferred. A
     * fast ACK (e.g., from a LAN peer) arriving in that window is silently dropped.
     *
     * Fix: callers that control both dispatch and waiting (PostDispatcher) call
     * [prepareAckWaiter] synchronously before dispatching fragments. [awaitAck] then
     * reuses the pre-registered deferred via [ConcurrentHashMap.computeIfAbsent].
     *
     * @return The deferred — retained by the caller only to confirm it was created;
     *         [awaitAck] owns the lifecycle.
     */
    fun prepareAckWaiter(postId: String): CompletableDeferred<ByteArray> {
        val deferred = CompletableDeferred<ByteArray>()
        awaitingAck[postId] = deferred
        return deferred
    }

    // ── Recipient: accumulate incoming fragments ───────────────────────────

    /**
     * Record an incoming fragment for [postId].
     * Returns [AccumulatorStatus] indicating current assembly progress.
     */
    fun onFragmentReceived(fragment: FragmentEntity): AccumulatorStatus {
        val acc = accumulators.computeIfAbsent(fragment.postId) {
            FragmentAccumulator(
                postId      = it,
                totalData   = fragment.totalData,
                totalParity = fragment.totalParity
            )
        }
        return acc.addFragment(fragment)
    }

    /**
     * Send ACK for a fully assembled post.
     * Called by the receiver when [AccumulatorStatus.Complete] is returned.
     *
     * ACK wire (unauthenticated): [4B "ACK\0"][32B postIdBytes][32B merkleRoot]         = 68 B
     * ACK wire (authenticated):   [4B "ACK\0"][32B postIdBytes][32B merkleRoot][32B MAC] = 100 B
     *
     * The MAC is HMAC-SHA3-256(registeredHmacKey, postIdBytes || merkleRoot). It is only
     * appended when [registerAckHmacKey] was called for this [postId] — the key is consumed
     * (removed and zeroed) on first use so a second call sends an unauthenticated ACK.
     */
    suspend fun sendAck(postId: String, merkleRoot: ByteArray, targetNodeId: String) {
        val postIdBytes = hexToBytes(postId)
        val hmacKey = ackHmacKeys.remove(postId)
        val ack = if (hmacKey != null) {
            val mac = hkdf.hmacSha3_256(hmacKey, postIdBytes + merkleRoot)
            hmacKey.fill(0)
            ACK_MAGIC + postIdBytes + merkleRoot + mac
        } else {
            ACK_MAGIC + postIdBytes + merkleRoot
        }
        transport.sendAck(targetNodeId, ack)
    }

    /**
     * Send NACK listing missing fragment sequence indices, with noise for privacy.
     * Called after [ACK_TIMEOUT_MS] if post is not fully assembled.
     *
     * NACK wire: [4B "NACK"][32B postIdBytes][2B count N][N × 2B sequenceIndex (big-endian)]
     * Total: 38 + N*2 bytes.
     *
     * Sequence indices are 2-byte unsigned big-endian (0–65535).
     *
     * Privacy: up to [NACK_NOISE_COUNT] already-received sequence indices are added to the
     * NACK and the combined list is shuffled. This prevents adversaries from confirming
     * which specific fragments were accepted vs rejected via injection-based oracle attacks —
     * noise creates false positives that mask the exact missing-fragment set. Relay nodes
     * serving noise fragments waste minor bandwidth; the recipient discards the duplicates
     * idempotently since [PostEngine.ingestFragment] handles already-stored fragments.
     */
    suspend fun sendNack(postId: String) {
        val acc = accumulators[postId] ?: return
        val missing = acc.missingFragmentSequences()
        if (missing.isEmpty()) return

        // Add noise from the already-received set to obscure the exact missing indices.
        val missingSet = missing.toHashSet()
        val noise = (0 until acc.totalFragments)
            .filter { it !in missingSet }
            .shuffled()
            .take(NACK_NOISE_COUNT)
        val requested = (missing + noise).shuffled()

        val postIdBytes    = hexToBytes(postId)
        val countBytes     = byteArrayOf((requested.size shr 8).toByte(), requested.size.toByte())
        val requestedBytes = ByteArray(requested.size * 2)
        requested.forEachIndexed { i, seq ->
            requestedBytes[i * 2]     = (seq shr 8).toByte()
            requestedBytes[i * 2 + 1] = seq.toByte()
        }

        val nack = NACK_MAGIC + postIdBytes + countBytes + requestedBytes
        transport.broadcastNack(postId, nack)
    }

    /**
     * Parse missing sequence indices from a received NACK payload.
     * Decodes the 2-byte-per-index format produced by [sendNack].
     * Header: 4B magic + 32B postId + 2B count = 38 bytes before index data.
     *
     * [count] is capped at [MAX_NACK_SEQUENCES] to prevent a crafted NACK from causing
     * unbounded iteration or log spam. The maximum realistic NACK size for ShadowMesh's
     * RS 10/10 scheme (20 fragments) + [NACK_NOISE_COUNT] noise entries is well under 64.
     */
    fun parseMissingSequences(nackBytes: ByteArray): List<Int> {
        if (nackBytes.size < 38) return emptyList()
        val rawCount = ((nackBytes[36].toInt() and 0xFF) shl 8) or (nackBytes[37].toInt() and 0xFF)
        val count = rawCount.coerceAtMost(MAX_NACK_SEQUENCES)
        if (nackBytes.size < 38 + count * 2) return emptyList()
        return (0 until count).map { i ->
            val off = 38 + i * 2
            ((nackBytes[off].toInt() and 0xFF) shl 8) or (nackBytes[off + 1].toInt() and 0xFF)
        }
    }


    // ── ACK wait (PostDispatcher integration) ────────────────────────────

    /**
     * Per-post deferred completions — fired when a valid ACK is received.
     * Used by [awaitAck] to suspend until the ACK arrives.
     */
    private val awaitingAck = ConcurrentHashMap<String,
        CompletableDeferred<ByteArray>>()  // postId → deferred(encryptedTier2)

    /**
     * Suspend until a valid Merkle ACK is received for [postId].
     *
     * Per the async forum model, SYNCING posts wait indefinitely — propagation time
     * is unbounded. However, the coroutine IS cancellable: if the calling scope
     * (PostDispatcher's launch) is cancelled (e.g., service restart, scope teardown),
     * the deferred is completed with cancellation and removed from [awaitingAck] so it
     * does not leak. A future reconnect and re-dispatch will re-register a new deferred.
     *
     * When the ACK arrives and is verified, [onConfirmed] is called with the assembled
     * encryptedTier2 bytes (the confirmed payload from the recipient).
     *
     * @param postId        Hex postId to wait for.
     * @param merkleRoot    Expected Merkle root — used to verify the incoming ACK.
     * @param onConfirmed   Called with verified encryptedTier2 on confirmation.
     */
    suspend fun awaitAck(
        postId:      String,
        merkleRoot:  ByteArray,
        onConfirmed: suspend (verifiedRoot: ByteArray) -> Unit
    ) {
        // Reuse a pre-registered deferred (from prepareAckWaiter) when present;
        // otherwise create and register one. computeIfAbsent is atomic — it will
        // not overwrite a deferred that prepareAckWaiter already inserted.
        val deferred = awaitingAck.computeIfAbsent(postId) { CompletableDeferred() }
        try {
            val verifiedRoot = deferred.await()
            onConfirmed(verifiedRoot)
        } finally {
            // Always remove — whether completed normally, cancelled by scope teardown,
            // or cancelled by the service restarting. Prevents a stale deferred from
            // accumulating in the map and blocking future registrations for the same postId.
            awaitingAck.remove(postId, deferred)
        }
    }

    /**
     * Called by [AckRouter] when a valid ACK arrives for [postId]. Completes the deferred
     * registered by [awaitAck] with the verified Merkle root from the ACK.
     *
     * NOTE: the ACK wire format is [magic][postId][merkleRoot] (68 bytes) and carries NO
     * post payload. [verifiedRoot] is a confirmation *signal*, not the assembled content —
     * the dispatcher confirms against its locally-held encTier0. Do not treat this value as
     * ciphertext.
     *
     * @param postId        Hex postId.
     * @param verifiedRoot  The verified Merkle root carried by the ACK.
     */
    fun notifyAckReceived(postId: String, verifiedRoot: ByteArray) {
        awaitingAck[postId]?.complete(verifiedRoot)
    }

    // ── Relay: serve NACK requests ────────────────────────────────────────

    /**
     * On receiving a NACK — serve any held fragments matching the missing sequences.
     * Rate-limited to [MAX_NACK_RETRANSMITS] per post.
     */
    suspend fun onNackReceived(
        postId:           String,
        missingSequences: List<Int>,
        heldFragments:    Map<Int, FragmentEntity>  // sequence → fragment, held by relay
    ) {
        var served = 0
        for (seq in missingSequences) {
            if (served >= MAX_NACK_RETRANSMITS) break
            val fragment = heldFragments[seq] ?: continue
            transport.retransmitFragment(fragment)
            served++
        }
    }

    // ── Sender: verify ACK ────────────────────────────────────────────────

    /**
     * Verify an ACK received from the remote peer.
     *
     * @param ackBytes            Raw ACK packet (68 or 100 bytes).
     * @param expectedMerkleRoot  Merkle root computed locally at fragmentation time.
     * @param postId              Optional hex postId. When non-null and a HMAC key is
     *                            registered for this post, verifies the 32-byte HMAC
     *                            appended to 100-byte ACK packets. A 68-byte ACK is
     *                            accepted without HMAC even when a key is registered
     *                            (backward-compatible rolling upgrade path). This
     *                            leniency is removed once all nodes have upgraded.
     */
    fun verifyAck(ackBytes: ByteArray, expectedMerkleRoot: ByteArray,
                  postId: String? = null): AckVerification {
        if (ackBytes.size < 68) return AckVerification.Invalid("ACK too short: ${ackBytes.size}")
        val magic      = ackBytes.copyOfRange(0, 4)
        if (!magic.contentEquals(ACK_MAGIC)) return AckVerification.Invalid("Wrong ACK magic")
        val merkleRoot = ackBytes.copyOfRange(36, 68)
        if (!merkleRoot.contentEquals(expectedMerkleRoot))
            return AckVerification.Invalid("Merkle root mismatch")

        // HMAC verification: when a key is registered for this post, the ACK MUST be
        // authenticated (100-byte format). Accepting 68-byte "backward-compat" ACKs when
        // a key is registered creates a downgrade attack: a relay that knows the Merkle
        // root (from storing the fragments) can forge a 68-byte ACK without the HMAC,
        // falsely confirming delivery to the sender.
        if (postId != null) {
            val hmacKey = ackHmacKeys[postId]
            if (hmacKey != null) {
                if (ackBytes.size < ACK_HMAC_SIZE)
                    return AckVerification.Invalid(
                        "ACK HMAC required (${ackBytes.size}B packet, need ${ACK_HMAC_SIZE}B) " +
                        "— possible downgrade attack; 68-byte ACK not accepted when key is registered"
                    )
                val postIdBytes = ackBytes.copyOfRange(4, 36)
                val receivedMac = ackBytes.copyOfRange(68, ACK_HMAC_SIZE)
                val expectedMac = hkdf.hmacSha3_256(hmacKey, postIdBytes + merkleRoot)
                // Constant-time comparison prevents timing oracle attacks on the HMAC key.
                // ByteArray.contentEquals() short-circuits on the first differing byte,
                // leaking information about how many leading bytes match.
                if (!java.security.MessageDigest.isEqual(receivedMac, expectedMac))
                    return AckVerification.Invalid("ACK HMAC mismatch — possible relay forgery")
            }
        }
        return AckVerification.Valid
    }

    // ── Accumulator access ────────────────────────────────────────────────

    fun getAccumulator(postId: String): FragmentAccumulator? = accumulators[postId]

    fun clearAccumulator(postId: String) { accumulators.remove(postId) }

    // ── Wire helpers ──────────────────────────────────────────────────────

    companion object {
        val ACK_MAGIC  = byteArrayOf('A'.code.toByte(), 'C'.code.toByte(), 'K'.code.toByte(), 0)
        val NACK_MAGIC = byteArrayOf('N'.code.toByte(), 'A'.code.toByte(), 'C'.code.toByte(), 'K'.code.toByte())
        const val ACK_TIMEOUT_MS       = 30_000L
        const val MAX_NACK_RETRANSMITS = 3

        /** Size of authenticated ACK packet (unauthenticated = 68, authenticated = 100). */
        const val ACK_HMAC_SIZE = 100

        /**
         * Number of already-received fragment indices added as noise to each NACK.
         * Prevents adversaries from pinpointing which fragments were accepted via
         * injection-based oracle attacks. Relay nodes serve the noise fragments as
         * duplicates; [PostEngine.ingestFragment] discards them idempotently.
         */
        const val NACK_NOISE_COUNT = 2

        /**
         * Maximum number of sequence indices accepted from a NACK packet.
         * ShadowMesh's largest RS scheme (10 data + 10 parity) has 20 fragments.
         * Adding [NACK_NOISE_COUNT] noise entries plus a generous margin gives 64.
         * Caps iteration and prevents log spam from crafted oversized NACKs.
         */
        const val MAX_NACK_SEQUENCES = 64
    }
}

// ── Fragment accumulator ──────────────────────────────────────────────────────

/**
 * Tracks received fragments for a single post during assembly.
 * Thread-safe via ConcurrentHashMap for fragment storage.
 */
class FragmentAccumulator(
    val postId:      String,
    val totalData:   Int,
    val totalParity: Int
) {
    private val received = ConcurrentHashMap<Int, FragmentEntity>()  // seq → fragment

    val totalFragments: Int get() = totalData + totalParity
    val receivedCount:  Int get() = received.size

    /** Fraction of data fragments received (0.0–1.0). */
    val dataFraction: Float get() {
        val dataReceived = received.count { it.key < totalData }
        return if (totalData == 0) 1f else dataReceived.toFloat() / totalData
    }

    fun addFragment(fragment: FragmentEntity): AccumulatorStatus {
        // Reject out-of-range indices before storing. An attacker can send fragments with
        // sequenceIndex = Int.MAX_VALUE; without this guard they inflate received.size and
        // trigger Complete status (count >= totalData) without providing real data shards,
        // causing reassembly to fail silently while the accumulator claims success.
        if (fragment.sequenceIndex < 0 || fragment.sequenceIndex >= totalFragments) return currentStatus()
        received[fragment.sequenceIndex] = fragment
        return currentStatus()
    }

    fun allReceived(): List<FragmentEntity> = received.values.toList()

    fun missingFragmentSequences(): List<Int> =
        (0 until totalFragments).filter { !received.containsKey(it) }

    fun currentStatus(): AccumulatorStatus {
        val count = received.size
        return when {
            // Complete means "RS-reconstructible": we have received at least [totalData]
            // fragments from the combined data+parity set. Reed-Solomon can reconstruct
            // the original content from any [totalData] shards regardless of whether they
            // are data or parity shards. This does NOT mean all data shards arrived —
            // some may have been recovered via parity. This is the correct RS threshold.
            //
            // Consequence: the Merkle root in attemptConfirmation must be built from the
            // DATA fragments only (sequenceIndex < totalData), not from the raw accumulator
            // which may include parity fragments — see attemptConfirmation in FragmentIngestor.
            count >= totalData -> AccumulatorStatus.Complete(received.values.toList())
            dataFraction >= PROGRESSIVE_TIER1_THRESHOLD ->
                AccumulatorStatus.PartialTier1(dataFraction, received.values.toList())
            count > 0 -> AccumulatorStatus.Partial(dataFraction, received.values.toList())
            else       -> AccumulatorStatus.Empty
        }
    }

    companion object {
        const val PROGRESSIVE_TIER1_THRESHOLD = 0.1f  // 10% for Tier 1 unlock
    }
}

// ── Status types ──────────────────────────────────────────────────────────────

sealed class AccumulatorStatus {
    object Empty : AccumulatorStatus()
    data class Partial(val fraction: Float, val fragments: List<FragmentEntity>) : AccumulatorStatus()
    /** ≥10% — Tier 1 (first sentence) can be displayed. */
    data class PartialTier1(val fraction: Float, val fragments: List<FragmentEntity>) : AccumulatorStatus()
    /** ≥ dataShards received — full reconstruction possible. */
    data class Complete(val fragments: List<FragmentEntity>) : AccumulatorStatus()
}

sealed class AckVerification {
    object Valid : AckVerification()
    data class Invalid(val reason: String) : AckVerification()
}

// ── Transport interface ───────────────────────────────────────────────────────

interface AckTransport {
    suspend fun sendAck(targetNodeId: String, ackBytes: ByteArray)
    suspend fun broadcastNack(postId: String, nackBytes: ByteArray)
    suspend fun retransmitFragment(fragment: FragmentEntity)
}

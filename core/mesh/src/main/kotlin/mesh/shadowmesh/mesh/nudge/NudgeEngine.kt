package mesh.shadowmesh.mesh.nudge

import mesh.shadowmesh.mesh.dht.NodeId
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.crypto.intTo4Bytes
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag

/**
 * Nudge system — design doc §9.
 *
 * A nudge is a 12-byte packet that tells a peer "something new arrived
 * in channel X". No content, no metadata beyond the channel hash.
 * No FCM. No Google. Routes through mesh peers only.
 *
 * Wire format (12 bytes total):
 *   [8B channelHash]  — first 8 bytes of SHA3-256(channelId)
 *   [4B timestamp]    — Unix epoch seconds, rounded to nearest minute
 *                       (minute-rounding prevents precise timing correlation)
 *
 * The 4-byte timestamp is deliberately imprecise. An observer sees that
 * channel X had activity in a given minute — not the exact second.
 * Combined with SNDP, this makes correlation significantly harder.
 *
 * BLE fallback:
 *   For devices within ~10m, a BLE nudge is sent as an alternative
 *   to the UDP nudge. Same 12-byte payload. BLE GATT characteristic write.
 *   Rate-limited to prevent BLE scan storms.
 *
 * Deduplication:
 *   Nudges are deduplicated per channel per minute — only one nudge
 *   per (channelHash, minute) forwarded. Multiple posts in the same
 *   minute produce one nudge.
 *
 * Thread-safety: ConcurrentHashMap for seen nudges and rate limiting.
 */
class NudgeEngine(
    private val scope:     CoroutineScope,
    private val transport: NudgeTransport,
    /**
     * Optional HMAC authenticator for received nudge packets.
     *
     * Unauthenticated nudges let any peer claim activity in any channel, triggering
     * spurious WorkManager syncs. Providing this callback closes the gap:
     *
     * Wire format (authenticated, 28 bytes):
     *   [8B channelHash][4B timestamp][16B HMAC-SHA3-256(nudgeKey, channelHash || tsBytes)]
     *
     * When non-null, [onNudgeReceived] rejects packets that:
     *   - Are 12 bytes (unauthenticated legacy format)
     *   - Are 28 bytes but fail HMAC verification
     * When null, the 12-byte unauthenticated format is accepted (backward compat during rollout).
     *
     * Wire in production: supply a lambda that computes
     *   HMAC-SHA3-256(channelDerivedNudgeKey, packet.copyOfRange(0, 12)) and checks
     *   constant-time equality against packet.copyOfRange(12, 28).
     */
    private val verifyHmac: ((packet: ByteArray) -> Boolean)? = null
) {
    // Dedup: (channelHash8hex + minuteTs) → last forward time
    private val sentNudges = ConcurrentHashMap<String, Long>()

    // BLE send rate limiter: nodeId → last BLE nudge time
    private val bleLastSent = ConcurrentHashMap<String, Long>()

    // Received nudge dedup: dedupeKey → last received time.
    // Prevents replay flooding: a peer sending the same nudge repeatedly triggers only one sync.
    private val receivedNudges = ConcurrentHashMap<String, Long>()

    // ── Send ──────────────────────────────────────────────────────────────

    /**
     * Send a nudge for [channelId] to all known peers.
     * Deduplicated per channel per minute — safe to call on every post.
     *
     * @param channelId    Raw 32-byte channel ID
     * @param peerIds      Peers to nudge (subset of routing table)
     */
    suspend fun sendNudge(channelId: ByteArray, peerIds: List<NodeId>) {
        val packet = buildNudgePacket(channelId)
        val dedupeKey = dedupeKey(packet)

        // Deduplicate: one nudge per channel per minute.
        // Use compute() for an atomic read-check-update so:
        //   (a) the first call within a window is gated correctly, and
        //   (b) once the window expires the timestamp is refreshed — putIfAbsent was wrong here
        //       because it never updates an existing entry, causing the dedup to become
        //       ineffective after the first window: every subsequent call saw stale last < now
        //       and bypassed the guard without updating the map, so all future calls also bypass.
        val now = System.currentTimeMillis()
        // Enforce size cap before computing a new entry.
        if (!sentNudges.containsKey(dedupeKey) && sentNudges.size >= MAX_DEDUP_ENTRIES) {
            Diag.fallback("nudge", "sent-dedup-full",
                "sentNudges at capacity ($MAX_DEDUP_ENTRIES) — nudge dropped")
            return
        }
        var shouldSend = false
        sentNudges.compute(dedupeKey) { _, last ->
            if (last == null || now - last >= DEDUP_WINDOW_MS) {
                shouldSend = true
                now   // refresh timestamp
            } else {
                last  // within window — keep, do not send
            }
        }
        if (!shouldSend) return

        peerIds.forEach { peerId ->
            scope.launch {
                try { transport.sendUdpNudge(peerId, packet) }
                catch (e: Exception) { Diag.swallowed("nudge", "udp-send", e, "peerId" to peerId.toHex()) }
            }
        }
    }

    /**
     * Send a BLE nudge to a proximate device (< 10m range).
     * Rate-limited to one BLE nudge per peer per [BLE_RATE_LIMIT_MS].
     */
    suspend fun sendBleNudge(channelId: ByteArray, peerId: NodeId) {
        val peerKey = peerId.toHex()
        val now = System.currentTimeMillis()
        // Atomic check-and-update: compute() holds the bucket lock so two concurrent callers
        // for the same peerId cannot both pass the rate-limit check simultaneously.
        var shouldSend = false
        bleLastSent.compute(peerKey) { _, last ->
            if (last == null || now - last >= BLE_RATE_LIMIT_MS) {
                shouldSend = true; now
            } else {
                last
            }
        }
        if (!shouldSend) return
        val packet = buildNudgePacket(channelId)
        try { transport.sendBleNudge(peerId, packet) }
        catch (e: Exception) { Diag.swallowed("nudge", "ble-send", e, "peerId" to peerId.toHex()) }
    }

    // ── Receive ───────────────────────────────────────────────────────────

    /**
     * Process an incoming nudge. Triggers WorkManager sync for the channel.
     * Returns the channel hash bytes if the nudge is valid, null otherwise.
     *
     * Authentication: when [verifyHmac] is provided, authenticated (28-byte) packets are
     * required. Unauthenticated 12-byte packets are rejected when a verifier is set.
     *
     * Deduplication: replayed nudges (same channelHash + minute) are silently dropped
     * within [DEDUP_WINDOW_MS]. This prevents a flooding attacker from triggering
     * unbounded WorkManager sync jobs by replaying the same nudge packet.
     */
    fun onNudgeReceived(packet: ByteArray): ByteArray? {
        // Accept 12-byte unauthenticated or 28-byte authenticated packets.
        val authenticated = packet.size == NUDGE_AUTHENTICATED_SIZE
        val unauthenticated = packet.size == NUDGE_PACKET_SIZE

        if (!authenticated && !unauthenticated) return null

        // Reject unauthenticated packets when an HMAC verifier is configured.
        if (unauthenticated && verifyHmac != null) {
            Diag.fallback("nudge", "unauthenticated-rejected",
                "Rejecting 12-byte unauthenticated nudge — HMAC verifier is configured")
            return null
        }

        // Verify HMAC for authenticated packets.
        if (authenticated) {
            if (verifyHmac != null && !verifyHmac.invoke(packet)) return null
        }

        val channelHash8 = packet.copyOfRange(0, CHANNEL_HASH_BYTES)
        val timestamp    = extractTimestampSecs(packet)

        // Validate timestamp is within reasonable window (±5 minutes)
        val nowSecs = System.currentTimeMillis() / 1000
        if (kotlin.math.abs(nowSecs - timestamp) > TIMESTAMP_TOLERANCE_SECS) return null

        // Dedup: reject replayed nudges for the same (channel, minute) within the window.
        // Prevents an attacker from flooding WorkManager sync jobs by replaying one nudge.
        // Size cap: without it, an attacker flooding unique channel hashes between prune
        // cycles (every 5 min) can grow receivedNudges without bound.
        val key  = dedupeKey(packet)
        val now  = System.currentTimeMillis()
        if (!receivedNudges.containsKey(key) && receivedNudges.size >= MAX_DEDUP_ENTRIES) {
            Diag.fallback("nudge", "received-dedup-full",
                "receivedNudges at capacity ($MAX_DEDUP_ENTRIES) — nudge dropped")
            return null
        }
        var shouldProcess = false
        receivedNudges.compute(key) { _, last ->
            if (last == null || now - last >= DEDUP_WINDOW_MS) {
                shouldProcess = true
                now
            } else {
                last
            }
        }
        if (!shouldProcess) return null

        return channelHash8
    }

    // ── Packet construction ───────────────────────────────────────────────

    /**
     * Build a 12-byte nudge packet.
     *   [0..7]  = first 8 bytes of SHA3-256(channelId)
     *   [8..11] = Unix epoch seconds rounded to nearest minute (big-endian)
     */
    fun buildNudgePacket(channelId: ByteArray): ByteArray {
        // Channel hash: first 8 bytes of SHA3-256(channelId)
        val hash8 = mesh.shadowmesh.crypto.Hkdf.instance
            .sha3_256(channelId)
            .copyOfRange(0, CHANNEL_HASH_BYTES)

        // Timestamp: seconds rounded to NEAREST minute (not truncated).
        // Design doc spec: "Unix epoch seconds, rounded to nearest minute".
        // At second 45 of a minute, round-nearest gives the current minute;
        // round-down (floor) would give the previous minute — incorrect per spec.
        val nowSecs    = System.currentTimeMillis() / 1000
        val roundedMin = ((nowSecs + 30) / 60) * 60  // +30 before divide = round-nearest
        val tsBytes    = intTo4Bytes(roundedMin.toInt())

        return hash8 + tsBytes
    }

    // ── Maintenance ───────────────────────────────────────────────────────

    fun pruneOldNudges() {
        val cutoff = System.currentTimeMillis() - DEDUP_WINDOW_MS * 2
        sentNudges.entries.removeIf { it.value < cutoff }
        bleLastSent.entries.removeIf { it.value < cutoff }
        receivedNudges.entries.removeIf { it.value < cutoff }
    }

    fun startPruneLoop() {
        scope.launch {
            while (isActive) {
                delay(5 * 60_000L)
                pruneOldNudges()
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun dedupeKey(packet: ByteArray): String {
        val hash8hex = packet.copyOfRange(0, CHANNEL_HASH_BYTES).toHex()
        val minuteTs = extractTimestampSecs(packet) / 60
        return "$hash8hex:$minuteTs"
    }

    private fun extractTimestampSecs(packet: ByteArray): Long {
        val b = packet
        return ((b[8].toLong() and 0xFF) shl 24) or
               ((b[9].toLong() and 0xFF) shl 16) or
               ((b[10].toLong() and 0xFF) shl 8) or
               (b[11].toLong() and 0xFF)
    }


    companion object {
        const val NUDGE_PACKET_SIZE        = 12
        /** Authenticated wire format: [8B channelHash][4B timestamp][16B HMAC] = 28 bytes. */
        const val NUDGE_AUTHENTICATED_SIZE = 28
        const val NUDGE_HMAC_BYTES         = 16
        const val CHANNEL_HASH_BYTES       = 8
        const val TIMESTAMP_BYTES          = 4
        const val DEDUP_WINDOW_MS          = 60_000L        // one minute
        const val BLE_RATE_LIMIT_MS        = 30_000L        // 30 seconds
        const val TIMESTAMP_TOLERANCE_SECS = 300L           // ±5 minutes

        /**
         * Maximum entries in [sentNudges] and [receivedNudges].
         * Each key is a ~20-char string (8-byte hex + ":" + minuteTs). At 10 000 entries
         * ≈ 800 KB — bounded. Without this cap, an attacker flooding unique channel hashes
         * between 5-minute prune cycles grows the maps without bound.
         */
        const val MAX_DEDUP_ENTRIES = 10_000
    }
}

// ── Transport interface ───────────────────────────────────────────────────────

interface NudgeTransport {
    suspend fun sendUdpNudge(peerId: NodeId, packet: ByteArray)
    suspend fun sendBleNudge(peerId: NodeId, packet: ByteArray)
}

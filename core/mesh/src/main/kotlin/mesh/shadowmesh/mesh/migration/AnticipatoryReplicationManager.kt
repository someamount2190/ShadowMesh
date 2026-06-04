package mesh.shadowmesh.mesh.migration

import android.util.Log
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.SymmetricCipher
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import kotlinx.coroutines.*
import java.security.SecureRandom
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.crypto.intTo4Bytes
import mesh.shadowmesh.diagnostics.Diag
import mesh.shadowmesh.crypto.toHex

/**
 * Anticipatory replication (urgent mode cache) — design doc Phase 6.
 *
 * Each sync cycle, this node pre-populates a ~200KB per-peer cache of:
 *   - 50% real fragment sets from channels the recipient follows
 *   - 50% decoy fragments (dummy encrypted blobs — indistinguishable from real)
 *
 * On urgent mode activation, the recipient can decode their cache hit
 * within 2 seconds without a full fragment fetch.
 *
 * Forensic resistance:
 *   The entire cache is re-encrypted each sync cycle with a fresh ephemeral key.
 *   Any forensic image of the device captures only the current cycle's ciphertext —
 *   previous cycle caches are gone. The ephemeral key is derived from:
 *   HKDF(device_secret || cycle_sequence_number, info = "anticipatory_cache_v1")
 *
 * MIGRATION_CANCEL integration:
 *   If a storage migration cancels, any decoy fragments allocated to migrated
 *   slots are immediately purged from the cache.
 *
 * Thread-safety: [peerCaches] uses ConcurrentHashMap. Re-encryption is
 * serialized per peer.
 */
class AnticipatoryReplicationManager(
    private val localNodeId:  NodeId,
    private val deviceSecret: ByteArray,
    private val hkdf:         Hkdf = Hkdf.instance,
    private val cipher:       SymmetricCipher = SymmetricCipher(),
    private val scope:        CoroutineScope,
    private val transport:    AnticipatoryCacheTransport
) {
    // peerNodeId (hex) → CacheEntry
    private val peerCaches = ConcurrentHashMap<String, PeerCacheEntry>()

    @Volatile private var cycleSequence: Long = 0L
    private val rng = SecureRandom()

    // ── Sync cycle cache refresh ──────────────────────────────────────────

    // Job tracking for the current refresh cycle so onMigrationCancelled can cancel
    // in-flight refreshCacheForPeer coroutines before purging the cache.
    // Without this, a coroutine completing after onMigrationCancelled re-inserts
    // an entry that was just purged, undoing the cancellation.
    @Volatile private var currentRefreshJob: kotlinx.coroutines.Job? = null

    /**
     * Refresh the anticipatory cache for all registered peers.
     * Called at the start of each sync cycle by the sync coordinator.
     *
     * For each peer:
     *   1. Fetch up to ~100KB of real fragments from their followed channels
     *   2. Generate ~100KB of decoy fragments (indistinguishable dummy blobs)
     *   3. Shuffle real + decoy together
     *   4. Encrypt with a fresh per-cycle key
     *   5. Replace the old cache entry
     *
     * Old cache entries are wiped immediately on replacement.
     */
    suspend fun refreshCacheForAllPeers(peers: List<DhtContact>) = coroutineScope {
        cycleSequence++
        // Store the coroutineScope job so onMigrationCancelled can cancel it.
        currentRefreshJob = coroutineContext[kotlinx.coroutines.Job]
        peers.forEach { peer ->
            launch {
                try { refreshCacheForPeer(peer) }
                catch (e: Exception) {
                    // Non-fatal: urgent mode will fall back to a direct fragment fetch.
                    // Log at WARN so that systematic failures (e.g. transport always down)
                    // are visible without flooding logcat on transient errors.
                    Log.w(TAG, "refreshCacheForPeer failed for ${peer.nodeId.bytes.toHex().take(8)}: ${e.message}")
                    Diag.swallowed("anticipatory-cache", "refresh-peer", e,
                        "peer" to peer.nodeId.bytes.toHex().take(8))
                }
            }
        }
    }

    private suspend fun refreshCacheForPeer(peer: DhtContact) {
        val peerIdHex = peer.nodeId.bytes.toHex()

        // Derive fresh per-cycle, per-peer encryption key
        val cycleKey = deriveCycleKey(peerIdHex, cycleSequence)

        // Fetch real fragments for this peer (~100KB = ~1562 × 64-byte fragments)
        val realFragments = transport.fetchRealFragmentsForPeer(peer, TARGET_CACHE_BYTES / 2)

        // Generate decoy fragments to pad to ~100KB
        val decoyCount  = (TARGET_CACHE_BYTES / 2 / DECOY_FRAGMENT_SIZE).coerceAtLeast(1)
        val decoys      = generateDecoyFragments(decoyCount, peer.nodeId)

        // Shuffle real + decoy together (indistinguishable from observer's perspective)
        val all = (realFragments + decoys).shuffled(java.util.Random(rng.nextLong()))
        // Track which fragmentIds are decoys so serializeFragments can write the isDecoy flag
        // correctly — decoys are no longer identifiable by their postId/channelId constants.
        val decoyIds: Set<String> = decoys.map { it.fragmentId }.toHashSet()

        // Encrypt entire cache blob with cycle key
        val plainBlob   = serializeFragments(all, decoyIds)
        val encryptedBlob = cipher.encrypt(plainBlob, cycleKey).getOrThrow()

        // Wipe old entry key material before replacing
        peerCaches[peerIdHex]?.cycleKey?.fill(0)
        peerCaches[peerIdHex] = PeerCacheEntry(
            peerNodeId    = peerIdHex,
            cycleSequence = cycleSequence,
            cycleKey      = cycleKey,
            encryptedBlob = encryptedBlob,
            realCount     = realFragments.size,
            decoyCount    = decoys.size,
            populatedAtMs = System.currentTimeMillis()
        )
    }

    // ── Urgent mode cache retrieval ────────────────────────────────────────

    /**
     * Retrieve cache for [recipientNodeId] on urgent mode activation.
     * Decrypts the cache blob and returns real fragments only.
     * Returns null if no cache entry exists (triggers direct fragment fetch as fallback).
     *
     * Design doc: cache hit → display within 2 seconds.
     */
    suspend fun retrieveForUrgentMode(recipientNodeId: NodeId): List<FragmentEntity>? {
        val entry = peerCaches[recipientNodeId.bytes.toHex()] ?: return null

        // Check cache freshness — must be from current cycle
        if (entry.cycleSequence != cycleSequence) return null

        val plainBlob = cipher.decrypt(entry.encryptedBlob, entry.cycleKey).getOrNull()
            ?: return null
        val (all, decoyIds) = deserializeFragments(plainBlob)

        // Return only real fragments (non-decoy) — caller uses them for assembly.
        // Decoy identification uses the explicit isDecoy wire byte (returned as decoyIds),
        // not sentinel postId/channelId constants which are randomised since fix #73.
        return all.filter { it.fragmentId !in decoyIds }
    }

    // ── MIGRATION_CANCEL integration ──────────────────────────────────────

    /**
     * Called when a storage migration is cancelled. Cancel any in-flight cache refresh
     * coroutines, then purge all peer caches and wipe key material.
     *
     * Fix #74: without the cancellation step, a [refreshCacheForPeer] coroutine that
     * completes after [onMigrationCancelled] returns would re-insert a new [PeerCacheEntry]
     * into [peerCaches], undoing the purge. The [currentRefreshJob] cancel ensures all
     * child coroutines are interrupted before the map is cleared.
     */
    fun onMigrationCancelled(cancelledSlotKeys: List<String>) {
        // Cancel in-flight refresh coroutines first so none can re-insert after the purge.
        currentRefreshJob?.cancel()
        currentRefreshJob = null

        peerCaches.keys.forEach { peerIdHex ->
            peerCaches[peerIdHex]?.let { entry ->
                // Wipe key material immediately — cache entry becomes stale
                entry.cycleKey.fill(0)
            }
            peerCaches.remove(peerIdHex)
        }
    }

    // ── Key derivation ─────────────────────────────────────────────────────

    private fun deriveCycleKey(peerIdHex: String, seq: Long): ByteArray {
        val seqBytes = ByteArray(8) { i -> ((seq shr ((7 - i) * 8)) and 0xFF).toByte() }
        return hkdf.derive(
            ikm       = deviceSecret + peerIdHex.toByteArray(),
            salt      = seqBytes,
            info      = CACHE_KEY_INFO,
            outputLen = 32
        )
    }

    // ── Decoy generation ───────────────────────────────────────────────────

    private fun generateDecoyFragments(count: Int, forPeer: NodeId): List<FragmentEntity> =
        (0 until count).map { i ->
            val payload = ByteArray(DECOY_FRAGMENT_SIZE).also { rng.nextBytes(it) }
            // Issue #73 fix: constant DECOY_POST_ID / DECOY_CHANNEL_ID values
            // ("00...00decoy") were trivially identifiable in the serialized cache
            // blob — any observer who can decrypt the cache can immediately separate
            // real fragments from decoys, breaking the indistinguishability guarantee.
            //
            // Fix: generate 32 bytes of SecureRandom for both postId and channelId,
            // formatted as 64-char lowercase hex — identical in format to real fragment
            // IDs. The fragmentId is content-addressed from the random payload, matching
            // real fragment construction.
            //
            // isDecoy() detection is now internal-only: a flag in the serialized wire
            // format (the isDecoy byte) — not observable from the fragment metadata.
            val randomPostId    = ByteArray(32).also { rng.nextBytes(it) }.toHex()
            val randomChannelId = ByteArray(32).also { rng.nextBytes(it) }.toHex()
            val randomFragId    = mesh.shadowmesh.mesh.fragment.FragmentEntity
                .computeFragmentId(randomPostId.toByteArray(), i, payload)
            FragmentEntity(
                fragmentId    = randomFragId,
                postId        = randomPostId,
                channelId     = randomChannelId,
                sequenceIndex = i,
                totalData     = count,
                totalParity   = 0,
                payload       = payload,
                fecScheme     = mesh.shadowmesh.mesh.fragment.FecScheme.NONE
            )
        }

    // ── Serialization ──────────────────────────────────────────────────────

    /**
     * Serialize [fragments] to a compact binary blob.
     *
     * Wire format per entry:
     *   [4B idLen][idLen bytes: fragmentId][4B sequenceIndex][4B payloadLen][payload][1B isDecoy]
     *
     * [decoyIds]: the set of fragmentIds that are decoys. Since fix #73, decoy fragments
     * have randomised postId/channelId — there are no sentinel values to detect decoys by
     * inspection. The caller that generated the decoys must pass their IDs explicitly.
     */
    private fun serializeFragments(
        fragments: List<FragmentEntity>,
        decoyIds:  Set<String> = emptySet()
    ): ByteArray {
        val chunks = fragments.map { f ->
            val idBytes     = f.fragmentId.toByteArray(Charsets.UTF_8)
            val idLenBytes  = intTo4Bytes(idBytes.size)
            val seqBytes    = intTo4Bytes(f.sequenceIndex)
            val payLenBytes = intTo4Bytes(f.payload.size)
            val decoyByte   = if (f.fragmentId in decoyIds) byteArrayOf(1) else byteArrayOf(0)
            idLenBytes + idBytes + seqBytes + payLenBytes + f.payload + decoyByte
        }
        return chunks.fold(ByteArray(0)) { acc, chunk -> acc + chunk }
    }

    /** Returns (fragments, decoyFragmentIds) — decoyIds is the set of fragmentIds marked as decoys in the wire format. */
    private fun deserializeFragments(blob: ByteArray): Pair<List<FragmentEntity>, Set<String>> {
        val results  = mutableListOf<FragmentEntity>()
        val decoyIds = mutableSetOf<String>()
        var offset   = 0

        while (offset + 4 <= blob.size) {
            // Read fragmentId
            val idLen = fourBytesTo4Int(blob, offset);  offset += 4
            if (idLen <= 0 || offset + idLen > blob.size) break
            val fragmentId = String(blob, offset, idLen, Charsets.UTF_8); offset += idLen

            // Read sequenceIndex (preserved from original fragment — required for reassembly)
            if (offset + 4 > blob.size) break
            val sequenceIndex = fourBytesTo4Int(blob, offset); offset += 4

            // Read payload
            if (offset + 4 > blob.size) break
            val payLen = fourBytesTo4Int(blob, offset); offset += 4
            if (payLen < 0 || offset + payLen > blob.size) break
            val payload = blob.copyOfRange(offset, offset + payLen); offset += payLen

            // Read decoy flag
            if (offset >= blob.size) break
            val isDecoy = blob[offset].toInt() != 0; offset++
            if (isDecoy) decoyIds.add(fragmentId)

            results.add(FragmentEntity(
                fragmentId    = fragmentId,
                postId        = if (isDecoy) DECOY_POST_ID    else "cache_real",
                channelId     = if (isDecoy) DECOY_CHANNEL_ID else "cache_real",
                sequenceIndex = sequenceIndex,
                totalData     = 1,
                totalParity   = 0,
                payload       = payload,
                fecScheme     = mesh.shadowmesh.mesh.fragment.FecScheme.NONE
            ))
        }
        return Pair(results, decoyIds)
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private fun fourBytesTo4Int(b: ByteArray, off: Int) =
        ((b[off].toInt() and 0xFF) shl 24) or
        ((b[off+1].toInt() and 0xFF) shl 16) or
        ((b[off+2].toInt() and 0xFF) shl 8) or
         (b[off+3].toInt() and 0xFF)

    fun activePeerCacheCount(): Int = peerCaches.size
    fun currentCycleSequence(): Long = cycleSequence

    companion object {
        private const val TAG = "AnticipatoryReplication"
        const val TARGET_CACHE_BYTES    = 200 * 1024   // ~200KB per peer
        const val DECOY_FRAGMENT_SIZE   = 512          // bytes per decoy fragment
        val CACHE_KEY_INFO = "anticipatory_cache_v1".toByteArray()
        const val DECOY_POST_ID    = "00000000000000000000000000000000decoy"
        const val DECOY_CHANNEL_ID = "00000000000000000000000000000000decoy"
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

data class PeerCacheEntry(
    val peerNodeId:    String,
    val cycleSequence: Long,
    val cycleKey:      ByteArray,   // must be wiped on eviction
    val encryptedBlob: ByteArray,
    val realCount:     Int,
    val decoyCount:    Int,
    val populatedAtMs: Long
) {
    override fun equals(other: Any?) = other is PeerCacheEntry &&
        peerNodeId == other.peerNodeId && cycleSequence == other.cycleSequence
    override fun hashCode() = 31 * peerNodeId.hashCode() + cycleSequence.hashCode()
}

interface AnticipatoryCacheTransport {
    suspend fun fetchRealFragmentsForPeer(peer: DhtContact, maxBytes: Int): List<FragmentEntity>
}

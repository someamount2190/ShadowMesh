package mesh.shadowmesh.forum.backend

import android.util.Log
import mesh.shadowmesh.diagnostics.Diag
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.ReceiveChannel
import mesh.shadowmesh.forum.ChannelManager
import mesh.shadowmesh.forum.PostEngine
import mesh.shadowmesh.forum.RatchetGapEvent
import mesh.shadowmesh.mesh.delivery.FragmentFetcher
import mesh.shadowmesh.mesh.delivery.StoreAndForwardManager
import mesh.shadowmesh.mesh.gossip.GossipEngine
import mesh.shadowmesh.mesh.mode.NetworkModeStateMachine
import mesh.shadowmesh.mesh.nudge.NudgeEngine
import mesh.shadowmesh.mesh.privacy.SndpEngine
import mesh.shadowmesh.crypto.hexToBytes
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.storage.PostState
import java.util.concurrent.ConcurrentHashMap

/**
 * Channel sync coordinator — reconnect and periodic sync.
 *
 * Owns two sync paths:
 *
 * ## 1. Reconnect sync ([onReconnect])
 *
 * Called by [ShadowMeshForegroundService.onMeshServiceCreated] and by
 * [ChannelSyncCoordinator.syncCycle] when a topology change is detected
 * (e.g., peer count crosses a mode threshold).
 *
 * Steps:
 *   a. Drain the offline outbound queue — posts created while in SURVIVAL mode
 *      are dispatched now that peers are reachable.
 *   b. Fetch missed inbound fragments — for each active channel, ask
 *      [FragmentFetcher] for fragments since the channel's last activity timestamp.
 *      Feed each returned fragment into [FragmentIngestor].
 *   c. Send nudges — tell peers this device is back online and wants to exchange.
 *
 * ## 2. Periodic sync ([syncCycle])
 *
 * Called by [MeshSyncWorker] every 15 minutes (WorkManager minimum interval).
 *
 * Steps:
 *   a. [GossipEngine.syncCycle] — gossip housekeeping (Bloom filter reset, peer health).
 *   b. For channels with SYNCING posts (in-flight, not yet confirmed): re-fetch missed
 *      fragments to catch up on partial assembly that may have stalled.
 *   c. [DistributedRetransmissionManager.evictExpired] — prune held fragments past 2h.
 *
 * ## Fragment-to-ViewModel path
 *
 * All fetched fragments are fed through [FragmentIngestor.onFragmentReceived] —
 * the same path as live gossip fragments. This ensures the trust gate, Bloom filter,
 * and ViewModel callbacks all fire consistently regardless of whether the fragment
 * arrived live or via fetch.
 *
 * Thread-safety: [onReconnect] and [syncCycle] are suspend functions. They may be
 * called concurrently from WorkManager and from the foreground service. Both are
 * idempotent — double-calling is safe because [StoreAndForwardManager.drainOnReconnect]
 * removes entries atomically and [FragmentFetcher] returns empty for already-seen fragments.
 */
class ChannelSyncCoordinator(
    private val channelManager:       ChannelManager,
    private val fragmentFetcher:      FragmentFetcher,
    private val fragmentIngestor:     FragmentIngestor,
    private val storeAndForwardMgr:   StoreAndForwardManager,
    private val nudgeEngine:          NudgeEngine,
    private val gossipEngine:         GossipEngine,
    private val retransmissionMgr:    mesh.shadowmesh.mesh.delivery.DistributedRetransmissionManager,
    private val postEngine:           PostEngine,
    private val scope:                CoroutineScope,
    /** When non-null, cover-traffic bursts are fired during each sync cycle. */
    private val sndpEngine:           SndpEngine? = null,
    /** Required when [sndpEngine] is non-null — supplies the current network mode for SNDP rate selection. */
    private val networkModeSM:        NetworkModeStateMachine? = null
) {
    // Per-channel retry count for SYNCING posts. Tracks how many consecutive syncCycle passes
    // have seen that channel still in SYNCING state without successfully fetching new fragments.
    // After MAX_SYNC_RETRIES the SYNCING posts are transitioned to FAILED to free resources.
    // Reset to 0 when a channel transitions out of SYNCING (confirmed, failed, or reconnect clears it).
    // In-memory only — resets on process restart (acceptable; TTL sweep provides final cleanup).
    private val syncRetries = ConcurrentHashMap<String, Int>()

    // Per-channel exponential backoff: maps channelId → earliest next eligible sync time (ms).
    // After each actual fetch attempt, the next retry window doubles up to MAX_BACKOFF_INTERVAL_MS:
    //   Attempt 1: 15 min, attempt 2: 30 min, attempt 3: 60 min, attempt 4+: 120 min.
    // This prevents hammering DHT peers every 15 min when fragments are persistently unavailable.
    // Reset alongside syncRetries on reconnect so a healed link gets immediate full retry window.
    private val syncNextEligibleMs = ConcurrentHashMap<String, Long>()
    /**
     * Run on mesh connectivity restore — drain queued outbound posts, fetch missed
     * inbound fragments, and nudge peers.
     *
     * Called from [ShadowMeshForegroundService.onMeshServiceCreated] after engines start.
     * Also called from [syncCycle] when the network mode improves (SURVIVAL → higher).
     */
    suspend fun onReconnect() = withContext(Dispatchers.IO) {
        // Reconnect means the mesh link is back — reset per-channel retry counts AND backoff
        // windows so posts that were SYNCING during a temporary outage get an immediate full
        // MAX_SYNC_RETRIES window now that peers are reachable again.
        syncRetries.clear()
        syncNextEligibleMs.clear()

        // a. Drain offline outbound queue
        val dispatched = storeAndForwardMgr.drainOnReconnect()
        if (dispatched > 0) {
            Log.d(TAG, "Drained $dispatched queued posts on reconnect")
        }

        // b. Fetch missed inbound fragments for every active channel
        val channels = channelManager.activeChannelSnapshot()
        val localNodeId = gossipEngine.localNodeId

        channels.forEach { channel ->
            scope.launch {
                try {
                    val channelIdBytes = hexToBytes(channel.channelId)
                    val missed = fragmentFetcher.fetchMissedFragments(
                        channelId  = channelIdBytes,
                        lastSeenMs = channel.lastActivityMs
                    )
                    missed.forEach { fragment ->
                        fragmentIngestor.onFragmentReceived(fragment, localNodeId)
                    }
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("channel-sync", "reconnect-fetch", e,
                        "channelId" to channel.channelId.take(8))
                }
            }
        }

        // c. Nudge peers for each active channel
        val activePeerIds = gossipEngine.activePeerIds()
        if (activePeerIds.isNotEmpty()) {
            channels.forEach { channel ->
                scope.launch {
                    nudgeEngine.sendNudge(hexToBytes(channel.channelId), activePeerIds)
                }
            }
        }
    }

    /**
     * Periodic sync cycle — called by [MeshSyncWorker] every 15 minutes.
     *
     * Lighter than [onReconnect]: only re-fetches for channels with SYNCING posts
     * (active in-flight delivery), rather than all channels. Full reconnect sync
     * is triggered on topology changes by the foreground service.
     */
    suspend fun syncCycle() = withContext(Dispatchers.IO) {
        // a. Gossip housekeeping
        gossipEngine.onSyncCycleStart()

        // a.1 SNDP cover traffic — fire baseline fake bursts probabilistically for
        // recent posts. Disabled in CRITICAL/SURVIVAL modes (sndpEnabled=false there).
        if (sndpEngine != null && networkModeSM != null) {
            scope.launch {
                try {
                    val mode        = networkModeSM.currentMode
                    val postHashes  = postEngine.recentPostHashes(limit = 50)
                    val knownPeers  = gossipEngine.activePeerIds()
                        .mapNotNull { gossipEngine.peerContact(it) }
                    sndpEngine.onSyncCycleStart(mode, postHashes, knownPeers)
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("sndp", "sync-cycle-cover", e)
                }
            }
        }

        // b. Re-fetch for channels with SYNCING posts
        val syncingChannels = channelManager.channelsWithState(PostState.SYNCING)
        val localNodeId = gossipEngine.localNodeId

        // Channels no longer SYNCING should not accumulate stale retry counts or backoff state.
        syncRetries.keys.retainAll(syncingChannels.toSet())
        syncNextEligibleMs.keys.retainAll(syncingChannels.toSet())

        syncingChannels.forEach { channelId ->
            scope.launch {
                val nowMs = System.currentTimeMillis()
                // Exponential backoff: skip this WorkManager cycle if the channel is still
                // within its backoff window from the previous attempt. Only actual fetch
                // attempts (not skipped cycles) increment the retry counter, so MAX_SYNC_RETRIES
                // reflects real delivery attempts rather than elapsed WorkManager invocations.
                if (nowMs < (syncNextEligibleMs[channelId] ?: 0L)) return@launch

                val retries = syncRetries.merge(channelId, 1, Int::plus) ?: 1
                if (retries > MAX_SYNC_RETRIES) {
                    // Fragment assembly has not completed across MAX_SYNC_RETRIES actual fetch
                    // attempts. The post is undeliverable — fail it so the UI shows a clear error
                    // instead of a permanently stuck SYNCING badge, and so the retry loop ends.
                    Diag.degraded("channel-sync", "sync-retries-exhausted",
                        "SYNCING posts in channel $channelId failed after $retries sync cycles",
                        "channelId" to channelId.take(8), "retries" to retries.toString())
                    postEngine.failSyncingPostsInChannel(channelId)
                    syncRetries.remove(channelId)
                    syncNextEligibleMs.remove(channelId)
                    return@launch
                }

                // Compute next eligible window with exponential backoff capped at 2 hours.
                // Schedule: attempt 1 → +15 min, attempt 2 → +30 min, attempt 3 → +60 min,
                // attempt 4+ → +120 min. Doubling uses shl to avoid Float arithmetic.
                val backoffSteps = (retries - 1).coerceIn(0, MAX_BACKOFF_STEPS)
                syncNextEligibleMs[channelId] =
                    nowMs + (BASE_SYNC_INTERVAL_MS shl backoffSteps).coerceAtMost(MAX_BACKOFF_INTERVAL_MS)

                try {
                    val missed = fragmentFetcher.fetchMissedFragments(
                        channelId  = hexToBytes(channelId),
                        lastSeenMs = System.currentTimeMillis() -
                            PostEngine.DEFAULT_TTL_MS
                    )
                    missed.forEach { fragment ->
                        fragmentIngestor.onFragmentReceived(fragment, localNodeId)
                    }
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("channel-sync", "sync-cycle-fetch", e,
                        "channelId" to channelId.take(8))
                }
            }
        }

        // c. Evict expired relay-held fragments
        retransmissionMgr.evictExpired()
    }

    /**
     * Fetch missed fragments for a single [channelId] identified by its 32-byte bytes.
     *
     * Called by [ShadowMeshForegroundService] immediately when a nudge is received
     * (bypassing the 15-minute WorkManager window) and by [FragmentIngestor] on the
     * first-fragment event.  Uses [FragmentFetcher.PREFER_LOCAL] so the anticipatory
     * cache and local peers are checked before the DHT.
     *
     * All fetched fragments are fed through [FragmentIngestor.onFragmentReceived] so
     * the NACK loop, accumulator, and ViewModel callbacks all fire correctly.
     *
     * @param channelIdBytes  Raw 32-byte channel ID.
     * @param sinceMs         Fetch fragments newer than this timestamp.
     *                        Defaults to [PostEngine.DEFAULT_TTL_MS] ago.
     */
    suspend fun fetchMissedForChannel(
        channelIdBytes: ByteArray,
        sinceMs:        Long = System.currentTimeMillis() -
                               mesh.shadowmesh.forum.PostEngine.DEFAULT_TTL_MS
    ) = withContext(Dispatchers.IO) {
        try {
            val missed = fragmentFetcher.fetchMissedFragments(
                channelId  = channelIdBytes,
                lastSeenMs = sinceMs
            )
            val localNodeId = gossipEngine.localNodeId
            missed.forEach { fragment ->
                fragmentIngestor.onFragmentReceived(fragment, localNodeId)
            }
            if (missed.isNotEmpty()) {
                Log.d(TAG,
                    "fetchMissedForChannel: pulled ${missed.size} fragment(s) for " +
                    channelIdBytes.copyOfRange(0, 4).toHex())
            }
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Diag.swallowed("channel-sync", "fetch-missed-channel", e,
                "channelPrefix" to channelIdBytes.copyOfRange(0, minOf(4, channelIdBytes.size)).toHex())
        }
    }

    /**
     * Fetch missed fragments for a single [channelId] identified by its hex string.
     * Convenience overload — resolves hex to bytes and delegates to [fetchMissedForChannel].
     */
    suspend fun fetchMissedForChannel(channelId: String) =
        fetchMissedForChannel(hexToBytes(channelId))

    /**
     * Subscribe to [gapEvents] and trigger a full channel re-fetch whenever a ratchet
     * desynchronisation is reported by [FragmentIngestor].
     *
     * The re-fetch requests all fragments for the affected channel from the beginning
     * of the TTL window. If the intermediate posts (whose postIds the ratchet missed)
     * arrive and are confirmed in order, the ratchet will advance back into sync and
     * subsequent posts in that channel will decrypt correctly.
     *
     * Limitation: if the missing intermediate posts are not available on any reachable
     * peer, the ratchet remains desynchronised for that channel. The next reconnect sync
     * will retry. This is a best-effort v1 implementation of the gap resolver.
     *
     * Must be called once from the composition root after all components are wired.
     * Launches a coroutine that runs for the lifetime of [scope].
     */
    /**
     * Per-channel timestamp of the last gap-fetch attempt, used to rate-limit re-fetches.
     * An adversary who can trigger ratchet gaps (e.g., by publishing fragments with
     * incorrect hashes) could otherwise cause O(N) channel re-fetches per second.
     */
    private val gapFetchNextEligibleMs = java.util.concurrent.ConcurrentHashMap<String, Long>()

    fun startGapResolution(gapEvents: ReceiveChannel<RatchetGapEvent>) {
        scope.launch(Dispatchers.IO) {
            for (event in gapEvents) {
                val now = System.currentTimeMillis()
                val eligible = gapFetchNextEligibleMs.getOrDefault(event.channelId, 0L)
                if (now < eligible) {
                    Diag.fallback("channel-sync", "gap-fetch-rate-limited",
                        "Gap-fetch rate limited for channel ${event.channelId.take(8)} — skipping",
                        "retryInMs" to (eligible - now).toString())
                    continue
                }
                gapFetchNextEligibleMs[event.channelId] = now + GAP_FETCH_MIN_INTERVAL_MS
                Diag.info("channel-sync", "ratchet-gap-resolve",
                    "Ratchet gap detected — re-fetching full channel fragment set",
                    "channelId" to event.channelId.take(8),
                    "gapPostId" to event.gapPostId.take(8))
                try {
                    // Fetch from the start of the TTL window to catch intermediate posts
                    // the ratchet missed. fetchMissedForChannel re-delivers through
                    // FragmentIngestor so the accumulator and confirmation paths fire.
                    fetchMissedForChannel(event.channelId)
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("channel-sync", "ratchet-gap-fetch", e,
                        "channelId" to event.channelId.take(8))
                }
            }
        }
    }

    companion object {
        private const val TAG = "ChannelSyncCoordinator"

        /**
         * Maximum number of actual fetch attempts on a SYNCING channel before its posts are
         * transitioned to FAILED. Unlike the previous definition, this counts only attempts
         * that were NOT skipped due to exponential backoff, so it represents real delivery
         * attempts rather than elapsed WorkManager invocations. A reconnect resets the counter.
         */
        const val MAX_SYNC_RETRIES = 48

        /** WorkManager minimum interval — base backoff window after the first retry. */
        const val BASE_SYNC_INTERVAL_MS  = 15L * 60 * 1000   // 15 min

        /** Maximum backoff window: attempts beyond [MAX_BACKOFF_STEPS] all use this cap. */
        const val MAX_BACKOFF_INTERVAL_MS = 120L * 60 * 1000  // 2 hours

        /** Number of doublings before the backoff window is capped at [MAX_BACKOFF_INTERVAL_MS].
         *  3 doublings: 15 min → 30 → 60 → 120 (capped). */
        const val MAX_BACKOFF_STEPS      = 3

        /**
         * Minimum interval between gap-fetch attempts for the same channel.
         * Prevents an adversary who can trigger ratchet gaps from causing a full
         * channel re-fetch on every fragment receipt. One minute is long enough to
         * let in-flight fragments arrive and self-heal without blocking legitimate syncs.
         */
        const val GAP_FETCH_MIN_INTERVAL_MS = 60_000L
    }
}

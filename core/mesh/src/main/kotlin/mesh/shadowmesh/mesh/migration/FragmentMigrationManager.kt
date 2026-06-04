package mesh.shadowmesh.mesh.migration

import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.mode.NetworkMode
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag

/**
 * Fragment migration manager — design doc Phase 6.
 *
 * Handles proactive fragment migration when a node reaches 80% storage capacity.
 *
 * Protocol:
 *   1. At 80% storage, anchor publishes a MIGRATION_NEEDED gossip message
 *      listing which relay slots it is relinquishing (by channel DHT key).
 *   2. The 3 closest surviving anchors claim the relinquished slots.
 *   3. Migrating node streams fragments to new holders before lease expiry.
 *   4. After migration: node publishes LEASE_EXPIRY for each migrated slot.
 *   5. Other nodes re-replicate from the new holders.
 *   6. If storage drops below 75% before migration completes, MIGRATION_CANCEL
 *      is sent and the original node retains its slots.
 *
 * Lease model:
 *   Each relay slot has a 24-hour lease. On expiry without renewal, other nodes
 *   re-replicate the slot. Renewal is a lightweight gossip message.
 *
 * User-facing storage management:
 *   At 80% storage, if migration is insufficient, the user is shown a notification.
 *   One-tap action: LRU relay fragments purged (own posts are NEVER purged).
 *   Network is notified via LEASE_EXPIRY.
 *
 * Thread-safety: [activeLeases] and [migrationState] use ConcurrentHashMap.
 */
class FragmentMigrationManager(
    private val localNodeId: NodeId,
    private val transport:   MigrationTransport,
    private val scope:       CoroutineScope
) {
    // Active relay leases: channelDhtKey (hex) → LeaseRecord
    private val activeLeases = ConcurrentHashMap<String, LeaseRecord>()

    // Current migration state — null if no migration in progress
    @Volatile private var migrationState: MigrationState? = null

    // ── Storage threshold monitoring ──────────────────────────────────────

    /**
     * Called when storage utilisation changes. Triggers migration at 80%;
     * cancels migration if utilisation drops back below 75%.
     *
     * @param storagePct  Current storage utilisation 0–100.
     * @return [StorageAction] indicating what action was taken.
     */
    fun onStorageChanged(storagePct: Int): StorageAction {
        val current = migrationState

        return when {
            storagePct >= MIGRATION_TRIGGER_PCT && current == null -> {
                startMigration(storagePct)
                StorageAction.MigrationStarted
            }
            storagePct < MIGRATION_CANCEL_PCT && current != null -> {
                cancelMigration()
                StorageAction.MigrationCancelled
            }
            storagePct >= USER_NOTIFICATION_PCT && current != null -> {
                StorageAction.UserNotificationRequired
            }
            else -> StorageAction.NoAction
        }
    }

    private fun startMigration(storagePct: Int) {
        val slots = activeLeases.keys.take(SLOTS_TO_MIGRATE)
        migrationState = MigrationState(
            startedAtMs   = System.currentTimeMillis(),
            slotsToMigrate= slots,
            storagePctAtStart = storagePct
        )
        scope.launch {
            try {
                slots.forEach { slotKey ->
                    transport.publishMigrationNeeded(localNodeId.bytes.toHex(), slotKey)
                }
            } catch (e: Exception) { Diag.swallowed("fragment-migration", "publish-needed", e) }
        }
    }

    private fun cancelMigration() {
        val state = migrationState ?: return
        migrationState = null
        scope.launch {
            state.slotsToMigrate.forEach { slotKey ->
                try { transport.publishMigrationCancel(localNodeId.bytes.toHex(), slotKey) }
                catch (e: Exception) { Diag.swallowed("fragment-migration", "publish-cancel", e, "slot" to slotKey) }
            }
        }
    }

    // ── Lease management ──────────────────────────────────────────────────

    /**
     * Claim a relay slot lease for [channelDhtKey].
     * Called when this node accepts a migrated slot from another anchor.
     */
    fun claimLease(channelDhtKey: String, fromNodeId: String) {
        activeLeases[channelDhtKey] = LeaseRecord(
            channelDhtKey = channelDhtKey,
            fromNodeId    = fromNodeId,
            grantedAtMs   = System.currentTimeMillis(),
            expiresAtMs   = System.currentTimeMillis() + LEASE_DURATION_MS
        )
    }

    /**
     * Renew the lease for [channelDhtKey].
     * Called when this node continues to hold a slot past its initial lease.
     */
    fun renewLease(channelDhtKey: String) {
        activeLeases[channelDhtKey]?.let {
            activeLeases[channelDhtKey] = it.copy(
                expiresAtMs = System.currentTimeMillis() + LEASE_DURATION_MS
            )
        }
    }

    /** Release a lease and publish LEASE_EXPIRY. */
    suspend fun releaseLease(channelDhtKey: String) {
        activeLeases.remove(channelDhtKey)
        transport.publishLeaseExpiry(localNodeId.bytes.toHex(), channelDhtKey)
    }

    /** Evict expired leases and notify network. Called by WorkManager periodically. */
    suspend fun evictExpiredLeases() {
        val now = System.currentTimeMillis()
        val expired = activeLeases.entries
            .filter { it.value.expiresAtMs < now }
            .map { it.key }
        expired.forEach { releaseLease(it) }
    }

    // ── User-facing LRU clear ─────────────────────────────────────────────

    /**
     * User-initiated LRU relay fragment clear (one-tap storage relief).
     * Purges relay fragments in LRU order. Own posts are NEVER purged.
     *
     * @param targetPct  Storage % target after purge (e.g. 70%).
     * @return Number of relay slot leases released.
     */
    suspend fun userInitiatedLruClear(targetPct: Int): Int {
        val lruSlots = activeLeases.entries
            .sortedBy { it.value.grantedAtMs }  // oldest first = LRU
        var released = 0
        for ((key, _) in lruSlots) {
            releaseLease(key)
            released++
            // Check if we've freed enough — transport reports current pct
            if (transport.currentStoragePct() <= targetPct) break
        }
        return released
    }

    // ── Live Mode pre-fetch budget ─────────────────────────────────────────

    /**
     * Per-thread Live Mode: pre-fetch posts every 90 seconds.
     * Global budget: 10 DHT queries per minute shared across all open threads.
     * Excess threads are queued.
     *
     * [threadCount] = number of currently open channel/post threads.
     */
    fun allocateLiveModeQueries(threadCount: Int): Int {
        val total = LIVE_MODE_QUERIES_PER_MIN
        return if (threadCount == 0) 0
        else (total / threadCount).coerceAtLeast(1)
    }

    // ── Queries ───────────────────────────────────────────────────────────

    fun activeLeasesCount(): Int = activeLeases.size
    fun isMigrationInProgress(): Boolean = migrationState != null
    fun currentMigrationState(): MigrationState? = migrationState

    companion object {
        const val MIGRATION_TRIGGER_PCT   = 80
        const val MIGRATION_CANCEL_PCT    = 75
        const val USER_NOTIFICATION_PCT   = 80
        const val SLOTS_TO_MIGRATE        = 5         // migrate 5 slots at a time
        const val LEASE_DURATION_MS       = 24L * 60 * 60 * 1000  // 24 hours
        const val LIVE_MODE_QUERIES_PER_MIN = 10
        const val LIVE_MODE_PREFETCH_INTERVAL_MS = 90_000L        // 90 seconds
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

data class LeaseRecord(
    val channelDhtKey: String,
    val fromNodeId:    String,
    val grantedAtMs:   Long,
    val expiresAtMs:   Long
) {
    fun isExpired(nowMs: Long = System.currentTimeMillis()) = nowMs >= expiresAtMs
}

data class MigrationState(
    val startedAtMs:      Long,
    val slotsToMigrate:   List<String>,
    val storagePctAtStart:Int
)

sealed class StorageAction {
    object NoAction               : StorageAction()
    object MigrationStarted       : StorageAction()
    object MigrationCancelled     : StorageAction()
    object UserNotificationRequired: StorageAction()
}

// ── Transport interface ────────────────────────────────────────────────────────

interface MigrationTransport {
    suspend fun publishMigrationNeeded(nodeId: String, channelDhtKey: String)
    suspend fun publishMigrationCancel(nodeId: String, channelDhtKey: String)
    suspend fun publishLeaseExpiry(nodeId: String, channelDhtKey: String)
    suspend fun currentStoragePct(): Int
}

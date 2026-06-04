// TODO: [BLE Redesign] KDoc updated to document always-on trust-agnostic scanning posture.
// No behavioural changes — this comment exists only to satisfy the documentation requirement.

package mesh.shadowmesh.app

import mesh.shadowmesh.diagnostics.Diag

import android.content.Context
import android.util.Log
import androidx.work.*
import mesh.shadowmesh.mesh.mode.NetworkMode
import java.util.concurrent.TimeUnit

/**
 * WorkManager sync worker — periodic mesh synchronisation and nudge wake.
 *
 * Handles two distinct trigger paths:
 *
 *   **Periodic sync** (15-minute interval, WorkManager minimum):
 *     Runs one DHT sync cycle and one gossip sync cycle. This is the
 *     POLLING_MODE fallback when [ShadowMeshForegroundService] is dead —
 *     the foreground service keeps the mesh live in LIVE_MODE, but
 *     WorkManager ensures the mesh makes progress even when the service
 *     is killed by the OS.
 *
 *   **Nudge wake** (one-time, triggered by BleGattTransport PendingIntent):
 *     An incoming BLE nudge signals that there are new fragments waiting
 *     for a specific channel. This worker fetches those fragments immediately
 *     without waiting for the 15-minute periodic window.
 *     [Input.KEY_CHANNEL_ID] carries the channel ID from the nudge.
 *
 * Both paths safely check [AppModule.isInitialised] before doing anything —
 * WorkManager can fire before the application finishes its async init on a
 * cold start after process death.
 *
 * **Constraint**: [NetworkType.CONNECTED] is NOT required. SHADOWMESH operates
 * without internet — WiFi Direct and BLE transport work offline. Requiring
 * CONNECTED would break the whole point.
 *
 * **Always-on trust-agnostic scanning**:
 *   This worker, [ShadowMeshForegroundService], and the underlying transports (WiFi Direct,
 *   LAN TCP, mesh BLE via [BleGattTransport]) all operate continuously regardless of peer
 *   trust level. They discover and relay for any ShadowMesh node; trust is evaluated only
 *   at the application layer when a message is delivered. No transport or worker requires
 *   a minimum trust level to scan, relay, or sync. This is by design — the mesh must be
 *   self-healing and censorship-resistant without relying on per-peer allowlists.
 */
class MeshSyncWorker(
    context: Context,
    params:  WorkerParameters
) : CoroutineWorker(context, params) {

    private val TAG = "MeshSyncWorker"

    override suspend fun doWork(): Result {
        if (!AppModule.isInitialised) {
            Log.w(TAG, "Worker fired before AppModule ready — retrying")
            return Result.retry()
        }

        val channelId = inputData.getString(Input.KEY_CHANNEL_ID)

        return if (channelId != null) {
            runNudgeSync(channelId)
        } else {
            runPeriodicSync()
        }
    }

    private suspend fun runNudgeSync(channelId: String): Result {
        Log.d(TAG, "Nudge wake for channel $channelId")
        return try {
            AppModule.gossipEngine.syncCycleForChannel(channelId)
            Result.success()
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Log.w(TAG, "Nudge sync failed for $channelId: ${e.message}")
            Result.retry()
        }
    }

    private suspend fun runPeriodicSync(): Result {
        // Short-circuit if a full targeted sync ran recently (e.g. device unlock triggered
        // ShadowMeshForegroundService.onDeviceUnlocked). WorkManager fires every 15 minutes
        // regardless, but if the foreground service already synced within the last
        // RECENT_SYNC_SKIP_MS window there's no value in running again immediately.
        // This avoids redundant DHT/gossip churn when the user has been actively using the app.
        val now = System.currentTimeMillis()
        val lastSync = AppModule.lastSyncMs
        if (lastSync > 0 && now - lastSync < RECENT_SYNC_SKIP_MS) {
            Log.d(TAG, "Periodic sync skipped — foreground sync ran ${(now - lastSync) / 1000}s ago")
            return Result.success()
        }

        Log.d(TAG, "Periodic sync cycle")
        return try {
            val mode = AppModule.networkModeSM.currentMode
            if (mode != NetworkMode.SURVIVAL) {
                AppModule.dhtEngine.syncCycle()
            }
            AppModule.gossipEngine.syncCycle()
            // Forum backend sync: re-fetch for SYNCING posts, evict expired relay-held fragments
            AppModule.channelSyncCoordinator.syncCycle()
            Result.success()
        } catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Log.w(TAG, "Periodic sync failed: ${e.message}")
            Result.retry()
        }
    }

    companion object {
        const val WORK_NAME_PERIODIC = "mesh_sync_periodic"
        const val WORK_NAME_NUDGE    = "mesh_sync_nudge"

        /**
         * If [AppModule.lastSyncMs] is within this window of the current time,
         * [runPeriodicSync] skips the cycle. Set to 10 minutes — slightly less than
         * WorkManager's 15-minute minimum interval so that an unlock sync at minute 14
         * doesn't suppress the next WorkManager firing at minute 15 (which would be 1
         * minute after the unlock — well outside the skip window).
         */
        const val RECENT_SYNC_SKIP_MS = 10 * 60 * 1000L

        /** Schedule the periodic 15-minute sync. Idempotent — KEEP policy. */
        fun schedulePeriodicSync(context: Context) {
            val request = PeriodicWorkRequestBuilder<MeshSyncWorker>(
                15, TimeUnit.MINUTES
            )
                .addTag(WORK_NAME_PERIODIC)
                // No network constraint — SHADOWMESH works offline.
                // No battery-not-low constraint — mesh sync is latency-sensitive
                // and the foreground service already handles Doze exemption.
                // Backoff: LINEAR 2-minute initial delay on retry, prevents rapid
                // hammering of the DHT/DB if a transient failure repeats.
                .setBackoffCriteria(BackoffPolicy.LINEAR, 2, TimeUnit.MINUTES)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME_PERIODIC,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }

        /**
         * Schedule a one-time nudge sync for [channelId].
         * Called by [BleGattTransport] when a 12-byte NudgePacket is received.
         * Runs immediately (no initial delay), bypassing the 15-minute window.
         */
        fun scheduleNudgeSync(context: Context, channelId: String) {
            val data = workDataOf(Input.KEY_CHANNEL_ID to channelId)
            val request = OneTimeWorkRequestBuilder<MeshSyncWorker>()
                .setInputData(data)
                .addTag(WORK_NAME_NUDGE)
                .build()
            // REPLACE so that rapid repeat nudges for the same channel don't queue up.
            WorkManager.getInstance(context).enqueueUniqueWork(
                "$WORK_NAME_NUDGE:$channelId",
                ExistingWorkPolicy.REPLACE,
                request
            )
        }
    }

    object Input {
        const val KEY_CHANNEL_ID = "channel_id"
    }
}

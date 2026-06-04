package mesh.shadowmesh.forum
import mesh.shadowmesh.diagnostics.Diag

import android.content.Context
import androidx.work.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mesh.shadowmesh.storage.ShadowMeshDao
import java.util.concurrent.TimeUnit

/**
 * WorkManager TTL sweep worker — Phase 3 gap.
 *
 * Runs every 6 hours to purge:
 *   - Posts past their TTL (default 7 days)
 *   - Orphaned fragments (no parent post, older than TTL)
 *
 * This is the only caller of [PostEngine.sweepExpired] in production.
 * The 6-hour schedule means the worst-case storage overrun from expired
 * posts is bounded: at most 6 hours of posts past their TTL at any time.
 *
 * Design note: the design doc says "WorkManager sweep" — we use
 * PeriodicWorkRequest with a 6-hour interval (minimum WorkManager period is
 * 15 minutes; 6 hours is conservative and appropriate for infrequent cleanup).
 *
 * The worker is injected with [PostEngine] via the app module ShadowMeshWorkerFactory.
 * The [postEngine] property is set by ShadowMeshWorkerFactory before doWork() is called.
 */
class TtlSweepWorker(
    appContext: Context,
    params:     WorkerParameters
) : CoroutineWorker(appContext, params) {

    // Set by the app module's ShadowMeshWorkerFactory before doWork() (no Hilt).
    var postEngine: PostEngine? = null

    /** Injected by ShadowMeshWorkerFactory. Used to sweep expired bootstrap nonces. */
    var dao: ShadowMeshDao? = null

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        val engine = postEngine ?: return@withContext Result.retry()
        try {
            engine.sweepExpired()

            // Sweep expired bootstrap nonces — retain for 10 minutes (2× validity window).
            dao?.deleteExpiredNonces(
                oldestAllowedMs = System.currentTimeMillis() - mesh.shadowmesh.storage.UsedBootstrapNonce.NONCE_RETAIN_MS
            )

            Result.success()
        } catch (e: Exception) {
            // WorkManager has no built-in max retry count for PeriodicWorkRequest. Without
            // a cap, transient failures (e.g., DB locked) cause the worker to retry with
            // exponential backoff indefinitely, wasting battery. Cap at MAX_RETRIES attempts
            // and give up (return failure) so the NEXT scheduled run starts fresh.
            Diag.swallowed("ttl-sweep", "sweep-failed", e)
            if (runAttemptCount >= MAX_RETRIES) {
                Diag.degraded("ttl-sweep", "max-retries-exceeded",
                    "TtlSweepWorker failed $runAttemptCount times — giving up until next 6h window")
                Result.failure()
            } else {
                Result.retry()
            }
        }
    }

    companion object {
        const val WORK_NAME        = "shadowmesh_ttl_sweep"
        const val INTERVAL_HOURS   = 6L
        /** Maximum consecutive failure retries before giving up until the next 6-hour window. */
        const val MAX_RETRIES      = 3

        /**
         * Enqueue the periodic TTL sweep.
         * Safe to call multiple times — KEEP policy deduplicates.
         */
        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<TtlSweepWorker>(
                INTERVAL_HOURS, TimeUnit.HOURS
            )
                .setConstraints(Constraints.Builder().build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.MINUTES)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request
            )
        }
    }
}

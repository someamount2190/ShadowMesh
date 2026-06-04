package mesh.shadowmesh.app

import android.content.Context
import androidx.work.ListenableWorker
import androidx.work.WorkerFactory
import androidx.work.WorkerParameters
import mesh.shadowmesh.forum.TtlSweepWorker
import mesh.shadowmesh.security.ApkIntegrityWorker

/**
 * WorkerFactory that injects runtime dependencies into WorkManager-instantiated workers.
 *
 * ## Why this exists
 *
 * WorkManager constructs workers via reflection using a no-arg constructor (or the
 * standard two-arg Context + WorkerParameters constructor). It has no access to the
 * application's object graph — so workers that need injected dependencies must receive
 * them here, after construction, before [doWork] is called.
 *
 * Previously [ApkIntegrityWorker] was scheduled but its `verifier` was never set —
 * the periodic APK integrity check silently returned `Result.retry()` forever.
 * [TtlSweepWorker] had the same problem: `postEngine` was null, posts never purged.
 * This factory fixes both by pulling the configured singletons from [AppModule].
 *
 * ## Silent-failure prevention — exhaustive when
 *
 * The original factory used `else -> null`, which silently passed any unregistered
 * worker class to WorkManager's default factory (which has no injection capability).
 * If a future worker uses the `lateinit var` injection pattern and is forgotten here,
 * it would loop on `Result.retry()` forever with no error — the exact failure mode
 * that caused [ApkIntegrityWorker] and [TtlSweepWorker] to be broken.
 *
 * The `else -> error(...)` branch turns that silent failure into a visible crash
 * during QA. Every worker class that exists in the codebase must appear explicitly:
 *   - Workers that need injection: implement the injection here.
 *   - Workers that do NOT need injection (use AppModule directly or only
 *     applicationContext): add an explicit `return null` branch with a comment
 *     explaining why no injection is needed.
 *
 * Registered via [ShadowMeshApplication.getWorkManagerConfiguration].
 */
class ShadowMeshWorkerFactory : WorkerFactory() {

    override fun createWorker(
        appContext:        Context,
        workerClassName:   String,
        workerParameters:  WorkerParameters
    ): ListenableWorker? = when (workerClassName) {

        // ── Workers that require field injection ──────────────────────────

        ApkIntegrityWorker::class.java.name -> {
            ApkIntegrityWorker(appContext, workerParameters).apply {
                // AppModule may not be initialised yet if WorkManager fires very early at
                // boot; in that case leave verifier null and the worker returns retry(),
                // which is the correct behaviour (try again once init completes).
                if (AppModule.isInitialised) {
                    verifier = AppModule.securityWiring.apkVerifier
                }
            }
        }

        TtlSweepWorker::class.java.name -> {
            TtlSweepWorker(appContext, workerParameters).apply {
                // Same convention: inject PostEngine from the app object graph so the
                // periodic TTL sweep actually runs. Without this the scheduled worker
                // would loop on Result.retry() and expired posts/orphaned fragments
                // would never be purged.
                if (AppModule.isInitialised) {
                    postEngine = AppModule.postEngine
                    // dao is also required: TtlSweepWorker.dao.deleteExpiredNonces() deletes
                    // used bootstrap nonces older than their retention window. Without this
                    // injection the nonce table grows unboundedly — every bootstrap attempt
                    // adds a row that is never cleaned up.
                    dao = AppModule.database.dao()
                }
            }
        }

        // ── Workers that do NOT need injection ────────────────────────────
        // Return null so WorkManager uses its default two-arg constructor.
        // Each entry must explain WHY injection is not needed.

        MeshSyncWorker::class.java.name -> {
            // MeshSyncWorker reads AppModule singletons directly (gossipEngine, dhtEngine,
            // networkModeSM) behind an isInitialised guard. No lateinit fields to inject.
            null
        }

        ForegroundRestartWorker::class.java.name -> {
            // ForegroundRestartWorker only uses applicationContext to send Intents.
            // No dependency on AppModule or any injected field.
            null
        }

        // ── Catch-all: missing registration is a compile-time-visible error ──
        //
        // If you add a new CoroutineWorker subclass and forget to register it here,
        // this branch will throw during QA, making the omission immediately visible.
        // DO NOT change this to `else -> null` — that restores the silent-failure mode.
        //
        // What to do when you see this error:
        //   1. If the new worker needs injection: add a branch above that injects it.
        //   2. If the new worker needs no injection: add an explicit `null` branch
        //      above with a comment explaining why (same pattern as MeshSyncWorker).
        else -> error(
            "Worker class '$workerClassName' is not registered in ShadowMeshWorkerFactory. " +
            "Add an explicit branch: inject dependencies if needed, or return null if the " +
            "worker reads AppModule directly or needs only applicationContext. " +
            "DO NOT use 'else -> null' — that re-introduces the silent-failure pattern."
        )
    }
}

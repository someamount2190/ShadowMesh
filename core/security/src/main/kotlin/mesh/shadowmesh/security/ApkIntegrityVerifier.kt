package mesh.shadowmesh.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import mesh.shadowmesh.diagnostics.Diag
import androidx.work.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mesh.shadowmesh.crypto.IntegrityBoundedKeyDerivation
import mesh.shadowmesh.crypto.Hkdf
import java.security.MessageDigest
import java.util.concurrent.TimeUnit

/**
 * APK self-verification — design doc §5.12.
 *
 * Checks the app's own signing certificate against a compile-time expected hash
 * ([BuildConfig.EXPECTED_SIGNATURE_HASH]). If the certificate does not match —
 * meaning the APK has been repackaged with a different signing key — the
 * [onTamperDetected] callback is invoked silently. No visible alert is shown;
 * the app appears to continue normally while keys are wiped.
 *
 * This is one half of the tamper-resistance system. The other half is
 * [IntegrityBoundedKeyDerivation] (§5.15): a repackaged APK produces a
 * different [buildApkBindingHash], so derived keys are cryptographically wrong
 * even if the wipe callback is patched out.
 *
 * Critical classes hashed for [buildApkBindingHash]:
 *   NetworkStateCoordinator, GossipEngine, DhtClient, HybridKem, FragmentAssembler.
 *   UI layer excluded — UI patches carry lower attack-surface significance.
 *
 * Schedule: called on app startup and every 4 hours via WorkManager.
 * Background schedule is registered by [schedulePeriodicCheck].
 *
 * Android-layer boundary: this class uses Android APIs (PackageManager,
 * WorkManager). [IntegrityBoundedKeyDerivation.buildApkBindingHash] is pure JVM
 * and fully testable separately.
 *
 * Thread-safety: all verify() operations dispatched to Dispatchers.IO.
 */
class ApkIntegrityVerifier(
    private val context:          Context,
    private val expectedSigHash:  String,          // BuildConfig.EXPECTED_SIGNATURE_HASH
    private val onTamperDetected: suspend () -> Unit,
    private val ibd:              IntegrityBoundedKeyDerivation = IntegrityBoundedKeyDerivation(Hkdf.instance)
) {

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Run the integrity check now (on Dispatchers.IO).
     * Calls [onTamperDetected] silently if the check fails.
     * Returns true if the APK is intact, false if tampered.
     *
     * Debug builds receive [EXPECTED_SIGNATURE_HASH] = [DEBUG_SENTINEL] from the
     * build config, which causes this function to return true immediately without
     * comparing any certificate bytes.  This prevents the all-zeros placeholder
     * from triggering a false-positive panic wipe on every debug launch.
     *
     * Release builds always receive the real signing-cert SHA-256 hash (enforced at
     * build time in app/build.gradle.kts), so the sentinel branch is never taken in
     * production.
     */
    suspend fun verify(): Boolean = withContext(Dispatchers.IO) {
        // Debug / CI builds use a named sentinel rather than a cert hash.
        // Return true immediately — no wipe, no comparison.
        if (expectedSigHash == DEBUG_SENTINEL) {
            Diag.info("apk-integrity", "debug-build",
                "APK integrity check skipped — debug sentinel present (not a release build)")
            return@withContext true
        }
        try {
            val certHash = computeSigningCertHash()
            if (!certHash.equals(expectedSigHash, ignoreCase = true)) {
                Log.w(TAG, "APK signature mismatch — invoking tamper callback")
                onTamperDetected()
                false
            } else {
                true
            }
        } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
            // The package is not found — this happens transiently during an OS-managed
            // update when the package record is temporarily unavailable. Treating this as
            // tamper would trigger a wipe during a legitimate update. Retry rather than wipe.
            Log.w(TAG, "APK integrity: package not found (transient during update?) — deferring")
            Diag.swallowed("apk-integrity", "verify-pkg-not-found", e)
            true   // optimistic: do not wipe; the next scheduled check will re-verify
        } catch (e: SecurityException) {
            // SecurityException from PackageManager is also transient in some OEM
            // implementations during package replacement. Same reasoning — defer.
            Log.w(TAG, "APK integrity: SecurityException from PackageManager (transient?) — deferring")
            Diag.swallowed("apk-integrity", "verify-security-exception", e)
            true   // optimistic: do not wipe
        } catch (e: Exception) {
            // Any other failure in cert retrieval is treated as tamper — fail closed.
            // This covers RuntimeException, IllegalStateException, JNI errors etc.
            // which are not expected on a legitimate device running the genuine app.
            Log.e(TAG, "APK integrity check threw — treating as tamper", e)
            Diag.swallowed("apk-integrity", "verify", e)
            onTamperDetected()
            false
        }
    }

    /**
     * Compute the APK binding hash for use in [IntegrityBoundedKeyDerivation].
     * Combines the signing certificate bytes with the SHA3-256 of each critical
     * class file's bytecode.
     *
     * The critical class bytecodes must be supplied by the caller — obtained via
     * [Class.forName] + class file resource lookup, or from a pre-computed list
     * populated at build time.
     *
     * @param criticalClassBytecodes Raw .class file bytes for NSC, GossipEngine,
     *                               DhtClient, HybridKem, FragmentAssembler.
     */
    suspend fun computeApkBindingHash(
        criticalClassBytecodes: List<ByteArray>
    ): ByteArray = withContext(Dispatchers.IO) {
        val certBytes = getSigningCertBytes()
        ibd.buildApkBindingHash(certBytes, criticalClassBytecodes)
    }

    /**
     * Register a periodic WorkManager job to re-run [verify] every 4 hours.
     * Safe to call multiple times — WorkManager deduplicates by [WORK_NAME].
     */
    fun schedulePeriodicCheck() {
        val request = PeriodicWorkRequestBuilder<ApkIntegrityWorker>(4, TimeUnit.HOURS)
            .setConstraints(Constraints.Builder().build())
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 15, TimeUnit.MINUTES)
            .build()

        WorkManager.getInstance(context).enqueueUniquePeriodicWork(
            WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    private fun computeSigningCertHash(): String {
        val certBytes = getSigningCertBytes()
        val digest    = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(certBytes)
        return hashBytes.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    }

    @Suppress("DEPRECATION")
    private fun getSigningCertBytes(): ByteArray {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNING_CERTIFICATES
            )
            val signingInfo = info.signingInfo
                ?: throw SecurityException("No signing info available")
            // Use current signer (index 0); rotation-aware if needed
            signingInfo.apkContentsSigners.firstOrNull()?.toByteArray()
                ?: throw SecurityException("No signatures found in signingInfo")
        } else {
            val info = context.packageManager.getPackageInfo(
                context.packageName,
                PackageManager.GET_SIGNATURES
            )
            @Suppress("DEPRECATION")
            info.signatures.firstOrNull()?.toByteArray()
                ?: throw SecurityException("No signatures found (legacy path)")
        }
    }

    companion object {
        private const val TAG       = "ApkIntegrityVerifier"
        const val WORK_NAME         = "shadowmesh_apk_integrity_check"
        const val CHECK_INTERVAL_H  = 4L

        /**
         * Sentinel value written into [BuildConfig.EXPECTED_SIGNATURE_HASH] by debug
         * builds (see app/build.gradle.kts).  When [verify] sees this value it returns
         * true immediately, preventing a false-positive panic wipe during development.
         *
         * This sentinel is never present in release builds — the build script enforces
         * that [BuildConfig.EXPECTED_SIGNATURE_HASH] is a real 64-char hex value for
         * release, and the script fails the build if shadowmesh.sigHash is unset.
         */
        const val DEBUG_SENTINEL = "SHADOWMESH_DEBUG_BUILD"
    }
}

// ── WorkManager Worker ────────────────────────────────────────────────────────

/**
 * Periodic WorkManager worker that triggers APK integrity re-verification.
 * The [ApkIntegrityVerifier] is injected by the app module's WorkerFactory
 * (ShadowMeshWorkerFactory), which pulls it from the app's object graph before the
 * worker runs. This module stays free of Hilt/app dependencies; the [verifier] field is
 * a plain settable hook the factory populates.
 *
 * If the factory has not set [verifier] (e.g. WorkManager fired before app init), the
 * worker returns Result.retry() so the check runs once initialisation completes.
 */
class ApkIntegrityWorker(
    appContext: Context,
    params:     WorkerParameters
) : CoroutineWorker(appContext, params) {

    // Set by the app module's WorkerFactory before doWork(). Kept Hilt-free on purpose so
    // core:security has no dependency on the app module.
    var verifier: ApkIntegrityVerifier? = null

    override suspend fun doWork(): Result {
        val v = verifier ?: run {
            // Not yet injected (early-boot race) — retry rather than silently passing.
            return Result.retry()
        }
        return if (v.verify()) Result.success() else Result.failure()
    }
}

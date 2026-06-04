package mesh.shadowmesh.security

import android.content.Context

/**
 * Application-layer security wiring — Phase 1 integration point.
 *
 * Connects [ApkIntegrityVerifier] to [PanicWipeManager] so that APK tamper
 * detection triggers a full panic wipe automatically.
 *
 * Design doc §5.12 + §5.11:
 *   When the APK signing certificate does not match [BuildConfig.EXPECTED_SIGNATURE_HASH],
 *   or when a critical class bytecode hash changes, the verifier calls [onTamperDetected].
 *   That callback must trigger [PanicWipeManager.triggerWipe] silently — no UI alert,
 *   no log of the tampered content. The cover UI is shown by [PanicWipeManager.onWipeComplete].
 *
 * Why a separate wiring class:
 *   [ApkIntegrityVerifier] and [PanicWipeManager] live in the same module but must
 *   not directly reference each other — [ApkIntegrityVerifier] accepts the callback
 *   as a constructor parameter (dependency inversion) so it can be tested without
 *   actually triggering a wipe. This class is the composition root that supplies
 *   the real callback in production.
 *
 * Usage (in Application.onCreate() or the Hilt app module):
 *
 *   val wiring = AppSecurityWiring.create(
 *       context              = applicationContext,
 *       scope                = applicationScope,
 *       expectedSigHash      = BuildConfig.EXPECTED_SIGNATURE_HASH,
 *       onWipeComplete       = { showCoverUi() }
 *   )
 *   wiring.apkVerifier.schedulePeriodicCheck()
 *   wiring.apkVerifier.verify()   // eager startup check
 *
 * @param apkVerifier    Configured verifier whose [ApkIntegrityVerifier.onTamperDetected]
 *                       callback is wired to [panicWipeManager.triggerWipe].
 * @param panicWipeManager  The wipe manager that will fire on tamper detection.
 */
class AppSecurityWiring private constructor(
    val apkVerifier:      ApkIntegrityVerifier,
    val panicWipeManager: PanicWipeManager
) {
    companion object {
        /**
         * Create the wired pair using a pre-built [PanicWipeManager].
         *
         * **Always use this overload.** The previous overload that accepted
         * `onWipeComplete` and built its own [PanicWipeManager] internally has been
         * removed because it produced a wipe manager with all step lambdas defaulting
         * to no-ops (circuit key zeroing, ratchet zeroing, WorkManager cancellation,
         * VPN teardown, and encrypted-prefs clearing were all skipped). APK tamper
         * detection would trigger a partial wipe — DB deleted but session keys live.
         *
         * Callers must construct [PanicWipeManager] with all required step lambdas
         * (see its KDoc) and pass the fully-wired instance here. In
         * [ShadowMeshApplication.buildObjectGraph] this is done before any engine
         * is started so all lambda captures are already constructed.
         *
         * @param context         Application context.
         * @param expectedSigHash [BuildConfig.EXPECTED_SIGNATURE_HASH] — SHA-256 hex
         *                        of the APK signing certificate. Embedded at build time.
         * @param wipeManager     Fully-wired [PanicWipeManager] (all step lambdas set).
         */
        fun create(
            context:         android.content.Context,
            expectedSigHash: String,
            wipeManager:     PanicWipeManager
        ): AppSecurityWiring {
            // Validate that all critical step lambdas are wired. Without this check,
            // a partially-constructed PanicWipeManager (default no-op lambdas) would
            // silently skip VPN teardown, circuit key zeroing, ratchet zeroing, and
            // WorkManager cancellation on APK tamper — leaving live key material in
            // memory while the database is deleted.
            require(wipeManager.isFullyWired) {
                "PanicWipeManager passed to AppSecurityWiring.create() must be fully wired " +
                "(isFullyWired=true). Construct it with all step lambdas explicitly set: " +
                "onTeardownVpn, onWipeCircuit, onWipeRatchets, onCancelWork."
            }
            // Wire: APK tamper → panic wipe.
            // triggerWipe() is non-suspending — safe to call from any callback context.
            val verifier = ApkIntegrityVerifier(
                context          = context,
                expectedSigHash  = expectedSigHash,
                onTamperDetected = {
                    wipeManager.triggerWipe()
                }
            )
            return AppSecurityWiring(verifier, wipeManager)
        }
    }
}

package mesh.shadowmesh.platform

import android.content.Context
import android.content.Intent
import android.os.Build
import android.provider.Settings
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL

/**
 * Biometric enrollment checker — Phase 9.
 *
 * Before [BiometricKeyManager] presents a BiometricPrompt, the device must
 * have at least one biometric enrolled. If no biometric is enrolled and no
 * PIN/pattern/password is set, the prompt crashes with no user-visible error.
 *
 * This class provides:
 *   1. Pre-flight enrollment status check for the onboarding wizard and key
 *      wrapping flows — surfaces a user-actionable error before attempting.
 *   2. Categorisation of the available authenticator strength (STRONG vs WEAK).
 *   3. A deep-link to the biometric enrollment Settings screen.
 *
 * Authenticator hierarchy (design doc §5.11):
 *   BIOMETRIC_STRONG — fingerprint, 3D face, iris. Required for Keystore binding.
 *   BIOMETRIC_WEAK   — 2D face on most Android devices. NOT sufficient for
 *                      Keystore-bound operations; [BiometricKeyManager] uses
 *                      BIOMETRIC_STRONG or DEVICE_CREDENTIAL fallback only.
 *   DEVICE_CREDENTIAL — PIN / pattern / password. Fallback when no biometric.
 *                       Accepted as a fallback authenticator in the Keystore spec.
 *
 * Thread-safety: stateless — thread-safe by construction.
 */
object BiometricEnrollmentChecker {

    /**
     * Describes the biometric / credential enrollment state.
     */
    enum class EnrollmentStatus {
        /** Strong biometric (fingerprint/iris/3D face) is enrolled and ready. */
        STRONG_BIOMETRIC_READY,
        /** Only weak biometric is enrolled (2D face). Keystore ops will fall back
         *  to device credential (PIN/pattern/password). */
        WEAK_BIOMETRIC_ONLY,
        /** No biometric enrolled, but PIN/pattern/password is set.
         *  BiometricKeyManager will use DEVICE_CREDENTIAL for key wrapping. */
        CREDENTIAL_ONLY,
        /** Neither biometric nor PIN/pattern/password is set.
         *  BiometricPrompt will fail — user must enroll before using SHADOWMESH. */
        NONE_ENROLLED,
        /** BiometricManager returned an unexpected error code. */
        UNKNOWN
    }

    /**
     * Check the enrollment status on this device.
     * Call this before invoking [BiometricKeyManager.wrapKey] or [unwrapKey]
     * to surface a pre-flight error in the onboarding wizard.
     */
    fun checkEnrollmentStatus(context: Context): EnrollmentStatus {
        val bm = BiometricManager.from(context)

        val strongResult    = bm.canAuthenticate(BIOMETRIC_STRONG)
        val weakResult      = bm.canAuthenticate(BIOMETRIC_WEAK)
        val credResult      = bm.canAuthenticate(DEVICE_CREDENTIAL)

        return when {
            strongResult == BiometricManager.BIOMETRIC_SUCCESS ->
                EnrollmentStatus.STRONG_BIOMETRIC_READY

            weakResult == BiometricManager.BIOMETRIC_SUCCESS ->
                EnrollmentStatus.WEAK_BIOMETRIC_ONLY

            credResult == BiometricManager.BIOMETRIC_SUCCESS ->
                EnrollmentStatus.CREDENTIAL_ONLY

            strongResult == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ||
            credResult   == BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED ->
                EnrollmentStatus.NONE_ENROLLED

            strongResult == BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE ->
                // Device has no biometric hardware — credential only possible
                if (credResult == BiometricManager.BIOMETRIC_SUCCESS)
                    EnrollmentStatus.CREDENTIAL_ONLY
                else
                    EnrollmentStatus.NONE_ENROLLED

            else -> EnrollmentStatus.UNKNOWN
        }
    }

    /**
     * Returns true if [BiometricKeyManager] can proceed with key wrapping/unwrapping.
     * Both STRONG_BIOMETRIC_READY and CREDENTIAL_ONLY are acceptable —
     * the Keystore wrapping key allows DEVICE_CREDENTIAL as a fallback authenticator.
     * WEAK_BIOMETRIC_ONLY is borderline — falls through to credential if available.
     */
    fun canProceedWithKeyOps(context: Context): Boolean = when (checkEnrollmentStatus(context)) {
        EnrollmentStatus.STRONG_BIOMETRIC_READY,
        EnrollmentStatus.WEAK_BIOMETRIC_ONLY,
        EnrollmentStatus.CREDENTIAL_ONLY -> true
        else -> false
    }

    /**
     * User-facing message for each enrollment status.
     * Used in the onboarding wizard and in error dialogs.
     */
    fun userMessage(status: EnrollmentStatus): String = when (status) {
        EnrollmentStatus.STRONG_BIOMETRIC_READY ->
            "Biometric authentication is ready."
        EnrollmentStatus.WEAK_BIOMETRIC_ONLY ->
            "Only a weak biometric (e.g. face recognition) is enrolled. " +
            "Key operations will use your PIN/pattern as a fallback. " +
            "Enroll a fingerprint for stronger security."
        EnrollmentStatus.CREDENTIAL_ONLY ->
            "No biometric enrolled. Key operations will use your PIN/pattern/password. " +
            "Enroll a fingerprint for faster, stronger authentication."
        EnrollmentStatus.NONE_ENROLLED ->
            "No screen lock is set up on this device. " +
            "SHADOWMESH requires at least a PIN, pattern, or password to protect your keys. " +
            "Please set up a screen lock before continuing."
        EnrollmentStatus.UNKNOWN ->
            "Could not determine authentication status. Please restart the app."
    }

    /**
     * Open the biometric enrollment screen in Android Settings.
     * Call this when [checkEnrollmentStatus] returns [EnrollmentStatus.NONE_ENROLLED].
     *
     * Must be called from Main dispatcher.
     */
    fun openEnrollmentSettings(context: Context) {
        val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Intent(Settings.ACTION_BIOMETRIC_ENROLL).apply {
                putExtra(
                    Settings.EXTRA_BIOMETRIC_AUTHENTICATORS_ALLOWED,
                    BIOMETRIC_STRONG or DEVICE_CREDENTIAL
                )
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        } else {
            // Pre-API 30: generic security settings
            Intent(Settings.ACTION_SECURITY_SETTINGS).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        }
        context.startActivity(intent)
    }
}

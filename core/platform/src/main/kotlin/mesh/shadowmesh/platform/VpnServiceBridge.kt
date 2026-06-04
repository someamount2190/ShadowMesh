package mesh.shadowmesh.platform

import android.content.Context
import android.content.Intent
import android.net.VpnService

/**
 * VPN integration point — Phase 8 / Phase 9. This is the `[VpnServiceBridge]` referenced
 * by [MeshForegroundService]'s KDoc.
 *
 * Responsibilities:
 *   - Drive the one-time system consent flow ([android.net.VpnService.prepare]) and remember
 *     that consent was granted so onboarding never re-asks unnecessarily (Phase 9:
 *     "one-time, persists across restart").
 *   - Start and stop [ShadowMeshVpnService].
 *
 * Permission model (Android contract):
 *   [VpnService.prepare] returns a consent `Intent` the first time, or `null` if the app is
 *   already an authorized VPN. Consent persists at the OS level until the user revokes it or
 *   authorizes a different VPN app. We additionally persist a local flag via [consent] so the
 *   onboarding wizard can show the correct state across process restarts without poking the OS
 *   on every launch. [onConsentResult] reconciles the local flag with the activity result.
 *
 * The pure decision logic ([permissionState]) is separated from the Android calls so it can be
 * unit-tested with a fake [VpnConsentStore].
 */
class VpnServiceBridge(
    private val consent: VpnConsentStore
) {

    /** Local view of VPN permission, independent of a live OS query. */
    enum class PermissionState {
        /** Never granted on this install — onboarding must run the consent flow. */
        NOT_REQUESTED,
        /** Granted previously and persisted — no dialog needed on restart. */
        GRANTED,
        /** Was granted but the user revoked it — must re-request. */
        REVOKED
    }

    /** Local permission state derived purely from the persisted flags. Testable. */
    fun permissionState(): PermissionState = when {
        consent.wasRevoked()   -> PermissionState.REVOKED
        consent.wasGranted()   -> PermissionState.GRANTED
        else                   -> PermissionState.NOT_REQUESTED
    }

    /**
     * Whether the onboarding step still needs the user to act. True for NOT_REQUESTED and
     * REVOKED; false once GRANTED. Pure — safe to call off the main thread and in tests.
     */
    fun needsConsent(): Boolean = permissionState() != PermissionState.GRANTED

    /**
     * Build the consent Intent if the OS still requires it, else null. Caller launches the
     * returned Intent with `startActivityForResult` and feeds the result to [onConsentResult].
     * When this returns null the app is already authorized; treat that as an immediate grant.
     */
    fun prepareConsent(context: Context): Intent? {
        val intent = VpnService.prepare(context)
        if (intent == null) {
            // Already authorized at the OS level — reconcile local flag.
            consent.setGranted(true)
            consent.setRevoked(false)
        }
        return intent
    }

    /**
     * Reconcile the activity result of the consent dialog.
     * [granted] is true when the consent activity returned RESULT_OK.
     */
    fun onConsentResult(granted: Boolean) {
        consent.setGranted(granted)
        consent.setRevoked(false)
    }

    /** Record that the OS revoked consent (e.g. surfaced via [ShadowMeshVpnService.onRevoke]). */
    fun onRevoked() {
        consent.setGranted(false)
        consent.setRevoked(true)
    }

    // ── Service control ────────────────────────────────────────────────────

    /** Start the tunnel. No-op-safe to call repeatedly; the service guards re-entry. */
    fun start(context: Context) {
        context.startService(Intent(context, ShadowMeshVpnService::class.java))
    }

    /** Stop the tunnel without revoking OS consent. */
    fun stop(context: Context) {
        context.startService(
            Intent(context, ShadowMeshVpnService::class.java)
                .apply { action = ShadowMeshVpnService.ACTION_DISCONNECT }
        )
    }
}

/**
 * Persistence seam for VPN consent flags. The production implementation
 * ([SharedPrefsVpnConsentStore]) is backed by SharedPreferences; tests use a fake.
 */
interface VpnConsentStore {
    fun wasGranted(): Boolean
    fun wasRevoked(): Boolean
    fun setGranted(value: Boolean)
    fun setRevoked(value: Boolean)
}

/** SharedPreferences-backed [VpnConsentStore]. */
class SharedPrefsVpnConsentStore(context: Context) : VpnConsentStore {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    override fun wasGranted() = prefs.getBoolean(KEY_GRANTED, false)
    override fun wasRevoked() = prefs.getBoolean(KEY_REVOKED, false)
    override fun setGranted(value: Boolean) { prefs.edit().putBoolean(KEY_GRANTED, value).apply() }
    override fun setRevoked(value: Boolean) { prefs.edit().putBoolean(KEY_REVOKED, value).apply() }

    companion object {
        const val PREFS_NAME  = "shadowmesh_vpn_consent"
        const val KEY_GRANTED = "vpn_consent_granted"
        const val KEY_REVOKED = "vpn_consent_revoked"
    }
}

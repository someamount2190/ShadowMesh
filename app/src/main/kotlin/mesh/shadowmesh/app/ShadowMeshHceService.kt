package mesh.shadowmesh.app

import android.nfc.cardemulation.HostApduService
import android.os.Bundle
import android.util.Log
import mesh.shadowmesh.attestation.nfc.NfcBootstrapCoordinator
import mesh.shadowmesh.bootstrap.nfc.NfcTransport
import kotlinx.coroutines.runBlocking
import java.util.concurrent.atomic.AtomicReference

/**
 * NFC Host Card Emulation service — routes incoming APDUs to the active
 * [NfcBootstrapCoordinator] during a TRUST_PHYSICAL bootstrap session.
 *
 * ## When this fires
 *
 * Android routes an NFC tap to this service when the peer's NFC reader selects
 * the SHADOWMESH AID (F0 4D455348 00 4D5348). This happens when:
 *   - The peer (QR generator, Device A) is in NFC reader mode with foreground dispatch.
 *   - This device (QR scanner, Device B) brings its phone near A.
 *   - Android's HCE routing table matches the AID to this service's `apduservice.xml`.
 *
 * ## Session scoping
 *
 * [NfcBootstrapCoordinator] is NOT a singleton — it is created fresh per bootstrap
 * session when the user navigates to the bootstrap flow. [activeCoordinator] holds
 * a weak reference. APDUs that arrive when no bootstrap is active (e.g., accidental
 * tap by a peer with a SHADOWMESH device outside a session) silently return SW_NOT_FOUND.
 *
 * ## Threading
 *
 * [processCommandApdu] is called by the NFC stack on its own thread. The method
 * is synchronous and must return a byte array. [runBlocking] is correct here —
 * we block the NFC stack's thread (which is expected to wait for the response)
 * while dispatching to [Dispatchers.IO].
 *
 * ## AID select handling
 *
 * The first APDU in a session is always a SELECT AID command. We detect it and
 * return SW_OK to confirm routing — the coordinator does not need to see it.
 * Subsequent APDUs carry the bootstrap protocol messages.
 */
class ShadowMeshHceService : HostApduService() {

    private val TAG = "ShadowMeshHce"

    override fun processCommandApdu(apdu: ByteArray, extras: Bundle?): ByteArray {
        return try {
            // SELECT AID: CLA=00, INS=A4, P1=04 (select-by-AID), P2=00 (first occurrence).
            // All four header bytes are validated — accepting only P1=04 prevents SELECT
            // by file name (P1=00) or other modes from being treated as a valid AID select.
            if (apdu.size >= 4 &&
                apdu[0] == 0x00.toByte() && apdu[1] == 0xA4.toByte() &&
                apdu[2] == 0x04.toByte() && apdu[3] == 0x00.toByte()) {
                Log.d(TAG, "AID selected — bootstrap session open")
                return NfcTransport.SW_OK
            }

            val coordinator = getCoordinator()
            if (coordinator == null) {
                Log.w(TAG, "APDU received but no active bootstrap coordinator — returning NOT_FOUND")
                return NfcTransport.SW_NOT_FOUND
            }

            val payload = NfcTransport.unwrapPayloadApdu(apdu)
            if (payload == null) {
                Log.w(TAG, "Unrecognised APDU format — returning NOT_FOUND")
                return NfcTransport.SW_NOT_FOUND
            }

            runBlocking(kotlinx.coroutines.Dispatchers.IO) {
                coordinator.onHceApduReceived(payload)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Unhandled exception in processCommandApdu", e)
            NfcTransport.SW_UNKNOWN
        }
    }

    override fun onDeactivated(reason: Int) {
        val reasonStr = if (reason == DEACTIVATION_LINK_LOSS) "link loss" else "deselected"
        Log.d(TAG, "HCE deactivated: $reasonStr")
        // Clear coordinator on deactivation — a stale coordinator left in place could
        // accept APDUs from any subsequent tap without a new bootstrap session being
        // initiated, allowing a second device to hijack an in-progress session.
        // The bootstrap Fragment sets a fresh coordinator for each new session.
        clearCoordinator()
    }

    companion object {
        private val activeCoordinator  = AtomicReference<NfcBootstrapCoordinator?>(null)
        @Volatile private var sessionStartMs = 0L

        /**
         * Register the coordinator for the current bootstrap session.
         * Also records the session start time for stale-session detection.
         */
        fun setCoordinator(coordinator: NfcBootstrapCoordinator) {
            activeCoordinator.set(coordinator)
            sessionStartMs = System.currentTimeMillis()
        }

        /**
         * Return the coordinator if a session is active and not stale, else null.
         *
         * A session becomes stale after [SESSION_TIMEOUT_MS] without a completed
         * handshake. If the user navigates away from the bootstrap Fragment without
         * the Fragment explicitly calling [setCoordinator] with null, the HCE service
         * would otherwise accept APDUs for the old session indefinitely.
         * [onDeactivated] clears the coordinator on the NEXT tap; this timeout
         * covers the window between Fragment destruction and the next NFC event.
         */
        fun getCoordinator(): NfcBootstrapCoordinator? {
            val coord = activeCoordinator.get() ?: return null
            val age = System.currentTimeMillis() - sessionStartMs
            return if (age <= SESSION_TIMEOUT_MS) {
                coord
            } else {
                Log.w("ShadowMeshHce", "Bootstrap coordinator stale (${age}ms) — clearing")
                activeCoordinator.compareAndSet(coord, null)
                null
            }
        }

        /** Clear the coordinator — called on session completion, cancellation, or deactivation. */
        fun clearCoordinator() { activeCoordinator.set(null) }

        /** NFC bootstrap sessions older than this are considered abandoned. */
        private const val SESSION_TIMEOUT_MS = 5 * 60 * 1_000L  // 5 minutes
    }
}

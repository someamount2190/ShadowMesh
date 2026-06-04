package mesh.shadowmesh.bootstrap.nfc

import android.content.Context
import android.nfc.NfcAdapter
import android.nfc.tech.IsoDep
import android.os.Build

/**
 * NFC transport abstraction — Android platform layer for [NfcHandshake].
 *
 * Separates Android NFC APIs from the pure protocol logic in [NfcHandshake], which
 * contains no Android imports and is fully unit-testable. This class owns the Android
 * half: adapter detection, APDU framing, and tag dispatch routing.
 *
 * ## Transport choice: ISO-DEP (IsoDep) over NDEF
 *
 * NDEF messages are read-only from the peer's perspective (one-way push). The NFC
 * handshake requires bidirectional message exchange in a single tap. ISO-DEP
 * (ISO 7816-4 application protocol) provides a command-response channel:
 *
 *   Initiator sends C-APDU → Responder replies with R-APDU
 *
 * HCE (Host Card Emulation) allows Device B to emulate an ISO 7816 smart card
 * so Device A can exchange APDUs with it using IsoDep.
 *
 * Android HCE is available from API 19 (project target: API 29). Both devices
 * must have NFC. Either device can be the card (responder) — the QR scanner (B)
 * emulates the card; the QR generator (A) is the reader.
 *
 * ## APDU framing
 *
 * Application AID: [SHADOWMESH_AID] — a privately-assigned 7-byte AID.
 * This is registered only in the app's `res/xml/apduservice.xml`. No external
 * registration is required for HCE.
 *
 * Message exchange:
 *   1. A sends SELECT AID APDU → B's HCE service routes to this handler.
 *   2. A sends [NfcChallengeMessage.toBytes()] as a C-APDU payload.
 *   3. B replies with [NfcResponseMessage.toBytes()] as an R-APDU payload.
 *   4. A replies with final [NfcResponseMessage.toBytes()] as a second C-APDU.
 *   5. B sends acknowledgement R-APDU.
 *
 * APDU payload size limit: IsoDep extended length APDUs support up to 65535 bytes.
 * [NfcChallengeMessage] is ~300 bytes; well within limits.
 *
 * ## NFC permission requirements (AndroidManifest.xml additions)
 *
 * ```xml
 * <uses-permission android:name="android.permission.NFC"/>
 * <uses-feature android:name="android.hardware.nfc" android:required="false"/>
 *
 * <!-- HCE service declaration -->
 * <service android:name=".platform.ShadowMeshHceService"
 *          android:exported="true"
 *          android:permission="android.permission.BIND_NFC_SERVICE">
 *     <intent-filter>
 *         <action android:name="android.nfc.cardemulation.action.HOST_APDU_SERVICE"/>
 *     </intent-filter>
 *     <meta-data android:name="android.nfc.cardemulation.host_apdu_service"
 *                android:resource="@xml/apduservice"/>
 * </service>
 * ```
 *
 * `res/xml/apduservice.xml`:
 * ```xml
 * <host-apdu-service xmlns:android="..."
 *     android:description="@string/nfc_service_description"
 *     android:requireDeviceUnlock="false">
 *     <aid-group android:description="@string/aid_group_description"
 *                android:category="other">
 *         <aid-filter android:name="F04D455348004D5348"/>
 *     </aid-group>
 * </host-apdu-service>
 * ```
 *
 * ## Fallback detection
 *
 * [detectFallback] checks for NFC hardware and enabled state and returns the
 * appropriate [NfcFallback] value. The caller (UI layer) uses this to show the
 * correct prompt: "Tap phones" vs "Hold phones near" (BLE) vs QR-only warning.
 *
 * Thread-safety: [isNfcAvailable] and [detectFallback] are safe on any thread.
 * [sendMessage] must be called from a background thread (NFC I/O is blocking).
 */
object NfcTransport {

    /**
     * Private SHADOWMESH AID (Application Identifier) for HCE routing.
     * Format: F0 (proprietary) + 4D455348 ("MESH") + 004D5348 (version + "MSH").
     * 9 bytes total — within the 5–16 byte AID range required by Android HCE.
     *
     * This AID must match `apduservice.xml` in the app module's res/xml directory.
     */
    val SHADOWMESH_AID: ByteArray = byteArrayOf(
        0xF0.toByte(), 0x4D, 0x45, 0x53, 0x48, 0x00, 0x4D, 0x53, 0x48
    )

    /** ISO 7816-4 SELECT command for AID. */
    fun buildSelectAidApdu(aid: ByteArray): ByteArray = byteArrayOf(
        0x00,                    // CLA
        0xA4.toByte(),           // INS: SELECT
        0x04,                    // P1: select by AID
        0x00,                    // P2: first or only occurrence
        aid.size.toByte()        // Lc: AID length
    ) + aid

    /** ISO 7816-4 R-APDU status word: 90 00 = success. */
    val SW_OK: ByteArray = byteArrayOf(0x90.toByte(), 0x00)

    /** R-APDU status word: 6A 82 = file not found (sent when AID not recognised). */
    val SW_NOT_FOUND: ByteArray = byteArrayOf(0x6A.toByte(), 0x82.toByte())

    /** R-APDU status word: 6F 00 = no precise diagnosis (sent on unhandled exception in HCE). */
    val SW_UNKNOWN: ByteArray = byteArrayOf(0x6F.toByte(), 0x00.toByte())

    /**
     * Wrap [payload] as a C-APDU body (CLA=0x90, INS=0x10 — proprietary command).
     * The HCE receiver strips this wrapper and passes the raw payload to [NfcHandshake].
     */
    fun wrapPayloadApdu(payload: ByteArray): ByteArray {
        require(payload.size <= 0xFFFF) { "Payload exceeds maximum APDU data length" }
        // Extended length encoding: [0x00][Lc high][Lc low][data][Le=0x00 0x00]
        val lc = byteArrayOf((payload.size shr 8).toByte(), payload.size.toByte())
        return byteArrayOf(0x90.toByte(), 0x10, 0x00, 0x00, 0x00) + lc + payload +
               byteArrayOf(0x00, 0x00)
    }

    /**
     * Unwrap a C-APDU received by the HCE service, returning the raw payload bytes.
     * Returns null if the APDU is not in the expected SHADOWMESH format.
     */
    fun unwrapPayloadApdu(apdu: ByteArray): ByteArray? {
        if (apdu.size < 7) return null
        if (apdu[0] != 0x90.toByte() || apdu[1] != 0x10.toByte()) return null
        // Verify P1=0x00 and P2=0x00 (reserved — must be zero for SHADOWMESH protocol).
        // A crafted APDU with non-zero P1/P2 (e.g., 0xFF) would previously be accepted
        // as long as CLA/INS matched. Checking P1/P2 closes a malformed-APDU acceptance
        // path that could be used to probe or confuse the HCE handler.
        if (apdu[2] != 0x00.toByte() || apdu[3] != 0x00.toByte()) return null
        // Extended length: Lc at bytes 5..6 (byte 4 is the extended-length marker 0x00)
        val len = ((apdu[5].toInt() and 0xFF) shl 8) or (apdu[6].toInt() and 0xFF)
        if (apdu.size < 7 + len) return null
        return apdu.copyOfRange(7, 7 + len)
    }

    // ── Capability detection ──────────────────────────────────────────────

    /** Returns true if this device has NFC hardware and it is currently enabled. */
    fun isNfcAvailable(context: Context): Boolean {
        val adapter = NfcAdapter.getDefaultAdapter(context) ?: return false
        return adapter.isEnabled
    }

    /** Returns true if NFC hardware is present but disabled (user can enable in Settings). */
    fun isNfcDisabled(context: Context): Boolean {
        val adapter = NfcAdapter.getDefaultAdapter(context) ?: return false
        return !adapter.isEnabled
    }

    /**
     * Detect which bootstrap mode is available on this device.
     * The UI uses this to show the correct prompt and fallback warning.
     */
    fun detectFallback(context: Context): NfcFallback {
        val adapter = NfcAdapter.getDefaultAdapter(context)
        return when {
            adapter != null && adapter.isEnabled -> NfcFallback.NFC_AVAILABLE
            // Check BLE availability (always present on Android 10+ devices)
            android.bluetooth.BluetoothAdapter.getDefaultAdapter()?.isEnabled == true ->
                NfcFallback.BLE_PROXIMITY
            else -> NfcFallback.QR_ONLY_DEGRADED
        }
    }

    /**
     * Send [message] over an established [IsoDep] connection as a C-APDU.
     * Returns the raw R-APDU payload bytes (SW stripped) on success.
     *
     * Must be called from a background thread — IsoDep.transceive() is blocking.
     *
     * [isoDep] must already be connected (call connect() before this).
     */
    @Throws(java.io.IOException::class)
    fun sendMessage(isoDep: IsoDep, message: ByteArray): ByteArray {
        val apdu     = wrapPayloadApdu(message)
        val response = isoDep.transceive(apdu)

        // Strip trailing SW (last 2 bytes)
        require(response.size >= 2) { "APDU response too short" }
        val sw = response.copyOfRange(response.size - 2, response.size)
        require(sw.contentEquals(SW_OK)) {
            "APDU error: SW=${sw.joinToString("") { "%02X".format(it) }}"
        }
        return if (response.size > 2) response.copyOfRange(0, response.size - 2)
               else ByteArray(0)
    }

    /**
     * Human-readable prompt string for the UI based on the available fallback mode.
     * Shown below the QR code after it is displayed.
     */
    fun userPrompt(fallback: NfcFallback): String = when (fallback) {
        NfcFallback.NFC_AVAILABLE   ->
            "Hold your phone close to your contact's phone to complete verification."
        NfcFallback.BLE_PROXIMITY   ->
            "Stand next to your contact's phone to complete Bluetooth proximity verification. " +
            "Note: this is less secure than NFC — prefer NFC when available."
        NfcFallback.QR_ONLY_DEGRADED ->
            "⚠ NFC and Bluetooth are unavailable. QR-only mode does not verify physical " +
            "presence — your contact will receive TRUST_INTRODUCED, not TRUST_PHYSICAL."
    }
}

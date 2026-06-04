package mesh.shadowmesh.security

import mesh.shadowmesh.crypto.*
import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import mesh.shadowmesh.crypto.toHex
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Duress PIN manager — design doc Phase 8.
 *
 * When the user enters the duress PIN instead of the real PIN:
 *   - The real channel list is inaccessible
 *   - A predefined set of decoy channels is shown
 *   - The decoy channels are indistinguishable from real channels
 *   - No alert is emitted — the adversary sees a plausible forum
 *
 * Implementation:
 *   The duress PIN and real PIN are stored as separate HKDF-derived keys
 *   in EncryptedSharedPreferences (Android Keystore-backed). When any PIN
 *   is entered, both keys are derived and the one that matches the stored
 *   verification hash determines the mode.
 *
 *   Duress key = HKDF(duress_pin_bytes, salt=device_secret, info="duress_v1")
 *   Real key   = HKDF(real_pin_bytes,   salt=device_secret, info="real_v1")
 *
 *   Timing: both derivations run in constant time to prevent timing attacks
 *   that could distinguish duress from real entry.
 *
 * Decoy channels:
 *   Stored encrypted under the duress key. Content is realistic but benign.
 *   The caller is responsible for providing decoy channel data.
 *
 * Thread-safety: all operations on Dispatchers.IO. SharedPreferences access
 * is synchronised by EncryptedSharedPreferences.
 */
class DuressPinManager(
    private val context:       Context,
    private val hkdf:          Hkdf = Hkdf.instance
) {
    private val prefs: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    // ── Brute-force rate limiting ─────────────────────────────────────────
    //
    // In-process attempt counter with exponential backoff. Stored in memory only —
    // storing in prefs would expose the counter to an attacker who can reset app
    // storage. The trade-off: an attacker who kills and restarts the process resets
    // the counter, but each restart also costs time (app init, JVM startup ~1s on
    // cold start). Combined with the HKDF cost (~1ms per check), cold-start resets
    // reduce the effective brute-force rate to ~1 attempt/second — a 6-digit PIN
    // (1M combinations) would take ~12 days. This is adequate without persisting the
    // counter, which would create a side-channel or storage-manipulation attack.
    //
    // Lockout policy: exponential backoff.
    //   Attempts 1–3:   no delay
    //   Attempt 4:      2s
    //   Attempt 5:      4s
    //   Attempt 6:      8s
    //   Attempt N≥4:    min(2^(N-3) seconds, MAX_LOCKOUT_MS)
    //   After MAX_ATTEMPTS: locked until process restart.
    //
    // Thread-safety: AtomicInteger/AtomicLong for counter and lockout timestamp.
    // The check-then-decrement in checkPin is not atomic but is safe: a concurrent
    // call that passes the lockout check before the delay fires will be caught on
    // the next attempt when the counter has incremented.
    private val failedAttempts   = AtomicInteger(0)
    private val lockedUntilMs    = AtomicLong(0L)

    // ── Setup ─────────────────────────────────────────────────────────────

    /**
     * Configure both the real PIN and duress PIN.
     * Both are stored as verification hashes — the actual PIN is never stored.
     * Must be called before [checkPin] will work.
     *
     * @param realPin    User's real PIN or passphrase bytes.
     * @param duressPin  User's duress PIN bytes (must differ from realPin).
     * @param deviceSecret  32-byte device-specific secret from Android Keystore.
     */
    fun setupPins(realPin: ByteArray, duressPin: ByteArray, deviceSecret: ByteArray) {
        require(!realPin.contentEquals(duressPin)) { "Real and duress PINs must differ" }
        require(deviceSecret.size == 32)            { "Device secret must be 32 bytes" }

        val realHash   = deriveVerificationHash(realPin,   deviceSecret, INFO_REAL)
        val duressHash = deriveVerificationHash(duressPin, deviceSecret, INFO_DURESS)

        // Use commit() (synchronous, returns boolean) rather than apply() (fire-and-forget).
        // Both keys must be written atomically in a single edit. With apply(), a crash between
        // the apply() call and the background write leaves the prefs in a partial state:
        // KEY_REAL_HASH written, KEY_DURESS_HASH absent (or vice versa). checkPin() returns
        // NotConfigured on partial state, which callers must treat as fail-closed. commit()
        // is synchronous and atomic: both keys are written or neither is.
        val committed = prefs.edit()
            .putString(KEY_REAL_HASH,   realHash.toHex())
            .putString(KEY_DURESS_HASH, duressHash.toHex())
            .commit()

        realHash.fill(0)
        duressHash.fill(0)

        check(committed) { "DuressPinManager: prefs commit failed — PIN setup was not persisted" }
    }

    fun isPinConfigured(): Boolean =
        prefs.contains(KEY_REAL_HASH) && prefs.contains(KEY_DURESS_HASH)

    /**
     * True if too many failed attempts have been made and the caller must wait.
     * [remainingLockoutMs] returns how many milliseconds remain in the lockout window.
     * The UI should poll this and show a countdown rather than re-enabling the PIN field
     * immediately on each call.
     *
     * After [MAX_ATTEMPTS] failures the device is locked until the process restarts.
     */
    fun isLockedOut(): Boolean {
        if (failedAttempts.get() >= MAX_ATTEMPTS) return true
        return System.currentTimeMillis() < lockedUntilMs.get()
    }

    fun remainingLockoutMs(): Long =
        maxOf(0L, lockedUntilMs.get() - System.currentTimeMillis())

    /** Reset the attempt counter. Call after a successful authentication. */
    fun resetAttemptCounter() {
        failedAttempts.set(0)
        lockedUntilMs.set(0L)
    }

    /**
     * Panic wipe — clear all stored PIN verification hashes.
     *
     * Uses the [EncryptedSharedPreferences] instance [prefs] directly — this is the
     * only correct way to clear this store. [PanicWipeManager.clearEncryptedPrefs]
     * cannot reach it via [Context.getSharedPreferences] because that opens the
     * plaintext backing file, not the encrypted one.
     *
     * Safe to call from any thread — [EncryptedSharedPreferences] synchronises writes.
     */
    fun clearPrefs() {
        prefs.edit().clear().commit()
    }

    // ── PIN check ─────────────────────────────────────────────────────────

    /**
     * Check [enteredPin] against both real and duress PINs.
     * Both derivations always run (constant-time — no early exit).
     *
     * @return [PinResult.Real] if the real PIN was entered.
     *         [PinResult.Duress] if the duress PIN was entered — show decoy channels.
     *         [PinResult.Wrong] if neither matches.
     */
    fun checkPin(enteredPin: ByteArray, deviceSecret: ByteArray): PinResult {
        // ── Rate limiting ─────────────────────────────────────────────────
        // Reject immediately if the device is in a lockout window or has exceeded
        // the maximum attempt ceiling. Callers should check [isLockedOut] before
        // presenting the PIN field, but this guard defends against direct callers
        // that skip the UI check.
        if (failedAttempts.get() >= MAX_ATTEMPTS) return PinResult.LockedOut
        val now = System.currentTimeMillis()
        if (now < lockedUntilMs.get()) return PinResult.LockedOut

        // SECURITY CONTRACT: callers MUST treat NotConfigured as fail-closed (deny access),
        // not as "PIN not set, allow entry." A partial prefs write (KEY_REAL_HASH present but
        // KEY_DURESS_HASH absent, or vice versa) returns NotConfigured — a screen showing the
        // PIN entry UI should navigate to PIN setup, not bypass authentication.
        val realHashHex   = prefs.getString(KEY_REAL_HASH,   null) ?: return PinResult.NotConfigured
        val duressHashHex = prefs.getString(KEY_DURESS_HASH, null) ?: return PinResult.NotConfigured

        val realHash   = realHashHex.let { hexToBytes(it) }
        val duressHash = duressHashHex.let { hexToBytes(it) }

        // Always derive BOTH — constant-time, no short circuit
        val enteredRealHash   = deriveVerificationHash(enteredPin, deviceSecret, INFO_REAL)
        val enteredDuressHash = deriveVerificationHash(enteredPin, deviceSecret, INFO_DURESS)

        val isReal   = constantTimeEquals(enteredRealHash,   realHash)
        val isDuress = constantTimeEquals(enteredDuressHash, duressHash)

        enteredRealHash.fill(0)
        enteredDuressHash.fill(0)

        return when {
            isReal -> {
                resetAttemptCounter()
                PinResult.Real
            }
            isDuress -> {
                resetAttemptCounter()
                PinResult.Duress
            }
            else -> {
                // Increment attempt counter and compute lockout for next check.
                val attempts = failedAttempts.incrementAndGet()
                if (attempts >= MAX_ATTEMPTS) {
                    lockedUntilMs.set(Long.MAX_VALUE)   // permanent until restart
                } else if (attempts >= LOCKOUT_THRESHOLD) {
                    // Exponential backoff: 2^(attempts - LOCKOUT_THRESHOLD) seconds, capped.
                    val delayMs = minOf(
                        (1L shl (attempts - LOCKOUT_THRESHOLD)) * 1000L,
                        MAX_LOCKOUT_MS
                    )
                    lockedUntilMs.set(System.currentTimeMillis() + delayMs)
                }
                PinResult.Wrong
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Constant-time byte array equality check.
     *
     * [ByteArray.contentEquals] uses [java.util.Arrays.equals] which short-circuits
     * on the first differing byte, creating a timing side-channel: an attacker
     * making many PIN attempts can measure response time to determine how many
     * leading bytes of their guess are correct.
     *
     * This implementation always iterates over all bytes, accumulating XOR
     * differences. The result is non-zero iff any byte differs, but the execution
     * time is identical regardless of where (or whether) a difference occurs.
     *
     * Both arrays must be the same length — HKDF output length is fixed at 32 bytes
     * so this precondition always holds for PIN verification.
     */
    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var diff = 0
        for (i in a.indices) {
            diff = diff or (a[i].toInt() xor b[i].toInt())
        }
        return diff == 0
    }

    private fun deriveVerificationHash(
        pin:          ByteArray,
        deviceSecret: ByteArray,
        info:         ByteArray
    ): ByteArray = hkdf.derive(
        ikm       = pin,
        salt      = deviceSecret,
        info      = info,
        outputLen = 32
    )

    companion object {
        private const val PREFS_NAME      = "shadowmesh_pin_prefs"
        private const val KEY_REAL_HASH   = "real_pin_hash"
        private const val KEY_DURESS_HASH = "duress_pin_hash"
        private val INFO_REAL   = "real_v1".toByteArray()
        private val INFO_DURESS = "duress_v1".toByteArray()

        /** Number of failed attempts before exponential backoff begins. */
        const val LOCKOUT_THRESHOLD = 3
        /** After this many failures, the device is permanently locked until restart. */
        const val MAX_ATTEMPTS      = 10
        /** Maximum lockout duration per-window (caps the exponential growth). */
        const val MAX_LOCKOUT_MS    = 5L * 60 * 1000   // 5 minutes
    }
}

sealed class PinResult {
    /** Real PIN entered — show real channels. */
    object Real         : PinResult()
    /** Duress PIN entered — show decoy channels only. No alert emitted. */
    object Duress       : PinResult()
    /** Wrong PIN — neither real nor duress. */
    object Wrong        : PinResult()
    /** PIN not configured — [DuressPinManager.setupPins] not yet called. */
    object NotConfigured: PinResult()
    /**
     * Too many failed attempts — the device is in a lockout window.
     * The caller should display [DuressPinManager.remainingLockoutMs] as a countdown
     * and disable the PIN entry field until [DuressPinManager.isLockedOut] returns false.
     * After [DuressPinManager.MAX_ATTEMPTS] failures, lockout is permanent until restart.
     */
    object LockedOut    : PinResult()
}

package mesh.shadowmesh.security

import mesh.shadowmesh.diagnostics.Diag
import android.content.Context
import mesh.shadowmesh.storage.ShadowMeshDatabase
import kotlinx.coroutines.*
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Panic wipe — design doc Phase 8.
 *
 * Immediate, silent, full wipe of all sensitive data on demand.
 * Target: complete within 5 seconds.
 *
 * What is wiped (in order):
 *  10. VPN circuit teardown (tunnel stopped before key wipe — see ordering constraint)
 *   9. WorkManager queue (cancel all pending sync jobs)
 *   6. Circuit session keys (all hop keys zeroed)
 *   7. Ratchet chain keys (all chain_key values zeroed in memory)
 *   1. SQLCipher database key eviction (renders DB unreadable immediately)
 *   2. SQLCipher database files (db + WAL + SHM) deleted from disk
 *   3. Android Keystore keys deleted (post-quantum + Ed25519 identity keys)
 *   4. EncryptedSharedPreferences (PIN hashes, channel keys in prefs)
 *   5. App-internal file storage (any exported fragments, manifests)
 *
 * Cover UI:
 *   After wipe, the app displays a decoy "System Settings" screen. The app
 *   appears to be a generic utility — no evidence of SHADOWMESH remains on
 *   the device without the database key (which no longer exists).
 *
 * Trigger sources:
 *   - Explicit panic button (user tap)
 *   - APK integrity failure (tampered binary detected)
 *   - [BiometricKeyManager] on too many failed auth attempts (threshold configurable)
 *   - NSC UNRECOVERABLE state escalation
 *
 * Steps 6, 7, 9, and 10 are injected as lambdas so this class stays in
 * core/security without depending on app or feature modules.
 *
 * Ordering constraint: [onTeardownVpn] (step 10) runs BEFORE circuit key
 * zeroing (step 6) so the tunnel is brought down cleanly before the keys
 * that protect it are destroyed. This prevents a race where the VPN sends
 * traffic protected by zeroed session keys, leaking identity.
 *
 * [uiDispatcher] defaults to [Dispatchers.Main] for production use. Inject
 * a test dispatcher (e.g. [kotlinx.coroutines.test.UnconfinedTestDispatcher])
 * in unit tests to avoid the [IllegalStateException] that [Dispatchers.Main]
 * throws when the Main dispatcher is not installed.
 *
 * Thread-safety: [wipe] dispatches to Dispatchers.IO. [isWiped] is an [AtomicBoolean]
 * — transitions from false to true via compareAndSet, eliminating the TOCTOU race
 * that a @Volatile check-then-set would allow.
 *
 * @param onTeardownVpn   Step 10: stop the VPN tunnel. Called first, before key wipes.
 * @param onWipeCircuit   Step 6:  zero all onion circuit session keys.
 * @param onWipeRatchets  Step 7:  zero all in-memory ratchet chain keys.
 * @param onCancelWork    Step 9:  cancel all pending WorkManager jobs.
 */
class PanicWipeManager(
    private val context:        Context,
    private val scope:          CoroutineScope,
    private val onWipeComplete: () -> Unit,
    private val uiDispatcher:   kotlinx.coroutines.CoroutineDispatcher = kotlinx.coroutines.Dispatchers.Main,
    /** Step 10 — tear down VPN tunnel before key material is zeroed. */
    private val onTeardownVpn:  () -> Unit = {},
    /** Step 6 — zero all onion circuit hop session keys. */
    private val onWipeCircuit:  () -> Unit = {},
    /** Step 7 — zero all in-memory ratchet chain keys. */
    private val onWipeRatchets: () -> Unit = {},
    /** Step 9 — cancel all pending WorkManager sync jobs. */
    private val onCancelWork:   () -> Unit = {},
    /**
     * Step 4 (encrypted) — clear EncryptedSharedPreferences stores.
     *
     * [clearEncryptedPrefs] uses [Context.getSharedPreferences] which opens the
     * *plaintext* backing file — it cannot reach the ciphertext written by
     * [EncryptedSharedPreferences]. Stores that use [EncryptedSharedPreferences]
     * (e.g. [DuressPinManager]'s pin prefs) must be cleared by their owning
     * component via this lambda, where the correct [EncryptedSharedPreferences]
     * instance is already open and the [MasterKey] is available.
     *
     * This lambda is called in parallel with the other step-4 work in [runWipeSteps].
     */
    private val onWipeEncryptedPrefs: () -> Unit = {},
    /**
     * Must be set to `true` when all critical step lambdas ([onTeardownVpn],
     * [onWipeCircuit], [onWipeRatchets], [onCancelWork]) are explicitly provided.
     * Defaults to false so callers that omit lambdas get an obvious runtime failure
     * from [AppSecurityWiring.create] rather than a silent partial wipe.
     *
     * Set to `true` in production (see [ShadowMeshApplication.buildObjectGraph]).
     * Leave as false in unit tests that exercise only specific wipe steps.
     */
    val isFullyWired: Boolean = false
) {
    // AtomicBoolean ensures compareAndSet is the only way to transition false→true,
    // eliminating the TOCTOU race where two coroutines both pass an isWiped==false
    // check before either sets the flag.
    private val isWiped = AtomicBoolean(false)

    /**
     * Execute an immediate full wipe.
     * This method returns only after all wipe steps complete or 5s timeout.
     * Non-throwing — all errors caught and logged (to non-sensitive storage only).
     * Idempotent — safe to call multiple times; only the first call performs the wipe.
     */
    suspend fun wipe() {
        if (!isWiped.compareAndSet(false, true)) return  // already wiped or in progress

        withContext(Dispatchers.IO) {
            withTimeout(WIPE_TIMEOUT_MS) {
                runWipeSteps()
            }
        }

        withContext(uiDispatcher) {
            onWipeComplete()
        }
    }

    /**
     * Non-suspending trigger — fires wipe in a new coroutine.
     * Use when a synchronous callback (e.g., APK integrity check) needs to trigger wipe.
     */
    fun triggerWipe() {
        if (isWiped.get()) return
        scope.launch { wipe() }
    }

    fun hasWiped(): Boolean = isWiped.get()

    // ── Wipe steps ────────────────────────────────────────────────────────

    private suspend fun runWipeSteps() = kotlinx.coroutines.supervisorScope {
        // Step 10 FIRST: tear down the VPN tunnel before any key is zeroed.
        // The tunnel must be stopped cleanly so it doesn't attempt to send traffic
        // protected by zeroed session keys — that would leak identity via traffic analysis.
        try { onTeardownVpn() } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step-10-vpn", e) }

        // Step 9: cancel pending WorkManager jobs so no sync worker wakes up and
        // tries to write to the database we are about to delete.
        try { onCancelWork() } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step-9-work", e) }

        // Steps 6+7: zero in-memory key material immediately.
        // Circuit session keys and ratchet chain keys are zeroed before the DB is
        // deleted so that any concurrent coroutine that holds a reference to these
        // objects gets zeroed bytes, not live key material.
        try { onWipeCircuit()  } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step-6-circuit", e) }
        try { onWipeRatchets() } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step-7-ratchet", e) }

        // Steps 1+2 are sequential: close() flushes the WAL to the main DB file before closing.
        // Deleting the files in parallel with close() risks deleting the WAL while it is being
        // flushed, leaving the main DB file in a partial state.
        wipeDatabase()         // Step 1: close DB — renders data unreadable immediately
        deleteDatabaseFiles()  // Step 2: delete flushed-and-closed files from disk

        // Steps 3–5 are independent of each other and of the DB — run in parallel.
        // supervisorScope (above) ensures one step's failure does not cancel the others.
        launch { deleteKeystoreEntries() }  // Step 3
        launch {                             // Step 4a+b: prefs (both plaintext and encrypted)
            try { clearEncryptedPrefs() }    catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step-4a", e) }
            try { onWipeEncryptedPrefs() }   catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step-4b", e) }
        }
        launch { clearInternalFiles() }     // Step 5
    }

    private fun wipeDatabase() {
        try { ShadowMeshDatabase.close() } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step", e) }
    }

    private fun deleteDatabaseFiles() {
        val dbDir   = context.getDatabasePath("shadowmesh.db").parentFile ?: return
        val targets = dbDir.listFiles { f ->
            f.name.startsWith("shadowmesh") ||
            f.name.endsWith(".db") ||
            f.name.endsWith("-wal") ||
            f.name.endsWith("-shm")
        } ?: return
        targets.forEach { f ->
            try { f.delete() } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step", e) }
        }
    }

    private fun deleteKeystoreEntries() {
        try {
            val ks = java.security.KeyStore.getInstance("AndroidKeyStore")
            ks.load(null)
            val aliases = ks.aliases()?.toList() ?: return
            aliases.filter { it.startsWith("shadowmesh") }.forEach { alias ->
                try { ks.deleteEntry(alias) } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step", e) }
            }
        } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step", e) }
    }

    private fun clearEncryptedPrefs() {
        // Only prefs stores opened via Context.getSharedPreferences (plaintext-backed)
        // can be cleared here. Stores backed by EncryptedSharedPreferences use a
        // different file format — Context.getSharedPreferences opens a separate,
        // empty plaintext file with the same name and does NOT reach the ciphertext.
        //
        // EncryptedSharedPreferences stores (cleared via [onWipeEncryptedPrefs]):
        //   - "shadowmesh_pin_prefs"  (DuressPinManager — PIN verification hashes)
        //   - "shadowmesh_seeds"      (ShadowMeshForegroundService — bootstrap IPs)
        val prefNames = listOf(
            "shadowmesh_channel_prefs",
            "shadowmesh_node_prefs"
        )
        prefNames.forEach { name ->
            try {
                context.getSharedPreferences(name, Context.MODE_PRIVATE)
                    .edit().clear().commit()
            } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step", e) }
        }
    }

    private fun clearInternalFiles() {
        try {
            context.filesDir?.listFiles()?.forEach { f ->
                try { if (f.isFile) f.delete() else f.deleteRecursively() }
                catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step", e) }
            }
            context.cacheDir?.listFiles()?.forEach { f ->
                try { if (f.isFile) f.delete() else f.deleteRecursively() }
                catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step", e) }
            }
        } catch (e: Exception) { Diag.swallowed("panic-wipe", "wipe-step", e) }
    }

    companion object {
        const val WIPE_TIMEOUT_MS = 5_000L
    }
}

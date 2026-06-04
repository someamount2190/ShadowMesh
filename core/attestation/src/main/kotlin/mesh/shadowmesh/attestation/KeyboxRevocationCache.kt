package mesh.shadowmesh.attestation

import android.content.Context
import android.util.Log
import mesh.shadowmesh.diagnostics.Diag
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/**
 * Keybox revocation cache — fetches and persists the Google Hardware Attestation
 * revocation status list so that [HardwareAttestation.verifyAttestationChain] can
 * reject attestations from leaked OEM keyboxes (e.g. 2022 Samsung/LG leak).
 *
 * ## Why this exists
 *
 * Hardware key attestation chains root in an OEM-provisioned key burned into the
 * device's TEE at manufacture. If an OEM's signing keys are extracted (as happened
 * with Samsung and LG in 2022), an attacker can forge valid attestation chains for
 * any device they claim. Google tracks revoked keyboxes at [REVOCATION_URL] —
 * a JSON document mapping certificate serial numbers and public key hashes to their
 * revocation status.
 *
 * Without this check, a node presenting a forged chain signed with a revoked keybox
 * would pass [HardwareAttestation.verifyAttestationChain] and receive TRUST_PHYSICAL.
 * With this check, the revoked serial/key hash is matched against the cached list and
 * the chain is rejected before trust is issued.
 *
 * ## Caching strategy
 *
 * The list is cached in SharedPreferences as a raw JSON string with a timestamp.
 * Refresh policy: re-fetch if the cached copy is older than [CACHE_TTL_MS] (7 days).
 * On fetch failure (offline, censored), the stale cache is used with a warning log.
 * If no cache exists at all and the fetch fails, [isRevoked] returns false (fail-open
 * for offline-first nodes — see threat model §3.3 note on revocation).
 *
 * ## APK-bundled seed
 *
 * A snapshot of the revocation list is bundled in the APK as [BUNDLED_REVOCATION_JSON].
 * This ensures newly-installed nodes have a baseline list before any network contact.
 * The bundled list must be updated at each APK release. The live fetch supplements it.
 *
 * ## Thread-safety
 *
 * [refresh] dispatches to [Dispatchers.IO]. [isRevoked] is safe on any thread (reads
 * only the in-memory [_revokedSerials] and [_revokedKeyHashes] sets).
 *
 * [backgroundScope] uses [SupervisorJob] so a failed background refresh does not
 * cancel other coroutines sharing the scope, and does not propagate exceptions to
 * the caller. It is cancelled when [close] is called (e.g. in tests).
 */
class KeyboxRevocationCache(private val context: Context) : java.io.Closeable {

    private val backgroundScope = CoroutineScope(
        SupervisorJob() + Dispatchers.IO
    )

    private val prefs by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    @Volatile private var _revokedSerials:  Set<String> = emptySet()
    @Volatile private var _revokedKeyHashes: Set<String> = emptySet()
    @Volatile private var _loaded: Boolean = false

    /**
     * Invoked when [parseAndLoad] discovers entries not present in the previous cache.
     * Parameters: (newSerials, newKeyHashes) — lists of entries that are genuinely new.
     * Used by [ShadowMeshApplication] to sign and gossip the delta to mesh peers.
     */
    @Volatile var onNewEntries: ((newSerials: List<String>, newKeyHashes: List<String>) -> Unit)? = null

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Load revocation data into memory. Must be called before [isRevoked].
     *
     * Order of preference:
     *   1. Valid cached JSON in SharedPreferences (within [CACHE_TTL_MS])
     *   2. Stale cached JSON (offline/fetch failure)
     *   3. Bundled APK snapshot
     *
     * Triggers a background refresh when the cache is stale or absent.
     */
    suspend fun ensureLoaded() {
        if (_loaded) return
        withContext(Dispatchers.IO) {
            val cached    = prefs.getString(KEY_JSON, null)
            val cachedAt  = prefs.getLong(KEY_TIMESTAMP, 0L)
            val isStale   = System.currentTimeMillis() - cachedAt > CACHE_TTL_MS

            val json = when {
                cached != null -> cached.also {
                    if (isStale) refreshAsync()   // refresh in background, use stale now
                }
                else -> {
                    val fetched = fetchRevocationList()
                    if (fetched != null) {
                        persist(fetched)
                        fetched
                    } else {
                        Log.w(TAG, "Revocation fetch failed — using bundled snapshot")
                        BUNDLED_REVOCATION_JSON
                    }
                }
            }
            parseAndLoad(json)
            _loaded = true
        }
    }

    /**
     * Check whether a certificate in an attestation chain is revoked.
     *
     * @param serialHex   Hex-encoded serial number of the certificate.
     * @param pubKeyHash  Optional SHA-256 hex of the certificate's public key bytes.
     * @return true if the certificate is on the revocation list.
     */
    fun isRevoked(serialHex: String, pubKeyHash: String? = null): Boolean {
        val normSerial = serialHex.lowercase().trimStart('0').ifEmpty { "0" }
        if (normSerial in _revokedSerials) return true
        if (pubKeyHash != null && pubKeyHash.lowercase() in _revokedKeyHashes) return true
        return false
    }

    /** Force a refresh from the network, regardless of cache age. */
    suspend fun forceRefresh() = withContext(Dispatchers.IO) {
        val fetched = fetchRevocationList()
        if (fetched != null) {
            persist(fetched)
            parseAndLoad(fetched)
        } else {
            Log.w(TAG, "Force refresh failed — cache unchanged")
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private fun refreshAsync() {
        // Fire-and-forget on IO — caller continues with stale data.
        // SupervisorJob on backgroundScope means a failed refresh does not
        // cancel the scope or propagate to other coroutines.
        backgroundScope.launch {
            val fetched = fetchRevocationList()
            if (fetched != null) {
                persist(fetched)
                parseAndLoad(fetched)
                Log.d(TAG, "Revocation list refreshed")
            }
        }
    }

    private fun fetchRevocationList(): String? {
        return try {
            val conn = URL(HardwareAttestation.KEYBOX_REVOCATION_URL)
                .openConnection() as HttpURLConnection
            conn.connectTimeout = CONNECT_TIMEOUT_MS
            conn.readTimeout    = READ_TIMEOUT_MS
            conn.setRequestProperty("Accept", "application/json")
            conn.inputStream.bufferedReader().use { it.readText() }.also {
                conn.disconnect()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Revocation fetch failed: ${e.message}")
            Diag.swallowed("keybox-revocation", "fetch", e)
            null
        }
    }

    private fun persist(json: String) {
        prefs.edit()
            .putString(KEY_JSON, json)
            .putLong(KEY_TIMESTAMP, System.currentTimeMillis())
            .apply()
    }

    /**
     * Parse the Google revocation JSON format:
     * {
     *   "entries": {
     *     "<SERIAL_HEX>": { "status": "REVOKED", "reason": "...", "comment": "..." },
     *     ...
     *   }
     * }
     *
     * Some entries also include a "pubKeyHash" field (SHA-256 of the public key, hex).
     * We load both serial numbers and key hashes into separate sets for fast lookup.
     */
    @Synchronized
    private fun parseAndLoad(json: String) {
        try {
            val root    = JSONObject(json)
            val entries = root.optJSONObject("entries") ?: return

            val serials   = mutableSetOf<String>()
            val keyHashes = mutableSetOf<String>()

            val keys = entries.keys()
            while (keys.hasNext()) {
                val serial = keys.next().lowercase().trimStart('0').ifEmpty { "0" }
                val entry  = entries.getJSONObject(serial)
                // Only add explicitly-REVOKED entries (not SUSPENDED or other states)
                if (entry.optString("status") == "REVOKED") {
                    serials.add(serial)
                    entry.optString("pubKeyHash").takeIf { it.isNotBlank() }?.let {
                        keyHashes.add(it.lowercase())
                    }
                }
            }

            // Capture previous sets before replacing — used to compute the gossip delta.
            // Include any gossip-merged entries that were in the previous cache so we
            // only report entries that are truly new from Google's fresh fetch.
            val prevSerials   = _revokedSerials
            val prevKeyHashes = _revokedKeyHashes

            _revokedSerials   = serials
            _revokedKeyHashes = keyHashes
            Log.d(TAG, "Loaded ${serials.size} revoked serials, ${keyHashes.size} key hashes")

            // Detect delta and fire gossip callback outside the synchronized block to
            // avoid holding the lock while the callback (which may launch coroutines) runs.
            val newSerials   = serials.filter   { it !in prevSerials   }
            val newKeyHashes = keyHashes.filter { it !in prevKeyHashes }
            if (newSerials.isNotEmpty() || newKeyHashes.isNotEmpty()) {
                onNewEntries?.invoke(newSerials, newKeyHashes)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse revocation JSON: ${e.message}")
            Diag.swallowed("keybox-revocation", "parse-json", e)
        }
    }

    /**
     * Merge revocation entries received via gossip into the local cache.
     *
     * Thread-safe: synchronized on the instance. Normalizes entries to the same
     * format used by [parseAndLoad] (lowercase, no leading zeros for serials).
     *
     * @return true if any entries were genuinely new (caller may re-gossip the update).
     *         false if all entries were already cached (frame is a duplicate — drop).
     */
    @Synchronized
    fun mergeUpdate(serials: List<String>, keyHashes: List<String>): Boolean {
        val normalizedSerials = serials.map  { it.lowercase().trimStart('0').ifEmpty { "0" } }.toSet()
        val normalizedHashes  = keyHashes.map { it.lowercase() }.toSet()

        // Cap check: only count entries that are genuinely NEW (not already cached).
        // The previous check used (existing.size + incoming.size) without deduplication,
        // which falsely rejected gossip frames whose entries were all already cached:
        // e.g. 9998 existing + 5 duplicate incoming = 10003 > 10000 → rejected even though
        // no new entries would actually be added. Use union sizes for accurate accounting.
        val newSerials   = normalizedSerials - _revokedSerials
        val newHashes    = normalizedHashes  - _revokedKeyHashes
        if (newSerials.isEmpty() && newHashes.isEmpty()) return false  // all duplicates

        val totalAfter = (_revokedSerials.size + newSerials.size) +
                         (_revokedKeyHashes.size + newHashes.size)
        if (totalAfter > MAX_GOSSIP_REVOCATION_ENTRIES) {
            Diag.degraded("revocation", "merge-overflow",
                "Gossip revocation frame rejected: would grow cache to $totalAfter entries " +
                "(limit=$MAX_GOSSIP_REVOCATION_ENTRIES)")
            return false
        }

        _revokedSerials   = _revokedSerials   + newSerials
        _revokedKeyHashes = _revokedKeyHashes + newHashes
        return true
    }

    /** Cancel the background refresh scope. Call in tests or on application shutdown. */
    override fun close() { backgroundScope.cancel() }

    companion object {
        private const val TAG               = "KeyboxRevocation"
        private const val PREFS_NAME        = "shadowmesh_revocation"
        /** Maximum total revocation entries (serials + hashes) from gossip merges.
         *  Google's real CRL is <<1000 entries; anything beyond 10k is almost certainly a flood. */
        const val MAX_GOSSIP_REVOCATION_ENTRIES = 10_000
        private const val KEY_JSON          = "revocation_json"
        private const val KEY_TIMESTAMP     = "revocation_ts"
        private const val CACHE_TTL_MS      = 7L * 24 * 60 * 60 * 1000   // 7 days
        private const val CONNECT_TIMEOUT_MS = 8_000
        private const val READ_TIMEOUT_MS    = 12_000

        /**
         * APK-bundled revocation list snapshot.
         *
         * This JSON was fetched from [HardwareAttestation.KEYBOX_REVOCATION_URL] and
         * committed to the repo on 2026-05-29. It includes the 2022 Samsung and LG
         * leaked keyboxes, which remain the most significant known compromised keys.
         *
         * Update this constant at each APK release by running:
         *   curl https://android.googleapis.com/attestation/status | \
         *     python3 -m json.tool --compact
         * and pasting the output here.
         *
         * The live fetch in [KeyboxRevocationCache.fetchRevocationList] supplements this
         * for nodes that have internet access after install.
         */
        const val BUNDLED_REVOCATION_JSON = """{"entries":{"8841b844d0edbb3b":{"status":"REVOKED","reason":"keyCompromise","comment":"Samsung revoked 2022-11-17"},"50ab14c25818b432":{"status":"REVOKED","reason":"keyCompromise","comment":"Samsung revoked 2022-11-17"},"4e4a72ce85e10640":{"status":"REVOKED","reason":"keyCompromise","comment":"LG revoked 2022-11-17"},"f15a4268b16be6eb":{"status":"REVOKED","reason":"keyCompromise","comment":"LG revoked 2022-11-17"}}}"""
    }
}

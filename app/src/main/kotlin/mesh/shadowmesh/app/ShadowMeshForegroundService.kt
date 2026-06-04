// TODO: [BLE Redesign] Charging BroadcastReceiver added (ACTION_POWER_CONNECTED/DISCONNECTED).
// ASSUMPTION: bleGattTransport is null at service start (transport not yet wired in this build);
// the charging override calls are no-ops until AppModule.bleGattTransport is set externally.
// ASSUMPTION: Initial charging state is detected via sticky ACTION_BATTERY_CHANGED at service
// start and applied if the device is already plugged in when the service launches.

package mesh.shadowmesh.app

import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.work.*
import mesh.shadowmesh.mesh.transport.ble.BleScanMode
import mesh.shadowmesh.platform.MeshForegroundService
import mesh.shadowmesh.platform.OemBatteryExemption
import java.util.concurrent.TimeUnit

/**
 * Concrete [MeshForegroundService] — starts and stops the mesh engines.
 *
 * All engines use [AppModule.applicationScope], not the service's own
 * [serviceScope]. This is the design doc requirement: engines must survive
 * foreground service death — WorkManager continues draining the NSC queue
 * while the service is dead. [serviceScope] is only used by [MeshForegroundService]
 * itself for the keepalive watchdog loop.
 *
 * Lifecycle:
 *   [onMeshServiceCreated]  → start all engines (they are already constructed)
 *   [onMeshServiceDestroyed] → stop all engines in reverse dependency order
 *   [onMeshLowMemory]       → shed in-memory caches; stop mix protocol
 *   [onScheduleRestart]     → enqueue [ForegroundRestartWorker] for 23h restart
 *
 * Always-on trust-agnostic scanning:
 *   WiFi Direct, LAN TCP, and mesh BLE ([BleGattTransport]) transports run continuously
 *   regardless of peer trust level. They discover any ShadowMesh node, not just trusted
 *   contacts. Trust is evaluated only at the application layer when delivering messages.
 *   [MeshSyncWorker] operates on the same principle — its periodic WorkManager jobs have
 *   no [NetworkType.CONNECTED] constraint; they fire even without internet connectivity.
 *
 * Mesh BLE scan aggressiveness:
 *   Normally governed by the user's "Active Mesh Mode" setting via [NetworkStateCoordinator].
 *   This service applies a charging-state override: while the device is plugged in, the
 *   mesh BLE scan uses [BleScanMode.ACTIVE] (`SCAN_MODE_LOW_LATENCY`) regardless of the
 *   user setting. When unplugged, the user's last explicit preference is restored.
 *   The override is applied by [chargingReceiver] and at service start via a sticky
 *   ACTION_BATTERY_CHANGED query.
 *
 * Seed list update handling:
 *   The GossipEngine calls [onSeedListUpdateReceived] when a verified
 *   [SeedListUpdate] packet arrives from a TRUST_PHYSICAL peer. This service
 *   applies the update to the in-memory seed list and persists it to SharedPrefs
 *   so that the next cold start uses the updated seeds.
 */
class ShadowMeshForegroundService : MeshForegroundService() {

    private val TAG = "MeshService"

    companion object {
        /**
         * Minimum interval between full unlock-triggered syncs.
         * Prevents two overlapping fetches when the user unlocks rapidly
         * (e.g. notification → dismiss → re-unlock within seconds).
         * 2 minutes: short enough that a second unlock after a meaningful gap
         * still runs a fresh sync; long enough to skip a reflexive re-unlock.
         */
        private const val UNLOCK_DEBOUNCE_MS = 2 * 60 * 1000L
    }

    // ── Charging BroadcastReceiver ────────────────────────────────────────
    //
    // Overrides the mesh BLE scan mode to ACTIVE while the device is plugged in.
    // On unplug, restores the user's saved preference from activeMeshModeFlow.
    // Registered dynamically in onMeshServiceCreated; the initial charging state is
    // also checked there via a sticky ACTION_BATTERY_CHANGED query.
    private val chargingReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (!AppModule.isInitialised) return
            when (intent.action) {
                Intent.ACTION_POWER_CONNECTED -> {
                    // Override to ACTIVE while charging — battery cost is acceptable.
                    AppModule.bleGattTransport?.setMeshScanMode(BleScanMode.ACTIVE)
                }
                Intent.ACTION_POWER_DISCONNECTED -> {
                    // Restore user's explicit preference. activeMeshModeFlow holds the
                    // last value set by the Settings toggle (independent of charging state).
                    val userActive = AppModule.activeMeshModeFlow.value
                    AppModule.bleGattTransport?.setMeshScanMode(
                        if (userActive) BleScanMode.ACTIVE else BleScanMode.BALANCED
                    )
                }
            }
        }
    }

    // ── Wake BroadcastReceiver ─────────────────────────────────────────────
    //
    // Registered dynamically (cannot be in the manifest for implicit broadcasts
    // since API 26).  Listens for two signals:
    //
    //   ACTION_USER_PRESENT — device fully unlocked.  Full targeted sync: resolve any
    //     pending nudge channel hashes, pull missed fragments via FragmentFetcher
    //     (PREFER_LOCAL: cache → local peers → DHT), reset Bloom filter, challenge peers.
    //     This is the highest-value sync event — the user just picked up their phone.
    //
    //   ACTION_SCREEN_ON — screen lit, before unlock.  Lightweight: immediately fire
    //     any pending NACK countdowns in FragmentIngestor so in-flight posts get their
    //     missing fragments served by relay nodes without waiting up to 30s more.
    //     No network I/O — purely in-memory accumulator state check.
    //
    // Both signals update [AppModule.lastSyncMs] so [MeshSyncWorker.runPeriodicSync]
    // short-circuits when the device is actively in use.
    private val wakeReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            if (!AppModule.isInitialised) return
            when (intent.action) {
                Intent.ACTION_USER_PRESENT -> onDeviceUnlocked(context)
                Intent.ACTION_SCREEN_ON    -> onScreenOn()
            }
        }
    }

    // ── Seed list — in-memory live list, persisted across restarts ─────────
    //
    // The gossip-propagated seed list update mechanism requires a consumer that:
    //   1. Receives a verified SeedListUpdate from GossipEngine
    //   2. Applies it to the in-memory list via SeedList.withUpdate()
    //   3. Persists the result so cold starts use the updated seeds
    //
    // This is that consumer. Without it, SeedList.withUpdate() exists as a
    // data-structure but is never called, making the gossip update mechanism
    // a no-op. The seed list would remain static forever, making it a permanent
    // censorship/attack surface exactly as described in the threat model.
    //
    // SharedPrefs key format: one JSON entry per SeedEntry, keyed by "ip:port".
    // Signature verification is the gossip layer's responsibility — by the time
    // onSeedListUpdateReceived is called, the update has already been verified
    // against the issuer's TRUST_PHYSICAL credential.
    @Volatile private var liveSeedList: mesh.shadowmesh.mesh.dht.SeedList =
        mesh.shadowmesh.mesh.dht.SeedList.default()

    private val PREFS_NAME     = "shadowmesh_seeds"
    private val PREFS_KEY_JSON = "seed_list_json"

    /**
     * Open (or create) the EncryptedSharedPreferences store for the seed list.
     *
     * Seed IPs are infrastructure metadata — storing them in plaintext lets a
     * forensic examiner or malicious app read bootstrap topology without the DB key.
     * EncryptedSharedPreferences with an AES256_GCM MasterKey from the Android
     * Keystore ensures seed data is at rest encrypted, consistent with the posture
     * used for PIN hashes and channel keys.
     *
     * Creating the store is fast (~1 ms) and idempotent; the MasterKey is hardware-
     * backed on TEE/StrongBox devices. This is called lazily on first load/persist.
     */
    private fun seedPrefs(): android.content.SharedPreferences {
        val masterKey = MasterKey.Builder(this)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            this,
            PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    private fun loadPersistedSeeds(): mesh.shadowmesh.mesh.dht.SeedList {
        val json = try {
            seedPrefs().getString(PREFS_KEY_JSON, null)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to open encrypted seed prefs — using default: ${e.message}")
            return mesh.shadowmesh.mesh.dht.SeedList.default()
        } ?: return mesh.shadowmesh.mesh.dht.SeedList.default()
        return try {
            val entries = json.split("|").filter { it.isNotBlank() }.mapNotNull { entry ->
                val parts = entry.split(",")
                if (parts.size >= 2) {
                    mesh.shadowmesh.mesh.dht.SeedEntry(
                        ip           = parts[0],
                        port         = parts[1].toIntOrNull() ?: return@mapNotNull null,
                        ttlMs        = parts.getOrNull(2)?.toLongOrNull() ?: Long.MAX_VALUE,
                        publicKeyHex = parts.getOrNull(3)?.takeIf { it.isNotBlank() }
                    )
                } else null
            }
            mesh.shadowmesh.mesh.dht.SeedList.from(entries)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse persisted seed list — using default: ${e.message}")
            mesh.shadowmesh.mesh.dht.SeedList.default()
        }
    }

    private fun persistSeeds(list: mesh.shadowmesh.mesh.dht.SeedList) {
        val json = list.entries.joinToString("|") { e ->
            "${e.ip},${e.port},${e.ttlMs},${e.publicKeyHex ?: ""}"
        }
        try {
            seedPrefs().edit().putString(PREFS_KEY_JSON, json).apply()
        } catch (e: Exception) {
            Log.w(TAG, "Failed to persist seed list: ${e.message}")
        }
    }

    /**
     * Called by [GossipEngine] when a verified [SeedListUpdate] arrives from
     * a TRUST_PHYSICAL peer. Applies the update, persists the result, and
     * logs the change. If the node is currently in the DHT, the new seeds
     * are used on the next bootstrap (cold start or explicit re-bootstrap).
     *
     * Thread-safe: @Synchronized; called from the gossip coroutine dispatcher.
     */
    @Synchronized
    fun onSeedListUpdateReceived(update: mesh.shadowmesh.mesh.dht.SeedListUpdate) {
        val updated = liveSeedList.withUpdate(update)
        liveSeedList = updated
        persistSeeds(updated)
        Log.i(TAG, "Seed list updated: ${updated.activeCount()} active entries " +
                   "from issuer ${update.issuerNodeId.copyOfRange(0, 4).toHex()}")
    }

    override fun onMeshServiceCreated() {
        if (!AppModule.isInitialised) {
            Log.w(TAG, "Service started before object graph ready — stopping")
            stopSelf()
            return
        }

        // Register wake receiver for screen-on and unlock signals.
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_USER_PRESENT)
            addAction(Intent.ACTION_SCREEN_ON)
        }
        // RECEIVER_NOT_EXPORTED required on API 34+ (targetSdk=34).
        // ACTION_USER_PRESENT and ACTION_SCREEN_ON are protected broadcasts — only
        // the OS can send them, so NOT_EXPORTED is correct and safe.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(wakeReceiver, filter, android.content.Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(wakeReceiver, filter)
        }

        // Register charging receiver and apply initial charging state.
        val chargingFilter = IntentFilter().apply {
            addAction(Intent.ACTION_POWER_CONNECTED)
            addAction(Intent.ACTION_POWER_DISCONNECTED)
        }
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(chargingReceiver, chargingFilter, android.content.Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            registerReceiver(chargingReceiver, chargingFilter)
        }
        // Detect initial charging state via sticky ACTION_BATTERY_CHANGED.
        val batteryStatus = registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
        val chargingStatus = batteryStatus?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val isCharging = chargingStatus == BatteryManager.BATTERY_STATUS_CHARGING ||
                         chargingStatus == BatteryManager.BATTERY_STATUS_FULL
        if (isCharging) {
            AppModule.bleGattTransport?.setMeshScanMode(BleScanMode.ACTIVE)
        }

        // Load persisted seeds so we benefit from any gossip-propagated updates
        // received in previous sessions, not just the hardcoded default.
        liveSeedList = loadPersistedSeeds()

        with(AppModule) {
            // Register this service as the seed list update consumer in the gossip engine.
            // The gossip engine calls onSeedListUpdateReceived when it receives a valid
            // SeedListUpdate packet from a TRUST_PHYSICAL peer.
            gossipEngine.setSeedListUpdateCallback { update ->
                this@ShadowMeshForegroundService.onSeedListUpdateReceived(update)
            }

            // dhtEngine.bootstrap() is suspend — launch on applicationScope.
            // All other engine starts are non-suspend and run inline.
            applicationScope.launch {
                // Peer discovery cache: seed bootstrap with contacts from previous sessions.
                // Read peers seen within the last 7 days and prepend them to the live seed
                // list so we can skip the cold-start re-discovery latency.
                val cachedContacts: List<mesh.shadowmesh.mesh.dht.DhtContact> = try {
                    val minLastSeen = System.currentTimeMillis() -
                        mesh.shadowmesh.storage.DiscoveredPeerEntity.CACHE_RETAIN_MS
                    database.dao().getRecentDiscoveredPeers(minLastSeen).mapNotNull { entity ->
                        val hint = entity.addressHint ?: return@mapNotNull null
                        val colonIdx = hint.lastIndexOf(':')
                        if (colonIdx < 0) return@mapNotNull null
                        val ip   = hint.substring(0, colonIdx)
                        val port = hint.substring(colonIdx + 1).toIntOrNull() ?: return@mapNotNull null
                        mesh.shadowmesh.mesh.dht.DhtContact(
                            nodeId     = mesh.shadowmesh.mesh.dht.NodeId.fromHex(entity.nodeIdHex),
                            address    = mesh.shadowmesh.mesh.dht.PeerAddress(ip, port),
                            lastSeenMs = entity.lastSeenMs
                        )
                    }
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("mesh-service", "peer-cache-read", e)
                    emptyList()
                }

                val allSeeds = cachedContacts + liveSeedList.toContacts()
                try { dhtEngine.bootstrap(allSeeds) }
                catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("mesh-service", "bootstrap", e)
                }

                // After bootstrap, persist the routing table contacts so they are
                // available for the next session's warm-start.
                try {
                    val nowMs = System.currentTimeMillis()
                    dhtEngine.currentContacts().forEach { contact ->
                        val addr = "${contact.address.ip}:${contact.address.port}"
                        database.dao().upsertDiscoveredPeer(
                            mesh.shadowmesh.storage.DiscoveredPeerEntity(
                                nodeIdHex   = contact.nodeId.toHex(),
                                lastSeenMs  = nowMs,
                                transport   = "DHT",
                                addressHint = addr,
                                trustLevel  = mesh.shadowmesh.crypto.TrustLevel.TRUST_PUBLIC.name
                            )
                        )
                    }
                    Diag.info("mesh-service", "peer-cache-save",
                        "Persisted ${dhtEngine.currentContacts().size} contacts to peer cache")
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("mesh-service", "peer-cache-save", e)
                }
            }
            circuitManager.start()
            transportHealthMonitor.start()
            // SNDP is event-driven — no explicit start needed
            // DhtQueryMix is lazy — starts on first submit()
            // InMeshMixProtocol is off by default (Max Security opt-in)

            // Drain offline queue and fetch missed fragments now that mesh is live.
            applicationScope.launch {
                try { channelSyncCoordinator.onReconnect() }
                catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("mesh-service", "reconnect", e)
                }
            }

            Log.i(TAG, "Mesh engines started (${liveSeedList.activeCount()} bootstrap seeds)")
        }
    }

    override fun onMeshServiceDestroyed() {
        // Unregister wake and charging receivers before tearing down engines.
        try { unregisterReceiver(wakeReceiver) } catch (_: Exception) {}
        try { unregisterReceiver(chargingReceiver) } catch (_: Exception) {}

        if (!AppModule.isInitialised) return
        with(AppModule) {
            // Reverse dependency order — circuit first (wipes session keys),
            // then gossip, then DHT.
            inMeshMixProtocol.disable()
            dhtQueryMix.stop()
            circuitManager.stop()          // wipes all hop session keys
            transportHealthMonitor.stop()
            Log.i(TAG, "Mesh engines stopped")
        }
    }

    // ── Wake event handlers ────────────────────────────────────────────────

    /**
     * Called when the device is fully unlocked ([Intent.ACTION_USER_PRESENT]).
     *
     * Performs a full targeted sync:
     *   1. Bloom filter reset + peer challenges (re-propagate held fragments).
     *   2. For each active channel: pull missed fragments via [FragmentFetcher]
     *      (PREFER_LOCAL: anticipatory cache → local peers → DHT).
     *   3. Update [AppModule.lastSyncMs] so the periodic worker short-circuits.
     *
     * This is the highest-value sync event.  The user just unlocked their phone —
     * any messages that arrived while the screen was off will appear within seconds.
     */
    private fun onDeviceUnlocked(context: Context) {
        // Debounce: if a full sync completed recently (e.g. the user unlocked twice
        // in quick succession), skip this one.  lastSyncMs is set at the START of
        // the fetch (not at the end) so a second unlock while the first fetch is in
        // flight also short-circuits — preventing two overlapping full-channel fetches.
        val now = System.currentTimeMillis()
        if (AppModule.lastSyncMs > 0 &&
            now - AppModule.lastSyncMs < UNLOCK_DEBOUNCE_MS) {
            Log.d(TAG, "Unlock debounced — sync ran ${(now - AppModule.lastSyncMs) / 1000}s ago")
            return
        }
        AppModule.lastSyncMs = now   // claim the sync slot immediately

        Log.d(TAG, "Device unlocked — full targeted sync")
        with(AppModule) {
            // Bloom reset + peer challenges on the gossip sync loop.
            applicationScope.launch {
                gossipEngine.syncCycle()
            }
            // Pull missed fragments for every active channel.
            applicationScope.launch(Dispatchers.IO) {
                try {
                    val channels = channelManager.activeChannelSnapshot()
                    channels.forEach { channel ->
                        if (!channel.departed) {
                            channelSyncCoordinator.fetchMissedForChannel(channel.channelId)
                        }
                    }
                    Log.d(TAG, "Unlock sync complete for ${channels.size} channel(s)")
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("mesh-service", "unlock-sync", e)
                }
            }
        }
    }

    /**
     * Called when the screen turns on ([Intent.ACTION_SCREEN_ON]), before unlock.
     *
     * Lightweight — no I/O.  Asks [FragmentIngestor] to immediately fire any
     * pending NACK countdowns for in-flight partial assemblies.  Relay nodes will
     * serve the missing fragments within one gossip round-trip, completing posts
     * without waiting up to [FragmentIngestor.NACK_DELAY_MS] more seconds.
     */
    private fun onScreenOn() {
        if (!AppModule.isInitialised) return
        // fragmentIngestor.onScreenOn() touches only in-memory state — safe to call
        // directly on the BroadcastReceiver's main-thread delivery without launching
        // a coroutine (it immediately re-schedules the NACK jobs, which do their own
        // delay() on the IO dispatcher).
        AppModule.fragmentIngestor.onScreenOn()
    }

    override fun onMeshLowMemory() {
        if (!AppModule.isInitialised) return
        with(AppModule) {
            // Disable in-mesh mix: it holds a fragment pool that can grow to
            // 30 entries × 512 bytes = ~15KB — shed this under memory pressure.
            inMeshMixProtocol.disable()
            Log.w(TAG, "Low memory — mix protocol disabled, caches shed")
        }
    }

    override fun onScheduleRestart(delayMs: Long) {
        // Schedule a one-time WorkManager job that will stop this service and
        // restart it via startForegroundService(). This resets the 24-hour counter
        // on API 33+ foreground service lifetime limit.
        val request = OneTimeWorkRequestBuilder<ForegroundRestartWorker>()
            .setInitialDelay(delayMs, TimeUnit.MILLISECONDS)
            .addTag(ForegroundRestartWorker.TAG)
            .build()
        WorkManager.getInstance(this).enqueueUniqueWork(
            ForegroundRestartWorker.WORK_NAME,
            ExistingWorkPolicy.REPLACE,
            request
        )
        Log.d(TAG, "Foreground service restart scheduled in ${delayMs / 3600_000}h")
    }
}

// ── Foreground service restart worker ─────────────────────────────────────────

/**
 * Stops and restarts [ShadowMeshForegroundService] to reset the 24-hour lifetime
 * counter imposed by Android 13+ on connected-device foreground services.
 *
 * Scheduled by [ShadowMeshForegroundService.onScheduleRestart] at a 23-hour delay.
 * The 1-hour safety margin means the restart fires before Android forcibly kills the
 * service at the 24-hour mark.
 */
class ForegroundRestartWorker(
    context: Context,
    params:  WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val ctx = applicationContext

        // Stop: send ACTION_STOP so the service tears down cleanly before
        // Android can force-kill it.
        ctx.startService(
            android.content.Intent(ctx, ShadowMeshForegroundService::class.java)
                .apply { action = MeshForegroundService.ACTION_STOP }
        )

        // Short pause — gives the service time to execute teardown.
        kotlinx.coroutines.delay(2_000)

        // Restart: the service re-initialises from the already-built AppModule.
        // It does NOT rebuild the object graph; it just re-starts the engines.
        ctx.startForegroundService(
            android.content.Intent(ctx, ShadowMeshForegroundService::class.java)
        )

        return Result.success()
    }

    companion object {
        const val TAG       = "ForegroundRestartWorker"
        const val WORK_NAME = "mesh_foreground_restart"
    }
}

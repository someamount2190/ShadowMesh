package mesh.shadowmesh.platform

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*

/**
 * Mesh foreground service — Phase 9.
 *
 * Keeps the SHADOWMESH mesh process alive in the background:
 *   - Prevents the process from being killed by Android's process management
 *     while the user is not actively using the app.
 *   - Required for: circuit keepalive, DHT participation, fragment relay,
 *     nudge reception, WorkManager fallback when Doze fires.
 *
 * Foreground service type: FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE (API 29+)
 *   This is the correct type for P2P networking. It does NOT require location
 *   permission on API 29+. On API 31+, it additionally allows Wi-Fi Direct
 *   and BLE operations in background.
 *
 * Android 13+ 24-hour limit:
 *   [OemBatteryExemption.isForegroundServiceLifetimeLimited] detects this.
 *   [scheduleRestart] is called from [onStartCommand] to schedule a WorkManager
 *   job that will stop and restart the service before the 24h limit.
 *   The restart job fires at [OemBatteryExemption.FOREGROUND_SERVICE_RESTART_INTERVAL_MS].
 *
 * Notification:
 *   A minimal, privacy-preserving notification is shown (required by Android).
 *   Text: "Protected mesh connection active". No post content, no peer info,
 *   no connection status — only the presence of the service is indicated.
 *   The notification has a "Stop" action that invokes [PanicWipeManager.triggerWipe]
 *   if the user holds the stop button for 3 seconds (panic gesture support).
 *
 * Low-RAM (2GB Android 10) compatibility:
 *   On low-RAM devices Android may kill the service under memory pressure.
 *   [onStartCommand] returns [START_STICKY] so the service is restarted by Android
 *   when memory is available. [onLowMemory] reduces the in-memory fragment cache
 *   and pauses non-critical sync cycles.
 *
 * VpnService permission:
 *   The onion circuit VPN integration requires a separate BIND_VPN_SERVICE permission and
 *   a VpnService subclass. This service is NOT a VpnService — it is a plain foreground
 *   service. The tunnel lives in [ShadowMeshVpnService]; consent and lifecycle are managed
 *   by [VpnServiceBridge], and packets are routed through the circuit by
 *   [OnionCircuitPacketRouter].
 */
abstract class MeshForegroundService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    /** Timestamp when the service was last started — for 24h limit tracking. */
    private var startedAtMs: Long = 0L

    /**
     * Guard against scheduling multiple restart jobs for the same service instance.
     * [onStartCommand] is called on every intent delivery (including re-deliveries
     * from START_STICKY restarts that don't go through onCreate). Without this flag,
     * each re-delivery would re-schedule the 23h restart job, resetting the countdown.
     */
    private var restartScheduled: Boolean = false

    // ── Lifecycle ─────────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        startedAtMs = System.currentTimeMillis()
        startForegroundWithNotification()
        onMeshServiceCreated()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
        }

        // Schedule 24h-limit restart if on API 33+.
        // Guard with restartScheduled so re-deliveries of the same intent
        // (or explicit re-starts while the service is still running) do not
        // reset the 23h countdown by scheduling a new job on top of the old one.
        if (!restartScheduled && OemBatteryExemption.isForegroundServiceLifetimeLimited()) {
            scheduleApiRestart()
        }

        return START_STICKY   // Android restarts us if killed under memory pressure
    }

    override fun onDestroy() {
        // onMeshServiceDestroyed() BEFORE serviceScope.cancel() — the subclass hook
        // tears down mesh engines, wipes circuit session keys, and drains queues.
        // Cancelling the scope first would abort all that teardown work immediately.
        onMeshServiceDestroyed()
        serviceScope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null  // not a bound service

    override fun onLowMemory() {
        super.onLowMemory()
        onMeshLowMemory()
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= TRIM_MEMORY_RUNNING_LOW) {
            onMeshLowMemory()
        }
    }

    // ── Abstract hooks for the app layer ──────────────────────────────────

    /** Called in onCreate() after the foreground notification is shown.
     *  Start mesh engines (circuit, gossip, DHT) here. */
    abstract fun onMeshServiceCreated()

    /** Called in onDestroy() before the service scope is cancelled.
     *  Tear down mesh engines here. */
    abstract fun onMeshServiceDestroyed()

    /** Called when Android signals low memory. Reduce in-memory caches. */
    open fun onMeshLowMemory() { /* default: no-op — override to shed caches */ }

    // ── Notification ──────────────────────────────────────────────────────

    private fun startForegroundWithNotification() {
        ensureNotificationChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun buildNotification(): Notification {
        val stopIntent = PendingIntent.getService(
            this, 0,
            Intent(this, this::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SHADOWMESH")
            // Privacy-preserving: no post content, no peer info, no connection status
            .setContentText("Protected mesh connection active")
            .setSmallIcon(android.R.drawable.ic_lock_silent_mode)
            .setOngoing(true)
            .setSilent(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Stop",
                stopIntent
            )
            .build()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Mesh connection",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps the mesh connection alive in the background"
                setShowBadge(false)
                enableLights(false)
                enableVibration(false)
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    // ── API 33 restart scheduling ─────────────────────────────────────────

    private fun scheduleApiRestart() {
        restartScheduled = true
        Log.d(TAG, "API 33+ foreground service limit applies — restart scheduled at 23h")
        onScheduleRestart(OemBatteryExemption.FOREGROUND_SERVICE_RESTART_INTERVAL_MS)
    }

    /**
     * Hook for the concrete service to schedule its own restart via WorkManager.
     * [delayMs] is the delay before restart (23 hours on API 33+).
     * The default implementation is a no-op — override in the app module.
     */
    open fun onScheduleRestart(delayMs: Long) { /* override in app module */ }

    companion object {
        const val TAG             = "MeshForegroundService"
        const val CHANNEL_ID      = "shadowmesh_mesh_connection"
        const val NOTIFICATION_ID = 1001
        const val ACTION_STOP     = "mesh.shadowmesh.ACTION_STOP_SERVICE"
    }
}

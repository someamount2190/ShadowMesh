package mesh.shadowmesh.platform

import android.app.ActivityManager
import android.content.Context
import android.os.Build

/**
 * Low-RAM device guard — Phase 9 (2GB Android 10 reliability target).
 *
 * SHADOWMESH targets 10-device reliability testing including 2GB RAM Android 10
 * devices. These devices exhibit specific failure modes:
 *
 *   1. Fragment cache growth: Each incoming fragment is held in memory until
 *      its post is fully assembled. At 512 bytes × 20 fragments × 100 concurrent
 *      posts = 1MB — acceptable. But at SURVIVAL mode with 1000 fragments in
 *      flight, this reaches 512KB × 1000 = 512MB — catastrophic on 2GB.
 *
 *   2. SurvivalModeEngine.seenFragmentIds: Capped at 10K per peer (fixed in
 *      Phase 7). On low-RAM, cap should be reduced to 2K.
 *
 *   3. PostRatchet chain key: Each channel holds one 32-byte chain key in memory.
 *      With 50 channels × 1KB ratchet state = 50KB — acceptable.
 *
 *   4. WorkManager job count: WorkManager holds job state in memory. On low-RAM,
 *      cap periodic jobs to prevent OOM in the job scheduler.
 *
 *   5. Circuit session keys: 4 × 32 bytes per circuit = 128 bytes — negligible.
 *
 * This class detects low-RAM conditions and provides tuned constants so each
 * component can self-adjust without knowing about each other.
 *
 * Detection: [ActivityManager.isLowRamDevice] (API 19+). On Android 10 (API 29)
 * with ≤2GB RAM, this reliably returns true on OEM devices (Samsung, Xiaomi).
 *
 * Thread-safety: stateless after [isLowRam] is computed — thread-safe.
 */
object LowRamDeviceGuard {

    /** True if Android classifies this device as low-RAM (≤2GB on most OEMs). */
    fun isLowRam(context: Context): Boolean {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        return am.isLowRamDevice
    }

    /**
     * Total physical RAM in bytes. Used for fine-grained tuning beyond the
     * binary [isLowRam] flag.
     */
    fun totalRamBytes(context: Context): Long {
        val am   = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val info = ActivityManager.MemoryInfo()
        am.getMemoryInfo(info)
        return info.totalMem
    }

    // ── Tuned constants ───────────────────────────────────────────────────

    /**
     * Maximum in-memory fragment cache entries.
     * Standard: 10_000 entries (~5MB at 512B/fragment).
     * Low-RAM:  2_000  entries (~1MB).
     */
    fun maxFragmentCacheEntries(context: Context): Int =
        if (isLowRam(context)) 2_000 else 10_000

    /**
     * Maximum seenFragmentIds per SurvivalModeEngine peer.
     * Standard: 10_000 (per Phase 7 fix).
     * Low-RAM:  2_000.
     */
    fun maxSeenFragmentIdsPerPeer(context: Context): Int =
        if (isLowRam(context)) 2_000 else 10_000

    /**
     * Maximum concurrent posts held in memory for progressive reconstruction.
     * Standard: 200.
     * Low-RAM:  50.
     */
    fun maxConcurrentPostsInFlight(context: Context): Int =
        if (isLowRam(context)) 50 else 200

    /**
     * SNDP burst fragment count — reduced on low-RAM to prevent OOM during
     * simultaneous real + fake fragment bursts.
     * Standard: 7 (per SndpEngine constant).
     * Low-RAM:  3.
     */
    fun sndpBurstFragmentCount(context: Context): Int =
        if (isLowRam(context)) 3 else 7

    /**
     * In-mesh mix protocol pool size cap.
     * Standard: unbounded within the flush window.
     * Low-RAM:  30 fragments max before forced flush.
     */
    fun mixProtocolMaxPoolSize(context: Context): Int =
        if (isLowRam(context)) 30 else Int.MAX_VALUE

    /**
     * WorkManager periodic job count cap.
     * Android has a system-wide limit of 100 periodic jobs across all apps.
     * On low-RAM devices, the scheduler becomes unstable near the limit.
     * Standard: 10.
     * Low-RAM:  3 (TTL sweep + DHT refresh + APK integrity check).
     */
    fun maxPeriodicWorkManagerJobs(context: Context): Int =
        if (isLowRam(context)) 3 else 10

    /**
     * Human-readable description of the detected device class.
     * Used in diagnostics and the developer settings screen.
     */
    fun deviceClassDescription(context: Context): String {
        val ramMb = totalRamBytes(context) / (1024 * 1024)
        val lowRam = isLowRam(context)
        return buildString {
            append("RAM: ${ramMb}MB")
            append(if (lowRam) " (low-RAM mode — reduced caches active)" else " (standard mode)")
            // Android 10 (API 29) is the project minimum SDK and has elevated OEM battery kill
            // risk due to incomplete Doze implementation. Flag it specifically.
            if (Build.VERSION.SDK_INT == Build.VERSION_CODES.Q) {
                append(" | Android 10 — OEM battery kill risk elevated")
            }
        }
    }
}

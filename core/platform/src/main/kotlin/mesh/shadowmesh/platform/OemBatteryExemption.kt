package mesh.shadowmesh.platform

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import mesh.shadowmesh.diagnostics.Diag

/**
 * OEM battery exemption — Phase 9.
 *
 * Android OEMs (MIUI, EMUI, OneUI, ColorOS, FuntouchOS) apply aggressive
 * battery optimisation beyond AOSP Doze. These OEM layers kill background
 * services minutes after the screen turns off, breaking:
 *   - The mesh sync WorkManager jobs
 *   - The foreground service keeping the circuit alive
 *   - BLE beaconing
 *   - The panic wipe watchdog
 *
 * Two exemption levels are needed:
 *
 *   Level 1 — AOSP standard: REQUEST_IGNORE_BATTERY_OPTIMIZATIONS.
 *     Requests that Android's Doze and App Standby not apply.
 *     On stock Android this is sufficient. On OEM ROMs, it is often ignored.
 *     Must be declared in AndroidManifest.xml; plays Settings UI.
 *
 *   Level 2 — OEM-specific: deep background exemption.
 *     Each OEM has a private Settings Activity that the user must open to
 *     grant "Autostart" or "Background activity" permission. This class
 *     detects the manufacturer and launches the correct OEM activity.
 *
 *     Supported OEMs:
 *       MIUI (Xiaomi / POCO / Redmi)  — com.miui.powerkeeper
 *       EMUI (Huawei / Honor)         — com.huawei.systemmanager
 *       OneUI (Samsung)               — com.samsung.android.lool
 *       ColorOS (OPPO / OnePlus)      — com.coloros.oppoguardelf
 *       FuntouchOS (Vivo)             — com.iqoo.secure
 *       Flyme (Meizu)                 — com.meizu.safe
 *
 *   Level 3 — Android 13+ foreground service restriction:
 *     From API 33, foreground services with type "connected device" are
 *     killed after 24 hours. The service must be restarted. This class
 *     provides the restart machinery and the detection check.
 *
 * None of these exemptions can be granted programmatically — they all
 * require user interaction with the Settings UI. This class only opens the
 * correct screen; the user must grant manually.
 *
 * Thread-safety: all methods safe on any thread; UI-opening methods must
 * be called from the Main dispatcher.
 */
object OemBatteryExemption {

    private const val TAG = "OemBatteryExemption"

    // ── AOSP Doze exemption ───────────────────────────────────────────────

    /**
     * Returns true if this app is already exempt from AOSP Doze/App Standby.
     * Does NOT check OEM-layer exemption — see [isOemExempted].
     */
    fun isDozeExempted(context: Context): Boolean {
        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        return pm.isIgnoringBatteryOptimizations(context.packageName)
    }

    /**
     * Open the AOSP battery optimisation exemption dialog.
     * The user sees "Allow app to ignore battery optimizations?" and must tap Allow.
     *
     * Must be called from Main dispatcher (starts an Activity).
     * Must have REQUEST_IGNORE_BATTERY_OPTIMIZATIONS in AndroidManifest.xml.
     *
     * On MIUI/EMUI/OneUI this is necessary but not sufficient —
     * also call [openOemExemptionSettings].
     */
    fun requestDozeExemption(context: Context) {
        if (isDozeExempted(context)) return
        val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
            data = Uri.parse("package:${context.packageName}")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        context.startActivity(intent)
    }

    // ── OEM-specific exemption ────────────────────────────────────────────

    /**
     * Detected OEM ROM family.
     */
    enum class OemRom {
        MIUI,        // Xiaomi, POCO, Redmi
        EMUI,        // Huawei, Honor
        ONE_UI,      // Samsung
        COLOR_OS,    // OPPO, OnePlus
        FUNTOUCH_OS, // Vivo
        FLYME,       // Meizu
        STOCK_AOSP,  // Stock Android / Google Pixel / unknown OEM
    }

    /** Detect the OEM ROM running on this device. */
    fun detectOemRom(): OemRom {
        val manufacturer = Build.MANUFACTURER.lowercase()
        val brand        = Build.BRAND.lowercase()
        return when {
            manufacturer.contains("xiaomi") ||
            brand.contains("xiaomi") ||
            brand.contains("poco")   ||
            brand.contains("redmi")  -> OemRom.MIUI

            manufacturer.contains("huawei") ||
            brand.contains("huawei") ||
            brand.contains("honor")  -> OemRom.EMUI

            manufacturer.contains("samsung") -> OemRom.ONE_UI

            manufacturer.contains("oppo") ||
            brand.contains("oppo")   ||
            brand.contains("oneplus") -> OemRom.COLOR_OS

            manufacturer.contains("vivo") ||
            brand.contains("vivo")   -> OemRom.FUNTOUCH_OS

            manufacturer.contains("meizu") ||
            brand.contains("meizu") -> OemRom.FLYME

            else -> OemRom.STOCK_AOSP
        }
    }

    /**
     * Returns true if an OEM-specific deep background exemption activity exists
     * on this device. Returns false for STOCK_AOSP or unsupported OEMs.
     */
    fun hasOemExemptionScreen(context: Context): Boolean {
        val intent = oemExemptionIntent(context) ?: return false
        return context.packageManager.resolveActivity(
            intent, PackageManager.MATCH_DEFAULT_ONLY
        ) != null
    }

    /**
     * Open the OEM-specific background app management screen.
     * The user must manually grant "Autostart" or "Background activity" permission.
     *
     * Must be called from Main dispatcher.
     * No-op if no OEM screen is available (STOCK_AOSP).
     *
     * Returns true if an activity was launched, false if not applicable.
     */
    fun openOemExemptionSettings(context: Context): Boolean {
        val intent = oemExemptionIntent(context) ?: return false
        return try {
            context.startActivity(intent)
            true
        } catch (e: Exception) {
            Log.w(TAG, "Could not open OEM exemption screen: ${e.message}")
            Diag.swallowed("oem-battery", "open-settings", e)
            false
        }
    }

    /**
     * Human-readable instruction for the user to follow after [openOemExemptionSettings]
     * opens the OEM screen.
     *
     * Prefer the overload [oemExemptionInstruction(OemRom)] when the caller already
     * has the result of [detectOemRom] to avoid a redundant re-detection.
     */
    fun oemExemptionInstruction(): String = oemExemptionInstruction(detectOemRom())

    /**
     * Human-readable instruction for the given [rom].
     * Use this overload when you already hold the result of [detectOemRom].
     */
    fun oemExemptionInstruction(rom: OemRom): String = when (rom) {
        OemRom.MIUI        -> "Tap SHADOWMESH → set to No restrictions. Also go to Security → Manage apps → SHADOWMESH → Autostart and enable it."
        OemRom.EMUI        -> "Find SHADOWMESH and enable 'Run in background'."
        OemRom.ONE_UI      -> "Tap SHADOWMESH → Allow background activity → turn On."
        OemRom.COLOR_OS    -> "Find SHADOWMESH and allow background running."
        OemRom.FUNTOUCH_OS -> "Find SHADOWMESH and enable background high-power consumption."
        OemRom.FLYME       -> "Find SHADOWMESH and enable autostart."
        OemRom.STOCK_AOSP  -> "No additional steps needed — Android battery optimization exemption is sufficient."
    }

    private fun oemExemptionIntent(context: Context): Intent? {
        val pkg = context.packageName
        val intents = when (detectOemRom()) {
            OemRom.MIUI -> listOf(
                // MIUI 10+ — PowerKeeper per-app battery mode (set to "No restrictions")
                Intent().apply {
                    setClassName("com.miui.powerkeeper",
                        "com.miui.powerkeeper.ui.HideAppControlSettings")
                    putExtra("package_name", pkg)
                    putExtra("package_label", pkg)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                },
                // Older MIUI fallback — Autostart management in Security Center
                Intent().apply {
                    setClassName("com.miui.securitycenter",
                        "com.miui.permcenter.autostart.AutoStartManagementActivity")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
            OemRom.EMUI -> listOf(
                Intent().apply {
                    setClassName("com.huawei.systemmanager",
                        "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
            OemRom.ONE_UI -> listOf(
                Intent().apply {
                    setClassName("com.samsung.android.lool",
                        "com.samsung.android.sm.battery.ui.BatteryActivity")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
            OemRom.COLOR_OS -> listOf(
                Intent().apply {
                    setClassName("com.coloros.oppoguardelf",
                        "com.coloros.powermanager.fuelgauge.PowerUsageModelActivity")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
            OemRom.FUNTOUCH_OS -> listOf(
                Intent().apply {
                    setClassName("com.iqoo.secure",
                        "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
            OemRom.FLYME -> listOf(
                Intent("com.meizu.safe.security.SHOW_APPSEC").apply {
                    addCategory(Intent.CATEGORY_DEFAULT)
                    putExtra("packageName", pkg)
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            )
            OemRom.STOCK_AOSP -> emptyList()
        }

        return intents.firstOrNull { intent ->
            context.packageManager.resolveActivity(
                intent, PackageManager.MATCH_DEFAULT_ONLY
            ) != null
        }
    }

    // ── Android 13+ foreground service 24h kill ───────────────────────────

    /**
     * Android 13+ (API 33) restricts foreground services of type "connectedDevice"
     * to 24 hours. After 24h the system stops the service and prevents restart
     * for a cooldown period.
     *
     * Returns true if the foreground service lifetime restriction applies to this device.
     * When true, the service coordinator must schedule a restart before the limit.
     */
    fun isForegroundServiceLifetimeLimited(): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU  // API 33

    /**
     * Recommended foreground service restart interval to stay within the 24h limit
     * with a safety margin. The service should stop and restart itself after this
     * duration to reset the 24h counter.
     *
     * Value: 23 hours (3 hours margin). WorkManager schedules the restart.
     */
    const val FOREGROUND_SERVICE_RESTART_INTERVAL_MS = 23L * 60 * 60 * 1000

    /**
     * Check if the foreground service has been running long enough that a restart
     * is due soon (within 1 hour of the 24h limit).
     *
     * @param serviceStartedAtMs System.currentTimeMillis() when the service started.
     */
    fun isForegroundServiceRestartDue(serviceStartedAtMs: Long): Boolean {
        if (!isForegroundServiceLifetimeLimited()) return false
        val elapsed = System.currentTimeMillis() - serviceStartedAtMs
        return elapsed >= FOREGROUND_SERVICE_RESTART_INTERVAL_MS
    }
}

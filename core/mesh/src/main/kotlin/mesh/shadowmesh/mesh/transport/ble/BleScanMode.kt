// TODO: [BLE Redesign] BleScanMode added as part of the network scanning redesign.
// BALANCED is the default and safe for all conditions (battery-friendly).
// ACTIVE should be used only when the device is charging or the user opts in
// via the "Active Mesh Mode" settings toggle, propagated by NetworkStateCoordinator.
// The ShadowMeshForegroundService charging-state optimisation also switches to ACTIVE
// when plugged in, overriding the user preference until unplugged.

package mesh.shadowmesh.mesh.transport.ble

/**
 * Controls the aggressiveness of the foreground mesh BLE scan in [BleGattTransport].
 *
 * This enum governs **mesh BLE only** — the always-on nudge/peer-discovery transport.
 * It has no effect on the **bootstrap BLE** proximity scanner ([BleProximityScanner]),
 * which always uses BALANCED regardless of this setting.
 *
 * - [BALANCED] maps to `SCAN_MODE_BALANCED` (Android default, balanced latency/battery).
 * - [ACTIVE]   maps to `SCAN_MODE_LOW_LATENCY` (maximum discovery rate; higher battery).
 *
 * Mode changes are applied immediately by [BleGattTransport.setMeshScanMode] —
 * the scan is restarted with the new mode if the foreground scan is already running.
 *
 * An adaptive fallback is also applied in BALANCED mode: if no new mesh peers are
 * discovered for [BleGattTransport.ADAPTIVE_NO_NODES_MS] (5 minutes), the scan
 * temporarily drops to `SCAN_MODE_LOW_POWER` until the next peer discovery event.
 */
enum class BleScanMode {
    /** Standard BLE scan (SCAN_MODE_BALANCED). Default. Battery-safe. */
    BALANCED,
    /** Aggressive BLE scan (SCAN_MODE_LOW_LATENCY). Higher battery/CPU. */
    ACTIVE,
}

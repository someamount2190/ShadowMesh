// TODO: [BLE Redesign] BleProximityScanner added as part of the network scanning redesign.
// ASSUMPTION: UUID constants are duplicated from BleGattTransport (core:mesh) to avoid a
// build-graph cycle (core:bootstrap must not depend on core:mesh). Keep in sync manually.
// ASSUMPTION: targetNodeIdBytes null means "any ShadowMesh device" — used when the
// initiator has not yet received the responder's node ID via QR exchange.
// ASSUMPTION: RSSI gate (-70 dBm default) is configurable per session and applies only
// after the GATT beacon read confirms the node ID. Unverified advertisements are ignored.

package mesh.shadowmesh.bootstrap.ble

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothManager
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.ParcelUuid
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Session-scoped BLE proximity scanner used during bootstrap to verify a peer is physically
 * nearby before the NFC handshake is offered.
 *
 * **Bootstrap BLE vs Mesh BLE:**
 * This class is entirely separate from `BleGattTransport` in `core:mesh`. It exists only
 * during a bootstrap session; once the session completes or is cancelled, [stop] releases all
 * resources immediately. It always uses [ScanSettings.SCAN_MODE_BALANCED] — it is not
 * influenced by the "Active Mesh Mode" setting or charging-state overrides.
 *
 * **Flow:**
 * 1. [start] begins a BALANCED BLE scan filtered to `SHADOWMESH_SERVICE_UUID`.
 * 2. When an advertisement is seen at or above [rssiThreshold], the scanner opens a GATT
 *    connection and reads the BEACON characteristic (32-byte raw nodeId).
 * 3. If the nodeId matches [targetNodeIdBytes] (or target is null), emits
 *    [ProximityState.Confirmed] with the observed RSSI and stops scanning.
 * 4. If no confirmation occurs within [timeoutMs], emits [ProximityState.Timeout].
 * 5. [stop] can be called at any time to cancel and free all BLE resources.
 *
 * Only one GATT read is attempted at a time ([isChecking] AtomicBoolean gate). If the read
 * fails or the node ID does not match, the gate is released and subsequent advertisements
 * are reconsidered until timeout.
 *
 * The caller (OnboardingViewModel) is responsible for calling [stop] when the session
 * ends — regardless of whether the outcome is Confirmed, Timeout, or user cancellation.
 */
class BleProximityScanner(
    private val context: Context,
    private val scope: CoroutineScope,
    private val targetNodeIdBytes: ByteArray?,
    private val rssiThreshold: Int = DEFAULT_RSSI_THRESHOLD,
    private val timeoutMs: Long = DEFAULT_TIMEOUT_MS,
) {

    sealed class ProximityState {
        object Scanning : ProximityState()
        data class Confirmed(val rssi: Int) : ProximityState()
        object Lost : ProximityState()
        object Timeout : ProximityState()
    }

    private val _state = MutableStateFlow<ProximityState>(ProximityState.Scanning)
    val state: StateFlow<ProximityState> = _state

    private val isChecking = AtomicBoolean(false)
    private var scanJob: Job? = null
    private var activeScanCallback: ScanCallback? = null
    private var activeGatt: BluetoothGatt? = null
    private var pendingBeaconRead: CompletableDeferred<ByteArray?>? = null

    fun start() {
        scanJob = scope.launch {
            _state.value = ProximityState.Scanning
            startScan()
            delay(timeoutMs)
            if (_state.value is ProximityState.Scanning) {
                _state.value = ProximityState.Timeout
                stopScan()
            }
        }
    }

    fun stop() {
        scanJob?.cancel()
        scanJob = null
        stopScan()
        pendingBeaconRead?.cancel()
        pendingBeaconRead = null
        safeCloseGatt()
    }

    private fun startScan() {
        val scanner = context.getSystemService(BluetoothManager::class.java)
            ?.adapter?.bluetoothLeScanner ?: return

        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(UUID.fromString(SHADOWMESH_SERVICE_UUID)))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_BALANCED)
            .build()

        val cb = object : ScanCallback() {
            override fun onScanResult(callbackType: Int, result: ScanResult) {
                if (_state.value !is ProximityState.Scanning) return
                if (result.rssi < rssiThreshold) return
                if (!isChecking.compareAndSet(false, true)) return

                scope.launch {
                    try {
                        val nodeId = readBeaconNodeId(result.device)
                        if (nodeId != null && nodeIdMatchesTarget(nodeId)) {
                            _state.value = ProximityState.Confirmed(result.rssi)
                            stopScan()
                        } else {
                            isChecking.set(false)
                        }
                    } catch (_: Exception) {
                        isChecking.set(false)
                    }
                }
            }

            override fun onScanFailed(errorCode: Int) {
                // Leave state as Scanning; timeout job will fire.
            }
        }
        activeScanCallback = cb
        scanner.startScan(listOf(filter), settings, cb)
    }

    private fun stopScan() {
        val scanner = context.getSystemService(BluetoothManager::class.java)
            ?.adapter?.bluetoothLeScanner ?: return
        activeScanCallback?.let { scanner.stopScan(it) }
        activeScanCallback = null
    }

    private suspend fun readBeaconNodeId(device: BluetoothDevice): ByteArray? {
        val deferred = CompletableDeferred<ByteArray?>()
        pendingBeaconRead = deferred

        val gattCb = object : BluetoothGattCallback() {
            override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
                when (newState) {
                    BluetoothGatt.STATE_CONNECTED -> gatt.discoverServices()
                    BluetoothGatt.STATE_DISCONNECTED -> {
                        if (!deferred.isCompleted) deferred.complete(null)
                        safeCloseGatt()
                    }
                }
            }

            override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    deferred.complete(null)
                    gatt.disconnect()
                    return
                }
                val characteristic = gatt
                    .getService(UUID.fromString(SHADOWMESH_SERVICE_UUID))
                    ?.getCharacteristic(UUID.fromString(BEACON_CHARACTERISTIC_UUID))
                if (characteristic == null || !gatt.readCharacteristic(characteristic)) {
                    deferred.complete(null)
                    gatt.disconnect()
                }
            }

            // API < 33 callback
            @Suppress("DEPRECATION", "OVERRIDE_DEPRECATION")
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                status: Int,
            ) {
                val value = if (status == BluetoothGatt.GATT_SUCCESS) characteristic.value else null
                if (!deferred.isCompleted) deferred.complete(value)
                gatt.disconnect()
            }

            // API 33+ callback
            override fun onCharacteristicRead(
                gatt: BluetoothGatt,
                characteristic: BluetoothGattCharacteristic,
                value: ByteArray,
                status: Int,
            ) {
                val resolved = if (status == BluetoothGatt.GATT_SUCCESS) value else null
                if (!deferred.isCompleted) deferred.complete(resolved)
                gatt.disconnect()
            }
        }

        activeGatt = device.connectGatt(context, false, gattCb, BluetoothDevice.TRANSPORT_LE)
        return withTimeoutOrNull(GATT_READ_TIMEOUT_MS) { deferred.await() }
            .also { safeCloseGatt() }
    }

    private fun safeCloseGatt() {
        try { activeGatt?.close() } catch (_: Exception) {}
        activeGatt = null
    }

    private fun nodeIdMatchesTarget(nodeId: ByteArray): Boolean {
        val target = targetNodeIdBytes ?: return true
        return nodeId.contentEquals(target)
    }

    companion object {
        const val DEFAULT_RSSI_THRESHOLD = -70
        const val DEFAULT_TIMEOUT_MS = 60_000L
        const val GATT_READ_TIMEOUT_MS = 4_000L

        // TODO: [BLE Redesign] UUID constants duplicated from BleGattTransport (core:mesh)
        // to avoid a build-graph cycle. Keep in sync if the UUIDs are ever changed there.
        private const val SHADOWMESH_SERVICE_UUID = "5d3a1f60-7c8e-4b2a-9f14-2e6b0a9c4d71"
        private const val BEACON_CHARACTERISTIC_UUID = "5d3a1f62-7c8e-4b2a-9f14-2e6b0a9c4d71"
    }
}

package mesh.shadowmesh.mesh.transport.wifi

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.NetworkInfo
import android.net.wifi.p2p.WifiP2pDevice
import android.net.wifi.p2p.WifiP2pManager.EXTRA_NETWORK_INFO
import android.net.wifi.p2p.WifiP2pManager.EXTRA_WIFI_STATE
import android.net.wifi.p2p.WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION
import android.net.wifi.p2p.WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION
import android.net.wifi.p2p.WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION
import android.net.wifi.p2p.WifiP2pManager.WIFI_P2P_STATE_ENABLED
import android.net.wifi.p2p.WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION
import android.os.Build
import mesh.shadowmesh.diagnostics.Diag

/**
 * BroadcastReceiver for WiFi Direct (WifiP2p) state events.
 *
 * This receiver is the integration layer that makes [WiFiDirectTransport] functional.
 * Without it, [WiFiDirectTransport.onConnectionInfoAvailable] is never called, the TCP
 * socket layer is never established, and peer discovery callbacks are never delivered.
 *
 * ## Events handled
 *
 * - [WIFI_P2P_STATE_CHANGED_ACTION]: WiFi Direct enabled/disabled.
 *   Updates [WiFiDirectTransport.p2pEnabled] so startDiscovery() guards on the state.
 *
 * - [WIFI_P2P_PEERS_CHANGED_ACTION]: Peer list changed after discovery.
 *   Calls [WifiP2pManager.requestPeers] here — NOT in startDiscovery() — because the peer
 *   list is only populated after asynchronous discovery completes.
 *
 * - [WIFI_P2P_CONNECTION_CHANGED_ACTION]: P2P connection state changed.
 *   When connected, requests WifiP2pInfo from the manager and routes it to
 *   [WiFiDirectTransport.onConnectionInfoAvailable], triggering TCP layer setup.
 *
 * - [WIFI_P2P_THIS_DEVICE_CHANGED_ACTION]: This device's WiFi Direct details changed.
 *   Informational only.
 *
 * ## Lifecycle
 *
 * Register in onResume() (or Service's onStartCommand()) with [intentFilter].
 * Unregister in onPause() (or onDestroy()).
 *
 * ```kotlin
 * val receiver = WifiP2pBroadcastReceiver(
 *     transport      = wifiDirectTransport,
 *     onPeersChanged = { devices -> updatePeerList(devices) },
 *     onP2pEnabled   = { enabled -> updateUiState(enabled) }
 * )
 * registerReceiver(receiver, WifiP2pBroadcastReceiver.intentFilter())
 * // ... later:
 * unregisterReceiver(receiver)
 * ```
 */
class WifiP2pBroadcastReceiver(
    private val transport:      WiFiDirectTransport,
    private val onPeersChanged: (List<WifiP2pDevice>) -> Unit = {},
    private val onP2pEnabled:   (Boolean) -> Unit = {}
) : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {

            WIFI_P2P_STATE_CHANGED_ACTION -> {
                val state   = intent.getIntExtra(EXTRA_WIFI_STATE, -1)
                val enabled = state == WIFI_P2P_STATE_ENABLED
                transport.p2pEnabled = enabled
                onP2pEnabled(enabled)
                if (!enabled) {
                    Diag.degraded("wifi-direct", "p2p-disabled",
                        "WiFi Direct disabled (state=$state) — discovery and connections unavailable")
                }
            }

            WIFI_P2P_PEERS_CHANGED_ACTION -> {
                // Discovery is asynchronous — the peer list is only populated after this
                // action fires. Request the updated list and deliver it to the caller.
                transport.manager.requestPeers(transport.channel) { peerList ->
                    val devices = peerList.deviceList.toList()
                    transport.onPeersChangedCallback?.invoke(devices)
                    onPeersChanged(devices)
                }
            }

            WIFI_P2P_CONNECTION_CHANGED_ACTION -> {
                val networkInfo: NetworkInfo? =
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                        intent.getParcelableExtra(EXTRA_NETWORK_INFO, NetworkInfo::class.java)
                    } else {
                        @Suppress("DEPRECATION")
                        intent.getParcelableExtra(EXTRA_NETWORK_INFO)
                    }
                if (networkInfo?.isConnected == true) {
                    // Connected — request WifiP2pInfo and route to transport.
                    // This triggers startFragmentServer() (group owner) or connectToGroupOwner()
                    // (client), establishing the TCP layer for fragment exchange.
                    transport.manager.requestConnectionInfo(transport.channel) { info ->
                        transport.onConnectionInfoAvailable(info)
                    }
                } else {
                    Diag.degraded("wifi-direct", "p2p-disconnected",
                        "WiFi Direct connection dropped — state: ${networkInfo?.state}")
                }
            }

            WIFI_P2P_THIS_DEVICE_CHANGED_ACTION -> {
                // This device's WiFi Direct details changed (name, address). Informational only.
            }
        }
    }

    companion object {
        /** IntentFilter covering all WiFi Direct state events. Pass to registerReceiver(). */
        fun intentFilter(): IntentFilter = IntentFilter().apply {
            addAction(WIFI_P2P_STATE_CHANGED_ACTION)
            addAction(WIFI_P2P_PEERS_CHANGED_ACTION)
            addAction(WIFI_P2P_CONNECTION_CHANGED_ACTION)
            addAction(WIFI_P2P_THIS_DEVICE_CHANGED_ACTION)
        }
    }
}

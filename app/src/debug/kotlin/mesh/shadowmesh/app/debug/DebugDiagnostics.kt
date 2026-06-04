package mesh.shadowmesh.app.debug

import androidx.compose.runtime.Composable
import mesh.shadowmesh.debug.DiagnosticsDeps
import mesh.shadowmesh.debug.DiagnosticsScreen

/**
 * DEBUG variant entry point. Returns the diagnostics screen content.
 *
 * The matching stub in app/src/release/ returns null with the same signature, so
 * MainActivity (in the main source set) can reference [debugDiagnosticsContent]
 * unconditionally; the release build links no diagnostics code at all.
 *
 * @param dbVersion optional hook the app supplies so the DB probe can read the live
 *                  Room schema version, e.g. { db.openHelper.readableDatabase.version }.
 */
fun debugDiagnosticsContent(
    dbVersion: (suspend () -> Int)? = null
): (@Composable () -> Unit)? = {
    // Wire the live database version from AppModule when available.
    // AppModule.database.openHelper.readableDatabase.version uses the CURRENT schema
    // version (after all migrations), not the @Database version annotation constant.
    val liveDbVersion: (suspend () -> Int)? = dbVersion
        ?: if (mesh.shadowmesh.app.AppModule.isInitialised) {
            { mesh.shadowmesh.app.AppModule.database.openHelper.readableDatabase.version }
        } else null

    DiagnosticsScreen(
        DiagnosticsDeps(
            expectedDbVersion  = 15,               // current ShadowMeshDatabase @Database version
            dbVersionProvider  = liveDbVersion,
            // nfcSelfTest / bleScanTest / wifiDirectTest / meshPropagationTest:
            // wire below from the app's transport singletons when running 2-device tests.
            // Example:
            //   nfcSelfTest = { /* run NfcBootstrapCoordinator as initiator, return ProbeResult */ }
            //   bleScanTest = { /* run BleGattTransport discovery, return discovered peers + RSSI */ }
        )
    )
}

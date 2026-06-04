package mesh.shadowmesh.app.debug

import androidx.compose.runtime.Composable

/**
 * RELEASE variant stub. Returns null — the diagnostics module is not on the release
 * classpath (it is wired as debugImplementation only), so there is intentionally nothing
 * to show. MainActivity treats a null result as "no debug entry point".
 *
 * Keep this signature identical to app/src/debug/.../debugDiagnosticsContent.
 */
fun debugDiagnosticsContent(
    @Suppress("UNUSED_PARAMETER") dbVersion: (suspend () -> Int)? = null
): (@Composable () -> Unit)? = null

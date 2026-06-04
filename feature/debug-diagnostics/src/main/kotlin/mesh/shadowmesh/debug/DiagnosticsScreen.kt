package mesh.shadowmesh.debug

import android.content.ClipData
import mesh.shadowmesh.diagnostics.Diag
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private fun verdictColor(v: Verdict): Color = when (v) {
    Verdict.PASS        -> Color(0xFF00FF7F)
    Verdict.WARN        -> Color(0xFFFFC107)
    Verdict.FAIL        -> Color(0xFFFF4D4D)
    Verdict.UNAVAILABLE -> Color(0xFF8A8A8A)
    Verdict.MANUAL      -> Color(0xFF4FA3FF)
    Verdict.RUNNING     -> Color(0xFFCCCCCC)
    Verdict.NOT_RUN     -> Color(0xFF555555)
}

private fun severityColor(s: mesh.shadowmesh.diagnostics.Severity): Color = when (s) {
    mesh.shadowmesh.diagnostics.Severity.INVARIANT_VIOLATED -> Color(0xFFFF4D4D)
    mesh.shadowmesh.diagnostics.Severity.SWALLOWED          -> Color(0xFFFFC107)
    mesh.shadowmesh.diagnostics.Severity.DEGRADED           -> Color(0xFFFF9800)
    mesh.shadowmesh.diagnostics.Severity.FALLBACK           -> Color(0xFF4FA3FF)
    mesh.shadowmesh.diagnostics.Severity.INFO               -> Color(0xFF8A8A8A)
}

/**
 * Throwaway on-device diagnostics console. Lists every [Probe], runs them on demand, and
 * lets you copy a plain-text report (device model + per-probe verdicts/evidence) to paste
 * into a test log. Compiled into debug builds only.
 */
@Composable
fun DiagnosticsScreen(deps: DiagnosticsDeps = DiagnosticsDeps()) {
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val probes = remember { ProbeRegistry.all() }
    val results = remember { mutableStateMapOf<String, ProbeResult>() }
    var running by remember { mutableStateOf(false) }
    var logTick by remember { mutableStateOf(0) }   // bump to refresh the event log
    val events = remember(logTick) { DiagRecorder.snapshot() }

    // Route production's Diag reports into the on-device recorder (debug only).
    LaunchedEffect(Unit) { Diag.install(DiagRecorder) }

    suspend fun runOne(p: Probe) {
        results[p.id] = ProbeResult(Verdict.RUNNING, "Running…")
        results[p.id] = try {
            withContext(Dispatchers.Default) { p.run(ctx, deps) }
        } catch (t: Throwable) {
            ProbeResult(Verdict.FAIL, "Probe threw", "${t::class.simpleName}: ${t.message}")
        }
        logTick++
    }

    Surface(color = Color(0xFF0A0A0A), modifier = Modifier.fillMaxSize()) {
        Column(Modifier.fillMaxSize().padding(12.dp)) {
            Text("SHADOWMESH · device diagnostics", color = Color(0xFFEDEDED),
                fontWeight = FontWeight.Bold, fontSize = 18.sp)
            Text("Debug build only — exercises hardware/integration layers a terminal can't.",
                color = Color(0xFF8A8A8A), fontSize = 12.sp)
            Spacer(Modifier.height(10.dp))

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = {
                        scope.launch {
                            running = true
                            probes.forEach { runOne(it) }
                            running = false
                        }
                    },
                    enabled = !running
                ) { Text(if (running) "Running…" else "Run all") }

                OutlinedButton(onClick = { copyReport(ctx, results) }) { Text("Copy report") }
                OutlinedButton(onClick = { results.clear() }) { Text("Clear") }
            }
            Spacer(Modifier.height(10.dp))

            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(probes, key = { it.id }) { probe ->
                    ProbeCard(
                        probe   = probe,
                        result  = results[probe.id],
                        onRun   = { scope.launch { runOne(probe) } }
                    )
                }

                // ── Live Diag event log: everything production code reported quietly ──
                item {
                    Spacer(Modifier.height(8.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text("Diag event log (${events.size})", color = Color(0xFFEDEDED),
                            fontWeight = FontWeight.Bold, fontSize = 15.sp, modifier = Modifier.weight(1f))
                        TextButton(onClick = { logTick++ }) { Text("Refresh") }
                        TextButton(onClick = { DiagRecorder.clear(); logTick++ }) { Text("Clear log") }
                    }
                    if (events.isEmpty()) {
                        Text("Empty — nothing swallowed/degraded since launch. Exercise the app, then Refresh.",
                            color = Color(0xFF777777), fontSize = 12.sp)
                    }
                }
                items(events) { e ->
                    Surface(color = Color(0xFF111111), shape = RoundedCornerShape(6.dp),
                        modifier = Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(8.dp)) {
                            Row {
                                Text(e.severity.name, color = severityColor(e.severity),
                                    fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                                Spacer(Modifier.width(8.dp))
                                Text("${e.subsystem} · ${e.code}", color = Color(0xFFCFCFCF), fontSize = 12.sp)
                            }
                            Text(e.message, color = Color(0xFF9A9A9A), fontSize = 11.sp)
                            e.throwableMsg?.let { Text(it, color = Color(0xFFFF8A8A),
                                fontFamily = FontFamily.Monospace, fontSize = 10.sp) }
                            e.fields.forEach { (k, v) -> Text("· $k = $v", color = Color(0xFF6FA8DC),
                                fontFamily = FontFamily.Monospace, fontSize = 10.sp) }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ProbeCard(probe: Probe, result: ProbeResult?, onRun: () -> Unit) {
    val verdict = result?.verdict ?: Verdict.NOT_RUN
    Surface(
        color = Color(0xFF111111),
        shape = RoundedCornerShape(8.dp),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier.size(10.dp).background(verdictColor(verdict), RoundedCornerShape(5.dp))
                )
                Spacer(Modifier.width(8.dp))
                Column(Modifier.weight(1f)) {
                    Text(probe.title, color = Color(0xFFEDEDED), fontWeight = FontWeight.SemiBold, fontSize = 15.sp)
                    Text(probe.category.label, color = Color(0xFF8A8A8A), fontSize = 11.sp)
                }
                Text(verdict.name, color = verdictColor(verdict), fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = onRun) { Text("Run") }
            }

            if (result == null) {
                Text(probe.description, color = Color(0xFF777777), fontSize = 12.sp)
            } else {
                Text(result.headline, color = Color(0xFFDDDDDD), fontSize = 13.sp,
                    fontWeight = FontWeight.Medium)
                if (result.detail.isNotBlank()) {
                    Spacer(Modifier.height(2.dp))
                    Text(result.detail, color = Color(0xFF9A9A9A), fontSize = 12.sp)
                }
                if (result.evidence.isNotEmpty()) {
                    Spacer(Modifier.height(4.dp))
                    result.evidence.forEach { (k, v) ->
                        Text("· $k = $v", color = Color(0xFF6FA8DC),
                            fontFamily = FontFamily.Monospace, fontSize = 11.sp)
                    }
                }
            }
        }
    }
}

private fun copyReport(ctx: Context, results: Map<String, ProbeResult>) {
    val sb = StringBuilder("SHADOWMESH device diagnostics\n")
    sb.append("device: ${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL} " +
        "(API ${android.os.Build.VERSION.SDK_INT}, ABIs ${android.os.Build.SUPPORTED_ABIS.joinToString(",")})\n\n")
    ProbeRegistry.all().forEach { p ->
        val r = results[p.id]
        sb.append("[${r?.verdict?.name ?: "NOT_RUN"}] ${p.title}\n")
        if (r != null) {
            sb.append("    ${r.headline}\n")
            if (r.detail.isNotBlank()) sb.append("    ${r.detail}\n")
            r.evidence.forEach { (k, v) -> sb.append("    $k = $v\n") }
        }
        sb.append('\n')
    }
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("shadowmesh-diagnostics", sb.toString()))
}

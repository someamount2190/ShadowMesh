@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package mesh.shadowmesh.app.debug

import mesh.shadowmesh.crypto.toHex
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlinx.coroutines.launch
import mesh.shadowmesh.app.AppModule
import mesh.shadowmesh.mesh.health.MeshHealthState
import mesh.shadowmesh.mesh.health.TransportType
import mesh.shadowmesh.ui.theme.Clr
import mesh.shadowmesh.ui.theme.MonoFamily

// ── Entry point ───────────────────────────────────────────────────────────────

@Composable
fun DebugConsoleScreen(onBack: () -> Unit) {
    val tabs = listOf("HEALTH", "DHT", "GOSSIP", "CRYPTO", "IDENTITY", "NSC", "LOGS")
    var selectedTab by remember { mutableIntStateOf(0) }

    Column(
        Modifier
            .fillMaxSize()
            .background(Clr.Bg0)
    ) {
        // Top bar
        Row(
            Modifier
                .fillMaxWidth()
                .background(Clr.Bg1)
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = onBack, modifier = Modifier.size(32.dp)) {
                Icon(Icons.Default.ArrowBack, contentDescription = "Back", tint = Clr.TextPri)
            }
            Spacer(Modifier.width(8.dp))
            Text(
                "DEBUG CONSOLE",
                color = Clr.Green,
                fontSize = 13.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = MonoFamily
            )
        }

        // Tab row
        ScrollableTabRow(
            selectedTabIndex = selectedTab,
            containerColor   = Clr.Bg1,
            contentColor     = Clr.Green,
            edgePadding      = 0.dp,
        ) {
            tabs.forEachIndexed { idx, label ->
                Tab(
                    selected = selectedTab == idx,
                    onClick  = { selectedTab = idx },
                    text     = {
                        Text(
                            label,
                            fontSize       = 9.sp,
                            fontFamily     = MonoFamily,
                            fontWeight     = FontWeight.Bold,
                            color          = if (selectedTab == idx) Clr.Green else Clr.TextMute
                        )
                    }
                )
            }
        }

        // Tab content
        Box(Modifier.fillMaxSize().padding(12.dp)) {
            when (selectedTab) {
                0 -> HealthTab()
                1 -> DhtTab()
                2 -> GossipTab()
                3 -> CryptoTab()
                4 -> IdentityTab()
                5 -> NscTab()
                6 -> LogsTab()
            }
        }
    }
}

// ── HEALTH tab ────────────────────────────────────────────────────────────────

@Composable
private fun HealthTab() {
    if (!AppModule.isInitialised) { NotReady(); return }
    val mon   = AppModule.transportHealthMonitor
    val state by mon.currentState.collectAsStateWithLifecycle()
    val hmap  by mon.perTransportHealth.collectAsStateWithLifecycle()
    val scope = rememberCoroutineScope()

    Column(Modifier.verticalScroll(rememberScrollState())) {
        MonoLabel("STATE", state.name, stateColor(state))
        MonoKv("Time in state", fmtDuration(mon.timeInCurrentStateMs))
        Spacer(Modifier.height(12.dp))

        SectionHeader("TRANSPORT PROBES")
        TransportType.values().forEach { type ->
            val entry = hmap[type]
            Row(
                Modifier.fillMaxWidth().padding(vertical = 3.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment     = Alignment.CenterVertically
            ) {
                Text(type.name, color = Clr.TextSec, fontSize = 11.sp, fontFamily = MonoFamily,
                    modifier = Modifier.weight(1f))
                val ok = entry?.isHealthy == true
                Text(
                    if (ok) "OK  ${entry!!.averageLatencyMs}ms" else "FAIL  ×${entry?.consecutiveFailures ?: 0}",
                    color      = if (ok) Clr.Green else Clr.Red,
                    fontSize   = 10.sp,
                    fontFamily = MonoFamily
                )
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = { scope.launch { mon.probeNow(type) } },
                    modifier        = Modifier.height(26.dp),
                    contentPadding  = PaddingValues(horizontal = 8.dp),
                    colors          = ButtonDefaults.buttonColors(containerColor = Clr.Bg2)
                ) { Text("PROBE", fontSize = 8.sp, fontFamily = MonoFamily) }
            }
        }

        Spacer(Modifier.height(12.dp))
        SectionHeader("FORCE STATE (TEST)")
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            MeshHealthState.values().forEach { s ->
                Button(
                    onClick        = { mon.forceState(s) },
                    modifier       = Modifier.height(28.dp),
                    contentPadding = PaddingValues(horizontal = 6.dp),
                    colors         = ButtonDefaults.buttonColors(containerColor = stateColor(s).copy(alpha = 0.3f))
                ) { Text(s.name.take(5), fontSize = 7.sp, fontFamily = MonoFamily, color = stateColor(s)) }
            }
        }

        Spacer(Modifier.height(12.dp))
        SectionHeader("TRANSITION HISTORY")
        val history = mon.transitionHistory
        if (history.isEmpty()) {
            Text("No transitions yet.", color = Clr.TextMute, fontSize = 10.sp, fontFamily = MonoFamily)
        } else {
            history.forEach { t ->
                Text(
                    "${t.fromState.name} → ${t.toState.name}  [${t.reason}]",
                    color      = Clr.TextSec,
                    fontSize   = 9.sp,
                    fontFamily = MonoFamily,
                    modifier   = Modifier.padding(vertical = 1.dp)
                )
            }
        }
    }
}

// ── DHT tab ───────────────────────────────────────────────────────────────────

@Composable
private fun DhtTab() {
    if (!AppModule.isInitialised) { NotReady(); return }
    val dht = AppModule.dhtEngine
    val rt  = dht.routingTable

    Column(Modifier.verticalScroll(rememberScrollState())) {
        MonoKv("Local node ID", dht.localNodeId.toHex().take(32) + "…")
        MonoKv("Routing table size", rt.size().toString())

        Spacer(Modifier.height(12.dp))
        SectionHeader("CLOSEST PEERS (top 8)")
        val closest = rt.findClosest(dht.localNodeId, 8)
        if (closest.isEmpty()) {
            Text("Routing table empty.", color = Clr.TextMute, fontSize = 10.sp, fontFamily = MonoFamily)
        } else {
            closest.forEach { c ->
                Text(
                    "${c.nodeId.toHex().take(20)}…  ${c.address.ip}:${c.address.port}",
                    color      = Clr.TextSec,
                    fontSize   = 9.sp,
                    fontFamily = MonoFamily,
                    modifier   = Modifier.padding(vertical = 1.dp)
                )
            }
        }
    }
}

// ── GOSSIP tab ────────────────────────────────────────────────────────────────

@Composable
private fun GossipTab() {
    if (!AppModule.isInitialised) { NotReady(); return }
    val gossip = AppModule.gossipEngine
    // Collect health state unconditionally — always wired once AppModule is initialised
    val healthState by AppModule.transportHealthMonitor.currentState.collectAsStateWithLifecycle()

    Column(Modifier.verticalScroll(rememberScrollState())) {
        MonoKv("Local node ID", gossip.localNodeId.toHex().take(32) + "…")
        Spacer(Modifier.height(8.dp))
        Text(
            "Gossip relay stats are runtime-only and not exposed as public state.\n" +
            "To observe relay activity, connect a Logcat filter: tag=GossipEngine.",
            color      = Clr.TextMute,
            fontSize   = 10.sp,
            fontFamily = MonoFamily,
            lineHeight = 14.sp
        )
        Spacer(Modifier.height(12.dp))
        SectionHeader("HEALTH GUARD")
        MonoKv("Health monitor wired", (gossip.healthMonitor != null).toString())
        MonoKv("Current state", healthState.name)
        MonoKv("Relay blocked (ISOLATED)", (healthState == MeshHealthState.ISOLATED).toString())
    }
}

// ── CRYPTO tab ────────────────────────────────────────────────────────────────

@Composable
private fun CryptoTab() {
    if (!AppModule.isInitialised) { NotReady(); return }
    val scope   = rememberCoroutineScope()
    var kemOut  by remember { mutableStateOf("Press RUN to test KEM only.") }
    var postOut by remember { mutableStateOf("Press RUN to test the full post pipeline.") }
    var kemRunning  by remember { mutableStateOf(false) }
    var postRunning by remember { mutableStateOf(false) }
    var iterCount   by remember { mutableIntStateOf(10) }

    Column(Modifier.verticalScroll(rememberScrollState())) {

        // ── KEM step-by-step ─────────────────────────────────────────────────
        SectionHeader("KEM STEP-BY-STEP (Kyber-1024 + X25519)")
        Text(
            "Isolates each KEM step: keygen → encap → decap → shared-secret equality.",
            color = Clr.TextMute, fontSize = 10.sp, fontFamily = MonoFamily, lineHeight = 14.sp
        )
        Spacer(Modifier.height(6.dp))
        Button(
            onClick = {
                if (!kemRunning) {
                    kemRunning = true
                    kemOut = "Running…"
                    scope.launch {
                        kemOut = runKemStepByStep()
                        kemRunning = false
                    }
                }
            },
            enabled        = !kemRunning,
            colors         = ButtonDefaults.buttonColors(containerColor = Clr.Green.copy(alpha = 0.2f)),
            contentPadding = PaddingValues(horizontal = 12.dp)
        ) { Text("RUN KEM", fontSize = 9.sp, fontFamily = MonoFamily, color = Clr.Green) }
        Spacer(Modifier.height(6.dp))
        Text(kemOut, color = Clr.TextPri, fontSize = 9.sp, fontFamily = MonoFamily, lineHeight = 13.sp)

        Spacer(Modifier.height(16.dp))

        // ── Post pipeline loop ────────────────────────────────────────────────
        SectionHeader("POST CRYPTO PIPELINE LOOP")
        Text(
            "KEM → channel key → PostRatchet sender + receiver → N × (encrypt + decrypt).\n" +
            "Verifies end-to-end post confidentiality and ratchet agreement on-device.",
            color = Clr.TextMute, fontSize = 10.sp, fontFamily = MonoFamily, lineHeight = 14.sp
        )
        Spacer(Modifier.height(6.dp))

        // Iteration count picker
        Row(verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text("Iterations:", color = Clr.TextMute, fontSize = 10.sp, fontFamily = MonoFamily)
            listOf(5, 10, 50, 100).forEach { n ->
                Button(
                    onClick        = { iterCount = n },
                    modifier       = Modifier.height(26.dp),
                    contentPadding = PaddingValues(horizontal = 8.dp),
                    colors         = ButtonDefaults.buttonColors(
                        containerColor = if (iterCount == n) Clr.Green.copy(0.3f) else Clr.Bg2
                    )
                ) { Text("$n", fontSize = 9.sp, fontFamily = MonoFamily,
                         color = if (iterCount == n) Clr.Green else Clr.TextSec) }
            }
        }
        Spacer(Modifier.height(6.dp))
        Button(
            onClick = {
                if (!postRunning) {
                    postRunning = true
                    postOut = "Running $iterCount-iteration post pipeline…"
                    scope.launch {
                        postOut = runPostPipeline(iterCount)
                        postRunning = false
                    }
                }
            },
            enabled        = !postRunning,
            colors         = ButtonDefaults.buttonColors(containerColor = Clr.Green.copy(alpha = 0.2f)),
            contentPadding = PaddingValues(horizontal = 12.dp)
        ) { Text("RUN POST PIPELINE", fontSize = 9.sp, fontFamily = MonoFamily, color = Clr.Green) }
        Spacer(Modifier.height(6.dp))
        Text(postOut, color = Clr.TextPri, fontSize = 9.sp, fontFamily = MonoFamily, lineHeight = 13.sp)

        Spacer(Modifier.height(16.dp))
        SectionHeader("APK BINDING HASH")
        Text(
            AppModule.apkBindingHash.toHex(),
            color = Clr.TextSec, fontSize = 9.sp, fontFamily = MonoFamily
        )
    }
}

// ── KEM step-by-step ──────────────────────────────────────────────────────────

private suspend fun runKemStepByStep(): String = buildString {
    val kem = AppModule.kem
    try {
        // Step 1: key generation
        val t0 = System.currentTimeMillis()
        val kp = runCatching { kem.generateKeyPair().getOrThrow() }.getOrElse { e ->
            appendLine("✗ KEYGEN FAILED: ${e.message}")
            return@buildString
        }
        appendLine("KEYGEN  OK  (${System.currentTimeMillis() - t0}ms)")
        appendLine("  Kyber pub : ${kp.publicKey.kyberPublicKey.size} B")
        appendLine("  X25519 pub: ${kp.publicKey.x25519PublicKey.size} B")
        appendLine("  Kyber priv: ${kp.privateKey.kyberPrivateKey.size} B")
        appendLine("  kyberPubForSalt matches pub: " +
            "${kp.privateKey.kyberPublicKeyForSalt.contentEquals(kp.publicKey.kyberPublicKey)}")

        // Step 2: encapsulate
        val t1 = System.currentTimeMillis()
        val enc = runCatching { kem.encapsulate(kp.publicKey).getOrThrow() }.getOrElse { e ->
            appendLine("✗ ENCAP FAILED: ${e.message}")
            return@buildString
        }
        appendLine("ENCAP   OK  (${System.currentTimeMillis() - t1}ms)")
        appendLine("  Kyber ct  : ${enc.ciphertext.kyberCiphertext.size} B")
        appendLine("  X25519 eph: ${enc.ciphertext.x25519EphPublicKey.size} B")
        appendLine("  ss (enc)  : ${enc.sharedSecret.toHex().take(32)}…")

        // Step 3: decapsulate
        val t2 = System.currentTimeMillis()
        val dec = runCatching { kem.decapsulate(enc.ciphertext, kp.privateKey).getOrThrow() }.getOrElse { e ->
            appendLine("✗ DECAP FAILED: ${e.message}")
            return@buildString
        }
        appendLine("DECAP   OK  (${System.currentTimeMillis() - t2}ms)")
        appendLine("  ss (dec)  : ${dec.toHex().take(32)}…")

        // Step 4: verify
        val match = enc.sharedSecret.contentEquals(dec)
        appendLine("MATCH   ${if (match) "✓ PASS" else "✗ FAIL — secrets diverge"}")
        if (!match) {
            appendLine("  enc[0..7]: ${enc.sharedSecret.toHex().take(16)}")
            appendLine("  dec[0..7]: ${dec.toHex().take(16)}")
        }

    } catch (e: Exception) {
        appendLine("✗ UNEXPECTED: ${e.javaClass.simpleName}: ${e.message}")
    }
}

// ── Post pipeline loop ─────────────────────────────────────────────────────────

private suspend fun runPostPipeline(iterations: Int): String = buildString {
    val hkdf   = AppModule.hkdf
    val cipher = AppModule.cipher
    val kem    = AppModule.kem

    try {
        // ── 1. KEM ────────────────────────────────────────────────────────────
        appendLine("=== 1. KEM ===")
        val kp  = runCatching { kem.generateKeyPair().getOrThrow() }.getOrElse { e ->
            appendLine("✗ keygen: ${e.message}"); return@buildString
        }
        val enc = runCatching { kem.encapsulate(kp.publicKey).getOrThrow() }.getOrElse { e ->
            appendLine("✗ encap: ${e.message}"); return@buildString
        }
        val dec = runCatching { kem.decapsulate(enc.ciphertext, kp.privateKey).getOrThrow() }.getOrElse { e ->
            appendLine("✗ decap: ${e.message}"); return@buildString
        }
        val kemOk = enc.sharedSecret.contentEquals(dec)
        appendLine("  ${if (kemOk) "✓" else "✗"} shared-secret match: $kemOk")
        if (!kemOk) { appendLine("  ABORTING — KEM mismatch is the root failure."); return@buildString }

        // ── 2. Channel key ────────────────────────────────────────────────────
        appendLine("=== 2. Channel key from KEM ss ===")
        val channelKey = hkdf.derive(
            ikm       = enc.sharedSecret,
            salt      = null,
            info      = "shadowmesh_channel_v1".toByteArray(),
            outputLen = 32
        )
        appendLine("  key: ${channelKey.toHex().take(32)}…")

        // ── 3. PostRatchet init ────────────────────────────────────────────────
        appendLine("=== 3. PostRatchet (sender + receiver) ===")
        // Set checkpointInterval above iterations so checkpoints don't fire mid-test.
        val senderR   = mesh.shadowmesh.crypto.PostRatchet.fromChannelKey(channelKey, hkdf, iterations + 1)
        val receiverR = mesh.shadowmesh.crypto.PostRatchet.fromChannelKey(channelKey, hkdf, iterations + 1)
        appendLine("  ✓ both ratchets initialised from same channel key")

        // ── 4. Encrypt / decrypt loop ──────────────────────────────────────────
        appendLine("=== 4. Loop ($iterations posts) ===")
        var passed = 0
        var totalEncMs = 0L
        var totalDecMs = 0L

        repeat(iterations) { i ->
            val plain    = "POST #${i + 1}: ${System.currentTimeMillis()}".toByteArray()
            val postHash = hkdf.sha3_256(plain)

            // Sender: advance ratchet → postKey → encrypt
            val tEnc = System.currentTimeMillis()
            val sStep    = senderR.advance(postHash)
            val sKey     = sStep.postKey.copyOf()  // capture before potential wipe
            val ct = runCatching { cipher.encrypt(plain, sStep.postKey).getOrThrow() }.getOrElse { e ->
                sStep.postKey.fill(0); sKey.fill(0)
                appendLine("  [${i+1}] ✗ encrypt: ${e.message}")
                return@repeat
            }
            sStep.postKey.fill(0)
            totalEncMs += System.currentTimeMillis() - tEnc

            // Receiver: advance same ratchet position → postKey → decrypt
            val tDec = System.currentTimeMillis()
            val rStep    = receiverR.advance(postHash)
            val rKey     = rStep.postKey.copyOf()
            val recovered = runCatching { cipher.decrypt(ct, rStep.postKey).getOrThrow() }.getOrElse { e ->
                rStep.postKey.fill(0); rKey.fill(0); sKey.fill(0)
                appendLine("  [${i+1}] ✗ decrypt: ${e.message}")
                appendLine("         sKey: ${sKey.toHex().take(16)}…")
                appendLine("         rKey: ${rKey.toHex().take(16)}…")
                return@repeat
            }
            rStep.postKey.fill(0)
            totalDecMs += System.currentTimeMillis() - tDec

            val keysMatch  = sKey.contentEquals(rKey)
            val plainMatch = plain.contentEquals(recovered)
            sKey.fill(0); rKey.fill(0)

            when {
                !keysMatch  -> appendLine("  [${i+1}] ✗ KEY MISMATCH — ratchets diverged (step ${i+1})")
                !plainMatch -> appendLine("  [${i+1}] ✗ PLAINTEXT MISMATCH after decrypt")
                else        -> {
                    passed++
                    // Print first 3, last 1, and ellipsis in between
                    when {
                        i < 3 || i == iterations - 1 ->
                            appendLine("  [${i+1}] ✓  ct=${ct.size}B  idx=${sStep.postIndex}")
                        i == 3 && iterations > 5 ->
                            appendLine("  … (${iterations - 4} more) …")
                    }
                }
            }
        }

        // ── 5. Summary ─────────────────────────────────────────────────────────
        appendLine("=== 5. Summary ===")
        val avgEnc = if (iterations > 0) totalEncMs / iterations else 0L
        val avgDec = if (iterations > 0) totalDecMs / iterations else 0L
        appendLine("  $passed / $iterations posts passed")
        appendLine("  avg encrypt: ${avgEnc}ms   avg decrypt: ${avgDec}ms")
        appendLine(if (passed == iterations) "  ✓ ALL PASS" else "  ✗ ${iterations - passed} FAILURES")

    } catch (e: Exception) {
        appendLine("✗ UNHANDLED: ${e.javaClass.simpleName}: ${e.message}")
        e.cause?.let { appendLine("  cause: ${it.message}") }
    }
}

// ── IDENTITY tab ──────────────────────────────────────────────────────────────

@Composable
private fun IdentityTab() {
    if (!AppModule.isInitialised) { NotReady(); return }
    val id = AppModule.localIdentity

    Column(Modifier.verticalScroll(rememberScrollState())) {
        MonoKv("Node ID", id.nodeId.toHex())
        Spacer(Modifier.height(8.dp))
        MonoKv("KEM pub (Kyber) size",  "${id.publicPart.kemPublicKey.kyberPublicKey.size} B")
        MonoKv("KEM pub (X25519) size", "${id.publicPart.kemPublicKey.x25519PublicKey.size} B")
        MonoKv("Sig pub (Dilithium) prefix",
            id.publicPart.signingPublicKey.dilithiumPublicKey.toHex().take(32) + "…")
        MonoKv("Sig pub (Ed25519) prefix",
            id.publicPart.signingPublicKey.ed25519PublicKey.toHex().take(32) + "…")
        Spacer(Modifier.height(8.dp))
        SectionHeader("ATTESTATION")
        MonoKv("Attestation required", AppModule.attestationRequired.toString())
    }
}

// ── NSC tab ───────────────────────────────────────────────────────────────────

@Composable
private fun NscTab() {
    if (!AppModule.isInitialised) { NotReady(); return }
    val nsc = AppModule.nsc
    val halted by nsc.haltedFlow.collectAsStateWithLifecycle(initialValue = false)

    Column(Modifier.verticalScroll(rememberScrollState())) {
        MonoLabel("NSC HALTED", halted.toString(), if (halted) Clr.Red else Clr.Green)
        Spacer(Modifier.height(8.dp))
        MonoKv("isHalted (direct)", nsc.isHalted.toString())
        Spacer(Modifier.height(12.dp))
        SectionHeader("NETWORK MODE")
        val nm = AppModule.networkModeSM
        MonoKv("Current mode", nm.currentMode.name)
        Spacer(Modifier.height(12.dp))
        SectionHeader("INTEGRITY")
        MonoKv("APK binding hash",
            AppModule.apkBindingHash.toHex().take(32) + "…")
    }
}

// ── LOGS tab ──────────────────────────────────────────────────────────────────

@Composable
private fun LogsTab() {
    if (!AppModule.isInitialised) { NotReady(); return }

    Column {
        SectionHeader("HEALTH TRANSITIONS (live)")
        val transitions = AppModule.transportHealthMonitor.transitionHistory
        if (transitions.isEmpty()) {
            Text("No transitions recorded.", color = Clr.TextMute, fontSize = 10.sp, fontFamily = MonoFamily)
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(transitions) { t ->
                    Text(
                        "${fmtDuration(System.currentTimeMillis() - t.timestampMs)} ago  " +
                        "${t.fromState.name} → ${t.toState.name}  [${t.reason}]",
                        color      = Clr.TextSec,
                        fontSize   = 9.sp,
                        fontFamily = MonoFamily,
                        modifier   = Modifier.padding(vertical = 2.dp)
                    )
                }
            }
        }
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

@Composable
private fun NotReady() {
    Text("AppModule not yet initialised.", color = Clr.Red, fontSize = 11.sp, fontFamily = MonoFamily)
}

@Composable
private fun SectionHeader(label: String) {
    Text(
        label,
        color      = Clr.TextMute,
        fontSize   = 9.sp,
        fontFamily = MonoFamily,
        fontWeight = FontWeight.Bold,
        modifier   = Modifier.padding(bottom = 4.dp)
    )
}

@Composable
private fun MonoKv(key: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text("$key:", color = Clr.TextMute, fontSize = 10.sp, fontFamily = MonoFamily,
            modifier = Modifier.width(180.dp))
        Text(value, color = Clr.TextPri, fontSize = 10.sp, fontFamily = MonoFamily)
    }
}

@Composable
private fun MonoLabel(key: String, value: String, valueColor: Color) {
    Row(Modifier.fillMaxWidth().padding(vertical = 2.dp), verticalAlignment = Alignment.CenterVertically) {
        Text("$key:", color = Clr.TextMute, fontSize = 10.sp, fontFamily = MonoFamily,
            modifier = Modifier.width(180.dp))
        Text(value, color = valueColor, fontSize = 11.sp, fontFamily = MonoFamily,
            fontWeight = FontWeight.Bold)
    }
}

private fun stateColor(state: MeshHealthState): Color = when (state) {
    MeshHealthState.FULL_MESH      -> Clr.Green
    MeshHealthState.LOCAL_MESH     -> Clr.Amber
    MeshHealthState.PROXIMITY_MESH -> Clr.Orange
    MeshHealthState.BLE_ONLY       -> Color(0xFF4FC3F7)
    MeshHealthState.ISOLATED       -> Clr.Red
}

private fun fmtDuration(ms: Long): String = when {
    ms < 0          -> "0s"
    ms < 60_000     -> "${ms / 1000}s"
    ms < 3_600_000  -> "${ms / 60_000}m ${(ms % 60_000) / 1000}s"
    else            -> "${ms / 3_600_000}h ${(ms % 3_600_000) / 60_000}m"
}


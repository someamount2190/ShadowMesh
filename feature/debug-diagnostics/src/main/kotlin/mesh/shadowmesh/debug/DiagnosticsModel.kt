package mesh.shadowmesh.debug

import android.content.Context

/**
 * Outcome of a single diagnostic probe.
 *
 * The point of the harness is to turn "does the hardware-rooted claim actually hold on
 * THIS device?" into a clear verdict a person with one or two phones can read, rather
 * than a guarantee asserted only in the README.
 */
enum class Verdict {
    PASS,         // property verified on this device
    WARN,         // works, but with a caveat that matters (e.g. TEE not StrongBox; roots unconfigured)
    FAIL,         // property does NOT hold — a real problem
    UNAVAILABLE,  // hardware/feature not present on this device (not a failure of the app)
    MANUAL,       // needs a human action / second device — see detail for instructions
    NOT_RUN,
    RUNNING
}

data class ProbeResult(
    val verdict:  Verdict,
    val headline: String,
    val detail:   String = "",
    /** Key/value facts shown under the headline and included in the exported report. */
    val evidence: Map<String, String> = emptyMap()
) {
    companion object {
        fun manual(headline: String, detail: String) =
            ProbeResult(Verdict.MANUAL, headline, detail)
    }
}

enum class ProbeCategory(val label: String) {
    KEYSTORE("Keystore / TEE"),
    ATTESTATION("Hardware attestation"),
    CRYPTO("Native crypto"),
    STORAGE("Database / migrations"),
    NFC("NFC bootstrap"),
    RADIO("BLE / WiFi-Direct"),
    MESH("Mesh propagation")
}

interface Probe {
    val id:          String
    val title:       String
    val category:    ProbeCategory
    val description: String
    suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult
}

/**
 * App-supplied hooks for the probes the diagnostics module deliberately does NOT implement
 * itself — because they need live singletons (the Room database, transport instances) or a
 * second device to orchestrate. The app wires these in its debug source set; when a hook is
 * absent the corresponding probe degrades to [Verdict.MANUAL]/[Verdict.UNAVAILABLE] rather
 * than guessing at transport internals.
 */
data class DiagnosticsDeps(
    val expectedDbVersion:   Int = -1,
    val dbVersionProvider:   (suspend () -> Int)? = null,
    val nfcSelfTest:         (suspend () -> ProbeResult)? = null,
    val bleScanTest:         (suspend () -> ProbeResult)? = null,
    val wifiDirectTest:      (suspend () -> ProbeResult)? = null,
    val meshPropagationTest: (suspend () -> ProbeResult)? = null
)

/** Every probe, in display order. Pure registry — no Android state held here. */
object ProbeRegistry {
    fun all(): List<Probe> = listOf(
        // hardware / device
        KeystoreTierProbe,
        HardwareAttestationSelfProbe,
        // native crypto + crypto invariants
        NativeCryptoRoundTripProbe,
        SignerRoundTripProbe,
        RatchetDeterminismProbe,
        // storage / FEC
        DatabaseVersionProbe,
        FountainLossProbe,
        // mesh logic invariants
        BloomFilterProbe,
        RateLimiterProbe,
        // anything production code reported as quietly failing
        SilentFailureProbe,
        // 2-device / app-wired
        NfcSelfTestProbe,
        BleScanProbe,
        WifiDirectProbe,
        MeshPropagationProbe
    )
}

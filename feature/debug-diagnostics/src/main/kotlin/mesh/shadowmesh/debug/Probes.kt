package mesh.shadowmesh.debug

import android.content.Context
import android.os.Build
import mesh.shadowmesh.attestation.AttestationResult
import mesh.shadowmesh.attestation.HardwareAttestation
import mesh.shadowmesh.attestation.VerificationResult
import mesh.shadowmesh.attestation.VerifiedBootState
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.HybridKem
import mesh.shadowmesh.security.BiometricKeyManager

private fun device() = "${Build.MANUFACTURER} ${Build.MODEL} (API ${Build.VERSION.SDK_INT})"

// ─── Keystore / TEE ───────────────────────────────────────────────────────────
// Confirms where private keys actually live on THIS device. The entire confidentiality
// claim in THREAT_MODEL.md §1 rests on this being hardware-backed; a software-only
// Keystore means "rooting does not expose your keys" is false here.
object KeystoreTierProbe : Probe {
    override val id = "keystore_tier"
    override val title = "Keystore backing tier"
    override val category = ProbeCategory.KEYSTORE
    override val description =
        "Generates a probe key and reports whether the Android Keystore is backed by " +
        "StrongBox, a TEE, or software only."

    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult {
        val tier = BiometricKeyManager(ctx).detectKeystoreTier()
        val ev = mapOf("device" to device(), "tier" to tier.name)
        return when (tier) {
            BiometricKeyManager.KeystoreTier.HARDWARE_STRONGBOX ->
                ProbeResult(Verdict.PASS, "StrongBox-backed Keystore", "Strongest hardware tier.", ev)
            BiometricKeyManager.KeystoreTier.HARDWARE_TEE ->
                ProbeResult(Verdict.PASS, "TEE-backed Keystore",
                    "Hardware-rooted via TEE (not a dedicated StrongBox element). Confidentiality claim holds.", ev)
            BiometricKeyManager.KeystoreTier.SOFTWARE_ONLY ->
                ProbeResult(Verdict.FAIL, "Software-only Keystore",
                    "Keys are NOT hardware-rooted on this device — the §1 confidentiality guarantee does not hold here.", ev)
        }
    }
}

// ─── Hardware attestation self-test ─────────────────────────────────────────────
// End-to-end exercise of the Tier-B pipeline (THREAT_MODEL §3): generate a Keystore key
// with an attestation challenge, parse the resulting certificate chain, and report the
// boot state, StrongBox backing, and whether the configured root actually matches.
object HardwareAttestationSelfProbe : Probe {
    override val id = "attestation_self"
    override val title = "Hardware attestation pipeline"
    override val category = ProbeCategory.ATTESTATION
    override val description =
        "Self-attests this device and runs the same chain verification a peer would, " +
        "reporting boot state, StrongBox, and root-cert configuration."

    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult {
        val googleConfigured = HardwareAttestation.isRootConfigured(
            HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA
        ) && HardwareAttestation.isRootConfigured(
            HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_EC
        )
        val challenge = HardwareAttestation.generateChallenge()

        return when (val gen = HardwareAttestation.generateAttestationKey(ctx, challenge)) {
            is AttestationResult.NoHardwareSupport ->
                ProbeResult(Verdict.UNAVAILABLE, "No key attestation on this device",
                    "Device/emulator has no attestation extension — peers can never reach the attested tier here.",
                    mapOf("device" to device()))

            is AttestationResult.Error ->
                ProbeResult(Verdict.FAIL, "Attestation key generation failed", gen.reason,
                    mapOf("device" to device()))

            is AttestationResult.Evidence -> {
                val verify = HardwareAttestation.verifyAttestationChain(
                    evidence          = gen.attestation,
                    expectedChallenge = challenge
                )
                when (verify) {
                    is VerificationResult.Invalid ->
                        ProbeResult(Verdict.FAIL, "Chain verification failed", verify.reason,
                            mapOf("device" to device()))

                    VerificationResult.NoAttestationExtension ->
                        ProbeResult(Verdict.UNAVAILABLE, "No attestation extension",
                            "Software-only attestation; no hardware root.", mapOf("device" to device()))

                    is VerificationResult.Valid -> {
                        // All chains (stock Android and GrapheneOS) root in the Google CA.
                        val rootMatches =
                            HardwareAttestation.verifyRootCertificate(
                                chain = gen.attestation.certificateChain,
                                expectedRootPublicKeyHex = HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA
                            ) || HardwareAttestation.verifyRootCertificate(
                                chain = gen.attestation.certificateChain,
                                expectedRootPublicKeyHex = HardwareAttestation.GOOGLE_HARDWARE_ATTESTATION_ROOT_EC
                            )
                        val ev = mapOf(
                            "device"        to device(),
                            "bootState"     to verify.verifiedBootState.name,
                            "strongBox"     to verify.isStrongBox.toString(),
                            "chainLength"   to gen.attestation.certificateChain.size.toString(),
                            "rootConfigured" to googleConfigured.toString(),
                            "rootMatches"   to rootMatches.toString()
                        )
                        when {
                            !googleConfigured -> ProbeResult(Verdict.WARN,
                                "Attestation works, but roots are placeholders",
                                "Chain + challenge verified, but GOOGLE/GRAPHENEOS root hex is unconfigured, so " +
                                "verifyRootCertificate fails closed and TRUST_PHYSICAL_ATTESTED is never issued. " +
                                "Set the real DER roots before deployment (README open item #1).", ev)
                            rootMatches -> ProbeResult(Verdict.PASS,
                                "Attestation verified against configured root", "Full Tier-B path holds on this device.", ev)
                            else -> ProbeResult(Verdict.WARN,
                                "Chain valid but root mismatch",
                                "Boot state and challenge verified, but the chain does not root in the configured " +
                                "attestation CA (wrong root hex, or unexpected OEM).", ev)
                        }
                    }
                }
            }
        }
    }
}

// ─── Native crypto round-trip ───────────────────────────────────────────────────
// JVM unit tests on a dev machine load desktop native libs; this confirms liboqs-java
// (Kyber) and lazysodium (X25519) actually load and round-trip on the DEVICE ABI — a
// real, device-specific failure mode (missing .so for arm64/x86, packaging issues).
object NativeCryptoRoundTripProbe : Probe {
    override val id = "native_crypto"
    override val title = "Hybrid KEM round-trip (native libs)"
    override val category = ProbeCategory.CRYPTO
    override val description =
        "Generates a hybrid keypair, encapsulates, and decapsulates — confirming the " +
        "post-quantum native libraries load and agree on this device's ABI."

    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult {
        val abis = Build.SUPPORTED_ABIS.joinToString(",")
        return try {
            val kem = HybridKem(Hkdf())
            val kp  = kem.generateKeyPair().getOrThrow()
            val enc = kem.encapsulate(kp.publicKey).getOrThrow()
            val dec = kem.decapsulate(enc.ciphertext, kp.privateKey).getOrThrow()
            val ok  = enc.sharedSecret.contentEquals(dec)
            val ev  = mapOf("abis" to abis, "secretBytes" to dec.size.toString())
            if (ok) ProbeResult(Verdict.PASS, "Kyber+X25519 KEM round-trips", "Native libs load and agree.", ev)
            else    ProbeResult(Verdict.FAIL, "Shared-secret mismatch",
                        "Encapsulated and decapsulated secrets differ — KEM combiner or native lib fault.", ev)
        } catch (t: Throwable) {
            ProbeResult(Verdict.FAIL, "Native crypto threw",
                "${t::class.simpleName}: ${t.message}. Often a missing/incompatible .so for this ABI.",
                mapOf("abis" to abis))
        }
    }
}

// ─── Database version ──────────────────────────────────────────────────────────
object DatabaseVersionProbe : Probe {
    override val id = "db_version"
    override val title = "Room database version"
    override val category = ProbeCategory.STORAGE
    override val description = "Opens the live database and checks the on-disk schema version."

    override suspend fun run(ctx: Context, deps: DiagnosticsDeps): ProbeResult {
        val provider = deps.dbVersionProvider
            ?: return ProbeResult.manual("DB hook not wired",
                "Pass DiagnosticsDeps.dbVersionProvider = { db.openHelper.readableDatabase.version } from the app.")
        return try {
            val v = provider()
            val ev = mapOf("onDiskVersion" to v.toString(), "expected" to deps.expectedDbVersion.toString())
            when {
                deps.expectedDbVersion < 0 -> ProbeResult(Verdict.PASS, "Database opened (version $v)", "", ev)
                v == deps.expectedDbVersion -> ProbeResult(Verdict.PASS, "Schema at expected version $v",
                    "Migrations applied cleanly.", ev)
                else -> ProbeResult(Verdict.WARN, "Version drift: on-disk $v, expected ${deps.expectedDbVersion}",
                    "A migration may be missing or the app downgraded.", ev)
            }
        } catch (t: Throwable) {
            ProbeResult(Verdict.FAIL, "Database open/migration failed",
                "${t::class.simpleName}: ${t.message}")
        }
    }
}

// ─── App-hook-backed probes (need a device and/or a second phone) ───────────────
// These deliberately do not reach into transport internals from here; the app wires a
// real test in its debug source set. Absent a hook, they print instructions.

private fun hookOrManual(hook: (suspend () -> ProbeResult)?, manualDetail: String): suspend () -> ProbeResult =
    { hook?.invoke() ?: ProbeResult.manual("Not wired / needs manual run", manualDetail) }

object NfcSelfTestProbe : Probe {
    override val id = "nfc_self"
    override val title = "NFC bootstrap handshake"
    override val category = ProbeCategory.NFC
    override val description = "Drives an NFC tap-to-exchange with a second device and reports the trust level."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps) = hookOrManual(
        deps.nfcSelfTest,
        "Bring a second SHADOWMESH device. Wire DiagnosticsDeps.nfcSelfTest to start the coordinator " +
        "as initiator/responder and return the BootstrapResult.Success trust level + attestation tier."
    ).invoke()
}

object BleScanProbe : Probe {
    override val id = "ble_scan"
    override val title = "BLE discovery + GATT"
    override val category = ProbeCategory.RADIO
    override val description = "Scans for SHADOWMESH peers, lists RSSI, and attempts a fragment transfer."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps) = hookOrManual(
        deps.bleScanTest,
        "Wire DiagnosticsDeps.bleScanTest to run BleGattTransport discovery and report discovered peers + " +
        "a SHADOWFILES fragment round-trip throughput."
    ).invoke()
}

object WifiDirectProbe : Probe {
    override val id = "wifi_direct"
    override val title = "WiFi-Direct transport"
    override val category = ProbeCategory.RADIO
    override val description = "Forms a WiFi-Direct group with a peer and measures fragment throughput."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps) = hookOrManual(
        deps.wifiDirectTest,
        "Wire DiagnosticsDeps.wifiDirectTest to form a group via WiFiDirectTransport and report throughput."
    ).invoke()
}

object MeshPropagationProbe : Probe {
    override val id = "mesh_prop"
    override val title = "Mesh propagation (store-and-forward)"
    override val category = ProbeCategory.MESH
    override val description = "Injects a test post and confirms it propagates + ACKs across nodes."
    override suspend fun run(ctx: Context, deps: DiagnosticsDeps) = hookOrManual(
        deps.meshPropagationTest,
        "Wire DiagnosticsDeps.meshPropagationTest to post on a test channel and observe fragment fetch + " +
        "MerkleAck across at least two reconnecting nodes."
    ).invoke()
}

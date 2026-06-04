// ─────────────────────────────────────────────────────────────────────────────
// :feature:debug-diagnostics  —  ON-DEVICE DIAGNOSTICS HARNESS  (REMOVE BEFORE RELEASE)
//
// This module exercises the layers that cannot be verified from a terminal or a JVM
// unit test: the hardware Keystore tier, the hardware-attestation pipeline, native
// crypto library loading on the device ABI, Room migrations on real SQLite, and
// (via app-supplied hooks) NFC / BLE / WiFi-Direct / mesh propagation.
//
// It is wired into the app ONLY as `debugImplementation` (see app/build.gradle.kts),
// so the release variant never compiles or links it. To remove entirely:
//   1. delete this directory
//   2. remove the `debugImplementation(project(":feature:debug-diagnostics"))` line
//   3. remove `":feature:debug-diagnostics"` from settings.gradle.kts
//   4. delete app/src/debug/.../DebugDiagnostics.kt (the src/release stub can stay; it is a no-op)
// ─────────────────────────────────────────────────────────────────────────────
plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

android {
    namespace  = "mesh.shadowmesh.debug"
    compileSdk = 34
    defaultConfig { minSdk = 29 }

    buildFeatures { compose = true }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.13" }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    // Probes call real production code paths — same classes the app uses.
    implementation(project(":core:diagnostics"))   // install the recording sink
    implementation(project(":core:crypto"))        // HybridKem / HybridSigner / PostRatchet / Hkdf
    implementation(project(":core:security"))       // BiometricKeyManager.detectKeystoreTier
    implementation(project(":core:attestation"))    // HardwareAttestation self-attestation
    implementation(project(":core:storage"))        // GossipBloomFilter / RateLimiter probes
    implementation(project(":core:distribution"))   // LtFountain loss-recovery probe

    implementation(libs.coroutines.android)
    implementation(libs.core.ktx)

    val composeBom = platform(libs.compose.bom)
    implementation(composeBom)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.unit)
    implementation(libs.compose.foundation)
    implementation(libs.compose.material3)
    implementation(libs.compose.activity)
    debugImplementation(libs.compose.ui.tooling)
}

plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

android {
    namespace  = "mesh.shadowmesh.ui"
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
    implementation(project(":core:storage"))
    implementation(project(":core:crypto"))
    implementation(project(":core:mesh"))
    implementation(project(":feature:forum"))
    implementation(project(":feature:onboarding"))
    // BootstrapState, BootstrapTrustLevel — for PhysicalExchangeStep status rendering.
    implementation(project(":core:bootstrap"))
    // AttestationTrustLevel — for buildVerifiedLabel() attestation badge.
    implementation(project(":core:attestation"))
    // BiometricEnrollmentChecker.EnrollmentStatus, VpnServiceBridge — used in OnboardingScreen.
    implementation(project(":core:platform"))

    implementation(libs.coroutines.android)
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.core.ktx)

    // ZXing core — QR code bitmap generation in PhysicalExchangeStep.QrBitmap composable.
    // Pure Java library; no Android-specific variant; no JNI. R8-safe (no keep rules needed).
    implementation(libs.zxing.core)
    // ZXing Android Embedded — camera-based QR scanner for "Scan instead" responder path.
    implementation(libs.zxing.android.embedded)

    // Compose BOM — all compose versions managed centrally
    val composeBom = platform(libs.compose.bom)
    implementation(composeBom)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.unit)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.compose.foundation)
    implementation(libs.compose.material3)
    implementation(libs.compose.material.icons)
    implementation(libs.compose.activity)
    implementation(libs.compose.navigation)
    implementation(libs.compose.lifecycle)
    implementation(libs.compose.viewmodel)
    implementation(libs.compose.hilt.nav)
    debugImplementation(libs.compose.ui.tooling)
}

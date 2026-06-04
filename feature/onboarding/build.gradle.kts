plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

android {
    namespace = "mesh.shadowmesh.onboarding"
    compileSdk = 34
    defaultConfig { minSdk = 29 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(project(":core:diagnostics"))   // Diag silent-failure reporting seam
    implementation(project(":core:platform"))
    implementation(project(":core:security"))
    // NfcBootstrapCoordinator, BootstrapResult, BootstrapState, BootstrapTrustLevel,
    // QrIntroductionCode — injected into OnboardingViewModel for physical exchange step.
    implementation(project(":core:bootstrap"))
    // AttestationTrustLevel — surfaced in achievedAttestationLevel state flow.
    implementation(project(":core:attestation"))

    implementation(libs.coroutines.android)
    implementation(libs.core.ktx)
    implementation(libs.lifecycle.viewmodel.ktx)
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    testImplementation(libs.kotest.runner)
    testImplementation(libs.kotest.assertions)
    testImplementation(libs.coroutines.test)
}

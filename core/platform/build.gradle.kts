plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "mesh.shadowmesh.platform"
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
    implementation(project(":core:mesh"))   // OnionCircuitPacketRouter bridges to CircuitManager
    implementation(project(":core:crypto"))   // toHex extension + crypto utilities

    implementation(libs.core.ktx)
    implementation(libs.coroutines.android)
    implementation(libs.biometric)

    testImplementation(libs.kotest.runner)
    testImplementation(libs.kotest.assertions)
    testImplementation(libs.coroutines.test)
}

plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

android {
    namespace  = "mesh.shadowmesh.crypto"
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
    // Post-quantum crypto via OQS JNI
    implementation(libs.liboqs)

    // Classical hybrid (Ed25519 + X25519) via BouncyCastle — pure Java, no JNA/JNI loading
    implementation(libs.bcprov)

    // Coroutines — crypto ops are CPU-bound, dispatched on IO pool
    implementation(libs.coroutines.core)

    // Test
    testImplementation(libs.junit)
    testImplementation(libs.kotest.runner)
    testImplementation(libs.kotest.assertions)
    testImplementation(libs.coroutines.test)
    testImplementation(libs.mockk)
}


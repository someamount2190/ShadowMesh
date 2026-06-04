plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "mesh.shadowmesh.distribution"
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
    implementation(project(":core:crypto"))    // Hkdf, Ed25519 via lazysodium
    implementation(project(":core:mesh"))       // ShadowFilesChunker/Reassembler, FecScheme
    implementation(project(":core:security"))   // signing-cert hash helper
    implementation(project(":core:storage"))    // ShadowMeshDao, TransferCheckpointEntity
    implementation(libs.core.ktx)
    implementation(libs.coroutines.android)
    implementation(libs.bcprov)

    testImplementation(libs.lazysodium.java)   // DistributionTest uses LazySodiumJava directly
    testImplementation(libs.kotest.runner)
    testImplementation(libs.kotest.assertions)
    testImplementation(libs.coroutines.test)
    testImplementation(libs.mockk)
}

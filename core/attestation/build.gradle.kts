plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "mesh.shadowmesh.attestation"
    compileSdk = 34
    defaultConfig { minSdk = 29 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(project(":core:diagnostics"))  // silent-failure reporting seam
    implementation(project(":core:crypto"))      // Hkdf, NodePublicIdentity
    implementation(project(":core:bootstrap"))    // PhysicalKeyExchange, QrIntroductionCode
    implementation(libs.core.ktx)
    implementation(libs.coroutines.android)

    testImplementation(libs.kotest.runner)
    testImplementation(libs.kotest.assertions)
}

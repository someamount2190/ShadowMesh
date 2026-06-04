plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "mesh.shadowmesh.security"
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
    implementation(project(":core:crypto"))
    implementation(project(":core:storage"))
    implementation(libs.biometric)
    implementation(libs.core.ktx)
    implementation(libs.security.crypto)
    implementation(libs.work.runtime.ktx)
    implementation(libs.coroutines.android)
    implementation(libs.liboqs)

    testImplementation(libs.kotest.runner)
    testImplementation(libs.kotest.assertions)
}

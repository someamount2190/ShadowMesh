plugins {
    id("com.android.library")
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "mesh.shadowmesh.bootstrap"
    compileSdk = 34
    defaultConfig { minSdk = 29 }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

dependencies {
    implementation(project(":core:crypto"))
    implementation(libs.coroutines.android)
    implementation(libs.bcprov)
    implementation(libs.liboqs)

    testImplementation(libs.kotest.runner)
    testImplementation(libs.kotest.assertions)
}

import java.security.MessageDigest

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    // Hilt — required because feature:ui uses hiltViewModel() and @HiltViewModel.
    // ShadowMeshApplication must be annotated @HiltAndroidApp; MainActivity @AndroidEntryPoint.
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
    // BuildConfig generation is enabled via android { buildFeatures { buildConfig = true } } below
}

android {
    namespace = "mesh.shadowmesh.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "mesh.shadowmesh"
        minSdk = 29
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        // BuildConfig fields referenced in ShadowMeshApplication.
        //
        // EXPECTED_SIGNATURE_HASH: SHA-256 hex of the release signing certificate bytes.
        // Derive once from your keystore:
        //   keytool -list -v -keystore release.jks -alias your_alias \
        //     | grep "SHA256:" | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f'
        // Then set shadowmesh.sigHash in gradle.properties (or CI secrets). Never hard-code here.
        //
        // RELEASE_PUBLIC_KEY: Base64-encoded DER of the Ed25519 release signing public key.
        // Used by AppArtifactVerifier to verify mesh-distributed APK updates.
        //
        // Debug builds use a named sentinel ("SHADOWMESH_DEBUG_BUILD") so ApkIntegrityVerifier
        // skips the cert-hash check rather than performing a comparison that always fails
        // (and would trigger a panic wipe on every debug launch).
        //
        // Release builds require shadowmesh.sigHash to be set — the build fails if it is absent.
        // This is enforced below in the release buildType block.
        buildConfigField(
            "String",
            "EXPECTED_SIGNATURE_HASH",
            "\"SHADOWMESH_DEBUG_BUILD\""   // overridden to real value in release block below
        )
        buildConfigField(
            "String",
            "RELEASE_PUBLIC_KEY",
            "\"${project.findProperty("shadowmesh.releasePublicKey") ?: ""}\""
        )
        // Bytecode-hash placeholders — empty strings; runtime falls back to class-name bytes.
        // (The circular embedCriticalClassHashes task was removed; a post-compile pipeline step
        //  would be needed to embed real hashes without a circular Gradle dependency.)
        buildConfigField("String", "SYMMETRIC_CIPHER_BYTECODE_HASH", "\"\"")
        buildConfigField("String", "HKDF_BYTECODE_HASH", "\"\"")
        buildConfigField("String", "POST_RATCHET_BYTECODE_HASH", "\"\"")
        buildConfigField("String", "NODE_IDENTITY_BYTECODE_HASH", "\"\"")
    }

    buildFeatures {
        compose    = true
        buildConfig = true    // enable BuildConfig generation
    }
    composeOptions { kotlinCompilerExtensionVersion = "1.5.13" }

    buildTypes {
        release {
            // Guard: only enforce release-specific checks when actually building release.
            // These blocks are evaluated at configuration time even for debug builds,
            // so the require() calls must be conditional to avoid blocking debug compiles.
            val isBuildingRelease = gradle.startParameter.taskNames.any { "release" in it.lowercase() }

            // Enforce that shadowmesh.sigHash is set before a release build proceeds.
            // A missing or empty sigHash means ApkIntegrityVerifier would either always
            // pass (if the sentinel matched a real cert — impossible) or always wipe.
            // Failing the build here is far safer than a silent misconfiguration.
            val releaseSigHash = project.findProperty("shadowmesh.sigHash")?.toString()
            if (isBuildingRelease) require(!releaseSigHash.isNullOrBlank()) {
                """
                |
                |  ╔══════════════════════════════════════════════════════════════╗
                |  ║  RELEASE BUILD BLOCKED — shadowmesh.sigHash is not set      ║
                |  ║                                                              ║
                |  ║  Derive the value once from your release keystore:           ║
                |  ║    keytool -list -v -keystore release.jks -alias <alias>    ║
                |  ║      | grep "SHA256:" | awk '{print $2}'                    ║
                |  ║      | tr -d ':' | tr 'A-F' 'a-f'                          ║
                |  ║  Then add to gradle.properties (or CI secrets):             ║
                |  ║    shadowmesh.sigHash=<64-char lowercase hex>               ║
                |  ╚══════════════════════════════════════════════════════════════╝
                """.trimMargin()
            }
            // Override the debug sentinel with the real value for release builds.
            buildConfigField(
                "String",
                "EXPECTED_SIGNATURE_HASH",
                "\"$releaseSigHash\""
            )

            // Enforce that both attestation root hex constants have been set before a
            // release build. Set these in gradle.properties (or CI secrets) once you
            // have derived the real DER-encoded public keys per BUILDING.md §3.3, then
            // paste the same values into HardwareAttestation.kt.
            //
            // Note: we read from gradle.properties here (not from the compiled source)
            // because build scripts cannot reference application classes at configuration time.
            val googleAttestationRoot    = project.findProperty("shadowmesh.googleAttestationRoot")?.toString()
            val grapheneosAttestationRoot = project.findProperty("shadowmesh.grapheneosAttestationRoot")?.toString()
            if (isBuildingRelease) require(!googleAttestationRoot.isNullOrBlank()) {
                """
                |
                |  ╔══════════════════════════════════════════════════════════════════╗
                |  ║  RELEASE BUILD BLOCKED — attestation root not configured        ║
                |  ║                                                                  ║
                |  ║  Set shadowmesh.googleAttestationRoot in gradle.properties.     ║
                |  ║  See BUILDING.md §3.3 and the KDoc in HardwareAttestation.kt    ║
                |  ║  for the exact derivation pipeline (openssl + xxd).             ║
                |  ╚══════════════════════════════════════════════════════════════════╝
                """.trimMargin()
            }
            if (isBuildingRelease) require(!grapheneosAttestationRoot.isNullOrBlank()) {
                """
                |
                |  ╔══════════════════════════════════════════════════════════════════╗
                |  ║  RELEASE BUILD BLOCKED — attestation root not configured        ║
                |  ║                                                                  ║
                |  ║  Set shadowmesh.grapheneosAttestationRoot in gradle.properties. ║
                |  ║  See BUILDING.md §3.3 and the KDoc in HardwareAttestation.kt    ║
                |  ║  for the exact derivation pipeline (openssl + xxd).             ║
                |  ╚══════════════════════════════════════════════════════════════════╝
                """.trimMargin()
            }

            // R8 full mode — significantly reduces APK size and obfuscates class names.
            // Custom rules below preserve reflection-sensitive classes.
            isMinifyEnabled   = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // Packaging: exclude duplicate META-INF files that liboqs and lazysodium both include.
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}

// lazysodium-android contains all lazysodium-java classes plus Android JNI bindings.
// Excluding lazysodium-java prevents a duplicate-class conflict at DEX time in case
// any transitive dependency pulls it in (e.g. test-only testImplementation in submodules
// does not affect the app configuration, but belt-and-suspenders exclusion is cheap).
configurations.all {
    exclude(group = "com.goterl", module = "lazysodium-java")
}


dependencies {
    // Debug-only on-device diagnostics harness (Keystore/TEE, hardware attestation,
    // native crypto, DB migrations, and app-wired NFC/BLE/mesh probes). debugImplementation
    // => NOT linked into release. Remove this line + the module dir to delete the feature.
    debugImplementation(project(":feature:debug-diagnostics"))

    // All SHADOWMESH modules — the app is the composition root.
    implementation(project(":core:crypto"))
    implementation(project(":core:nsc"))
    implementation(project(":core:security"))
    implementation(project(":core:bootstrap"))
    implementation(project(":core:attestation"))   // explicit — buildRevocationCache() uses it
    implementation(project(":core:mesh"))
    implementation(project(":core:storage"))
    implementation(project(":core:platform"))
    implementation(project(":core:distribution"))
    implementation(project(":feature:forum"))
    implementation(project(":feature:onboarding"))
    implementation(project(":feature:ui"))

    implementation(project(":core:diagnostics"))

    implementation(libs.core.ktx)
    implementation(libs.coroutines.android)
    implementation(libs.work.runtime.ktx)
    implementation(libs.appcompat)
    implementation(libs.lifecycle.runtime.ktx)

    // Hilt — app-level wiring for @HiltAndroidApp + Hilt module that bridges
    // AppModule singletons to the Hilt component graph.
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)
    implementation(libs.hilt.work)
    ksp(libs.hilt.work.compiler)

    // Compose BOM — needed so Compose dependencies in the app module resolve correctly
    // alongside feature:ui's BOM. Declaring the same BOM at app level is correct;
    // Gradle deduplicates to a single version.
    val composeBom = platform(libs.compose.bom)
    implementation(composeBom)
    // activity-compose provides setContent{} and exposes compose.runtime via api(),
    // which the Compose compiler plugin needs to resolve @Composable in this module.
    implementation(libs.compose.activity)
    // compose.runtime (runtime-android) puts @Composable on the compile classpath
    // so the Compose compiler plugin can resolve it in this module.
    implementation(libs.compose.runtime)
    // MainActivity directly uses these Compose APIs; feature:ui declares them as
    // implementation so they don't flow transitively to the app compile classpath.
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.unit)      // dp / sp extensions
    implementation(libs.compose.foundation)
    implementation(libs.compose.material3)
    implementation(libs.compose.lifecycle)
    // animateFloatAsState / tween / FastOutSlowInEasing / Crossfade — not in catalog.
    // animation-core:1.6.7 is a KMP stub (166 bytes); the real impl is animation-core-android.
    // AGP variant selection doesn't upgrade it automatically, so declare the Android artifact
    // directly so it lands on the compile classpath.
    implementation("androidx.compose.animation:animation")
    implementation("androidx.compose.animation:animation-core-android")

    // Room runtime on the app classpath so ShadowMeshDatabase (RoomDatabase subtype)
    // is accessible from the composition root without relying on transitive exposure.
    implementation(libs.room.runtime)
    // security-crypto: EncryptedSharedPreferences / MasterKey used in wipe handlers.
    implementation(libs.security.crypto)

    testImplementation(libs.kotest.runner)
    testImplementation(libs.kotest.assertions)
    testImplementation(libs.coroutines.test)

    androidTestImplementation(libs.androidx.test.ext.junit)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.coroutines.test)
    androidTestImplementation(libs.liboqs)
}

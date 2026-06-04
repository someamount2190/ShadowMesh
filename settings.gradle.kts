rootProject.name = "shadowmesh"

// ── Dependency resolution ─────────────────────────────────────────────────────
//
// Vendored mode (offline-first):
//   Run scripts/vendor_deps.py once on a connected machine to populate
//   libs/maven/ with all artifacts in the standard Maven local-repo layout.
//   The local repo is listed FIRST so offline builds never hit the network.
//
// Connected mode (fallback):
//   If libs/maven/ is empty or an artifact is missing, Gradle falls back to
//   Google Maven and Maven Central in the normal way.
//
// To force a fully offline build after vendoring:
//   ./gradlew assembleRelease --offline
//
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        // Local vendored repo — populated by scripts/vendor_deps.py
        // Listed first so all artifact resolution hits disk before the network.
        val vendored = rootProject.projectDir.resolve("libs/maven")
        if (vendored.exists() && vendored.list()?.isNotEmpty() == true) {
            maven {
                name = "VendoredLocal"
                url  = uri(vendored)
                // No authentication — purely local filesystem reads.
                content {
                    // Serve everything from the vendored repo; Gradle will fall
                    // through to the remote repos below for anything not found here.
                }
            }
        }

        // Remote fallbacks (used when vendored repo is absent or incomplete)
        google()
        mavenCentral()
        maven {
            name = "GradlePluginPortal"
            url  = uri("https://plugins.gradle.org/m2/")
        }
        // JitPack — required for lazysodium-android, liboqs-java, backblaze:erasure
        maven {
            name = "JitPack"
            url  = uri("https://jitpack.io")
        }
    }
    // Note: gradle/libs.versions.toml is auto-discovered by Gradle 8+ as the "libs" catalog.
    // No explicit versionCatalogs { create("libs") { from(...) } } block needed.
}

// ── Plugin resolution ─────────────────────────────────────────────────────────
//
// Plugin marker artifacts (e.g. com.android.application:com.android.application.gradle.plugin)
// are vendored alongside the library artifacts. The pluginManagement block mirrors
// the repository ordering from dependencyResolutionManagement.
//
pluginManagement {
    repositories {
        val vendored = rootProject.projectDir.resolve("libs/maven")
        if (vendored.exists() && vendored.list()?.isNotEmpty() == true) {
            maven {
                name = "VendoredLocal"
                url  = uri(vendored)
            }
        }
        google()
        mavenCentral()
        gradlePluginPortal()
        maven {
            name = "JitPack"
            url  = uri("https://jitpack.io")
        }
    }
}

include(
    ":app",
    ":core:crypto",
    ":core:diagnostics",
    ":core:nsc",
    ":core:security",
    ":core:bootstrap",
    ":core:mesh",
    ":core:storage",
    ":core:platform",
    ":core:attestation",
    ":core:distribution",
    ":feature:forum",
    ":feature:onboarding",
    ":feature:ui",
    // Debug-only on-device diagnostics harness. Wired into the app via debugImplementation;
    // release builds never include it. Safe to delete this line + the module dir to remove.
    ":feature:debug-diagnostics"
)

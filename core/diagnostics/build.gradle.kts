// ─────────────────────────────────────────────────────────────────────────────
// :core:diagnostics — silent-failure reporting seam.
//
// Pure kotlin-jvm (no Android deps), like :core:crypto, so EVERY module — including
// the pure-JVM crypto layer — can route its currently-swallowed errors here. In a
// release build the sink stays NoOp and `Diag.enabled` is false, so the calls cost a
// boolean check. The debug-diagnostics module installs a recording sink and flips
// `enabled = true`.
//
// This module is permanent and free; only the *consumer* (the debug recorder + UI) is
// removable. Removing the tool later does NOT require reverting the instrumentation.
// ─────────────────────────────────────────────────────────────────────────────
plugins {
    id("java-library")
    alias(libs.plugins.kotlin.android) apply false
    kotlin("jvm")
}

java {
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
    kotlinOptions { jvmTarget = "17" }
}

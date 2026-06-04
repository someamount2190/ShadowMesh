# ── SHADOWMESH ProGuard / R8 rules ───────────────────────────────────────────
#
# Applied only to release builds (isMinifyEnabled = true in app/build.gradle.kts).
# These rules preserve classes and members that are accessed via reflection, JNI,
# or Android framework callbacks that R8 cannot trace statically.

# ── liboqs (OQS-Java JNI) ────────────────────────────────────────────────────
# liboqs loads native code via System.loadLibrary and instantiates algorithm
# classes by name at runtime. R8 cannot see these usages across the JNI boundary.
-keep class org.openquantumsafe.** { *; }
-keepclassmembers class org.openquantumsafe.** { *; }

# ── lazysodium-android ────────────────────────────────────────────────────────
-keep class com.goterl.lazysodium.** { *; }
-keepclassmembers class com.goterl.lazysodium.** { *; }

# ── SQLCipher ─────────────────────────────────────────────────────────────────
# Room generates code that references SQLCipher's SupportSQLiteOpenHelper by class name.
-keep class net.sqlcipher.** { *; }
-keep class net.sqlcipher.database.** { *; }

# ── Room ──────────────────────────────────────────────────────────────────────
# Room's generated _Impl classes are instantiated via reflection by RoomDatabase.
-keep class * extends androidx.room.RoomDatabase { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }
-dontwarn androidx.room.paging.**

# ── WorkManager ───────────────────────────────────────────────────────────────
# WorkManager instantiates worker classes by their fully-qualified class name string.
# ShadowMeshWorkerFactory handles injection, but R8 still needs the class preserved.
-keep class * extends androidx.work.ListenableWorker {
    public <init>(android.content.Context, androidx.work.WorkerParameters);
}

# ── Hilt ──────────────────────────────────────────────────────────────────────
# Hilt-generated component classes are referenced by string in Hilt's internal
# ComponentManager. The Hilt Gradle plugin injects these rules automatically since
# Hilt 2.40, but we include them explicitly for clarity.
-keep class dagger.hilt.** { *; }
-keep @dagger.hilt.android.lifecycle.HiltViewModel class * { *; }
-keep class * extends dagger.hilt.android.internal.managers.ViewComponentManager { *; }

# ── Kotlin serialisation / reflection ─────────────────────────────────────────
-keepattributes *Annotation*
-keepattributes Signature
-keepattributes InnerClasses
-keepattributes EnclosingMethod

# Kotlin metadata — required for kotlinx.reflect and coroutines
-keep class kotlin.Metadata { *; }
-keepclassmembers class kotlin.Metadata {
    public <methods>;
}

# Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
-keepclassmembernames class kotlinx.** {
    volatile <fields>;
}

# ── Compose ───────────────────────────────────────────────────────────────────
# R8 handles Compose well in full mode. These suppress false-positive warnings
# from the Compose BOM interacting with older Android API stubs.
-dontwarn androidx.compose.**
-dontwarn kotlin.reflect.jvm.internal.**

# ── ZXing ─────────────────────────────────────────────────────────────────────
# ZXing core is used via direct API calls (not reflection), so R8 traces it
# correctly. No keep rules needed — but suppress the legacy sun.* warnings.
-dontwarn com.google.zxing.**

# ── ShadowMesh application classes ───────────────────────────────────────────
# Keep the Application and Activity entry points — Android framework instantiates
# these by class name from AndroidManifest.xml.
-keep class mesh.shadowmesh.app.ShadowMeshApplication { *; }
-keep class mesh.shadowmesh.app.MainActivity { *; }
-keep class mesh.shadowmesh.app.CoverActivity { *; }
-keep class mesh.shadowmesh.app.ShadowMeshHceService { *; }
-keep class mesh.shadowmesh.app.ShadowMeshForegroundService { *; }
-keep class mesh.shadowmesh.platform.ShadowMeshVpnService { *; }

# Keep NFC HCE service — Android HCE framework instantiates it by name.
-keep class * extends android.nfc.cardemulation.HostApduService { *; }

# Keep RollbackOpcode sealed class hierarchy — NSC serialises/deserialises
# opcode strings across process restarts. Class names must be stable.
-keep class mesh.shadowmesh.nsc.RollbackOpcode { *; }
-keep class mesh.shadowmesh.nsc.RollbackOpcode$* { *; }

# ── Suppress warnings for known-safe missing classes ─────────────────────────
-dontwarn javax.annotation.**
-dontwarn sun.misc.Unsafe

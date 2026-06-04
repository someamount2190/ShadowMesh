# SHADOWMESH — Build & Deployment Guide

This document covers everything needed to go from source to a signed, deployable APK.
Follow the sections in order for a first build. Subsequent builds only need §4.

---

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Repository setup](#2-repository-setup)
3. [One-time configuration](#3-one-time-configuration)
   - 3.1 [Signing keystore](#31-signing-keystore)
   - 3.2 [BuildConfig secrets](#32-buildconfig-secrets)
   - 3.3 [Attestation root certificates](#33-attestation-root-certificates)
   - 3.4 [Vendor dependencies (offline builds)](#34-vendor-dependencies-offline-builds)
4. [Building](#4-building)
   - 4.1 [Debug build](#41-debug-build)
   - 4.2 [Release build](#42-release-build)
   - 4.3 [Fully offline build](#43-fully-offline-build)
5. [Running tests](#5-running-tests)
6. [Installing on device](#6-installing-on-device)
7. [Module structure](#7-module-structure)
8. [Pre-production checklist](#8-pre-production-checklist)
9. [Troubleshooting](#9-troubleshooting)

---

## 1. Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| JDK | 17 | OpenJDK 17 recommended. `JAVA_HOME` must point to it. |
| Android SDK | API 34 | Build Tools 34.0.0, Platform Tools latest |
| Android NDK | 25c or 26 | Required by liboqs-java and lazysodium JNI layers |
| Python | 3.8+ | Only needed for dependency vendoring (§3.4). stdlib only, no pip. |
| `openssl` CLI | Any modern | Only needed for attestation root extraction (§3.3). |
| `keytool` | Bundled with JDK | For keystore creation (§3.1). |

**Minimum device for testing:** Android 10 (API 29), any architecture. The project targets
`minSdk = 29` and `compileSdk = 34`.

Install Android SDK components (if not already done):

```bash
sdkmanager "platforms;android-34" \
            "build-tools;34.0.0"  \
            "ndk;25.2.9519653"    \
            "platform-tools"
```

Set environment variables:

```bash
export ANDROID_HOME=$HOME/Library/Android/sdk   # macOS
export ANDROID_HOME=$HOME/Android/Sdk           # Linux
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/25.2.9519653
export PATH=$PATH:$ANDROID_HOME/platform-tools
```

---

## 2. Repository setup

Clone and verify the layout:

```bash
git clone <your-repo-url> shadowmesh
cd shadowmesh
```

Expected top-level structure:

```
shadowmesh/
├── app/
├── core/
│   ├── attestation/
│   ├── bootstrap/
│   ├── crypto/
│   ├── distribution/
│   ├── mesh/
│   ├── nsc/
│   ├── platform/
│   ├── security/
│   └── storage/
├── feature/
│   ├── forum/
│   ├── onboarding/
│   └── ui/
├── gradle/
│   └── libs.versions.toml
├── libs/
│   └── maven/          ← populated by vendor script (§3.4)
├── scripts/
│   └── vendor_deps.py
├── settings.gradle.kts
├── build.gradle.kts
└── BUILDING.md         ← this file
```

---

## 3. One-time configuration

### 3.1 Signing keystore

Create a release keystore. Keep this file off source control — it is the root
of trust for APK signing and mesh-distributed update verification.

```bash
keytool -genkey -v \
  -keystore release.jks \
  -alias shadowmesh \
  -keyalg EC \
  -keysize 256 \
  -validity 10000 \
  -dname "CN=ShadowMesh, O=YourOrg, C=US"
```

Store it somewhere permanent and backed up (e.g. an encrypted volume, a hardware
token, or a CI secret store). **Loss of this keystore means you cannot issue
signed updates that existing nodes will accept.**

### 3.2 BuildConfig secrets

The build reads two values from `gradle.properties`. Create or edit
`~/.gradle/gradle.properties` (user-level, never committed):

```properties
# SHA-256 fingerprint of the release signing certificate, lowercase hex, no colons.
# Used by ApkIntegrityVerifier to bind symmetric keys to this specific APK build.
# Derive it from your keystore:
#
#   keytool -list -v -keystore release.jks -alias shadowmesh \
#     | grep "SHA256:" | awk '{print $2}' | tr -d ':' | tr 'A-F' 'a-f'
#
shadowmesh.sigHash=<paste 64-char lowercase hex here>

# Base64-encoded DER of the Ed25519 public key used to sign mesh-distributed APK
# update descriptors. Corresponds to the private key used by AppArtifactSeeder.
# If you are not using mesh APK distribution yet, leave this as the empty string.
shadowmesh.releasePublicKey=
```

To derive `shadowmesh.sigHash`:

```bash
keytool -list -v -keystore release.jks -alias shadowmesh \
  | grep "SHA256:" \
  | awk '{print $2}' \
  | tr -d ':' \
  | tr 'A-F' 'a-f'
```

Paste the 64-character output as the value.

**Local development:** If you do not set these properties, the build uses
placeholder values (`sigHash` = 64 zeros). Debug builds work fine.
`ApkIntegrityVerifier` will reject the APK in a release build that reaches
the integrity check — which is correct behaviour, since there is nothing to
verify in a dev build.

### 3.3 Attestation root certificates

Hardware attestation — the strongest trust anchor for `TRUST_PHYSICAL` bootstrapping
— requires the public keys of two certificate authorities to be embedded in the
source code. Until these are set, `verifyRootCertificate()` fails closed (rejects
all attestation chains), meaning bootstrap succeeds at `TRUST_PHYSICAL_NFC` only,
without hardware verification.

**File to edit:**
`core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/HardwareAttestation.kt`

Look for the two `DEPLOYMENT BLOCKER` comments.

#### Google Hardware Attestation Root

Download the root certificate:

```bash
curl -O https://developer.android.com/training/articles/security-key-attestation
# Or directly from AOSP:
curl -O "https://android.googlesource.com/platform/cts/+/refs/heads/main/tests/tests/keystore/src/android/keystore/cts/AndroidKeyStoreTest.java?format=TEXT" 
# The cert is embedded in various AOSP test files.
# Easiest: extract from a real device — see below.
```

Extract the public key from a real Android device:

```bash
# On any stock Android 10+ device, run an attestation and extract the chain.
# Then on your workstation, with the root cert saved as google_root.crt:
openssl x509 -in google_root.crt -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | xxd -p -c 256 \
  | tr -d '\n'
```

Paste the output into `GOOGLE_HARDWARE_ATTESTATION_ROOT_HEX` in the source file,
breaking it into continuation strings for readability:

```kotlin
const val GOOGLE_HARDWARE_ATTESTATION_ROOT_HEX =
    "3059301306072a8648ce3d020106082a8648ce3d030107034200..." +
    "..."   // continue until the full hex is pasted
```

#### GrapheneOS Attestation Root

```bash
# Clone GrapheneOS Auditor to get their root cert:
git clone https://github.com/GrapheneOS/Auditor
# The cert is in app/src/main/res/raw/ or the attestation assets directory.
# With the cert saved as grapheneos_root.crt:
openssl x509 -in grapheneos_root.crt -noout -pubkey \
  | openssl pkey -pubin -outform DER \
  | xxd -p -c 256 \
  | tr -d '\n'
```

Paste into `GRAPHENEOS_ATTESTATION_ROOT_HEX` the same way.

**Verification:** After setting both roots, run:

```bash
./gradlew :core:attestation:test
```

The `HardwareAttestationTest` will confirm the constants are non-empty and
pass the `isRootConfigured()` check.

### 3.4 Vendor dependencies (offline builds)

Skip this step if you have a reliable internet connection during builds —
Gradle will fetch dependencies from Google Maven and Maven Central normally.

For **offline or air-gap builds**, populate the local Maven repository first.
Run this once on any machine with internet access:

```bash
python3 scripts/vendor_deps.py
```

This downloads all ~40 direct dependencies plus their transitive closure into
`libs/maven/` in standard Maven layout. It is idempotent — re-running only
fetches missing or changed files. Expect 5–15 minutes on a fast connection.

After vendoring, all builds can run with `--offline`:

```bash
./gradlew assembleRelease --offline
```

See `libs/maven/README.md` for air-gap transfer instructions.

---

## 4. Building

All Gradle commands are run from the repository root. Use `./gradlew` (Unix) or
`gradlew.bat` (Windows). Gradle 8.6+ is required; the wrapper downloads it
automatically on the first run.

### 4.1 Debug build

```bash
./gradlew assembleDebug
```

Output: `app/build/outputs/apk/debug/app-debug.apk`

Debug builds use a debug signing key generated automatically by Android Gradle
Plugin. They do not perform APK integrity verification (the `sigHash` placeholder
is accepted). Suitable for development and testing.

### 4.2 Release build

Ensure `gradle.properties` has `shadowmesh.sigHash` set (§3.2) and your keystore
is accessible. Pass signing config via environment variables (preferred for CI)
or a local `keystore.properties` file:

**Option A — environment variables (CI):**

```bash
KEYSTORE_PATH=/path/to/release.jks \
KEYSTORE_PASSWORD=your_password    \
KEY_ALIAS=shadowmesh               \
KEY_PASSWORD=your_key_password     \
./gradlew assembleRelease
```

Add to `app/build.gradle.kts` to read these:

```kotlin
signingConfigs {
    create("release") {
        storeFile     = file(System.getenv("KEYSTORE_PATH") ?: "release.jks")
        storePassword = System.getenv("KEYSTORE_PASSWORD") ?: ""
        keyAlias      = System.getenv("KEY_ALIAS") ?: "shadowmesh"
        keyPassword   = System.getenv("KEY_PASSWORD") ?: ""
    }
}
buildTypes {
    release {
        signingConfig = signingConfigs.getByName("release")
        // ... existing config
    }
}
```

**Option B — local keystore.properties (developer machine):**

Create `keystore.properties` in the project root (add to `.gitignore`):

```properties
storeFile=../release.jks
storePassword=your_password
keyAlias=shadowmesh
keyPassword=your_key_password
```

Then read it in `app/build.gradle.kts`:

```kotlin
val keystoreProps = java.util.Properties().also { props ->
    val f = rootProject.file("keystore.properties")
    if (f.exists()) props.load(f.inputStream())
}
signingConfigs {
    create("release") {
        storeFile     = file(keystoreProps["storeFile"] as? String ?: "release.jks")
        storePassword = keystoreProps["storePassword"] as? String ?: ""
        keyAlias      = keystoreProps["keyAlias"] as? String ?: "shadowmesh"
        keyPassword   = keystoreProps["keyPassword"] as? String ?: ""
    }
}
```

Then build:

```bash
./gradlew assembleRelease
```

Output: `app/build/outputs/apk/release/app-release.apk`

The release build enables R8 full-mode minification and resource shrinking.
ProGuard rules are in `app/proguard-rules.pro` — all crypto JNI classes,
Room entities, WorkManager workers, Hilt components, and Kotlin metadata
are already kept.

### 4.3 Fully offline build

After running `scripts/vendor_deps.py` (§3.4):

```bash
./gradlew assembleRelease --offline
```

Gradle resolves all dependencies from `libs/maven/` and never contacts the
network. If any artifact is missing, the build fails with a resolution error
listing the missing coordinate — re-run the vendor script to fetch it.

---

## 5. Running tests

### Unit tests (JVM, no device needed)

```bash
# All modules
./gradlew test

# Specific module
./gradlew :core:crypto:test
./gradlew :feature:forum:test
./gradlew :core:mesh:test
```

Tests use Kotest with the JUnit 5 runner. Output in
`<module>/build/reports/tests/test/index.html`.

### Android instrumented tests (requires connected device or emulator)

```bash
# All instrumented tests
./gradlew connectedAndroidTest

# Specific module
./gradlew :core:storage:connectedAndroidTest
./gradlew :core:nsc:connectedAndroidTest
```

These require a device running Android 10+ (API 29+). The NSC and Room tests
use an in-memory database and do not require special permissions.

### Continuous test run during development

```bash
./gradlew test --continuous
```

Re-runs tests automatically whenever source files change.

---

## 6. Installing on device

**Via ADB (debug build):**

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

**Via ADB (release build):**

```bash
adb install -r app/build/outputs/apk/release/app-release.apk
```

**First launch requirements:**
- Grant permissions when prompted: Bluetooth, Nearby Devices, WiFi,
  Location (required for BLE scanning on Android 12+), Notifications.
- The app requests battery optimisation exemption on first launch
  (`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`). Grant it — without it,
  the mesh foreground service is aggressively killed by Doze, breaking
  store-and-forward delivery.

**Minimum device configuration for full functionality:**
- Bluetooth LE (BLE) — required for BLE nudge transport
- WiFi Direct — required for LAN/WiFi Direct transport  
- NFC — required for physical key exchange bootstrap
- Hardware-backed Keystore — required for biometric key wrapping and
  hardware attestation (all Pixel, most Samsung/Xiaomi API 29+ devices)

---

## 7. Module structure

| Module | Depends on | Purpose |
|--------|-----------|---------|
| `:core:crypto` | — | Hybrid KEM (Kyber+X25519), hybrid signer (Dilithium+Ed25519), HKDF, XChaCha20-Poly1305, node identity |
| `:core:storage` | `:core:crypto`, `:core:nsc` | Room + SQLCipher database, all entities, DAO, bloom filter, rate limiter |
| `:core:nsc` | — | Network State Coordinator — saga log, priority transitions, UNRECOVERABLE escalation |
| `:core:bootstrap` | `:core:crypto` | Physical key exchange (QR, NFC wire format), nonce store |
| `:core:attestation` | `:core:crypto`, `:core:bootstrap` | Hardware attestation parsing, root cert verification, NFC bootstrap coordinator |
| `:core:mesh` | `:core:crypto`, `:core:nsc`, `:core:storage` | DHT, gossip, BLE/LAN/WiFi transports, onion circuits, store-and-forward, SNDP, mix protocol, fragmentation |
| `:core:security` | `:core:crypto`, `:core:storage` | Biometric key manager, duress PIN, panic wipe, APK integrity verifier |
| `:core:platform` | `:core:mesh` | VPN service bridge, foreground service base, battery exemption, BLE scan result handler |
| `:core:distribution` | `:core:crypto`, `:core:mesh`, `:core:security` | Offline APK distribution via fountain codes, APK verification |
| `:feature:forum` | `:core:crypto`, `:core:storage`, `:core:mesh`, `:core:security`, `:core:nsc` | Post engine, channel manager, key orchestrator, ratchet, dispatchers, sync coordinator |
| `:feature:onboarding` | `:core:platform`, `:core:security`, `:core:bootstrap`, `:core:attestation` | Onboarding ViewModel and flow |
| `:feature:ui` | `:core:crypto`, `:core:storage`, `:core:mesh`, `:feature:forum`, `:feature:onboarding`, `:core:bootstrap`, `:core:attestation`, `:core:platform` | All Compose screens, nav graph, theme |
| `:app` | all modules | Composition root, Application class, object graph wiring, Hilt module, MainActivity, HCE service |

Build order (enforced by dependency graph, no cycles):

```
core:crypto → core:nsc → core:bootstrap → core:storage → core:attestation
           → core:mesh → core:security → core:platform
           → feature:forum → core:distribution → feature:onboarding → feature:ui → app
```

---

## 8. Pre-production checklist

Work through this list before distributing the APK to users.

### Security — blocking

- [ ] **Attestation root certificates set.**
  `GOOGLE_HARDWARE_ATTESTATION_ROOT_HEX` and `GRAPHENEOS_ATTESTATION_ROOT_HEX`
  in `HardwareAttestation.kt` must contain real DER-encoded public keys, not
  placeholder hex strings. See §3.3. Without this, `TRUST_PHYSICAL_ATTESTED`
  is never issued — bootstrapping falls back to NFC-only without hardware
  verification.

- [ ] **`shadowmesh.sigHash` set to real keystore certificate fingerprint.**
  Without this, `ApkIntegrityVerifier` accepts any certificate hash, breaking
  the APK-binding that ties symmetric keys to this specific build.

- [ ] **`shadowmesh.releasePublicKey` set** if using mesh APK distribution.
  Leave empty only if `AppArtifactSeeder` is not deployed.

- [ ] **Keystore is backed up** in at least two independent locations.
  A separate encrypted backup and a hardware token or CI secret store.

### Security — important but not blocking

- [ ] **Keybox revocation cache.** The gossip-propagated revocation update
  mechanism described in the threat model is not yet implemented. Until it is,
  the revocation list is static (loaded from a bundled resource or empty).
  Nodes with leaked OEM keyboxes (e.g. 2022 Samsung/LG leak) will pass
  chain verification but not root verification. Acceptable for an initial
  deployment; revocation should be implemented before wide distribution.

- [ ] **`TODO(resume)` in `AppArtifactAcquirer`.** Multi-session APK acquisition
  resume is not implemented. Mid-transfer interruptions restart from zero.
  Acceptable for small meshes; problematic on poor BLE links with large APKs.

### Build quality

- [ ] Run full test suite and confirm zero failures:
  ```bash
  ./gradlew test connectedAndroidTest
  ```

- [ ] Confirm R8 does not strip required classes. Build release and launch on
  a clean device; check logcat for `ClassNotFoundException` or
  `NoSuchMethodException` during the first 60 seconds.

- [ ] Test on at least three device families: Pixel (stock Android),
  Samsung (One UI), Xiaomi (MIUI). OEM BiometricPrompt implementations vary.

- [ ] Test with a 2 GB RAM Android 10 device (`LowRamDeviceGuard` tuning).

- [ ] Verify foreground service survives 30 minutes of background time
  on each tested device. Check that `OemBatteryExemption` granted the
  exception and that the periodic WorkManager jobs fire.

### Distribution

- [ ] If distributing via the mesh self-update mechanism: seed the APK using
  `AppArtifactSeeder` from at least two nodes before announcing the update.

- [ ] If distributing via conventional channels (direct APK sideload):
  provide SHA-256 of the APK so recipients can verify before installing.
  ```bash
  sha256sum app/build/outputs/apk/release/app-release.apk
  ```

---

## 9. Troubleshooting

### `AAPT2 error: check logs for details`

Usually a missing Android SDK component. Run:

```bash
sdkmanager --list | grep installed
sdkmanager "build-tools;34.0.0"
```

### `Could not resolve com.google.devtools.ksp:...`

The KSP Gradle plugin version must match the Kotlin version exactly.
Both are pinned in `gradle/libs.versions.toml`:

```toml
kotlin = "1.9.23"
ksp    = "1.9.23-1.0.19"
```

If you upgrade Kotlin, update KSP to the matching `<kotlin>-<ksp-patch>` version.
KSP releases are listed at https://github.com/google/ksp/releases.

### `java.lang.UnsatisfiedLinkError: liboqs` or `liblazysodium`

The JNI native libraries did not load. Causes:

1. **Wrong NDK version.** The `.so` files in `liboqs-java` and `lazysodium-android`
   are compiled against a specific NDK ABI. Use NDK 25c or 26 as specified in §1.
2. **ABI mismatch.** If testing on an emulator, ensure it is x86_64 (not x86).
   The native libs ship `arm64-v8a`, `armeabi-v7a`, and `x86_64` slices.
   Add to `app/build.gradle.kts` if needed:
   ```kotlin
   android {
       defaultConfig {
           ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
       }
   }
   ```
3. **R8 stripping JNI registration.** Ensure `proguard-rules.pro` keeps
   `org.openquantumsafe.**` and `com.goterl.lazysodium.**` (already present).

### `Room schema export` warning

Room can export its schema to a JSON file for migration verification. To enable:

```kotlin
// app/build.gradle.kts, inside android { defaultConfig { ... } }
javaCompileOptions {
    annotationProcessorOptions {
        arguments += mapOf("room.schemaLocation" to "$projectDir/schemas")
    }
}
```

Add `schemas/` to `.gitignore` or commit it for migration diffing.

### `BiometricPrompt: no authenticators available`

The test device has no biometric enrolled. Either enroll a fingerprint/face in
device Settings, or use the duress PIN path (which falls back to PIN-only
authentication via `BiometricManager.BIOMETRIC_STRONG` with device credential).

### Offline build fails with `Could not resolve ...`

An artifact is missing from `libs/maven/`. Re-run the vendor script:

```bash
python3 scripts/vendor_deps.py
```

Then identify which coordinate failed (the error message includes it) and
confirm it appears in `libs/maven/<group>/<artifact>/<version>/`.

### `NSC halted after initialise()` on first launch

The Network State Coordinator found an unrecoverable saga log entry from a
previous interrupted session. This is expected on a fresh install that crashed
during the async init sequence. Clear app data and relaunch:

```bash
adb shell pm clear mesh.shadowmesh
```

On a production device this should not happen — the NSC only halts when a
rollback lambda itself throws after `ROLLBACK_MAX_ATTEMPTS` retries. If it
recurs, check logcat for the `UNRECOVERABLE` tag to identify which transition
failed.

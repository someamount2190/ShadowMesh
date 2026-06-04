# :feature:debug-diagnostics — on-device diagnostics harness

**Debug builds only. Remove before any release. See "Removal" below.**

This harness exercises the layers that a terminal, a JVM unit test, and Claude Code cannot
verify on their own — the things that need real hardware and/or a second phone:

| Probe | What it actually checks | Needs |
|---|---|---|
| Keystore backing tier | StrongBox vs TEE vs software-only (THREAT_MODEL §1 confidentiality root) | device |
| Hardware attestation pipeline | self-attests, parses the chain, reports boot state + StrongBox + whether the configured root matches (§3 Tier B) | device |
| Hybrid KEM round-trip | liboqs (Kyber) + lazysodium (X25519) actually load and agree **on this ABI** | device |
| Room database version | live on-disk schema version vs expected (migration drift) | running app |
| NFC bootstrap | tap-to-exchange trust level + attestation tier | 2 devices + app hook |
| BLE / WiFi-Direct | peer discovery, RSSI, fragment throughput | 2 devices + app hook |
| Mesh propagation | post → fragment fetch → MerkleAck across nodes | 2 devices + app hook |

The first four run unattended and call the real production classes. The last three are
app-wired: this module does not reach into transport internals — instead the app supplies
a lambda from its debug source set (see hooks below). Without a hook they print MANUAL with
instructions, rather than guessing.

## Opening the panel

The app references the entry point unconditionally; it resolves to real content in debug
and to `null` in release (`app/src/{debug,release}/.../DebugDiagnostics.kt`). In MainActivity:

```kotlin
// inside your Compose content, e.g. behind a long-press on the app logo or a debug nav route
val diagnostics = remember {
    mesh.shadowmesh.app.debug.debugDiagnosticsContent(
        dbVersion = { database.openHelper.readableDatabase.version }  // your Room instance
    )
}
if (diagnostics != null) {
    // route to it, show in a dialog, or gate behind a hidden gesture
    diagnostics()
}
```

In a release build `diagnostics` is `null`, so nothing renders and nothing links.

## Wiring the 2-device hooks (optional, when you have a second phone)

In `app/src/debug/.../DebugDiagnostics.kt`, populate the remaining `DiagnosticsDeps` fields
from your DI graph, e.g.:

```kotlin
DiagnosticsDeps(
    expectedDbVersion = 8,
    dbVersionProvider = dbVersion,
    nfcSelfTest = {
        // start NfcBootstrapCoordinator, await BootstrapResult.Success, map to a ProbeResult
    },
    bleScanTest = { /* BleGattTransport discovery + fragment round-trip */ },
)
```

## Removal (one commit, fully reversible)

1. Delete `feature/debug-diagnostics/`.
2. Remove `debugImplementation(project(":feature:debug-diagnostics"))` from `app/build.gradle.kts`.
3. Remove `":feature:debug-diagnostics"` from `settings.gradle.kts`.
4. Delete `app/src/debug/.../DebugDiagnostics.kt` (the `src/release` stub is a harmless no-op; the MainActivity call site then needs deleting too).

Because the module is `debugImplementation`-only and the release entry point is a `null`
stub, **no diagnostics code is present in a release APK even before you remove it** — removal
is just hygiene.

## Status / caveat

Authored without a compiler in the loop (no Android SDK available where this was written).
The first four probes call confirmed production signatures; the Compose screen uses only
Material3 + foundation. Build it with Claude Code / Android Studio and iterate — treat a
green `:feature:debug-diagnostics:compileDebugKotlin` as the gate, then run the probes on a
real device.

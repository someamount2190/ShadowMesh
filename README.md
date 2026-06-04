# SHADOWMESH

A serverless, encrypted, peer-to-peer mesh messaging system for Android. No internet connection required. No central server. No phone number. No account.

SHADOWMESH nodes discover each other over Bluetooth LE, WiFi Direct, and LAN. Messages are fragmented, FEC-encoded, and propagated through the mesh using a Kademlia DHT with store-and-forward delivery. Every message is encrypted end-to-end with a post-quantum hybrid scheme (Kyber-1024 + X25519 for key encapsulation, Dilithium-3 + Ed25519 for signatures, XChaCha20-Poly1305 for symmetric encryption). Trust is established physically — devices exchange keys face-to-face over NFC, optionally with hardware attestation.

> **Transport status (beta — read before relying on the offline claims).** In the current
> build only the **DHT-over-UDP** transport is wired into the gossip layer
> (`buildGossipTransport` → `DhtBackedGossipTransport`). The BLE, WiFi Direct, and LAN-subnet
> transports are fully implemented in `core/mesh/transport/` and unit-tested, but are **not yet
> instantiated/wired** into gossip (they require Android `Context` and scan/advertise lifecycles
> owned by the foreground service — tracked as a separate integration task). The DHT transport is
> an IP transport, so **message propagation in this build needs IP reachability (LAN or internet)
> — the "no infrastructure / Bluetooth-only" path is not active end-to-end yet.** Additionally the
> compiled DHT bootstrap seed list is **empty** (`SeedList.hardcoded()` returns `emptyList()`), so
> a fresh node has no built-in first peer to reach over that transport until a deployment supplies
> a signed seed list. Treat the offline-first bullets below as the design target, not the
> as-shipped beta behaviour. See `STUB_AUDIT.md` S1/S2.

---

## What it is

- **Offline-first.** Operates entirely without internet. Nodes relay messages for each other; a message posted while two nodes are separated is delivered when they reconnect.
- **Post-quantum.** Every key exchange and signature uses a hybrid classical + post-quantum scheme. Classical keys (X25519, Ed25519) protect against today's adversaries; Kyber and Dilithium protect against future quantum computers.
- **Forward-secret.** Each post is encrypted with a per-post key derived from a per-channel ratchet (HKDF-based, checkpoint-persisted). Compromise of today's key does not expose past messages.
- **Hardware-rooted.** Private keys never leave the Android Keystore / TEE. Key extraction requires a physical hardware attack on the secure element, not software.
- **Self-distributing.** The app itself can be distributed over the mesh as a SHADOWFILES payload, verified by the release signing key. No app store required.

## What it is not

- A replacement for Signal, WhatsApp, or any centralized messenger — those have servers, phone numbers, and reliable delivery. SHADOWMESH trades those for the ability to operate with no infrastructure at all.
- Guaranteed-delivery or low-latency. Message propagation depends on physical proximity of nodes. In a small or fragmented mesh, delivery can take minutes or hours.
- Anonymous against a local mesh observer who can see BLE/WiFi traffic. Traffic shape, timing, and presence are visible to nearby passive listeners. SNDP cover traffic and the in-mesh mix protocol (Maximum Security mode) reduce correlation but do not eliminate it. See `THREAT_MODEL.md` for precise statements.

---

## Architecture

```
feature/ui          ← Compose UI, nav graph, all screens
feature/onboarding  ← Onboarding flow (key generation, NFC bootstrap, VPN setup)
feature/forum       ← Post engine, channel manager, ratchet, dispatchers, sync

core/attestation    ← Hardware attestation parsing, NFC bootstrap coordinator
core/bootstrap      ← Physical key exchange (QR, NFC wire format), nonce store
core/crypto         ← Hybrid KEM/signer, HKDF, XChaCha20-Poly1305, node identity
core/distribution   ← Offline APK distribution (fountain codes, descriptor, verifier)
core/mesh           ← DHT, gossip, BLE/WiFi/LAN transports, onion circuits,
                       store-and-forward, SNDP cover traffic, fragmentation
core/nsc            ← Network State Coordinator (saga log, priority transitions)
core/platform       ← VPN service bridge, foreground service, battery exemption
core/security       ← Biometric key manager, duress PIN, panic wipe, APK integrity
core/storage        ← Room + SQLCipher database, all entities, bloom filter
```

All modules are pure Kotlin. `core/crypto` is a JVM library (no Android dependencies) so its cryptographic primitives can be unit-tested on the JVM. All other modules are Android libraries.

### Trust model in one paragraph

Nodes are identified by a 32-byte node ID derived from their Kyber and Dilithium public keys. Trust is established in person: two devices exchange signed identity payloads over NFC (`TRUST_PHYSICAL`). A physically-trusted node can introduce a third party (`TRUST_INTRODUCED`, one hop only — introduced nodes cannot introduce further). Unknown nodes are `TRUST_PUBLIC` and can only access open channels. Hardware attestation (`AttestedPhysicalExchange`) optionally upgrades a physical bootstrap to `TRUST_PHYSICAL_ATTESTED` by verifying the peer's device is running unmodified Android on genuine hardware. See `THREAT_MODEL.md` for the full trust hierarchy, what each level means, and where each guarantee terminates.

---

## Building

See `BUILDING.md` for complete build instructions including:
- Prerequisites (JDK 17, Android SDK 34, NDK 25c/26)
- One-time configuration (signing keystore, BuildConfig secrets, attestation root certificates)
- Offline/air-gap builds via `scripts/vendor_deps.py`
- Pre-production deployment checklist

Quick start for a debug build on a connected machine:

```bash
./gradlew assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## Minimum requirements

- Android 10 (API 29) or later
- Bluetooth LE
- WiFi (for WiFi Direct and LAN subnet transport)
- NFC (for physical key exchange bootstrap)
- Hardware-backed Android Keystore (TEE or StrongBox) — present on all Pixel and most Samsung/Xiaomi devices from 2018+

---

## Key dependencies

| Library | Purpose |
|---------|---------|
| `liboqs-java` | Kyber-1024 (post-quantum KEM) and Dilithium-3 (post-quantum signatures) |
| `lazysodium-android` | X25519, Ed25519, XChaCha20-Poly1305 via libsodium |
| `sqlcipher-android` | AES-256 encrypted SQLite database |
| `androidx.room` | SQLite ORM (compile-time verified queries, migrations, Flow) |
| `androidx.biometric` | Biometric prompt for Keystore key release |
| `androidx.work` | Periodic background tasks (TTL sweep, mesh sync, APK integrity check) |
| `androidx.compose` | UI toolkit |
| `hilt` | Dependency injection (ViewModel wiring) |
| `backblaze:erasure` | Reed-Solomon erasure coding for fragment FEC |
| `zxing:core` | QR code generation for physical key exchange |

All dependencies are declared in `gradle/libs.versions.toml`. For offline builds, `scripts/vendor_deps.py` downloads all artifacts into `libs/maven/`.

---

## Security

**Read `THREAT_MODEL.md` before deploying.**

The short version:
- Key confidentiality is hardware-rooted (TEE/StrongBox). Rooting the phone does not expose private keys.
- Software integrity checks (`ApkIntegrityVerifier`) are defeated by Magisk/Zygisk. Hardware attestation during bootstrap (`AttestedPhysicalExchange`) is not, but requires real attestation root certificates to be configured before deployment (see `BUILDING.md §3.3` and `THREAT_MODEL.md §3`).
- Keybox revocation (defence against leaked OEM attestation keys) is architecturally specified but not yet implemented in this build.

---

## Open items

The following are known gaps. This list is reconciled against the source — items that
have since been implemented are marked **[resolved]** with where the code lives, so the list
states the *real* current posture rather than a stale snapshot.

1. **Attestation root certificates are placeholders.** `GOOGLE_HARDWARE_ATTESTATION_ROOT_HEX` and `GRAPHENEOS_ATTESTATION_ROOT_HEX` in `HardwareAttestation.kt` are `DEPLOYMENT_PLACEHOLDER_*` sentinels and must be replaced with real DER-encoded public keys before any deployment. The code fails closed on placeholder values (`verifyRootCertificate()` returns false), so no chain is accepted and `TRUST_PHYSICAL_ATTESTED` is never issued until they are set. **This is the highest-priority gap: with placeholders in place the hardware-attestation tier is inert and every bootstrap falls back to `TRUST_PHYSICAL_NFC` (NFC key exchange without hardware verification).** Replacing the roots requires extracting them outside this repo — see `BUILDING.md §3.3`.

2. **[resolved] NFC onboarding gates on attestation when required.** `OnboardingViewModel` derives `attestationGatePassed` from the achieved trust level and blocks `PHYSICAL_EXCHANGE` step completion (surfacing an error) when `requireAttestation = true` and the peer did not reach `TRUST_PHYSICAL_ATTESTED`. The remaining design decision — not a bug — is that `NfcBootstrapCoordinator.requireAttestation` **defaults to `false`**, so out of the box a peer is accepted at `TRUST_PHYSICAL_NFC` without hardware verification. Set `requireAttestation = true` for high-security deployments (and note this only has teeth once item 1 is done).

3. **Keybox revocation: checking is wired; offline distribution is not.** `KeyboxRevocationCache.isRevoked(serial, pubKeyHash)` **is** now called from `HardwareAttestation.verifyAttestationChain` (and the cache is constructed and `ensureLoaded()` in `ShadowMeshApplication.buildRevocationCache`). Two real residual gaps remain: (a) the cache refreshes over HTTP from `REVOCATION_URL`, which **requires internet and so contradicts the offline-first premise** — the *signed-gossip* distribution path described in `THREAT_MODEL.md §3` is still unbuilt, so on an air-gapped mesh revocation freshness is only as good as the bundled APK snapshot; and (b) `isRevoked` **fails open** (returns `false` when there is no cache and the fetch fails). A leaked-but-not-yet-revoked keybox still passes.

4. **[resolved] `AppArtifactAcquirer` multi-session resume is implemented.** Gated on the optional `dao` param, which production supplies (`ShadowMeshApplication` line ~470). `acquire()` checkpoints each assembled chunk and resumes from the last checkpoint after a mid-transfer process death, with write-before-checkpoint ordering and a stale-cache fall back to full re-fetch. Resume is disabled only when `dao == null` (tests).

5. **`ArtifactFetcher` BLE/WiFi-Direct implementation and `:bootstrap-app` stub are not built.** The seeder, acquirer (with resume), descriptor, fountain codes, and verifier exist, but `buildArtifactFetcher()` has no real peer-to-peer transport behind it and the tiny bootstrap APK does not exist — so **self-distribution is not functional end-to-end**: every piece is present except the one that actually moves bytes between devices. This is feature build-out requiring on-device BLE/WiFi-Direct work, not a code-cleanup fix.

### Not closing here, and why

Items 1, 3a, and 5 are not fixable as a source edit in isolation: item 1 needs real attestation root keys extracted outside this repo; item 3a needs the signed-gossip revocation transport built and tested on a real mesh; item 5 needs device-tested BLE/WiFi-Direct transport code. The circuit-STUN reply path (`CircuitStunSenderImpl`, one-way circuit → returns null fail-closed), BLE/QR onboarding completion (`NfcBootstrapCoordinator` only completes the NFC path), IPv6 in `DatagramSocketUdpAdapter`, and replacing the commit-reveal `VrfElection` with a real RFC 9381 VRF are all in the same category — each is a build-out whose correctness depends on the Android runtime and would need compile + instrumented-test verification before shipping into a security tool. They are left explicitly flagged rather than stubbed.

---

## Licence

[Add licence here]

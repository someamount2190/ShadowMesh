# SHADOWMESH

A serverless, encrypted, peer-to-peer mesh messaging system for Android. No central server. No phone number. No account.

SHADOWMESH nodes discover each other over Bluetooth LE, WiFi Direct, and LAN. Messages are fragmented, FEC-encoded, and propagated through the mesh using a Kademlia DHT with store-and-forward delivery. Every message is encrypted end-to-end with a post-quantum hybrid scheme (Kyber-1024 + X25519 for key encapsulation, Dilithium-3 + Ed25519 for signatures, XChaCha20-Poly1305 for symmetric encryption). Trust is established physically — devices exchange keys face-to-face over NFC, gated behind BLE proximity confirmation to prevent remote relay attacks.

> **Transport status (beta — read before relying on the offline claims).** Three transports are active in the current build:
> - **DHT-over-UDP** is the primary gossip transport (`DhtBackedGossipTransport`).
> - **LAN subnet** is wired and active (`dhtGossipTransport.lanTransport = LanSubnetTransport`) — nodes on the same network discover each other via UDP broadcast and exchange fragments over TCP without internet.
> - **BLE GATT** is wired for peer discovery and nudge delivery — BLE-discovered peers are registered in the gossip engine and nudges schedule WorkManager sync jobs, but fragments do not flow directly over BLE GATT yet.
> - **WiFi Direct** transport is fully implemented in `core/mesh/transport/wifi/` but is not yet instantiated in production (requires Android `WifiP2pManager` lifecycle integration in the foreground service — tracked as an open item below).
>
> The compiled DHT bootstrap seed list is **empty** (`SeedList.hardcoded()` returns `emptyList()`) in this open-source build — a fresh node with no LAN peers and no externally-supplied seed list cannot reach the DHT until a deployment provides a signed seed file. On a LAN or with another device in range via BLE, no seed list is required. See `SeedList.kt` for the signed-update mechanism.
>
> Treat the "Offline-first" and "Bluetooth-only" bullets below as the design target; LAN and BLE nudges are active, full BLE gossip routing and WiFi Direct are not yet end-to-end.

---

## What it is

- **Offline-first.** Operates without internet on a local network or in close BLE range. Nodes relay messages for each other; a message posted while two nodes are separated is delivered when they reconnect.
- **Post-quantum.** Every key exchange and signature uses a hybrid classical + post-quantum scheme. Classical keys (X25519, Ed25519) protect against today's adversaries; Kyber-1024 and Dilithium-3 protect against future quantum computers.
- **Forward-secret.** Each post is encrypted with a per-post key derived from a per-channel ratchet (HKDF-based, checkpoint-persisted). Ratchet gap resolution re-fetches intermediate posts when out-of-order delivery desynchronises a receiver's ratchet.
- **Hardware-rooted.** Private keys never leave the Android Keystore / TEE. Key extraction requires a physical hardware attack on the secure element, not software.
- **Relay-resistant bootstrap.** NFC trust exchange is gated behind BLE proximity confirmation (`BleProximityScanner`, RSSI ≥ −70 dBm). An attacker who intercepts the QR invitation code cannot trigger a trust credential exchange remotely — the NFC handshake is blocked until the peer is confirmed physically adjacent.
- **Self-distributing.** The app can be distributed over the mesh as a SHADOWFILES payload, verified by the release signing key. The acquirer, seeder, fountain codes, verifier, and DHT-backed fetch are all implemented; BLE/WiFi Direct chunk transfer and the bootstrap APK stub are the remaining build-out items.

## What it is not

- A replacement for Signal, WhatsApp, or any centralized messenger — those have servers, phone numbers, and reliable delivery. SHADOWMESH trades those for the ability to operate with no infrastructure at all.
- Guaranteed-delivery or low-latency. Message propagation depends on physical proximity of nodes. In a small or fragmented mesh, delivery can take minutes or hours.
- Anonymous against a local mesh observer who can see BLE/WiFi traffic. Traffic shape, timing, and presence are visible to nearby passive listeners. SNDP cover traffic and the in-mesh mix protocol (Maximum Security mode) reduce correlation but do not eliminate it. See `THREAT_MODEL.md` for precise statements.

---

## Architecture

```
feature/ui              ← Compose UI, nav graph, all screens
feature/onboarding      ← Onboarding flow (key generation, NFC bootstrap, BLE proximity gate)
feature/forum           ← Post engine, channel manager, ratchet, dispatchers, sync
feature/debug-diag      ← Optional instrumentation screen (debug builds only)

core/attestation        ← Hardware attestation parsing, NFC bootstrap coordinator
core/bootstrap          ← Physical key exchange (QR, NFC wire format), nonce store
core/crypto             ← Hybrid KEM/signer, HKDF, XChaCha20-Poly1305, node identity
core/distribution       ← Offline APK distribution (fountain codes, descriptor, verifier)
core/mesh               ← DHT, gossip, BLE/WiFi/LAN transports, onion circuits,
                           store-and-forward, SNDP cover traffic, fragmentation,
                           transport health monitor, hardened challenge layer
core/nsc                ← Network State Coordinator (saga log, priority transitions)
core/platform           ← VPN service bridge, foreground service, battery exemption
core/security           ← Biometric key manager, duress PIN, panic wipe, APK integrity
core/storage            ← Room + SQLCipher database, all entities, bloom filter
```

All modules are pure Kotlin. `core/crypto` is a JVM library (no Android dependencies) so its cryptographic primitives can be unit-tested on the JVM. All other modules are Android libraries.

### Trust model

Nodes are identified by a 32-byte node ID derived from their Kyber and Dilithium public keys. Trust is established in person: two devices exchange signed identity payloads over NFC (`TRUST_PHYSICAL`), gated by BLE proximity confirmation so the handshake cannot be relayed remotely. A physically-trusted node can introduce a third party (`TRUST_INTRODUCED`, one hop only — introduced nodes cannot introduce further). Unknown nodes are `TRUST_PUBLIC` and can only access open channels. Hardware attestation (`AttestedPhysicalExchange`) optionally upgrades a physical bootstrap to `TRUST_PHYSICAL_ATTESTED` by verifying the peer's device is running unmodified Android on genuine hardware — see **Open items** for the current wiring status.

---

## Building

See `BUILDING.md` for complete build instructions including:
- Prerequisites (JDK 17, Android SDK 34, NDK 25c/26)
- One-time configuration (signing keystore, BuildConfig secrets)
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
- Bluetooth LE (for peer discovery, nudges, and proximity-gated bootstrap)
- WiFi (for LAN subnet transport and WiFi Direct)
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
- Software integrity checks (`ApkIntegrityVerifier`) are defeated by Magisk/Zygisk. Hardware attestation during bootstrap (`AttestedPhysicalExchange`) is not — but it defaults to `requireHardwareAttestation = false` (graceful fallback to `TRUST_PHYSICAL_NFC`). See open item 1.
- Keybox revocation checking is wired; offline gossip distribution is partial. See open item 2.
- QR-code relay attacks are blocked by the BLE proximity gate added in v22. An intercepted QR code cannot be used to trigger an NFC handshake unless the attacker's device is within BLE range (≤ ~10 m) of the initiator.

---

## Open items

The following are known gaps, verified against the current source. Items marked **[resolved]** have confirmed implementations; everything else is still outstanding.

### 1. Hardware attestation not wired into NFC onboarding UI

The `AttestedPhysicalExchange` class is constructed and called, and the Google hardware attestation root certificates are embedded with real DER-encoded values (`GOOGLE_HARDWARE_ATTESTATION_ROOT_RSA`, `GOOGLE_HARDWARE_ATTESTATION_ROOT_EC` in `HardwareAttestation.kt`). However, the NFC onboarding flow does not yet embed attestation evidence in the NFC payload or require the peer to prove hardware integrity:

- `NfcBootstrapCoordinator` only reaches `AttestedPhysicalExchange.verifyPeerAttestation()` when the peer voluntarily includes attestation evidence — there is no enforcement.
- `AttestedPhysicalExchange` is constructed with `requireHardwareAttestation = false`, so bootstraps succeed at `TRUST_PHYSICAL_NFC` regardless of whether the peer is rooted.

**What remains:** The onboarding UI must be updated to (a) always generate a fresh attestation challenge in `buildQrIntroductionCode`, (b) require the responder to embed attestation evidence in its NFC payload, and (c) downgrade or reject the bootstrap if `verifyPeerAttestation` fails. Until then, `TRUST_PHYSICAL_ATTESTED` is never issued and rooted-device resistance at bootstrap time is not enforced. High-security deployments can set `requireAttestation = true` on `NfcBootstrapCoordinator` to block non-attested peers immediately.

### 2. Keybox revocation: checking wired; offline distribution partial

`KeyboxRevocationCache.isRevoked()` is called from `HardwareAttestation.verifyAttestationChain()` and the cache is constructed and pre-loaded in `ShadowMeshApplication`. Two real residual gaps remain:

- **Fail-open on cache miss.** `isRevoked()` returns `false` when the cache is unavailable and the HTTP fetch fails. A leaked-but-not-yet-revoked keybox still passes attestation until the cache is populated.
- **HTTP fetch requirement.** The cache refreshes over HTTP from `REVOCATION_URL`. This contradicts the offline-first premise. The signed-gossip revocation pipeline is implemented (`RevocationUpdateFrame`, re-gossip in `AckRouter`), but it depends on at least one NFC-bootstrapped peer publishing a fresh update — DHT-only peers cannot originate signed revocation frames.

### 3. WiFi Direct transport not wired

`WiFiDirectTransport` is fully implemented in `core/mesh/transport/wifi/` (including `WifiDirectTransportSecurity` and `WifiP2pBroadcastReceiver`) but is never instantiated in production. The foreground service does not own the `WifiP2pManager` lifecycle required to run peer discovery and group negotiation. Until this is integrated, WiFi Direct peer discovery and fragment transfer are inactive. LAN subnet and BLE GATT cover the local-transport use case in the interim.

### 4. NSC rollback handlers partially implemented

Five of the six NSC rollback opcodes are partially implemented:
- `CANCEL_FRAGMENT` — fully implemented; deletes the fragment via DAO.
- `RESTORE_NETWORK_MODE`, `RESTORE_BEACON_MODE`, `RESTORE_PEER_SELECTION` — rehydrate mode enums from the persisted string and apply them when the target engine has a public setter; emit `Diag.degraded` and return normally when no setter exists yet.
- `RECLAIM_DHT_SLICE`, `REVERT_TIER_PROMOTION` — no fine-grained DHT API exists yet; both emit `Diag.degraded` and return. These opcodes are currently unreachable in production (the anchor-handoff subsystem that would emit them is not yet wired), so there is no live exposure.

### 5. **[resolved]** NFC onboarding gates on attestation when required

`OnboardingViewModel` derives `attestationGatePassed` from the achieved trust level and blocks `PHYSICAL_EXCHANGE` step completion when `requireAttestation = true` and the peer did not reach `TRUST_PHYSICAL_ATTESTED`. The design decision — not a bug — is that `NfcBootstrapCoordinator.requireAttestation` **defaults to `false`**, so out of the box a peer is accepted at `TRUST_PHYSICAL_NFC`. Set `requireAttestation = true` for high-security deployments (see open item 1 for the remaining onboarding UI work).

### 6. **[resolved]** AppArtifactAcquirer multi-session resume

Gated on the `dao` parameter, which production supplies. `acquire()` checkpoints each assembled chunk and resumes from the last checkpoint after a mid-transfer process death, with write-before-checkpoint ordering and a stale-cache fallback to full re-fetch. Resume is disabled only when `dao == null` (tests).

### 7. **[resolved]** ArtifactFetcher backed by DHT

`buildArtifactFetcher()` in `ShadowMeshApplication` is a real DHT-backed implementation: it fetches the descriptor, manifest, chunk index, and chunk fragments from the DHT via `dhtEngine.findValue()`. The remaining build-out item is BLE/WiFi Direct chunk transfer — `AppArtifactSeeder` publishes to DHT and over the mesh, but chunk retrieval over BLE GATT or WiFi Direct is not yet wired. The bootstrap APK stub (`:bootstrap-app`) also does not exist. Self-distribution is functional for nodes with DHT reachability; the radio-only path is not yet end-to-end.

### Not closing here, and why

Items 1 (attestation onboarding UI) and 3 (WiFi Direct lifecycle) require device-tested Android runtime work whose correctness cannot be verified with unit tests alone. Item 2 (offline revocation distribution) requires a real mesh for end-to-end testing. These are left explicitly flagged rather than silently stubbed.

---

## Licence

[Add licence here]

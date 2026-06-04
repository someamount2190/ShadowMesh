# SHADOWMESH — Self-Distribution & Offline Bootstrap (Design)

Four related capabilities, none of which require new cryptography or new transports —
each composes primitives the codebase already ships. This document defines the flows,
the trust model, the new code surface (deliberately small), and the failure modes.

The unifying idea: **the app is just another SHADOWFILES payload, and its own signing
key is the distribution trust anchor.** A device with no internet can acquire, verify,
and run SHADOWMESH entirely from a nearby peer.

Primitives reused (all present today):
- `ShadowFilesChunker` / `ShadowFilesReassembler` — chunk → manifest (Merkle root) →
  FEC fragments → reassemble, with resume checkpoints. Already has `buildQrPayload` /
  `parseQrPayload` and key derivation from an ephemeral secret.
- `PhysicalKeyExchange` / `QrIntroductionCode` — signed QR payloads (Ed25519), 5-minute
  validity, replay-protected by nonce.
- `ChannelManager` / `PostEngine` — channel types `OPEN/CLOSED/COMPARTMENTED/ANONYMOUS`,
  per-post `ttlMs`, `burnAfterRead`, `rotateKey`, `departChannel`; `TtlSweepWorker` reaps.
- `ApkIntegrityVerifier` — SHA-256 of the app's signing certificate vs
  `BuildConfig.EXPECTED_SIGNATURE_HASH`; `IntegrityBoundedKeyDerivation.buildApkBindingHash`.
- `DhtEngine.bootstrap(seeds)` — network entry from a seed list.
- BLE / WiFi Direct transports carry SHADOWFILES fragments offline.

---

## Feature 1 — App self-distribution via the mesh (APK as a mesh artifact)

### Goal
A device pulls the full APK from nearby nodes over BLE/WiFi-Direct, never touching the
internet, and verifies it is the genuine SHADOWMESH build before installing.

### Design
Treat the APK as a SHADOWFILES payload with a **well-known, reserved transfer identity**
so any node can advertise and any node can request it without prior coordination.

New concept: an **AppArtifactDescriptor** — the small, signed record that says "build
version V of SHADOWMESH is available as SHADOWFILES manifest M."

```
AppArtifactDescriptor (signed):
  versionCode      : Int
  versionName      : String
  manifestHash     : ByteArray(32)   // identifies the SHADOWFILES TransferManifest
  apkSha256        : ByteArray(32)   // hash of the assembled, decrypted APK bytes
  signingCertHash  : String          // == BuildConfig.EXPECTED_SIGNATURE_HASH
  minSdk           : Int
  signature        : ByteArray       // Ed25519 over the above, by the release key
```

Distribution flow (offline):
1. **Publish (seeder).** A device already running SHADOWMESH reads its own installed
   base APK (`context.applicationInfo.sourceDir`), runs `ShadowFilesChunker.chunk(...)`
   over it on a reserved channelId (`APP_DISTRIBUTION_CHANNEL`), and holds the resulting
   `FragmentSet`s. It advertises the `AppArtifactDescriptor` in its BLE beacon manufacturer
   data (just the versionCode + manifestHash truncation; full descriptor served on request).
2. **Discover (acquirer).** A device without the app can't run this code — so discovery is
   bootstrapped by Feature 2 (QR). Once it has the descriptor + transfer key, it requests
   chunks by their content-addressed `chunkPostId`s over BLE/WiFi-Direct, exactly like any
   SHADOWFILES fetch, with `ShadowFilesReassembler` driving resume.
3. **Reassemble + verify.** On `finalAssemble` success, the acquirer verifies the
   Merkle root (already done by the reassembler) **and** the `apkSha256` and
   `signingCertHash` from the descriptor (Feature 3). Only then is the APK handed to the
   package installer.

Key derivation: the APK is not secret, so the distribution channel uses
`ShadowFilesChunker.deriveKeyFromChannel(APP_DISTRIBUTION_KEY, manifestHash)` with a
**fixed, public** channel key compiled into the app. Encryption here is not for
confidentiality (anyone may have the app) but to keep all SHADOWFILES fragments
structurally identical to private ones, so a passive observer can't distinguish "someone
is pulling the app" from "someone is pulling a private file."

### New code surface (small)
- `core/distribution/` (new module, depends on `core:mesh` + `core:security`):
  - `AppArtifactDescriptor` (+ sign/verify against the release Ed25519 key).
  - `AppArtifactSeeder` — chunk the installed APK, answer descriptor + chunk requests.
  - `AppArtifactAcquirer` — given a descriptor + key, drive `ShadowFilesReassembler`,
    verify, and emit a verified APK file path.
- Reserved constants: `APP_DISTRIBUTION_CHANNEL`, `APP_DISTRIBUTION_KEY` (public),
  `RELEASE_SIGNING_PUBKEY` (the Ed25519 key that signs descriptors).

### Why not in the roadmap already
SHADOWFILES was specified for user file transfer; nothing designated the APK itself as a
hosted artifact. The only genuinely new piece is the signed descriptor + the seeder/acquirer
glue; transport, chunking, FEC, resume, and Merkle verification are all reused.

---

## Feature 2 — Bootstrap via QR without internet

### Goal
A device with no app and no internet acquires the app from a nearby peer, triggered by a
single QR code. The QR is the *minimal* bootstrap seed; the bytes come over the mesh.

### Design
A QR code cannot carry an APK (~megabytes). It carries a **bootstrap trigger**: enough to
(a) find a nearby seeder, (b) name the exact build, and (c) derive the transfer key. This
reuses `ShadowFilesChunker.buildQrPayload`, which already XORs an ephemeral secret with the
manifest hash into 65 bytes — well within QR capacity.

```
AppBootstrapQR  (≈ 80–110 bytes, fits a QR comfortably):
  magic            : 4 bytes  "SMBP"   (SHADOWMESH BootstraP)
  versionCode      : varint
  manifestHash     : 32 bytes
  transferKeySeed  : 32 bytes  (XOR-wrapped, as buildQrPayload does)
  seederHint       : 6 bytes   (BLE manufacturer-data tag of the advertising seeder)
  descriptorSig8   : 8 bytes   (first 8 bytes of the release signature over the above —
                                a fast reject for typo'd/forged QRs before any pull)
```

Acquisition flow:
1. The seeder displays the QR (generated by `AppArtifactSeeder.buildBootstrapQr()`).
2. The acquirer — running only a **tiny bootstrap stub** (see below) — scans it, parses
   via `parseQrPayload`, and recovers the transfer key + manifestHash + version.
3. The stub scans BLE for the `seederHint`, connects via the existing `BleGattTransport`,
   pulls the descriptor, confirms `descriptorSig8`, then runs Feature 1's acquire flow.
4. After install, the freshly-installed full app runs normal onboarding (`OnboardingViewModel`)
   and **separately** joins the DHT via `DhtEngine.bootstrap(seeds)` — note these are two
   different bootstraps (see "Two bootstraps" below).

### The bootstrap stub
The chicken-and-egg problem: you need the app to pull the app. Options, in order of
preference:
- **A. Companion lightweight bootstrap APK** (~tens of KB): a stripped build containing
  only QR scan + BLE GATT client + `ShadowFilesReassembler` + signature verify, no UI/forum/
  crypto-heavy modules. This is the clean answer; it is itself self-distributable the same way.
- **B. Web-bootstrap fallback** (only if one device has connectivity): a single static page
  that is the bootstrap stub as a PWA. Out of scope for the pure-offline goal but worth noting.

The stub is a new `:bootstrap-app` application module sharing `core:mesh` (files + BLE) and a
minimal slice of `core:crypto`. It must be buildable independently and kept tiny.

### Two bootstraps (important distinction)
- **App-acquisition bootstrap** (this feature): "get the APK bytes." QR-triggered, BLE pull.
- **Network bootstrap** (existing roadmap): "join the DHT." `DhtEngine.bootstrap(seeds)` from
  a seed list. These are independent: you can have the app but not be in the mesh, or be in
  the mesh and re-distribute the app. The QR may optionally carry seed contacts to chain into
  network bootstrap immediately after install, but that is additive.

### Why not in the roadmap already
The roadmap covers DHT seed-list bootstrapping (network entry). App *acquisition* was never a
defined phase. The new pieces are the QR schema and the bootstrap stub; the pull itself is
Feature 1.

---

## Feature 3 — Mesh-hosted APK with signature verification as the distribution trust anchor

### Goal
However the APK arrives — mesh pull, Bluetooth share, SD card, a friend's phone — the
recipient can prove it is the genuine SHADOWMESH build before trusting/installing it. This
closes the "fake copy" problem without a central download server.

### Design
Reuse the integrity primitive that already exists for runtime tamper detection. The same
signing-certificate hash that `ApkIntegrityVerifier` checks at runtime is the distribution
anchor:

Three independent checks, all must pass before install is offered:
1. **APK content hash.** `SHA-256(assembledApkBytes) == descriptor.apkSha256`. Catches
   corruption and truncation; the SHADOWFILES Merkle root already guarantees this for mesh
   pulls, but recompute end-to-end for any acquisition channel.
2. **Signing-certificate hash.** Extract the APK's signing cert (same
   `PackageManager.GET_SIGNING_CERTIFICATES` path `ApkIntegrityVerifier` uses, but applied to
   the *candidate file* via `PackageManager.getPackageArchiveInfo(path, GET_SIGNING_CERTIFICATES)`)
   and require `certHash == BuildConfig.EXPECTED_SIGNATURE_HASH`. A repackaged/fake APK signed
   with a different key fails here.
3. **Descriptor signature.** The `AppArtifactDescriptor` is Ed25519-signed by the release key;
   verify it against the compiled-in `RELEASE_SIGNING_PUBKEY`. This binds versionCode ↔
   manifestHash ↔ apkSha256 ↔ signingCertHash so an attacker cannot swap a real-but-old APK's
   hash into a descriptor for a different version (downgrade/confusion).

```
verifyAcquiredApk(file, descriptor):
  require sha256(file.bytes) == descriptor.apkSha256                 // (1) content
  require archiveSigningCertHash(file) == EXPECTED_SIGNATURE_HASH    // (2) authenticity
  require archiveSigningCertHash(file) == descriptor.signingCertHash // (2b) descriptor agrees
  require ed25519Verify(descriptor.signedBytes, descriptor.signature,
                        RELEASE_SIGNING_PUBKEY)                      // (3) descriptor integrity
  -> VerifiedApk(file, descriptor.versionCode)
```

Trust anchor termination (be explicit — see THREAT_MODEL.md §3): the anchor is the **release
signing key fingerprint compiled into every installed copy**. This is a *software* anchor: a
device that already runs a genuine SHADOWMESH carries the correct `EXPECTED_SIGNATURE_HASH`
and `RELEASE_SIGNING_PUBKEY`, so it can vet any candidate APK. The unavoidable bootstrap caveat:
the *very first* copy a person ever obtains has no on-device anchor to check against — they must
get the fingerprint out-of-band (printed on a trusted flyer, spoken, from a second source) and
compare. Once one genuine copy exists, it transitively vets all future copies. This is the same
trust-on-first-acquisition limit every offline software-distribution scheme has; the design
makes it explicit rather than hiding it.

### New code surface
- In `core/distribution/`: `ApkArtifactVerifier` (the four checks above), reusing
  `ApkIntegrityVerifier`'s cert-extraction helper, generalised to accept an archive path.

### Why not in the roadmap already
Runtime self-verification was specified; verification as a *distribution* gate was not. The
mechanism is identical — the design just points the existing check at a candidate file plus a
signed descriptor.

---

## Feature 4 — One-time forum pattern (printed QR → ephemeral channel → burn → destroy key)

### Goal
A documented, supported use case: print a QR, hand it out physically, run a temporary channel
that auto-expires and burns posts on read, then destroy the key so the channel is
unrecoverable. For protests, sources, one-off coordination.

### Design
This is **pure composition** of existing channel features; the work is defining the pattern,
the lifecycle, and one convenience wrapper — not new mechanism.

Lifecycle:
1. **Create.** `ChannelManager.createChannel(type = ANONYMOUS or COMPARTMENTED, ttlMs = T)`.
   ANONYMOUS suits a wide physical drop; COMPARTMENTED (biometric-gated) suits a small trusted
   set. The channel key is generated locally and never digitally distributed.
2. **Print.** Encode the channel key + channelId + expiry into a `QrIntroductionCode`-style
   signed payload (reuse `PhysicalKeyExchange.buildQrIntroductionCode`, extended with a
   `channelKey` field). Render to an image for printing. **The QR is the only copy of the key
   that leaves the device.**
3. **Join.** Recipients scan the printed QR, recover the channel key, and join. No network
   round-trip needed beyond mesh gossip.
4. **Operate.** Posts are created with `PostEngine.createPost(ttlMs = ..., burnAfterRead = true)`.
   Reading a post deletes it locally (existing burn path); TTL reaps the rest via `TtlSweepWorker`.
5. **Destroy.** At expiry (or on demand), `ChannelManager.departChannel(channelId)` plus an
   explicit **key-destruction** step: wipe the channel key from `BiometricKeyManager`/storage
   and `fill(0)` any in-memory copy. After this the channel is cryptographically unrecoverable
   even from this device — matching the "destroy the key" intent.

Convenience wrapper (new, thin):
```
OneTimeChannel.create(ttl, gate):  -> (channelId, printableQrBitmap)
OneTimeChannel.destroy(channelId): -> wipes key, departs channel, sweeps posts
```
Lives in `feature/forum/`. It is sugar over `ChannelManager` + `PostEngine` + the QR builder;
no new storage, crypto, or transport.

Pattern guarantees and limits (document honestly):
- **Forward-secret after destroy:** once the key is wiped and posts swept, the on-device data
  is gone. But anyone who screenshotted the printed QR retains the key until *they* destroy it —
  paper key custody is a human problem the software can't solve.
- **Burn-after-read is best-effort across the mesh:** it deletes *local* copies on read; a
  replica held by another node expires on its own TTL, not on your read. State this so users
  don't over-trust "burn."
- **No retroactive unjoin:** destroying the key stops *future* access; it cannot retract posts
  already pulled and decrypted by a recipient.

### Why not in the roadmap already
Every primitive existed (channel types, TTL, burn, rotation, depart, QR), but the *pattern* —
the specific compose-and-destroy lifecycle as a first-class supported use case — was never
written down or wrapped. This feature is mostly documentation + a 2-method helper.

---

## Cross-cutting: build, modules, and order of work

New module: `core/distribution/` → depends on `core:mesh`, `core:security`, `core:crypto`.
New app module: `:bootstrap-app` (tiny acquirer stub) → depends on `core:mesh` (files+BLE) +
minimal `core:crypto`. Register both in `settings.gradle.kts`; keep the dependency graph
acyclic (distribution sits above mesh/security, like platform does).

Suggested build order (each independently testable):
1. Feature 3 first (`ApkArtifactVerifier`) — it is the trust gate everything else feeds into,
   and it is pure logic, unit-testable without transport.
2. Feature 1 (`AppArtifactDescriptor` + seeder/acquirer) — depends on (3) for the verify step.
3. Feature 2 (QR schema + `:bootstrap-app` stub) — depends on (1) for the pull.
4. Feature 4 (`OneTimeChannel` wrapper + docs) — independent of 1–3; can land any time.

## Threat-model deltas to record in THREAT_MODEL.md
- Distribution trust anchor = release signing key fingerprint (software anchor); first-copy
  acquisition needs an out-of-band fingerprint check (trust-on-first-acquisition).
- The public `APP_DISTRIBUTION_KEY` provides traffic-shape uniformity, **not** confidentiality —
  state plainly that app distribution is not a secret.
- Downgrade protection rests on the descriptor binding versionCode↔hashes; a revocation/min-version
  policy (refuse descriptors below a floor) should be added before relying on it in the field.

## What this design deliberately does NOT solve (open items)
- **Release key custody / rotation** for `RELEASE_SIGNING_PUBKEY` — if the release key rotates,
  old installed copies trust the old key; needs a signed key-transition record. Out of scope here.
- **Seeder incentive / availability** — nothing guarantees a seeder is in range; this is a
  physical-proximity assumption, same as all of SHADOWMESH's offline modes.
- **Installer permission UX** — `REQUEST_INSTALL_PACKAGES` and the OS installer flow are an
  Android integration detail for the acquirer app, not designed here.

---

## Implementation status (this build)

Implemented in `core/distribution/` (new module, registered in settings) and `feature/forum/`:

- **Feature 3** — `ApkArtifactVerifier`: the four-check gate (content hash, archive signing-cert
  == compiled-in expected hash, descriptor agreement, Ed25519 descriptor signature) + downgrade
  floor. Unit-tested via `DistributionTest` with a fake cert provider.
- **Feature 1** — `AppArtifactDescriptor` (signed, round-trip serialised), `AppArtifactSeeder`
  (chunks the installed APK on the public distribution channel; release-time descriptor signer),
  `AppArtifactAcquirer` (fetch → reassemble via `ShadowFilesReassembler` with resume → verify →
  emit verified APK; deletes the file if verification fails).
- **Feature 2** — `AppBootstrapQr` (compact trigger schema, round-trip tested), `ArtifactFetcher`
  interface (transport seam; BLE/WiFi-Direct impl belongs in the app / bootstrap stub).
- **Feature 4** — `OneTimeChannel` in `feature/forum`: create (ANONYMOUS/COMPARTMENTED + TTL) →
  printable wrapped-key payload → `destroy` (evict ratchet, depart, delete posts + channel row).
  Added DAO `deletePostsForChannel` / `deleteChannel`.

Not yet built (require app-layer / build-pipeline integration, intentionally out of this module):
- The `ArtifactFetcher` BLE/WiFi-Direct implementation and the `:bootstrap-app` stub (Feature 2,
  option A). The acquirer is transport-agnostic and ready for it.
- Release-pipeline wiring of `createAndSignDescriptor` (needs the release private key, which no
  device holds) and bundling the signed descriptor + chunk index into the APK.
- `RELEASE_SIGNING_PUBKEY` / `EXPECTED_SIGNATURE_HASH` are supplied by the caller; the app module
  must pass real values from BuildConfig.
- Cross-session partial-file resume in the acquirer is simplified to single-session full assembly
  (noted inline); multi-session resume would persist assembled chunks to disk.

---

## Feature 5 — Visual distribution: the QR frames ARE the data channel

### The idea (refinement of Feature 2)
Earlier, the QR was only a *trigger* and the APK bytes came over BLE. This feature makes the
**camera itself the data channel**: the seeder displays a looping animation of barcode frames on
its screen, the acquirer films the screen, and the APK is reconstructed from the captured frames.
No radio, no internet, no pairing — light through a lens. A phone behind glass, across a room, can
receive the app.

### This is established, not speculative
Prior art that ships today:
- **txqr** (divan) — data over animated QR, moved to fountain codes precisely because cameras
  miss frames.
- **libcimbar / cfc** (sz3) — color-icon-matrix barcodes; sustains ~106 KB/s (850 kbit/s) screen→
  camera, handles files up to 33 MB using fountain codes (wirehair) + Reed-Solomon + zstd.
Our design mirrors theirs, reusing SHADOWMESH's existing Reed-Solomon (intra-frame) and adding the
two pieces that were missing: a fountain code (inter-frame) and the frame protocol.

### Why a fountain code is the crux
A camera filming a loop misses frames (blur, refresh/shutter beat, focus). A fixed sequence forces
the seeder to loop until the receiver happens to catch every index. A **rateless** code instead lets
the seeder emit an unbounded stream of encoded blocks (each an XOR of a pseudo-random subset of the
K source blocks); the receiver collects ANY ~K·(1+ε) distinct blocks, in any order, and rebuilds.
Missed frames cost nothing.

Implemented as `LtFountain` (Luby Transform, robust soliton degree distribution) + a peeling decoder.
Two FEC layers, complementary:
- **Reed-Solomon** (existing `FragmentationEngine`) — corrects bit errors *within* a captured frame.
- **LT fountain** (`LtFountain`) — recovers *whole missing frames* across the stream.

### Frame protocol (`VisualFrameProtocol`)
- **Header frame** (emitted every N frames so a late joiner can sync): totalLen, blockSize, K,
  PRNG seed, and the signed `AppArtifactDescriptor`.
- **Data frame**: seqNo + the LT-encoded block. Each frame is CRC32-checked; a corrupt capture is
  dropped, never fed to the decoder.
The QR *image* codec (bytes ↔ displayed/scanned barcode) lives in the app/UI using a QR or
color-barcode library; this protocol layer is pure bytes and fully unit-tested without a camera.

### Trust gate unchanged
The descriptor rides in on the header frame; once the file is reassembled it goes through the same
`ApkArtifactVerifier` (Feature 3) — content hash, signing-cert == genuine release key, descriptor
signature. Visual transport changes how bytes arrive, not how trust is established.

### Validated
The LT encode→lossy-channel→decode loop was simulated (identical algorithm) and reconstructs the
file with **0%, 30%, and 40% random frame loss plus full reordering**, at ~1.9–2.3× block overhead.
Reconstruction is exact; overhead is the (acceptable) cost of a simple LT vs an optimal Raptor code.

### Honest limits (state plainly)
- **Throughput is low.** Monochrome QR ≈ 2–3 KB/usable-frame at ~10–15 fps → tens of KB/s; color
  barcodes (libcimbar-style) reach ~100 KB/s. A multi-MB APK therefore takes minutes (color) to tens
  of minutes (plain QR). Acceptable for "no other option"; not a replacement for BLE/WiFi-Direct when
  those are available.
- **You still need a decoder on the receiver.** A stock camera app scans ONE QR (→ a URL, useless
  offline); it cannot decode a 3000-frame APK stream. So the minimal bootstrap stub (Feature 2,
  option A) is still required — but the channel it uses now needs only a camera, no radio/pairing.
- **Bootstrap floor remains.** The first copy of even the tiny stub must arrive out-of-band; the
  first fingerprint must be checked out-of-band. Visual transport shrinks the bootstrap, it does not
  eliminate it.
- **LT overhead** (~2×) is higher than Raptor/wirehair; swapping in a better fountain code later is a
  drop-in improvement, no protocol change.

### Implementation status
Implemented + tested (pure JVM, no camera needed): `LtFountain` (encoder + peeling decoder),
`VisualFrameProtocol` (header/data frames, CRC, `StreamEncoder`/`StreamReceiver`), and
`VisualDistributionTest` (ideal, 30%/40%-loss-and-shuffled, corrupt-frame-rejected, late-joiner).
Not built (app/UI layer): the QR/color-barcode image codec (bytes ↔ on-screen barcode ↔ camera
capture) and the animation/scan UI — these need a barcode library and CameraX, and belong in the
`:bootstrap-app` stub.

# SHADOWMESH — Threat Model: Roots of Trust

This document states plainly **where trust terminates** for each security property
SHADOWMESH claims. It exists because the most common way these systems fail in the
field is not a broken primitive but a *misunderstood guarantee* — assuming a property
holds against an adversary it was never designed to stop.

The central point: **SHADOWMESH has two different roots of trust for two different
properties, and they do not survive the same attacks.**

---

## 1. Key confidentiality — HARDWARE root, survives root

**Claim:** An adversary who roots the device, modifies the OS, or images storage cannot
extract the private keys that protect message content and identity.

**Why it holds:** Private keys are generated and held in the Android Keystore, backed by
the device's TEE or StrongBox secure element (`BiometricKeyManager`,
`HardwareAttestation`). They are created non-exportable with
`setUserAuthenticationRequired`. The key bytes never enter the app's address space — the
app asks the secure hardware to sign/decrypt, it does not hold the key. Rooting grants
control of the OS, not of the secure element; extracting a non-exportable Keystore key
requires a hardware attack on the TEE/HSM, not Magisk.

**Where it terminates:** the device's secure hardware. This is a genuine hardware root.

**Residual risk:**
- Physical hardware attacks on the secure element (glitching, decapping) — out of scope
  for the software threat model; assume a determined nation-state with the physical
  device and a lab can eventually win.
- Keys used *after* biometric/PIN unlock are exposed to a compromised OS for the duration
  of the authorized operation. Root does not export the key but can ask the key to work
  while the app is unlocked. Mitigation: short auth validity windows, panic wipe.

---

## 2. Data-at-rest (backup exfiltration) — addressed at config + hardware

**Claim:** App data cannot be silently exfiltrated via Android cloud backup or
device-to-device transfer.

**Why it holds:**
- `android:allowBackup="false"` plus `data_extraction_rules.xml` (API 31+) and
  `backup_rules.xml` (API ≤30) exclude all app data from both cloud backup and D2D
  transfer.
- Defense in depth: even if a backup were taken, the SQLCipher database and
  EncryptedSharedPreferences are encrypted under Keystore-held keys that are **never
  backed up** (see §1). A restored blob is undecryptable on the target device.

**Where it terminates:** manifest configuration (to prevent the copy) backed by the
hardware key root (to make any copy useless).

**Residual risk:**
- `commit()`-style clears and file deletion are **not** secure erasure. Flash
  wear-leveling can leave stale ciphertext that no app-level API can scrub. The mitigating
  factor is again §1: stale ciphertext without the Keystore key is inert.
- A backup taken on a device whose Keystore key is later compromised (see §1 residual)
  would become readable. Treat backup exclusion and key confidentiality as linked.
- **`peer_models` table — coarsened but not eliminated metadata.** The `PeerModelEntity`
  table stores derived abstractions from observed peer behaviour. Time-of-day contact
  profiles are coarsened to 6-hour buckets (not raw timestamps), which is the
  honestly-stated guarantee. Prior to v11, `observedChannelsMask` was a lifetime OR-
  accumulation of channel co-membership bitsets across all encounters — an adversary
  seizing the DB could read the full history of channel slots shared with each peer,
  regardless of how long ago. From v11 onwards this is replaced with a sliding window
  (`channelsMaskRecentWindow`, reset every `CHANNEL_MASK_WINDOW_ENCOUNTERS` encounters),
  so the DB reveals only recent co-membership. The window bound is configurable; the
  residual surface is that "recent" is still readable without the Keystore key by anyone
  who seizes the encrypted DB and later obtains or breaks the key.

---

## 3. Code/OS integrity attestation — SOFT then HARDWARE, does NOT fully survive root

This is the property most easily over-claimed. SHADOWMESH answers **"am I talking to a
genuine, unmodified SHADOWMESH app running on an untampered OS?"** in two tiers.

### Tier A — software self-checks (weak; defeated by root)
`ApkIntegrityVerifier` (signing-cert hash) and `PerProcessIntegrityChecker` (runtime
self-checks) run entirely on the device being checked. On a rooted device every input
they rely on — `PackageManager` output, `BuildConfig`, the probe results — is under the
attacker's control. Tools in wide use (Magisk Hide, Zygisk, Shamiko, Play Integrity Fix)
defeat exactly this class of check. **Treat Tier A as tamper-*evidence*, not
tamper-*proofing*: it raises the cost of casual repackaging, nothing more.**

### Tier B — hardware key attestation (strong; peer-verified, serverless)
`HardwareAttestation` + `AttestedPhysicalExchange` use the standard Android key
attestation API (API 26+). During `TRUST_PHYSICAL` bootstrap a peer issues a 32-byte
challenge; the attesting device generates a Keystore key with
`setAttestationChallenge(...)` and returns a certificate chain rooted in the OEM's
hardware attestation key. The verifying peer checks chain signatures, challenge freshness
(anti-replay), `verifiedBootState`, and the app-ID/signing fingerprint. This roots in the
secure hardware and is **not** defeated by Magisk/Zygisk/modified OS, because the TEE
signs the verdict and TEE firmware cannot be reflashed without physical access.

This is modeled on the GrapheneOS Auditor design and is **peer-to-peer** — no Google Play
Services and no server, matching SHADOWMESH's serverless/no-Google posture. (Play
Integrity is deliberately *not* used: it requires Play Services + a validating server, and
its "strong" tier is itself a less-strict wrapper over this same hardware API.)

**Where it terminates:** the OEM-provisioned hardware attestation key in the peer's secure
element — **provided that key has not been extracted**.

**Residual risk (the honest caveat):**
- **Leaked/stolen OEM keyboxes.** Real-world keybox leaks let an attacker hook the
  attestation request and produce a software-signed chain that embeds the challenge and
  presents a valid OEM root. The only defense is **revocation** — checking the leaked-key
  list (`KEYBOX_REVOCATION_URL`, cached in-APK and updated via signed gossip). A node with
  a non-revoked leaked keybox can pass attestation. This is a cat-and-mouse surface, not a
  closed door.
- **Device support.** Pre-API-26 devices and emulators have no attestation extension;
  `verifyAttestationChain` returns `NoHardwareSupport` and such peers can only reach lower
  trust tiers, never `TRUST_PHYSICAL` via hardware attestation.
- **Custom OS.** GrapheneOS/CalyxOS report `SELF_SIGNED` boot state; accepting them
  requires `allowCustomOS=true` and pinning the custom-OS verified-boot key. This is a
  deliberate trust decision, not an automatic pass.
- **Placeholder roots.** `GOOGLE_HARDWARE_ATTESTATION_ROOT_HEX` and
  `GRAPHENEOS_ATTESTATION_ROOT_HEX` are placeholders in the current code and MUST be
  replaced with the real DER public keys before any deployment, or root verification is
  not actually enforced.

---

## Summary table

| Property | Root of trust | Survives root? | Defeated by |
|---|---|---|---|
| Key confidentiality (§1) | TEE / StrongBox (hardware) | **Yes** | Physical TEE attack only |
| Backup exfiltration (§2) | Manifest config + hardware key | **Yes** (data inert without key) | Non-secure erasure leaves inert ciphertext |
| Integrity — Tier A (§3) | On-device software checks | **No** | Magisk / Zygisk / modified OS |
| Integrity — Tier B (§3) | OEM hardware attestation key | **Mostly** | Extracted/leaked keybox (mitigated by revocation) |

**One-line statement for users and reviewers:** *On a rooted device an attacker still
cannot read your messages or steal your keys (confidentiality is hardware-rooted), but the
weaker software integrity checks can be spoofed; the strong defense against a tampered peer
is hardware key attestation during physical bootstrap, which holds unless the peer's OEM
attestation key has been leaked and not yet revoked.*

---

## Implementation status (cross-references)

- §1 — `core/security/BiometricKeyManager.kt`, `core/attestation/HardwareAttestation.kt`
- §2 — `app/src/main/AndroidManifest.xml`, `app/src/main/res/xml/{data_extraction_rules,backup_rules}.xml`,
  `core/security/PanicWipeManager.kt`
- §3 Tier A — `core/security/ApkIntegrityVerifier.kt`, `core/nsc/PerProcessIntegrityChecker.kt`
- §3 Tier B — `core/attestation/HardwareAttestation.kt`, `core/attestation/AttestedPhysicalExchange.kt`,
  `core/attestation/nfc/NfcBootstrapCoordinator.kt`, `core/bootstrap/nfc/NfcHandshake.kt`

### Known open items

1. **Attestation roots are placeholders.** `GOOGLE_HARDWARE_ATTESTATION_ROOT_HEX` and
   `GRAPHENEOS_ATTESTATION_ROOT_HEX` in `HardwareAttestation.kt` must be replaced with
   the real DER-encoded SubjectPublicKeyInfo hex before any deployment. The code fails
   closed: `verifyRootCertificate()` returns `false` for placeholder values, and
   `isRootConfigured()` lets callers detect the unconfigured state. Shipping the placeholder
   does not silently accept any chain — but it does mean `TRUST_PHYSICAL_ATTESTED` is never
   issued, so bootstrap falls back to `TRUST_PHYSICAL_NFC` (NFC key exchange without hardware
   verification). See `BUILDING.md §3.3` for the extraction procedure.

2. **Attestation gating is enforced at the UI; the default policy is permissive.** The onboarding
   flow now gates: `OnboardingViewModel.attestationGatePassed` is derived from the achieved trust
   level (`!attestationRequired || level == TRUST_PHYSICAL_ATTESTED`), and when `requireAttestation
   = true` and the peer did not reach `TRUST_PHYSICAL_ATTESTED`, `PHYSICAL_EXCHANGE` step
   completion is blocked and an error is surfaced (both the initiator and responder paths). What
   remains is a *policy default*, not a missing gate: `NfcBootstrapCoordinator.requireAttestation`
   **defaults to `false`**, so unless a deployment sets it true a peer is still accepted at
   `TRUST_PHYSICAL_NFC` without hardware verification. And note the gate only has real teeth once
   open item 1 is closed — with placeholder roots, `TRUST_PHYSICAL_ATTESTED` can never be reached,
   so setting `requireAttestation = true` would block *all* bootstraps rather than admit attested
   ones.

3. **Keybox revocation: checking is wired into verification; offline distribution is not, and the
   check fails open.** `KeyboxRevocationCache.isRevoked(serial, pubKeyHash)` is now invoked from
   `HardwareAttestation.verifyAttestationChain` (cache built and `ensureLoaded()` in
   `ShadowMeshApplication.buildRevocationCache`), so a chain carrying a serial/key-hash on the
   list is rejected. Two residual gaps: (a) the cache refreshes over HTTP from `REVOCATION_URL`,
   which **requires internet and therefore contradicts the offline-first premise** — the
   *signed-gossip* distribution path (the offline-appropriate mechanism) is still unbuilt, so on an
   air-gapped mesh revocation freshness equals the bundled APK snapshot; and (b) `isRevoked`
   **fails open** — it returns `false` when there is no cache and the live fetch fails, so a leaked
   keybox not yet present in any reachable list still passes. This remains a cat-and-mouse surface,
   not a closed door.

### Resolved (this audit pass)

- **Root certificate verification is now enforced.** `AttestedPhysicalExchange.verifyPeerAttestation()`
  now calls `HardwareAttestation.verifyRootCertificate()` after a successful chain verification,
  selecting the correct root (Google vs GrapheneOS) by `verifiedBootState`. A mismatched root
  returns `AttestationFailed` and blocks the exchange. Previously the root constants existed but
  were never called.
- **`NfcBootstrapCoordinator` moved to `core/attestation`.** The coordinator was in `core/bootstrap`
  but imported five types from `core/attestation`, while `core/attestation` already depended on
  `core/bootstrap`. This created a build-breaking cycle. The coordinator now lives at
  `core/attestation/src/.../attestation/nfc/` where the dependency flow is correct.
- **NFC session key folds the verified peer node ID into HKDF salt.** (Resolved in previous audit.)
  An all-zero node ID is rejected by a guard.
- **Attestation app-ID binding and StrongBox detection** are extracted from the attestation extension.
  (Resolved in previous audit.)
- **BLE service/characteristic UUIDs** are fixed app-assigned values. (Resolved in previous audit.)
- **Documentation reconciled against source (this pass).** Three items previously listed as "not
  implemented" were found already built and were corrected here and in `README.md` rather than
  re-implemented: UI-layer attestation gating (`OnboardingViewModel.attestationGatePassed`),
  keybox-revocation *checking* wired into `verifyAttestationChain`, and `AppArtifactAcquirer`
  multi-session resume (DAO-gated, wired in production). The stale "single-session / TODO(resume)"
  KDoc on `AppArtifactAcquirer` was rewritten to match its implementation. Stale "known gap" docs
  are themselves a hazard in a security tool — a reviewer trusts them and mis-estimates the
  posture — so this reconciliation is treated as a fix, not housekeeping. The genuinely-open items
  (placeholder roots, offline/gossip revocation distribution, fail-open revocation, P2P artifact
  transport, circuit-STUN reply path, IPv6, real VRF) remain flagged above and in `README.md`.

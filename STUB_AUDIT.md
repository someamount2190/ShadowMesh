# SHADOWMESH — Stub & Unimplemented-Function Audit

Method: grep sweep across `*/src/main/*.kt` (133 files, ~34k LOC) for hard stubs
(`TODO()`, `NotImplementedError`, `throw … not implemented`,
`UnsupportedOperationException`), documented-unimplemented paths, no-op
implementations, placeholder returns, empty bodies, and crypto/security
shortcuts. Each finding below carries a `file:line` anchor and the *functional
consequence*, not just the marker. Severity reflects gap-vs-claim, not effort.

**Headline:** there are **no runtime-throwing stubs** (zero reachable `TODO()` /
`NotImplementedError`), and the crypto/security layer is clean. But three
findings are material because they sit under headline product claims and are
**not** in `README.md`/`THREAT_MODEL.md` open items. The most important: in this
build the app's wired message path is IP/DHT only — the "offline-first, no
internet" local-radio transports are implemented but never wired in.

---

## Tier 1 — contradicts a headline claim (not previously documented)

### S1. Local transports (BLE / WiFi Direct / LAN) are implemented but not wired into gossip
- **Evidence:** `buildGossipTransport()` returns only `DhtBackedGossipTransport(dhtEngine)`
  (`app/.../ShadowMeshApplication.kt:751`, constructed at `:218` via `:752`).
  `BleGattTransport`, `WiFiDirectTransport`, and `LanSubnetTransport` have **zero
  instantiations** anywhere in main source (only their own files + tests). The
  composition-root comment (`ShadowMeshApplication.kt:1212`) concedes BLE/WiFi
  Direct "are not yet wired as GossipTransport adapters … The DHT-backed
  implementations below provide full internet-transport functionality for beta."
- **Consequence:** the gossip layer — the thing that actually propagates
  fragments/posts — moves data over the Kademlia DHT (UDP/IP) only. The three
  no-infrastructure transports are effectively dead code in this build. The
  README identity ("No internet connection required", "Offline-first. Operates
  entirely without internet", "discover each other over Bluetooth LE, WiFi
  Direct, and LAN") is **not realized end-to-end here**. The DHT/UDP path itself
  is real and functional (see note), but it is an IP transport, not the BLE/WiFi
  mesh.
- **Note (rules out a worse case):** production wires the real
  `DatagramSocketUdpAdapter` (`ShadowMeshApplication.kt:189`); `NoOpUdpSocketAdapter`
  is only a construction-failure fallback (`:196`). So the DHT transport works —
  it just isn't the offline one.
- **Fix class:** integration/wiring + Android lifecycle (scan/advertise owned by
  the foreground service). Build-out, needs on-device verification.

### S2. DHT bootstrap seed list is empty
- **Evidence:** `SeedList.hardcoded()` and `SeedList.bootstrapEmpty()` both return
  `SeedList(emptyList())` (`core/mesh/.../dht/SeedList.kt:102,108`). Comment is
  honest: "Hardcoded List A — returns an EMPTY seed list in this build … Real
  deployments must supply seed entries."
- **Consequence:** compounds S1. The one wired transport (DHT) has no built-in
  peers to reach, and no local-radio transport is wired to discover a first peer
  without seeds. Out of the box a fresh install has no path into the mesh unless
  a deployment supplies a signed seed list (which itself needs an IP-reachable
  peer). "An empty seed list is safe: the node waits for a peer to connect" only
  holds once a local transport is wired (S1).
- **Fix class:** deployment config (ship a signed `seeds.json`) — but only
  *meaningful* after S1, otherwise discovery still has no offline path.

---

## Tier 2 — false guarantee in a consistency-critical subsystem (not previously documented)

### S3. NSC saga rollback — 5 of 6 opcodes are no-ops  — **FIXED (fail-loud) this pass**

> **Status:** the five handlers now emit `Diag.degraded` and then **throw** (`error(...)`),
> and both replay call-sites handle that correctly: the init-recovery path already kept the
> NSC halted on a failed replay, and the watchdog path was hardened this pass to escalate to
> `UNRECOVERABLE` (release lock, finalise `UNRECOVERABLE`, set halted, drain) instead of
> leaking the lock. The false `ROLLED_BACK` is gone. Real revert logic still requires the
> missing engine APIs (below) — that is the remaining build-out, but the dishonest part (a
> rollback that lied) is closed.
- **Evidence:** `registerRollbackHandlers()` in `ShadowMeshApplication.kt`. Only
  `CANCEL_FRAGMENT` (`:1063`) actually reverts (deletes the fragment). These five
  log `Diag.degraded` and **return normally**:
  `RESTORE_NETWORK_MODE` (:1075), `RESTORE_BEACON_MODE` (:1086),
  `RESTORE_PEER_SELECTION` (:1095), `RECLAIM_DHT_SLICE` (:1104),
  `REVERT_TIER_PROMOTION` (:1120). The handlers return normally **by design** so
  NSC "marks the checkpoint as rolled-back rather than halting."
- **Reachable, not test-only:** the opcodes are emitted by production sagas —
  `NetworkStateCoordinator.kt:57–62` serializes `ReclaimDhtSlice`,
  `RevertTierPromotion`, `RestoreNetworkMode`, `RestoreBeaconMode`,
  `RestorePeerSelection` as checkpoint rollback opcodes (and `:72–77` parse them
  back).
- **Engine APIs confirmed absent:** no `DhtEngine.reclaimSlice()`,
  `DhtEngine.setNodeTier()`, `GossipEngine.setNetworkMode()`, beacon, or
  peer-selection restore API exists (grep: none in main).
- **Consequence:** the NSC's whole purpose is consistent multi-step state
  transitions with rollback. For network-mode change, beacon mode, peer
  selection, DHT slice reassignment, and tier promotion, an aborted saga records
  the checkpoint as **cleanly rolled back while the live state stays changed**.
  The inconsistency is invisible except in the debug `Diag` log (release builds
  have `Diag.enabled == false`, so it is invisible there). This is a hollow
  rollback guarantee, and it is the most under-documented risk in the tree.
- **Fix class:** requires building the five engine APIs first, then real
  handlers. Each touches live mesh state → needs instrumented-test verification.

---

## Tier 3 — feature gaps already in the open-items docs (reconfirmed, all fail-closed/correct)

- **S4. Circuit STUN reply path** — `CircuitStunSenderImpl.sendStunBindingViaCircuit`
  returns `null` (fail-closed, no clear-text leak) because the one-way circuit has
  no exit-hop reply channel (`core/mesh/.../transport/CircuitStunSender.kt:34,48`).
  Privacy-preserving NAT discovery over onion is therefore inert; working STUN is
  `DIRECT_IP_ONLY` (leaks to operator) or mesh relay.
- **S5. NFC bootstrap fallbacks** — `BLE_PROXIMITY` and `QR_ONLY_DEGRADED`
  completion exchanges are unimplemented; only the NFC path issues a trust level
  (`core/bootstrap/.../nfc/NfcHandshake.kt:95,539`,
  `core/attestation/.../nfc/NfcBootstrapCoordinator.kt:55`). `FallbackMode` means
  "no trust established," so there is no degraded onboarding when NFC is
  unavailable.
- **S6. Artifact P2P transport + bootstrap stub** — `buildArtifactFetcher()` has no
  real BLE/WiFi-Direct transport behind it and `:bootstrap-app` does not exist, so
  self-distribution does not move bytes end-to-end (README open item 5).
- **S7. Attestation roots are placeholders** — `DEPLOYMENT_PLACEHOLDER_*`
  (`core/attestation/.../HardwareAttestation.kt:638,684`); fails closed, so
  `TRUST_PHYSICAL_ATTESTED` is never issued until real DER roots are set. Highest
  deployment blocker.
- **S8. Keybox revocation** — checking is wired (`verifyAttestationChain` →
  `isRevoked`) but distribution is HTTP-fetch (offline tension) and `isRevoked`
  fails open on no-cache. Signed-gossip distribution unbuilt.

---

## Ruled out (swept and found benign — not stubs)

- **No hard stubs:** zero `TODO()`, `NotImplementedError`,
  `throw … not implemented`, or `UnsupportedOperationException` in main source.
- **Empty `{}` bodies are legitimate:** Android callback overrides
  (`WiFiDirectTransport` `onSuccess/onFailure`, `BleGattTransport.onStartSuccess`)
  whose result is observed elsewhere, and SQLCipher's `preKey(){}` hook
  (`ShadowMeshDatabase.kt:287`). Not stubs.
- **`NoOp*` types are intentional fail-closed/test seams:** `NoOpUdpSocketAdapter`
  / `NoOpDhtTransport` (fallback-only in prod), `Diag.NoOpSink` (release no-op by
  design), `RollbackOpcode.NoOp` (a real opcode meaning "nothing to undo").
- **Crypto/security layer is clean:** no `fake`/`dummy`/`insecure`/`simplified`/
  hardcoded-secret shortcuts in `core/crypto` or `core/security`.
- **`peersOfType()`** — the grep hit is a comment describing a *fixed* bug
  (Issue #90); `allLocalPeers()` is now implemented
  (`ShadowMeshApplication.kt:882+`). Resolved, not open.
- **`VrfElection`** — not a stub; it is a real commit-reveal that is honestly
  documented as weaker than an RFC-9381 VRF (grindable). A primitive-strength
  choice, not an unimplemented function.

---

## Follow-up (engine-API investigation, this pass)

### S9. Anchor-handoff subsystem is unwired — both consistency-critical rollback opcodes are unreachable in production
- **Why this matters:** the previous pass flagged S3's `RECLAIM_DHT_SLICE` and
  `REVERT_TIER_PROMOTION` as the consistency-critical opcodes to implement real reverts for.
  Tracing them shows there is nothing to implement against yet:
  - `RECLAIM_DHT_SLICE` is emitted **only** by `buildAnchorHandoffTransition`
    (`core/mesh/anchor/AnchorHandoffManager.kt:211/221/234`). `AnchorHandoffManager` is **never
    constructed** in main (zero call sites), and `AnchorTransport` has **no concrete
    implementation** — it is a bare interface. So the handoff transition is never submitted, no
    `RECLAIM_DHT_SLICE` checkpoint is ever persisted, and the replay handler is unreachable in
    production. (The in-memory failure path already reverts correctly: each handoff checkpoint
    carries `rollback = { transport.revertSliceTransfer(...) }`.)
  - `REVERT_TIER_PROMOTION` has **no production emitter** (only test code constructs it), and
    `NodeTierManager` is **stateless** — there is no node→tier store, so a `DhtEngine.setNodeTier()`
    would have nothing to write.
- **Consequence:** the entire anchor-handoff path — a `P1_DATA_INTEGRITY` feature whose stated
  exit gate is "zero data loss" — is dead code in this build (no manager, no transport). This is
  a larger gap than the rollback stubs themselves and belongs alongside S1 (unwired transports).
- **Correct fix (deferred, correctly):** do **not** add `DhtEngine.reclaimSlice()/setNodeTier()`
  — wrong layer / no backing state. When anchor handoff is wired (construct `AnchorHandoffManager`
  + a concrete `AnchorTransport`), route the `RECLAIM_DHT_SLICE` replay handler to the same
  `AnchorTransport.revertSliceTransfer(from, to)` the in-memory lambda uses. For tier, add a tier
  store + emitter first. Handler comments in `ShadowMeshApplication` were corrected this pass to
  say exactly this (previously they pointed at a non-existent `DhtEngine` API — a misleading
  breadcrumb).
- **Until then:** fail-loud (S3) is the correct terminal behaviour; the throw is never reached in
  production because nothing emits the opcodes.
- **Design doc (this pass):** `docs/DESIGN_anchor_handoff_wiring.md` pins the ownership-model
  decision and maps each `AnchorTransport` method to existing primitives vs. new protocol work.
  Implementation is blocked on that decision, not on effort.

---



1. **S3 — DONE (this pass).** The five handlers now fail loud (throw → NSC stays halted on
   init replay / escalates to UNRECOVERABLE on watchdog) instead of recording a false
   `ROLLED_BACK`. Real revert logic still pending the missing engine APIs
   (`DhtEngine.reclaimSlice()` / `setNodeTier()`, `GossipEngine.setNetworkMode()`, beacon,
   peer-selection) — those are state-mutating and need on-device test verification.
2. **S1 + S2 — partially addressed (docs).** The offline-first claim is now correctly scoped
   in `README.md` (Transport status note). The actual wiring (S1) and a real seed list (S2)
   remain build-outs needing a radio / real infrastructure, so they are flagged, not faked.
3. **S7** — deployment blocker for the attestation tier (external keys).
4. **S4–S6, S8** — build-outs; correct as fail-closed today.

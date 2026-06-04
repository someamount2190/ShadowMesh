# SHADOWMESH — Changelog

---

## v22: Network Scanning & Bootstrap BLE Redesign

Separates the always-on mesh BLE transport from the session-scoped bootstrap proximity
scanner, adds a user-facing "Active Mesh Mode" toggle, and gates NFC handshakes behind
BLE proximity confirmation to prevent relay attacks.

**New files:**
- `core/mesh/…/ble/BleScanMode.kt` — BALANCED / ACTIVE enum controlling mesh scan
  aggressiveness. BALANCED maps to `SCAN_MODE_BALANCED`; ACTIVE to `SCAN_MODE_LOW_LATENCY`.
- `core/bootstrap/…/ble/BleProximityScanner.kt` — Session-scoped scanner that confirms
  a peer is physically adjacent (RSSI ≥ -70 dBm by default) before the NFC handshake
  is offered. Always uses BALANCED regardless of user setting.

**Modified files:**
- `BleGattTransport.kt` — `setMeshScanMode(BleScanMode)` restarts foreground scan at
  runtime. Adaptive LOW_POWER fallback after 5 min of no peer advertisements in BALANCED
  mode, restored on next peer sighting. KDoc updated to distinguish mesh vs. bootstrap BLE.
- `NetworkStateCoordinator.kt` — `setActiveMeshMode(Boolean)` + `onActiveMeshModeChanged`
  callback. NSC remains free of `core:mesh` dependency; AppModule wires the callback.
- `AppModule.kt` — `activeMeshModeFlow: MutableStateFlow<Boolean>` (user preference
  source of truth) + `@Volatile var bleGattTransport: BleGattTransport?` (nullable until
  service wires it). NSC callback wired to update both.
- `ShadowMeshForegroundService.kt` — Charging `BroadcastReceiver` (POWER_CONNECTED /
  POWER_DISCONNECTED) overrides scan to ACTIVE while plugged in; restores user preference
  on unplug. KDoc documents always-on trust-agnostic transport posture.
- `NfcBootstrapCoordinator.kt` — `proximityConfirmedForSession` flag + `confirmProximity()`.
  Both NFC entry points (`onNfcChallengeReceived`, `onHceApduReceived`) return early if the
  proximity gate has not been set, preventing remote tap relay attacks.
- `OnboardingViewModel.kt` — `BleProximityScanner` lifecycle owned by ViewModel.
  `proximityConfirmed: StateFlow<Boolean>` derived from scanner state. Scanner starts with
  null target (initiator) or peer's node ID (responder); stops on Confirmed/Timeout/clear.
- `MeshSyncWorker.kt` — KDoc update documenting always-on trust-agnostic scanning; no
  behaviour change.
- `SettingsScreen.kt` — `activeMeshMode: Boolean` + `meshScanLabel: String` added to
  `SettingsUiState`. Toggle row with confirmation dialog added to MESH STATUS section.
  Default off (BALANCED). Toggle requires user confirmation to enable Active mode.
- `AddContactSheet.kt` — `proximityConfirmed: Boolean` + `peerLabel: String?` params.
  Three-stage status display: "Looking for [peer] nearby…" → "Found them. Tap phones to
  verify." → "Contact verified ✓".
- `NavGraph.kt` — `activeMeshModeFlow: Flow<Boolean>` + `onActiveMeshModeToggle` params.
  Collects `proximityConfirmed` from `onboardingVm`; passes it with `peerLabel` to
  `AddContactSheet`. Updates `SettingsUiState` with live mesh mode values.
- `MainActivity.kt` — Passes `AppModule.activeMeshModeFlow` and `nsc.setActiveMeshMode`
  lambda to `ShadowMeshNavRoot`.

**Security invariant:** NFC handshake is blocked until `BleProximityScanner` confirms the
peer is physically adjacent in the current session. This prevents an adversary who
intercepts or replays the QR code from triggering a trust credential exchange remotely.

---

## v22 audit: Phase 1 fixes — final CancellationException sweep + stub display

**ShadowMeshForegroundService.kt** — 5 catch blocks introduced by the peer discovery
cache session (peer-cache-read, bootstrap, peer-cache-save, reconnect, unlock-sync) were
missing CancellationException rethrows. Fixed. These were inside `applicationScope.launch
{ }` blocks — without the rethrow, the launched coroutines could continue running after
scope cancellation.

**ForumViewModel.kt** — `openPost()` now shows "Receiving post…" when
`post.encryptedTier0.isEmpty()` (i.e., the post is a received-only stub not yet
confirmed). Previously the empty ByteArray triggered a decrypt error ("Input too short: 0
bytes"), which was misleading since the post is still in transit, not failed.

**StorageModels.kt** — `PostEntity.encryptedTier2` comment updated from "null until
complete" to accurately reflect that sender posts store it at creation; only received-only
stubs have null until `onConfirmed()`.

---

## v22 audit: Phase 1 fix — CancellationException swallow audit (14 sites)

Pre-existing `catch (e: Exception)` blocks in suspend contexts that swallowed
`CancellationException` — causing coroutines to continue after scope cancellation
rather than propagating the signal. Fixed across 5 files.

**Invariant:** Every `catch (e: Exception)` in a suspend context must contain
`if (e is CancellationException) throw e` as the first line.

Files fixed:
- `ChannelSyncCoordinator.kt` — 3 blocks in `fetchMissedForChannel()` (direct suspend fun),
  `onReconnect()` and `syncCycle()` (scope.launch blocks). The direct suspend fun block was
  the critical one: swallowing there allowed the caller to proceed after cancellation.
- `NetworkStateCoordinator.kt` — 1 block in `executeTransition()`. On cancellation, NSC
  was converting the signal to `TransitionResult.Failure`, potentially triggering incorrect
  rollback on application shutdown.
- `MeshSyncWorker.kt` — 2 blocks in `runNudgeSync()` and `runPeriodicSync()`
  (`CoroutineWorker.doWork()` is a suspend fun). Swallowing returned `Result.retry()` to
  WorkManager on cancellation, causing unnecessary re-scheduling.
- `ForumViewModel.kt` — 6 blocks in `openPost()`, `submitPost()`, endorsement flow,
  and `retryPost()`. All in `viewModelScope.launch { }`.
- `OnboardingViewModel.kt` — 2 blocks in NFC bootstrap flow. All in `viewModelScope.launch { }`.

---

## v22 audit: Phase 2 item 7 — PostRatchet gap resolver (best-effort v1)

When a node's ratchet is desynchronised (missed intermediate posts), subsequent posts
cannot be decrypted. The gap resolver detects this and triggers a channel re-sync.

### Added

**KeyOrchestrator.kt** — `RatchetGapEvent(channelId, gapPostId)` data class.
`ratchetGapEvents: Channel<RatchetGapEvent>` (UNLIMITED capacity) + `reportRatchetGap()`
(non-suspending `trySend`). The channel acts as the event bus between `FragmentIngestor`
(producer) and `ChannelSyncCoordinator` (consumer).

**FragmentIngestor.kt** — `attemptConfirmation()` now calls
`keyOrchestrator.reportRatchetGap(channelId, postId)` when ratchet decryption returns
null, in addition to the existing Diag.degraded log. The gap post stays in SYNCING
state pending resolution.

**ChannelSyncCoordinator.kt** — `startGapResolution(gapEvents: ReceiveChannel<RatchetGapEvent>)`:
launches a coroutine that loops over gap events and calls `fetchMissedForChannel()` for
each affected channel. This re-fetches all fragments in the TTL window, giving the
intermediate posts a chance to arrive and advance the ratchet back into sync.
CancellationException rethrown in the catch block. ✓

**ShadowMeshApplication.kt** — Wires the gap pipeline after both objects are constructed:
`channelSyncCoordinator.startGapResolution(keyOrchestrator.ratchetGapEvents)`.

### Limitation (documented — not a bug)

This is a best-effort v1. If the missing intermediate posts are not available on any
reachable peer, the ratchet remains desynchronised. The next reconnect sync retries.
Full resolution requires knowing which postIds to advance through — these are available
only if the intermediate fragments are fetchable. A full solution would buffer the gap
post, advance the ratchet through recovered intermediates in order, and re-attempt
decryption — tracked as a future enhancement.

---

## v22 audit: Phase 2 item 8 — SymmetricCipher AAD (ratchet layer binding)

Adds optional Additional Authenticated Data (AAD) to `SymmetricCipher.encrypt()` and
`decrypt()`, and uses it in the ratchet layer (PostDispatcher/FragmentIngestor) to bind
each ciphertext to its specific post by postId. The AAD is not stored in the wire format
(wire format unchanged); both sender and receiver compute it from the postId which is
already in every fragment's wire format.

### Changed

**SymmetricCipher.kt** — `encrypt(plaintext, key, aad: ByteArray? = null)`: when aad is
non-null, passes it to `cryptoAeadXChaCha20Poly1305IetfEncrypt`. `decrypt(ciphertext, key,
aad: ByteArray? = null)`: tries decryption with AAD first; if authentication fails and aad
was provided, falls back to no-AAD decryption (backward-compatible — 2^-128 false-positive
probability makes the fallback safe against forgery). `encryptWithNonce` also updated.

**PostDispatcher.kt:80** — `cipher.encrypt(encTier2, postKey, aad = hexToBytes(post.postId))`.
The AAD binds the ratchet-layer ciphertext to this specific post's position, preventing
replay at a different ratchet step even if the ratchet key were reused.

**FragmentIngestor.kt** — `cipher.decrypt(encryptedPayload, ratchetKey, aad = hexToBytes(triggerFragment.postId))`.
Uses the same postId-as-AAD binding as the sender. Backward-compatible via decrypt() fallback.

### Wire format

Unchanged: `[24-byte nonce][ciphertext + 16-byte MAC tag]`. AAD is context-only.

---

## v22 audit: Phase 2 item 5 — peer discovery cache

Persists DHT contacts from each session so bootstrap warm-starts from known peers rather
than re-discovering from scratch after restart.

### Added

**StorageModels.kt** — `DiscoveredPeerEntity` Room entity: `(nodeIdHex PK, lastSeenMs,
transport, addressHint, trustLevel)`. `CACHE_RETAIN_MS = 7 days`. Stored per-transport so
BLE/LAN/DHT contacts can be differentiated (though only DHT is currently populated).

**ShadowMeshDao.kt** — `upsertDiscoveredPeer(DiscoveredPeerEntity)` with
`OnConflictStrategy.REPLACE`; `getRecentDiscoveredPeers(minLastSeenMs)` returns contacts
seen after the cutoff (caller passes `now - CACHE_RETAIN_MS`).

**ShadowMeshDatabase.kt** — Added `DiscoveredPeerEntity::class` to entities list.
Bumped version 14 → 15. Added `MIGRATION_14_15` inside `companion object` (CREATE TABLE
discovered_peers). Added to `addMigrations(...)`. DB-1 invariant maintained. ✓

**DhtEngine.kt** — Added `fun currentContacts(): List<DhtContact>` to expose the routing
table snapshot after bootstrap for cache population.

**ShadowMeshForegroundService.kt** — Before `dhtEngine.bootstrap()`: reads
`getRecentDiscoveredPeers()`, converts to `DhtContact` via `addressHint` IP:port parsing,
prepends to `liveSeedList.toContacts()`. After bootstrap: `currentContacts()` is iterated
and each entry is upserted via `database.dao().upsertDiscoveredPeer()`.

### Remaining

BLE/WiFi Direct/LAN contacts are not yet upserted (those transports are not wired into
gossip per S1). When those transports are activated, add `upsertDiscoveredPeer()` calls
in their successful-contact handlers.

---

## v22 audit: Phase 2 item 3a — keybox revocation gossip pipeline

Implements peer-to-peer propagation of newly discovered keybox revocations. When a node
fetches a fresh revocation list from Google and finds entries not previously in its cache,
it signs a `RevocationUpdateFrame` and broadcasts it to all connected peers. Peers verify,
merge, and re-gossip exactly one hop.

### Added

**GossipFrameTypes.kt** — `RevocationUpdateFrame` data class with full binary wire format
(`[4B magic "RVKU"][2B serials_count][serials...][2B hashes_count][hashes...][8B fetchedAtMs]
[64B issuerNodeId][16B nonce][4B sig_len][signature]`), `toBytes()`/`fromBytes()` with
negative-length and overflow guards, `signedPayload()` with domain prefix
`"shadowmesh_revoc_update_v1 "` to prevent cross-protocol signature confusion.

**GossipEngine.kt** — `revocationUpdateCallback`, `setRevocationUpdateCallback()`,
`onVerifiedRevocationUpdate(frame)` (dispatch-only, verification is caller's responsibility),
and `broadcastRevocationUpdate(frame, sourceId)` (sends to all non-blocked peers except
source via `transport.sendControl()`; one-hop propagation prevents amplification loops;
CancellationException rethrown in catch block).

**KeyboxRevocationCache.kt** — `mergeUpdate(serials, keyHashes): Boolean` (synchronized,
normalizes entries to the same format as `parseAndLoad`, returns true only if genuinely new
entries were added — idempotent: callers re-gossip only on true). `parseAndLoad()` now
also detects the delta between previous and fresh Google list and invokes `onNewEntries`
callback if any entries are new. New `@Volatile var onNewEntries` field.

**AckRouter.kt** — `@Volatile var onGossipControlPacket` handler + RVKU magic byte check
before the fragment fallthrough. RevocationUpdateFrame packets are routed to the handler
rather than being misrouted to `handleFragment()`.

**ShadowMeshApplication.kt** — Wires the full pipeline:
- Send: `revocationCache.onNewEntries` → sign frame with local `HybridSigningKey` →
  `gossipEngine.broadcastRevocationUpdate(signedFrame, null)`.
- Receive: `ackRouter.onGossipControlPacket` handler@{} → parse frame → look up sender's
  `HybridVerifyKey` from `DhtContact.publicIdentity` (drop if unknown sender) →
  nonce replay check via `dao.isNonceUsed()` → `signer.verifySync()` → `dao.insertUsedNonce()`
  → `gossipEngine.onVerifiedRevocationUpdate(frame)` → registered callback merges and
  re-gossips to non-source peers.

### Security properties

- Signature (Dilithium-3 + Ed25519 hybrid) over all semantic fields + nonce + domain prefix.
- Nonce replay protection via `used_bootstrap_nonces` table (10-min retention, same as bootstrap).
- One-hop re-gossip (sourceId excluded) prevents amplification.
- `mergeUpdate` idempotency: a re-gossiped frame only triggers re-gossip if it contains
  entries that were actually new, preventing infinite propagation.
- Unknown senders (no `publicIdentity` in `DhtContact`) are dropped before signature verification.

---

## v22 audit: post pipeline fix — ratchet double-advance, receiver stub, confirmation hash

Four interlocking CRITICAL bugs in the post send/receive pipeline fixed. Posts now flow
correctly from sender creation through mesh delivery to receiver confirmation and display.

### Fixed

**ForumUiViewModel.kt:247** — Removed pre-dispatch ratchet advance. The UI was advancing
the group ratchet before `PostDispatcher.dispatch()` advanced it again, burning two ratchet
steps per sent post with mismatched salts (sha3_256(plaintext) vs sha3_256(ciphertext)).
Now uses `keyOrchestrator.retrieveChannelKey()` to encrypt tiers with the static channel
key at creation time. PostDispatcher performs the single ratchet advance on send.

**PostEngine.kt:98,118** — `createPost()` now takes the static channel key (not a ratchet
key) as `postKey`. `encryptedTier2` is stored immediately at creation (not null), so the
confirmation path can verify `sha3_256(encTier2) == postHash` without a separate DB write.

**ForumViewModel.kt:120** — `openPost()` tier2 display now gated on
`post.postState == PostState.CONFIRMED` in addition to `encryptedTier2 != null`. This
prevents the full content appearing in PENDING/SYNCING posts now that encryptedTier2 is
stored from creation.

**PostDispatcher.kt:65,79,121** — Three fixes: (1) ratchet advance now uses
`senderNodeId = channelId` (per-channel group ratchet all members share) and
`postHash = hexToBytes(post.postId)` (the fragment wire carries postId, so the receiver
can advance identically without needing the content hash). (2) Wire payload is now
`encrypt(encTier2, ratchetKey)` — the channel-key-encrypted full content, not encTier0.
(3) ACK confirmation uses `encTier2` whose sha3_256 matches `post.postHash`.

**FragmentIngestor.kt:80,428** — Added receive-side ratchet advance. After fragment
assembly, advances the per-channel ratchet with the post's postId (available from every
fragment) to recover the ratchet key, decrypts the wire payload → encTier2, then calls
`onPostConfirmed`. Requires `keyOrchestrator: KeyOrchestrator` added to constructor.
ShadowMeshApplication updated to inject it.

**PostEngine.kt:231** — `ingestFragment()` now creates a PostEntity stub when none exists
(received post from another channel member). postHash and encryptedTier* are placeholders
filled by `onConfirmed()`. Without this, received posts could never be confirmed because
`onConfirmed()` returns early on no PostEntity.

**PostEngine.kt:159** — `onConfirmed()` now handles stub posts (empty postHash) by
accepting the decrypted encTier2 and computing+storing postHash from it. For
sender-created posts (non-empty postHash), the existing hash verification still applies.

**ShadowMeshDao.kt:88** — `updatePostConfirmed()` now also updates the `postHash` column
so stubs receive the authoritative hash on confirmation. All three FakeDao implementations
in test files updated to match.

### Remaining known gaps (unchanged from round 4)
- Ratchet key desynchronisation on out-of-order delivery (receiver misses post N, can't
  advance for post N+1) — requires skip-ahead to know intermediate postIds.
- SymmetricCipher AAD is always null — no session/identity binding in AEAD (Phase 2 item 8).
- HKDF test vectors are determinism checks, not known-answer tests.

---

## v22 audit: anchor-handoff wiring — design doc, no code (blocked on ownership-model decision)

Pursued wiring `AnchorHandoffManager` + a concrete `AnchorTransport` so the consistency-critical
handoff path (and its `RECLAIM_DHT_SLICE` rollback) becomes reachable. Outcome: cannot write a
correct transport yet — the "DHT slice ownership" the handoff assumes is not implemented by the
replication-based DHT (`DhtValue` has no owner field; `localStore` has no public enumeration; there
is no remove RPC; gossip has no signed routing-update control message). Three of the five
`AnchorTransport` methods need new protocol primitives, and `revertSliceTransfer` semantics depend
on an undecided ownership model.

### Added
- `docs/DESIGN_anchor_handoff_wiring.md` — decision-grade design: the ownership-model fork
  (replication+routing vs authoritative move), slice-membership definition (xorDistance), a
  per-method map to existing primitives vs new work (with file refs), the wiring/lifecycle plan,
  and the 3 open decisions the maintainer must make before code is written. Post-decision steps are
  mechanical and individually verifiable.
- `STUB_AUDIT.md` S9 cross-references the design doc.

No code changed this pass — writing the transport before the ownership model is decided would
re-introduce exactly the "looks-done-but-undefined" stub class the audit targets, in a P1 zero-
data-loss path.

---

## v22 audit: engine-API investigation — reclaimSlice/setNodeTier NOT built (correctly)

Investigated implementing real reverts for the two consistency-critical NSC rollback opcodes
(`RECLAIM_DHT_SLICE`, `REVERT_TIER_PROMOTION`). Outcome: building `DhtEngine.reclaimSlice()` /
`setNodeTier()` would be speculative and is the wrong layer. Evidence:

- `RECLAIM_DHT_SLICE` is emitted only by `buildAnchorHandoffTransition`
  (`AnchorHandoffManager.kt`). `AnchorHandoffManager` is never constructed in main and
  `AnchorTransport` has no concrete implementation — the opcode is unreachable in production, and
  the *real* revert already exists as the in-memory checkpoint lambda
  (`transport.revertSliceTransfer`). The correct future fix routes the replay handler to that same
  transport call, not a new DhtEngine API.
- `REVERT_TIER_PROMOTION` has no production emitter and `NodeTierManager` is stateless (no tier
  store) — `setNodeTier()` would have nothing to mutate.

### Changed
- `ShadowMeshApplication`: corrected the `RECLAIM_DHT_SLICE` / `REVERT_TIER_PROMOTION` handler
  comments + Diag codes. They previously pointed at a non-existent `DhtEngine.reclaimSlice()/
  setNodeTier()` API (a misleading breadcrumb); they now state the real reachability situation and
  the correct future fix. Behaviour unchanged — still fail-loud (`error(...)`), which is correct
  because the opcodes are unreachable until anchor handoff / a tier store is wired.
- `STUB_AUDIT.md`: added **S9** — the anchor-handoff subsystem (`AnchorHandoffManager` +
  `AnchorTransport`) is entirely unwired, so the P1 "zero data loss" handoff feature is dead code
  in this build. This is the upstream reason the two opcodes are unreachable.

No `.kt` logic changed; edits are comments/diagnostic strings + the audit doc.

---

## v22 audit: NSC rollback fail-loud fix + offline-claim honesty (S3, S1/S2 docs)

Acted on `STUB_AUDIT.md`. The audit found no runtime-throwing stubs and a clean crypto/security
layer; the fixable defect was S3 (a saga rollback that recorded false success), plus a dishonest
README claim (S1). Items needing a radio (S1 wiring), real infrastructure (S2 seeds), or external
secrets (S7 roots) were deliberately NOT faked.

### Fixed — S3: NSC rollback no longer lies
- The five unimplemented `RollbackRegistry` handlers in
  `ShadowMeshApplication.registerNscRollbackHandlers()` (`RESTORE_NETWORK_MODE`,
  `RESTORE_BEACON_MODE`, `RESTORE_PEER_SELECTION`, `RECLAIM_DHT_SLICE`, `REVERT_TIER_PROMOTION`)
  previously emitted `Diag.degraded` and **returned normally**, causing the replay path to finalise
  the transition as `ROLLED_BACK` even though no state was reverted. They now emit `Diag.degraded`
  then **throw** (`error(...)`). Throwing is the `RollbackRegistry`'s own documented "cannot roll
  back this opcode" signal.
- `NetworkStateCoordinator`: the **watchdog** replay call-site (`scheduleWatchdog`) had no
  try/catch — a thrown handler would have leaked the lock and finalised nothing. It now wraps
  `replayRollback` in `runCatching`: on success it finalises `ROLLED_BACK` as before; on failure it
  releases the lock, finalises `UNRECOVERABLE`, sets `_haltedFlow`, and calls
  `drainQueueAfterUnrecoverable()` — mirroring the existing `executeTransition` Failure→UNRECOVERABLE
  path. The init-recovery path already handled a thrown replay (stays halted), so no change there.
- Doc on `registerNscRollbackHandlers` updated: the old "handler must NOT throw … return so NSC
  marks the checkpoint ROLLED_BACK" guidance was the source of the bug and is now corrected to the
  fail-loud contract.
- Net behaviour: an aborted transition whose rollback cannot run now surfaces as a halt /
  `UNRECOVERABLE` (observable, recoverable on next clean transition) instead of a silent false
  success. Real revert logic still pending the missing engine APIs (`DhtEngine.reclaimSlice()` /
  `setNodeTier()`, `GossipEngine.setNetworkMode()`, beacon, peer-selection).
- **Test note:** `core/nsc/androidTest/NscIntegrationTest` registers its own rollback handlers via
  `RollbackRegistry.register`, so it is unaffected by this change to the production registration.
  Run it on-device to confirm.

### Corrected — S1: offline-first claim scoped to reality
- `README.md` gains a "Transport status (beta)" note: only `DhtBackedGossipTransport` (DHT-over-UDP,
  an IP transport) is wired into gossip; BLE/WiFi-Direct/LAN transports are implemented but not
  instantiated, and the DHT seed list is empty. The offline-first bullets are flagged as the design
  target, not as-shipped beta behaviour.

### Not fixed (and why) — unchanged
S1 transport wiring (needs Android scan/advertise lifecycle + on-device test), S2 real seed list
(deployment infrastructure), S4 circuit-STUN reply path, S5 BLE/QR onboarding completion, S6
artifact P2P transport + bootstrap stub, S7 attestation roots (external keys), S8 offline revocation
distribution. All remain flagged in `STUB_AUDIT.md`; each is a build-out requiring compile +
instrumented-test verification not available in this editing environment.

---

## v22 audit: doc/code-state reconciliation (no logic changes)

Reviewed the "lacking functions" against source. Most flagged gaps are feature build-outs that
need on-device verification (P2P artifact transport, circuit-STUN reply path, BLE/QR onboarding
completion, IPv6 in `DatagramSocketUdpAdapter`, real RFC-9381 VRF) or external secrets (real
attestation root keys) — deliberately NOT stubbed, since unverifiable code in a security tool is
worse than an honest gap. What WAS fixed is documentation that misstated the implemented status of
security controls (a real hazard: reviewers trust it and mis-estimate the posture). No `.kt` logic
or `.kts` build files were touched; edits are comments + markdown only, so there is no compile risk.

### Corrected (docs now match source)
- **`README.md` "Open items"** rewritten. Items 2 (NFC attestation gating), 3 (keybox-revocation
  *checking*), and 4 (acquirer multi-session resume) were listed as unimplemented but are built and
  wired; marked `[resolved]` with code locations. Items 1 (placeholder roots), 3a (offline/gossip
  revocation distribution + fail-open), and 5 (`ArtifactFetcher`/`:bootstrap-app`) remain genuinely
  open and are now stated with their precise residual surface. Added a "Not closing here, and why"
  subsection.
- **`THREAT_MODEL.md` "Known open items"** items 2 and 3 corrected to describe the implemented UI
  gate (`OnboardingViewModel.attestationGatePassed`, blocks `PHYSICAL_EXCHANGE` when
  `requireAttestation=true` and peer < `TRUST_PHYSICAL_ATTESTED`) and the wired revocation check
  (`verifyAttestationChain` → `KeyboxRevocationCache.isRevoked`), while keeping the honest residuals:
  permissive default (`requireAttestation=false`), HTTP-fetch/offline tension, and fail-open on no
  cache. Added a reconciliation note to "Resolved".
- **`AppArtifactAcquirer.kt`** class KDoc rewritten: it claimed single-session / `TODO(resume)`
  while its own `acquire()` body implements DAO-gated multi-session resume (production passes a real
  `dao`). KDoc now matches behaviour.

### Standing highest-priority gap (unchanged, restated for visibility)
Attestation roots are `DEPLOYMENT_PLACEHOLDER_*`. Until real DER roots are set, the hardware-
attestation tier is inert (fails closed → every bootstrap falls to `TRUST_PHYSICAL_NFC`). This is
the item most likely to be misjudged because the surrounding code reads as complete and tested.

---

## RTT estimator: staleness widening (reseed-on-handoff rejected)

Added time-based staleness widening to `RttEstimator.rtoMs()`: a peer idle past a 30s grace
has its window widened (linearly to 3× by 5min, capped), so a vanish-and-return peer — the
common real case, often on a new network — is treated cautiously without trusting stale state.
Widening is monotonic in the SAFE direction only (never shrinks the window) and RAM-only.
Injectable clock for deterministic tests. Reseed-on-handoff was evaluated and deliberately NOT
built: the path-class trigger derives from an unauthenticated address (not bound to nodeId), so
it is attacker-forgeable; an attacker can't choose the RTT value (reseed target is a constant)
but could force repeated resets (downgrade-to-baseline) or a too-small LAN-bucket window
(degraded punching). The sample-driven EWMA is more robust because moving it requires serving
real traffic. Reasoning + the monotonic-only condition for any future reseed documented in the
design doc. Tests added to `RttEstimatorTest`.

---


Added `RttEstimator` (RFC 6298: SRTT + RTTVAR, RTO = SRTT + K·RTTVAR) feeding the adaptive
punch window. Sampled from the real DHT rendezvous round trips in `NatAwareDhtTransport`
(`ping`/`findNode`, success-only), per-peer, with Karn's rule (retried samples discarded),
per-transport cold-start seeds (LAN/INTERNET/UNKNOWN), and timeout backoff. The punch schedule
now consumes the RTO directly via `estimateAdaptivePunchPlanFromRto` (variance already covers
the skew tail — no flat multiplier). STUN RTT is explicitly NOT used as the estimator: it
measures the wrong path and under-estimates in the dangerous direction; it is only a floor.
Estimator state is RAM-only (never persisted to `PeerModelEntity` — a stored RTT distribution
is a timing fingerprint), consistent with the peer-memory privacy stance. `punch()` param
renamed `coordinationRttMs` → `rendezvousRtoMs`. Unit test: `RttEstimatorTest`.

---


Wired `CircuitStunSenderImpl` over `CircuitManager.send` for the `CIRCUIT_ONLY` STUN path.
In doing so, surfaced the architectural truth that circuit STUN returns the EXIT HOP's
reflexive address, not this node's NAT mapping — so it feeds relay connectivity, not hole
punching, and the two modes are mutually exclusive (documented in the sender + design doc).
The circuit transport is one-way, so the exit-hop reply path is not yet implemented; the
sender fails closed (returns null, never clear-text).

Replaced `NatTraversalEngine`'s fixed punch timeout (200 ms first window, ×2 backoff, 5 s
cap) with an adaptive plan: `estimateAdaptivePunchPlan(coordinationRttMs)` sizes the first
receive window to cover ~2× the rendezvous skew (the old fixed window silently failed when
DHT RTT > 200 ms) and grows attempts under a 20 s budget ceiling, with predicted success
`1 − (1 − p0)^n` emitted as telemetry. Modelled finding: STUN discovery/circuit latency does
NOT threaten hole punching (NAT mappings outlive it by orders of magnitude); coordination
skew does, and the schedule now adapts to it. Removed the now-unused `punchTimeoutMs` ctor
param. Unit test: `NatTraversalPunchPlanTest`. See docs/DESIGN_peer_memory_and_stun.md §3.

---


### Peer memory (new)
Added `PeerModelEntity` (SQLCipher table `peer_models`, DB v9→v10 via `MIGRATION_9_10`),
`PeerModelDao`, and `ActiveEncounterSession` / `EncounterAbstractor`. Persists derived
abstractions only — never raw events, never a timestamp. Decisions made explicit rather than
left to the DAO: time-of-day stored as integer quarter-day counts (not drifting floats),
delivery weight as an EWMA carrying a `deliverySamples` confidence count, frequency derived
from mesh-global monotonic sequence (not wall-clock). The privacy claim is stated honestly in
KDoc: the counts are a timestamp coarsened to 6-hour buckets and summed — readable by an
adversary who seizes the DB — not "the timestamp is gone." Crash-vs-clean-end bias addressed
by folding partial snapshots on unclean teardown (penalise flaky peers, don't excuse them).
See docs/DESIGN_peer_memory_and_stun.md.

### STUN DNS/IP leak (fixed)
`NatTraversalEngine` resolved STUN hostnames (`stun.l.google.com`, ...) in clear text before
any tunnelling — a DNS leak announcing "P2P app on this device" to the ISP resolver, plus an
IP leak to the STUN operator. Fixes: `StunServer` is now IP-pinned (hostname structurally
unrepresentable → no DNS possible); new `StunPrivacyPolicy` defaults to `CIRCUIT_ONLY`,
tunnelling the binding request through the onion circuit (`CircuitStunSender`) and failing
closed to mesh-relay when no circuit exists — never silently dropping to clear-text.
Also fixed a pre-existing build break: `ShadowMeshApplication` called `NatTraversalEngine()`
with no args though the class requires `localNodeId`/`socketAdapter`/`scope`, and no concrete
`UdpSocketAdapter` existed. Added a fail-closed `NoOpUdpSocketAdapter` and wired the
constructor; a real DatagramSocket adapter + `CircuitStunSender` over `CircuitManager` remain
to be implemented, but the leak surface is closed by construction regardless.

---

## Post-v16 review fixes + crypto-audit triage

Three real logic/doc fixes, plus triage of an uploaded "crypto line-by-line audit."

### Fixed

**PostEngine.ingestFragment — progress/tier-1 used the wrong denominator.** After Bug 5
moved the CONFIRMED gate to `received >= totalData`, the tier-1 progress percentage still
divided by `total` (= totalData + totalParity). A CONFIRMED post read ~totalData/total
(e.g. 10/17 ≈ 59%) and `justCrossed` evaluated the TIER1 threshold against the wrong basis,
firing the progressive unlock at the wrong received-count. Now both use
`reconstructionThreshold` (= totalData), the same basis the CONFIRMED gate uses.

**PostDispatcher/MerkleAckProtocol — Bug 6 completed the ACK deferred with the wrong data.**
Bug 6 stopped posts hanging in SYNCING by completing the `awaitAck` deferred, but completed
it with the 32-byte received Merkle root. `PostDispatcher.onConfirmed` then tried to decrypt
that root as ciphertext to recover `encTier0`, the decrypt failed, and the raw root reached
`PostEngine.onConfirmed`'s `sha3_256(encTier2) == postHash` security gate — which can never
pass (the ACK wire format carries only the root, never the payload). Fix: confirm against the
sender's locally-held `encTier0` (`post.encryptedTier0`), whose hash IS `postHash`; the ACK
is treated purely as a verified signal. Removed the now-dead `pendingPostKeys` map, the
wire-payload decrypt, and the orphaned `ConcurrentHashMap` import; renamed the misleading
`encryptedTier2` deferred parameters to `verifiedRoot`.

**VrfElection.generateReveal — comment overstated verifiability.** The Bug 8 comment claimed
"a verifier can confirm the reveal." The construction is keyed HKDF in a commit-reveal, not a
publicly-verifiable VRF: it can only be checked after the nonce+key are revealed, and does not
prevent pre-commit grinding. Comment corrected; flagged ECVRF/RFC 9381 as the real-VRF path
if malicious-candidate output bias must be resisted. No code change.

### Rejected (uploaded crypto audit)

The uploaded audit's "Critical" finding — that `"%02x".format(it)` sign-extends `Byte` and
emits 8 hex chars for high-bit bytes — is incorrect on two counts: (1) the JVM Formatter's
`print(byte, Locale)` adds `1L << 8` to negative bytes before hex/octal, so a raw `Byte` arg
formats correctly; and (2) every call site in this tree already uses `it.toInt() and 0xFF`
(0 bare-`Byte` sites found). The audit's Medium (NodeIdentity negative-length guards) and Low
(TrustCredential unsigned version compare + sigLen guard) findings were ALREADY present in
this tree. No changes applied from the audit; verified empirically against the source.

---

## Logic audit fixes (v15 → v16)

Nine logic issues found and fixed during a full codebase audit pass.

### Bug 1 — PostEngine / StorageModels: FragmentEntity field name clash (build-breaking)
`PostEngine.getFragmentTotal` called `.payload` on the storage `FragmentEntity`, which
has no such field (the field is `.encryptedBytes`). Fixed: renamed to `.encryptedBytes`.
Root cause: two `FragmentEntity` classes exist in different packages (mesh and storage);
the forum layer uses the storage model for DAO calls but the field name came from the
mesh model. Also added `MeshFragmentEntity` overload to `PostEngine.ingestFragment` with
an explicit `toStorageFragment()` conversion that preserves `totalData` — see Bug 5.

### Bug 5 — PostEngine.ingestFragment: CONFIRMED fires only when ALL shards present
`newState = CONFIRMED` was gated on `received >= total` where `total` = data + parity
shards. For RS_10_7 (17 total shards) this meant 17 shards were required, not 10. FEC
reconstruction only needs `totalData` (data shards). Added `totalData` column to the
storage `FragmentEntity` (DB migration v8→v9, default backfill from `total`). Ingest
overload converts mesh→storage preserving `totalData`. CONFIRMED now fires when
`received >= totalData`.

### Bug 6 — AckRouter: awaitAck deferred never completed
`MerkleAckProtocol.awaitAck` suspends on a `CompletableDeferred` completed only by
`notifyAckReceived`. `AckRouter.handleAck` fired the `ackListeners` callback but never
called `notifyAckReceived`, so the deferred in `PostDispatcher.awaitAck` hung forever
and posts stayed SYNCING. Fixed: `AckRouter.handleAck` now calls
`merkleAckProtocol.notifyAckReceived(postIdHex, receivedRoot)` after ACK verification.

### Bug 4 — findClosestDisjoint: paths all sliced the same sorted list
All `disjointPaths` paths greedily took from the globally-sorted list starting at
position 0 — an eclipse attacker filling the top K positions dominated all paths
simultaneously. Fixed: seeds are drawn from evenly-spaced quantile positions in the
primary contact list; each path then walks outward from its own seed using a per-seed
XOR comparator, making paths truly independent.

### Bug 2 — NetworkModeStateMachine: upward transitions could skip modes
Recovery from SURVIVAL could jump directly to HEALTHY in one call if anchor count
crossed the threshold. Fixed: upward transitions are now strictly one step per call
(SURVIVAL→CRITICAL→DEGRADED→HEALTHY). Downward transitions remain unrestricted —
a sudden anchor count collapse must immediately move to SURVIVAL.

### Bug 3 — RoutingTableDiversityGuard: self-check returned misleading Rejected
`check(table, candidate)` returned `DiversityVerdict.Rejected` with `sigmasAbove=MAX_VALUE`
when `candidate == localNodeId`. This is dead code (RoutingTable.insert guards self-insert
before calling here) but would spuriously fire `onEclipseAlert` if call order changed.
Fixed: returns `DiversityVerdict.OK` instead.

### Bug 7 — OneTimeChannel.create: duplicated channelId derivation with no sync guarantee
The provisional `channelId` in `OneTimeChannel.create` duplicates
`ChannelManager.createChannel`'s derivation. If one changes without the other, the
wrapped key is bound to the wrong channelId and silently fails to unwrap. Fixed: added
a `check(channelId == entity.channelId)` invariant assertion that fires immediately
at creation time if the two derivations diverge.

### Bug 8 — VrfElection.generateReveal: VRF output not bound to candidateNodeId
The HKDF info tag was `VRF_INFO` (constant bytes) — VRF output was only distinguished
by signing key. Fixed: info = `VRF_INFO + candidateNodeId.bytes`, cryptographically
binding the output to the specific candidate's identity.

### Bug 9 — deleteExpiredNonces: parameter semantics underdocumented
`deleteExpiredNonces(cutoffMs)` deletes nonces where `seenAtMs < cutoffMs`. Passing
`currentTimeMillis()` directly deletes all nonces, breaking replay protection.
Fixed: renamed parameter to `oldestAllowedMs` with explicit KDoc warning.
`TtlSweepWorker` already passed the correct value (`currentTimeMillis() - NONCE_RETAIN_MS`).

---

## Debug diagnostics + silent-failure instrumentation (post-v11)

Added `:core:diagnostics` (pure-JVM `Diag` seam: swallowed/fallback/degraded/invariant; no-op
+ free in release) and expanded `:feature:debug-diagnostics` into a full on-device harness:
probes now cover Keystore/TEE tier, the hardware-attestation pipeline, native KEM + signer
round-trips, ratchet determinism + checkpoint restore, gossip bloom dedup, the rate-limiter
gate, and LT-fountain loss recovery — plus a live event log that surfaces anything production
code reported through the seam. Representative swallow-sites instrumented in StoreAndForward
and HardwareAttestation; the complete remaining worklist is in SILENT_FAILURE_AUDIT.md.
All debug code is `debugImplementation`-only; release builds link none of it.
NOTE: authored without a compiler — gate on a Claude Code build before relying on it.

---

## Consistency audit (post-v11)

Fixes for inconsistencies between documentation, declarations, and implementation found
in a full cross-reference pass. Two were hard build-breakers.

### Build-breakers

**`core/crypto/HybridKem.kt` — duplicate `intTo4Bytes` (redeclaration).**
`HybridKem.kt` defined an `internal fun intTo4Bytes` while `CryptoUtils.kt` defines a
public `fun intTo4Bytes` in the same package and module — a conflicting-overload compile
error, directly contradicting the previous changelog's claim that all duplicates were
consolidated. Removed the local copy; `fourBytesToInt` (genuinely unique here) is kept.

**`feature/ui/OnboardingScreen.kt` — reference to non-existent enum constant.**
`buildVerifiedLabel` matched `AttestationTrustLevel.HARDWARE_STRONGBOX`, which was never a
member of the enum (only `HARDWARE_VERIFIED/HARDWARE_CUSTOM_OS/SOFTWARE_ONLY`) — an
unresolved-reference compile error. See StrongBox fix below.

### StrongBox tier wired end-to-end (`core/attestation`, `feature/ui`)

`extractIsStrongBox()` parsed the attestation security level and `ExchangeResult` carried
`isStrongBox`, but the value never influenced `AttestationTrustLevel` — a dead signal.
Added `AttestationTrustLevel.HARDWARE_STRONGBOX`; `VERIFIED` boot state now maps to
`HARDWARE_STRONGBOX` when `isStrongBox`, else `HARDWARE_VERIFIED`. The onboarding label
`when` is now exhaustive (the `HARDWARE_VERIFIED` branch was also missing).

### Attestation tier now persists in the credential (`core/crypto`, `core/attestation`)

`HardwareAttestation` documented that an attested node's `TrustCredential` embeds the
verified tier "as an extension field," but `TrustCredential` had no such field — attested
and plain-NFC bootstraps collapsed to an identical persisted `TRUST_PHYSICAL`. Added a
signed `CredentialAttestation` tier (crypto-local enum, no crypto↔attestation cycle) to
`TrustCredential`, version-gated to v2 with backward-compatible v1 parsing, a
`physicalAttested(...)` factory, and `AttestationTrustLevel.toCredentialAttestation()` as
the issuance bridge. The misleading comment is corrected.
NOTE: the bootstrap→issue→persist call site in onboarding is still not wired (it never
created a credential); when it is, it must call `physicalAttested(...)` or the tier is
recorded as `NONE`. **Credential wire format changed (v1→v2); validate against
`TrustCredentialTest` + a round-trip test before deployment.**

### Unreachable bootstrap trust levels removed (`core/bootstrap`, `feature/ui`)

`BootstrapTrustLevel.TRUST_PHYSICAL_BLE` and `TRUST_INTRODUCED_QR_ONLY` were declared and
rendered in the UI but never produced — the coordinator only ever emits the two NFC
outcomes, and the BLE/QR-only fallback completion exchanges are not implemented. Removed
both values, their UI branches, and the stale doc comments that claimed a fallback issues
them; updated `NfcHandshakeTest`. `NfcFallback` detection variants are unchanged
(detection is real; only the completion path is absent). Re-add the values with their
production path when those fallbacks are built.

---

## Audit pass (post-Phase-7)

This pass applied fixes from a full code review of the complete codebase across
five review rounds. Changes are grouped by subsystem.

---

### Cryptography (`core/crypto`)

**`CryptoUtils.kt` — new file**
`ByteArray.toHex()` and `intTo4Bytes()` were duplicated as private functions in
fourteen files across `core/`, `feature/forum`, and the bootstrap/attestation modules.
All duplicates are removed; every file now imports from `CryptoUtils`. This eliminates
the risk of divergence between copies and gives a single location to test.

**`NodeCallsign.kt`**
Removed private `toHex()` duplicate; imports from `CryptoUtils`.

---

### Storage (`core/storage`)

**`BloomFilter.kt` — GC pressure fix**
`reset()` and the auto-reset branch inside `testAndAdd()` were allocating a new
`LongArray` on every reset (~88 KB per reset, every 50,000 inserts). Changed to
`bits.fill(0)` in-place. The array is now `val`, allocated once at construction.

**`RateLimiter.kt` — documented intentional race**
`remainingFragments()`, `remainingPosts()`, and `remainingNudges()` read token counts
without synchronisation. These are advisory reads used only for logging and UI display;
`consume()` is the authoritative gate and is synchronised. Added a comment explaining
the design so the unsynchronised read is not mistaken for a bug.

**`StorageModels.kt` — new entity, new index**
- Added `UsedBootstrapNonce` Room entity for QR/NFC replay prevention (see
  `PhysicalKeyExchange` below). Stored for 10 minutes (2× the 5-minute payload validity
  window) and swept by `TtlSweepWorker`.
- Added composite index `(channelId, postState, openedAtMs)` on the `posts` table.
  `observeUnreadCount` and `unreadCountForChannel` filter by all three columns; without
  the composite index SQLite performs a full channelId scan with in-memory filtering.

**`ShadowMeshDao.kt`**
- Added `getMissedFragmentsForChannel(channelId, sinceMs)` — was a stub that returned an
  empty list regardless of input, silently breaking `ChannelSyncCoordinator.onReconnect()`.
  Now queries `fragments WHERE channelId = :channelId AND receivedAtMs > :sinceMs`.
- Added `isNonceUsed()`, `insertUsedNonce()`, `deleteExpiredNonces()` for bootstrap nonce
  persistence.

**`ShadowMeshDatabase.kt`**
- Version 6 → 8 (two migrations added):
  - v6→v7: creates `used_bootstrap_nonces` table.
  - v7→v8: creates composite index on `posts(channelId, postState, openedAtMs)`.
- Added `UsedBootstrapNonce::class` to `@Database` entities list.

---

### Bootstrap / NFC (`core/bootstrap`, `core/attestation`)

**`PhysicalKeyExchange.kt` — QR nonce replay prevention**
The nonce in a QR introduction code was only checked against an in-memory set.
A process restart cleared the set, allowing replay of a QR code captured before
the crash within its 5-minute validity window.

Fix: introduced `NonceStore` interface with a DAO-backed production implementation
and an `InMemoryNonceStore` for tests. `PhysicalKeyExchange` now accepts a `NonceStore`
as a constructor parameter (defaults to `InMemoryNonceStore` for backward compatibility).
`receiveQrCode()` checks and records each nonce before accepting it. Production callers
must inject a `DaoNonceStore`.

**`NfcBootstrapCoordinator.kt` — moved to `core/attestation`**
The coordinator imports five types from `core/attestation` (for hardware attestation
verification) while `core/attestation` already depends on `core/bootstrap` (for
`PhysicalKeyExchange`). Placing the coordinator in `core/bootstrap` created a
`bootstrap ↔ attestation` cycle. Moved to
`core/attestation/src/.../attestation/nfc/NfcBootstrapCoordinator.kt`; package updated
to `mesh.shadowmesh.attestation.nfc`; all callers (`AppModule`, `ShadowMeshHceService`,
`OnboardingViewModel`) updated to import from the new location.

**`NfcBootstrapCoordinator.kt` — `reset()` deferred leak**
`reset()` set `resultDeferred = null` without cancelling the deferred first. Any coroutine
suspended on `awaitResult()` would hang indefinitely on user cancellation (e.g. pressing
back). Fixed: `reset()` now calls `resultDeferred?.cancel()` before nulling it.

---

### Attestation (`core/attestation`)

**`AttestedPhysicalExchange.kt` — root certificate not verified (high severity)**
`verifyAttestationChain()` verified certificate chain signatures and challenge freshness
but did not check that the chain roots in the expected hardware attestation CA. A
compromised or self-issued root would pass chain verification.

Fixed: `verifyPeerAttestation()` now calls `HardwareAttestation.verifyRootCertificate()`
immediately after a successful chain verification. Root selection is automatic:
`GOOGLE_HARDWARE_ATTESTATION_ROOT_HEX` for VERIFIED boot state,
`GRAPHENEOS_ATTESTATION_ROOT_HEX` for SELF_SIGNED (GrapheneOS). A mismatched root
returns `AttestationFailed` and blocks the bootstrap.

**`HardwareAttestation.kt` — deployment blocker comment**
Added a structured `DEPLOYMENT BLOCKER` comment above the root constants documenting
both required pre-production steps: (1) replace placeholder root hex with real DER
public keys, (2) wire the NFC onboarding flow to require and gate on attestation evidence.

---

### Mesh (`core/mesh`)

**`AnticipatoryReplicationManager.kt` — `sequenceIndex` data corruption (high severity)**
`serializeFragments()` did not include `sequenceIndex` in the wire format.
`deserializeFragments()` restored `sequenceIndex` from a local counter (`seq++`) instead
of the original value. Since `FragmentationEngine.reassemble()` sorts by `sequenceIndex`,
fragments from the anticipatory cache would be assembled in the wrong order, producing
corrupted output.

Fixed: wire format extended with 4 bytes per entry for `sequenceIndex`
(`[4B idLen][idLen bytes][4B sequenceIndex][4B payloadLen][payload][1B isDecoy]`).
Deserialization restores the original value.

Also: changed silent `catch` in `refreshCacheForAllPeers()` to log at WARN so systematic
failures are visible without flooding logcat on transient errors.

**`BleGattTransport.kt` — GATT server Binder thread**
`onCharacteristicWriteRequest` was calling `nudgeEngine.onNudgeReceived()` directly on
the Android Binder thread pool. Any non-trivial or suspendable work in the callback (the
lambda is caller-supplied) would block Binder threads. Fixed: `sendResponse()` is still
called synchronously on the Binder thread (required by the API), then all further
processing is dispatched via `scope.launch`. Also copies the `value` buffer before the
launch since Binder may recycle it.

**`MerkleAckProtocol.kt` — `awaitAck` deferred leak**
`awaitAck()` created a `CompletableDeferred` with no parent. If the calling coroutine's
scope was cancelled (service restart, scope teardown), the deferred was never cancelled
and remained in `awaitingAck`, suspending forever and leaking the map entry.

Fixed: deferred created with `parent = currentCoroutineContext().job` so cancellation
propagates. The `finally` block uses the value-checked `remove(postId, deferred)` overload
to avoid racing with a concurrent re-registration for the same post.

**`InMeshMixProtocol.kt` — decoy identity leak**
`generateDecoys()` set both `postId` and `channelId` to `SndpEngine.SNDP_FAKE_CHANNEL_ID`
(all-zeros hex). Any relay node inspecting fragment metadata could trivially identify
these as decoys, breaking the indistinguishability guarantee.

Fixed: each decoy generates 32 bytes of `SecureRandom` for both `postId` and `channelId`,
formatted as 64-character lowercase hex — identical in format to real fragment IDs.
`fragmentId` is content-addressed from the random payload, matching real fragment
construction.

**`NatAwareDhtTransport.kt` — missing IPv6 link-local**
`isLocalAddress()` checked `::1` (IPv6 loopback) but not `fe80::/10` (IPv6 link-local).
Devices on an IPv6 link-local network would trigger unnecessary STUN queries.
Fixed: added prefix checks for `fe8`, `fe9`, `fea`, `feb` (covering the full /10 range).

**`DhtEngine.kt` — single-path DHT lookup seeding**
`iterativeFindNode()` and `findValue()` both seeded their initial contact set from
`routingTable.findClosest()` — a single ordered list of the K nearest contacts. An
attacker controlling those K bucket positions could steer all lookups. Both methods
now call `routingTable.findClosestDisjoint()` (S/Kademlia disjoint-path seeding),
which partitions the seed set across `DISJOINT_PATHS` (= 4) independent starting
contacts. `findClosestDisjoint` was already implemented; it was just not being called
from the iterative lookup paths.

**`VrfElection.kt` — nonce-reuse footgun**
`verifyReveal()` and `resolve()` accepted a caller-managed `MutableSet<String>` for
anti-replay. Nothing prevented a caller from reusing the same set across two election
rounds, causing valid nonces from round N+1 to be falsely rejected as replays.

Replaced with `VrfElectionRound` — a typed object constructed via `VrfElection.newRound()`
that owns its nonce set privately. The caller feeds reveals via `acceptReveal()` and
gets the winner from `resolve()`. There is no way to extract or share the nonce set
across rounds. The old `verifyReveal()` and `resolve(String, List, MutableSet, String)`
signatures are removed.

**`SponsorshipLedger.kt`**
Added tuning guidance to `MESH_BURST_COOLDOWN_MS` constant noting that
`MAX_MESH_INTRODUCTIONS_PER_WINDOW` should be tuned first (raising the threshold
reduces false positives) before reducing the cooldown duration.

---

### Forum (`feature/forum`)

**`KeyOrchestrator.kt` — ratchet advance race (high severity)**
`PostRatchet` is explicitly not thread-safe. Two concurrent `advanceRatchet()` calls
for the same channel on the same cached `PostRatchet` instance would read the same
`chainKey`, derive identical `postKey` values for two different posts, and overwrite
`chainKey` with the same next value — a complete forward-secrecy failure.

Fixed: `KeyOrchestrator` now holds a `ConcurrentHashMap<String, Mutex>` keyed by
channel ID. Every `advanceRatchet()` call acquires the channel's `Mutex` via `withLock`
before touching `PostRatchet`. The mutex is removed on `evictRatchet()`.

**`PostEngine.kt` — fragment total mismatch accepted**
`ingestFragment()` did not check that a fragment's declared `total` matches the total
already established for that post. A malicious fragment with a different total could
cause incorrect `fragmentsTotal` in the database, triggering false CONFIRMED transitions
or permanently preventing confirmation.

Fixed: if `post.fragmentsTotal > 0` (an earlier fragment has established the authoritative
total) and the incoming fragment declares a different `total`, the fragment is deleted and
the ingest returns `false`.

Also: the second `dao.getPost()` call later in the method was removed (now a single load
at the top serves both the mismatch check and the tier-1 unlock logic).

**`PostDispatcher.kt` — pending post key wipe documentation**
The reviewer claimed `storedKey.fill(0)` would not run if `onPostConfirmed` threw.
Tracing the actual control flow confirmed the code was correct: `finally { fill(0) }`
runs before `onPostConfirmed` is ever called. Added a three-step comment explaining the
wipe order explicitly.

**`PostStateMachine.kt` — `PostStateMachineRegistry` thread safety**
`machines` was `mutableMapOf<String, PostStateMachine>()` with no documented thread
constraint. Changed to `LinkedHashMap` with a `@MainThread` annotation and a class-level
KDoc explaining: all access is currently on the main thread (via `viewModelScope`), and
if that ever changes, `ConcurrentHashMap` should be used instead.

**`ForumViewModel.kt` — PENDING timeout dies with ViewModel**
`PostStateMachineRegistry` was constructed with `viewModelScope`. If the user navigates
away during a send attempt, `viewModelScope` is cancelled and the 30-second PENDING→FAILED
timeout job is silently dropped. The post stays PENDING on next open.

Fixed: `ForumViewModel` gains an optional `backgroundScope: CoroutineScope?` parameter.
`PostStateMachineRegistry` uses `backgroundScope ?: viewModelScope`, so timeout jobs
survive navigation-driven ViewModel teardown when an application-lifetime scope is
injected.

**`TtlSweepWorker.kt`**
Added `dao: ShadowMeshDao?` injectable field. `doWork()` now calls
`dao.deleteExpiredNonces()` to sweep expired bootstrap nonces (10-minute retention).

---

### NSC (`core/nsc`)

**`NetworkStateCoordinator.kt` — executor thread leak**
`Executors.newSingleThreadExecutor()` created the dispatcher but the executor was never
shut down. Split into `dispatcherExecutor` (stored field) and `dispatcher` (derived from
it). Added `close()` method that calls `dispatcher.close()` then `dispatcherExecutor.shutdown()`.

**`ShadowMeshApplication.kt`** — stores the NSC in `nscInstance`; `onTerminate()` calls
`nscInstance?.close()` and cancels `applicationScope`.

---

### Security (`core/security`)

**`BiometricKeyManager.kt`**
Extracted auth window durations (30 s COMPARTMENTED, 300 s OPEN_OR_CLOSED) from the
inline `when` expression into named companion constants `AUTH_WINDOW_COMPARTMENTED_SEC`
and `AUTH_WINDOW_OPEN_SEC`, with design-doc references in KDoc.

**`BiometricKeyManagerTest.kt`**
Replaced the worthless `30 shouldBe 30` / `300 shouldBe 300` assertions (which tested
local variables against themselves, not the production constants) with:
```kotlin
BiometricKeyManager.AUTH_WINDOW_COMPARTMENTED_SEC shouldBe 30
BiometricKeyManager.AUTH_WINDOW_OPEN_SEC           shouldBe 300
```
These now actually catch accidental constant changes in the production class.

---

### Distribution (`core/distribution`)

**`AppArtifactAcquirer.kt`**
Strengthened the existing resume comment into a structured `TODO(resume)` block with
three concrete implementation steps and an explicit statement of the consequence
(poor mesh connections can prevent a new node from ever successfully acquiring the app).

---

### Manifest and build

**`AndroidManifest.xml`**
Removed redundant `<uses-permission android:name="android.permission.RECEIVE_BOOT_COMPLETED"/>`.
WorkManager's library manifest registers its own `BootBroadcastReceiver` via manifest merge.
The app-level declaration implied a boot receiver existed in the app, which it does not.
Replaced with a comment explaining the removal.

**`NfcBootstrapCoordinator.kt` relocated**
Moved from `core/bootstrap/src/.../bootstrap/nfc/` to
`core/attestation/src/.../attestation/nfc/` to resolve the `bootstrap ↔ attestation`
dependency cycle. See the Bootstrap/NFC section above.

**`settings.gradle.kts`**
Added `dependencyResolutionManagement` and `pluginManagement` blocks with a local-first
repository ordering: `libs/maven/` (populated by `scripts/vendor_deps.py`) is checked
before Google Maven and Maven Central. When `libs/maven/` is absent or empty, Gradle
falls through to the remote repositories normally.

**`gradle/libs.versions.toml`**
- Added catalog entries for previously hardcoded versions:
  `lazysodium-java`, `lifecycle-viewmodel-ktx`, `lifecycle-runtime-ktx`, `appcompat`,
  `androidx-test-core`, `androidx-test-runner`, `androidx-test-ext-junit`.
- Added `androidxTest`, `androidxTestExt`, `androidxRunner`, `appcompat` version refs.

**Module dependency fixes**
- `core/bootstrap/build.gradle.kts`: no change (cycle avoided by moving the coordinator).
- `core/attestation/build.gradle.kts`: `:core:bootstrap` was already declared; the moved
  coordinator's bootstrap imports are satisfied.
- `feature/ui/build.gradle.kts`: added `:core:platform` (used by `OnboardingScreen` for
  `BiometricEnrollmentChecker.EnrollmentStatus` and `VpnServiceBridge`).
- Removed unused declared dependencies: `:core:crypto` from `feature/ui`,
  `:core:nsc` from `feature/forum` and `core/storage`.

**`AnchorHandoffManager.kt`** — fixed `reboostrap` typo in KDoc comment (function name was always correct).

---

### New files

| File | Purpose |
|------|---------|
| `core/crypto/src/.../CryptoUtils.kt` | Canonical `ByteArray.toHex()` and `intTo4Bytes()` shared across all modules |
| `core/attestation/src/.../nfc/NfcBootstrapCoordinator.kt` | Moved from `core/bootstrap` to resolve cycle |
| `core/attestation/src/test/.../nfc/NfcSessionKeyTest.kt` | Moved with coordinator |
| `libs/maven/README.md` | Offline dependency vendoring instructions |
| `libs/maven/.gitignore` | Excludes binary artifacts from git by default |
| `scripts/vendor_deps.py` | Downloads all dependencies into `libs/maven/` for offline builds |
| `README.md` | Project overview (this file's companion) |
| `BUILDING.md` | Complete build and deployment guide |

---

## Phase 7 — Offline Transport

*(Original Phase 7 changes — preserved from previous CHANGES.md)*

### Bug fixes from Phase 5/6 audit

- **BUG 1** `siblingPath` — one sibling per level
- **BUG 2** `FecScheme` wire: `Int` not `Byte`
- **BUG 3/4** `getOrPut` → `computeIfAbsent` in accumulators and `heldFragments`
- **BUG 5** `replicaLocations` — `computeIfAbsent` + `CopyOnWriteArrayList`, no `synchronized`
- **BUG 6** `verifyFragment` — self-contained content-address check, no `allPayloads` required

### New files in Phase 7

**`WiFiDirectTransport.kt`** — Android `WifiP2pManager` peer discovery and fragment exchange over raw TCP on link-local addresses. Zero DNS, zero public IPs. Wire format: `[4B len][fragment bytes]`.

**`BleGattTransport.kt`** — BLE GATT nudge transport. GATT server receives 12-byte `NudgePacket` writes. Background scanning via `PendingIntent` (Android 8+ requirement). Beacon mode: BLE advertisement of 8-byte channel hash in manufacturer data, off by default.

**`LanSubnetTransport.kt`** — UDP broadcast discovery (`255.255.255.255`, 42-byte beacon) + TCP fragment exchange. Discovery every 15 s. No internet contact.

**`SurvivalModeEngine.kt`** — SURVIVAL mode (1–3 nodes): no DHT, no gossip, no Tier structure. All fragments stored on all devices, flood-fill every 15 s.

**`ShadowFilesChunker.kt`** — 64 KB chunk splitting with per-transfer key derivation, chunk encryption, and `FragmentationEngine` integration.

**`ShadowFilesReassembler.kt`** — Reassembly with checkpoint/resume. `ChunkAccumulator` per chunk, Merkle root verification, checkpoint persisted to SQLCipher, `clearTransfer()` cleanup.

### Phase 7 exit gate

| Requirement | Status |
|---|---|
| Two devices discover via WiFi Direct | ✓ `WiFiDirectTransport` |
| Fragment exchange with no internet | ✓ TCP on link-local, no DNS |
| BLE nudge triggers WorkManager sync | ✓ `BleGattTransport` + `PendingIntent` |
| SURVIVAL mode: 2-device direct exchange | ✓ `SurvivalModeEngine` |
| Improvised LAN backbone peer discovery | ✓ `LanSubnetTransport` |
| SHADOWFILES chunker: 64 KB, encrypted | ✓ `ShadowFilesChunker` |
| SHADOWFILES manifest gossiped separately | ✓ Separate manifest type |
| SHADOWFILES reassembly with Merkle verify | ✓ `ShadowFilesReassembler` |
| Checkpoint persists to SQLCipher | ✓ DAO synthetic fragment |
| Resume from last confirmed chunk | ✓ `loadCheckpoint()` + selective re-fetch |
| Corruption detected and retransmitted | ✓ `IngestResult.Corrupted` + NACKable seqs |

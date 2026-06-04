# SHADOWMESH — Audit Log

---

## Session 2026-06-02

### Phase 0 findings

- [CRITICAL] ForumUiViewModel.kt:253 — Double ratchet advance per sent post. UI advanced with sha3_256(plaintext) before PostDispatcher advanced again with sha3_256(encTier2), burning two steps and deriving mismatched keys.
- [CRITICAL] PostDispatcher.kt:79 — Wire payload encrypted with encTier0 (50-char metadata) instead of encTier2 (full content). Receivers would receive undecodable wire bytes even if ratchet were correct.
- [CRITICAL] PostDispatcher.kt:121 — Sender confirmation used encTier0 for hash check; postHash = sha3_256(encTier2). Check always failed → all sent posts stuck in SYNCING → FAILED.
- [CRITICAL] FragmentIngestor.kt (attemptConfirmation) — No receive-side ratchet advance. Assembled wire bytes passed directly to onPostConfirmed without ratchet decryption → hash check always failed for received posts.
- [HIGH] PostEngine.kt:231 — ingestFragment() returned early (true) when no PostEntity existed for a postId, preventing stub creation for received-only posts → onConfirmed() returned immediately → received posts never confirmed.
- [MEDIUM] ForumViewModel.kt:120 — tier2 display gated only on `encryptedTier2 != null`; now that encryptedTier2 is stored from creation, PENDING/SYNCING posts would have shown full content prematurely.
- [INFO] ShadowMeshApplication.kt:936 — ACK sending previously noted as stub is NOW wired via gossipEngine.sendControl (fixed in prior session; confirmed correct this session).
- [INFO] All prior fixes (crypto, wire format, NSC, concurrency, ACK pipeline instance) verified correct.

### Phase 1 fixes

- PostEngine.kt:95 — createPost() now takes channel key (not ratchet key) as postKey; encryptedTier2 stored at creation (not null). postHash = sha3_256(encTier2) unchanged and correct.
- ForumViewModel.kt:120 — openPost() tier2 display now gated on postState == CONFIRMED.
- PostDispatcher.kt:65,79,121 — Ratchet advance uses per-channel model (senderNodeId=channelId, postHash=hexToBytes(postId)); wire payload uses encTier2; confirmation uses encTier2.
- FragmentIngestor.kt:80,428 — Added keyOrchestrator + cipher to constructor; attemptConfirmation() advances ratchet and decrypts wire payload before calling onPostConfirmed. CancellationException rethrown in catch block.
- PostEngine.kt:231 — ingestFragment() creates PostEntity stub for received-only posts. postHash="" placeholder filled by onConfirmed().
- PostEngine.kt:159 — onConfirmed() accepts stub posts (empty postHash) and stores computed postHash.
- ShadowMeshDao.kt:88 — updatePostConfirmed() now also writes postHash column.
- ShadowMeshApplication.kt:657 — FragmentIngestor construction updated to inject keyOrchestrator.
- ForumUiViewModel.kt:247 — Uses retrieveChannelKey() instead of advancing ratchet at post creation time.
- Phase3Tests.kt, Phase3IntegrationTests.kt, Phase3CompletionTests.kt — FakeDao.updatePostConfirmed updated to match new signature.

### Phase 2 work

None this session — Phase 1 had unresolved CRITICAL findings.

### Invariants checked

- CRYPTO-4: CancellationException rethrow added to new catch block in FragmentIngestor.attemptConfirmation.
- CRYPTO-5: PostRatchet.advance() order unchanged (postKey before chainKey advance). Verified correct.
- CRYPTO-6: ratchetKey.fill(0) in finally block in FragmentIngestor. postKey.fill(0) in PostDispatcher on error path and after use.
- WIRE-1: No wire format changes this session.
- WIRE-2: No byte version comparisons changed.
- WIRE-3: No hex encoding changed.
- DB-1: updatePostConfirmed() SQL only updates existing columns (postHash already in schema). No version bump needed.
- CONCURRENCY-2: advanceRatchet() in FragmentIngestor uses same per-channel Mutex as PostDispatcher (senderNodeId=channelId). Both serialize correctly.
- DEP-1: KeyOrchestrator and SymmetricCipher are in feature/forum and core/crypto respectively — both already in feature/forum build.gradle.kts. No new deps added.
- DEP-2: No new cross-module imports without build.gradle.kts declarations.

### Open items (updated)

1. [DEPLOYMENT BLOCKER] HardwareAttestation.kt — GOOGLE_HARDWARE_ATTESTATION_ROOT_HEX and GRAPHENEOS_ATTESTATION_ROOT_HEX are DEPLOYMENT_PLACEHOLDER_*. Tier TRUST_PHYSICAL_ATTESTED not issued until real DER roots set. (Phase 2 item 1)
2. [ARCH] S1: BLE/WiFi Direct/LAN transports implemented but not wired into gossip — app is IP/DHT only in production.
3. [ARCH] S2: DHT seed list is empty — no bootstrap peers in production build.
4. [MEDIUM] Ratchet desynchronisation on out-of-order delivery — receiver missing post N cannot advance for post N+1.
5. [MEDIUM] SymmetricCipher AAD always null — no session/identity binding in AEAD (Phase 2 item 8).
6. [LOW] HKDF test vectors are determinism checks only, not known-answer tests.
7. [LOW] PostEntity stub's encryptedTier0 = ByteArray(0) — opening a SYNCING received post shows decrypt error rather than placeholder text.
8. [S4-S9] Circuit STUN reply, NFC fallbacks, artifact P2P transport, attestation roots, revocation gossip (NOW DONE), anchor handoff — all documented in STUB_AUDIT.md.

---

### Phase 2 work (continued 2026-06-02)

**Item 3a — Keybox revocation gossip pipeline — BUILT**

Files changed: GossipFrameTypes.kt, GossipEngine.kt, KeyboxRevocationCache.kt, AckRouter.kt, ShadowMeshApplication.kt

What was built:
- `RevocationUpdateFrame` wire type with `toBytes()/fromBytes()`, `signedPayload()` (domain-separated).
- `GossipEngine.broadcastRevocationUpdate()` — sends serialized frame to all non-blocked peers except source (one-hop propagation).
- `KeyboxRevocationCache.mergeUpdate()` — synchronized, idempotent merge; returns true only if new entries were added.
- `KeyboxRevocationCache.parseAndLoad()` now detects delta vs. previous cache and fires `onNewEntries` callback.
- `AckRouter.onGossipControlPacket` handler — intercepts RVKU-magic packets before fragment fallthrough.
- `ShadowMeshApplication` wiring: sign-and-broadcast on new entries; verify-nonce-sig-merge-regossip on receive.

What remains:
- `DhtContract` must carry `publicIdentity` for gossip peers (currently null for DHT-only peers) for signature verification to work. This is a known limitation: revocation updates from NFC-bootstrapped peers work; updates from DHT-only contacts are dropped until their publicIdentity is populated.

### Open items (updated)

1. [DEPLOYMENT BLOCKER] Attestation roots (GOOGLE/GRAPHENEOS placeholders).
2. [ARCH] S1: BLE/WiFi/LAN transports not wired into gossip — IP/DHT only.
3. [ARCH] S2: DHT seed list empty.
4. [MEDIUM] Ratchet desync on out-of-order delivery.
5. [MEDIUM] SymmetricCipher AAD always null (Phase 2 item 8).
6. [LOW] HKDF test vectors determinism-only.
7. [LOW] PostEntity stub encryptedTier0=ByteArray(0) for SYNCING received posts.
8. [LOW] revocationUpdate: DHT-only peers without publicIdentity can't have their updates verified.

---

### Phase 2 continued (item 5) 2026-06-02

**Item 5 — Peer discovery cache — BUILT**

Files changed: StorageModels.kt, ShadowMeshDao.kt, ShadowMeshDatabase.kt, DhtEngine.kt, ShadowMeshForegroundService.kt

- `DiscoveredPeerEntity(nodeIdHex PK, lastSeenMs, transport, addressHint, trustLevel)` — new Room entity.
- `upsertDiscoveredPeer()` + `getRecentDiscoveredPeers(minLastSeenMs)` — new DAO methods.
- DB version 14→15 via `MIGRATION_14_15` (CREATE TABLE discovered_peers). DB-1 invariant maintained.
- `DhtEngine.currentContacts()` — exposes routing table snapshot.
- `ShadowMeshForegroundService`: reads cache before bootstrap (prepends to seed list), persists routing table after bootstrap.

Remaining: BLE/LAN transports not wired, so only DHT contacts are currently upserted. Add upsert calls in BLE/LAN success handlers when those transports are activated.

### Open items (updated — superseded; see final open items below)

---

### Phase 2 item 8 — SymmetricCipher AAD (2026-06-02)

**Files changed:** SymmetricCipher.kt, PostDispatcher.kt, FragmentIngestor.kt

Added optional `aad: ByteArray? = null` to `encrypt()` and `decrypt()`. Wired postId as
AAD in the ratchet layer: PostDispatcher passes `hexToBytes(post.postId)` to encrypt;
FragmentIngestor passes `hexToBytes(triggerFragment.postId)` to decrypt. The backward-compat
fallback in decrypt() retries without AAD if the AAD-version fails, covering old messages.
Wire format unchanged. Phase 2 item 8 COMPLETE.

### Phase 2 item 7 — RatchetGapResolver (2026-06-02)

**Files changed:** KeyOrchestrator.kt, FragmentIngestor.kt, ChannelSyncCoordinator.kt, ShadowMeshApplication.kt

- `RatchetGapEvent(channelId, gapPostId)` + `ratchetGapEvents: Channel<RatchetGapEvent>` in KeyOrchestrator.
- `KeyOrchestrator.reportRatchetGap()` — non-suspending trySend.
- `FragmentIngestor.attemptConfirmation()` — emits gap event when decrypt returns null.
- `ChannelSyncCoordinator.startGapResolution()` — loops over gap events, fetches missed fragments per affected channel.
- ShadowMeshApplication wires the pipeline.
- Best-effort v1: resolution succeeds only if missing intermediate posts are fetchable from peers.

### Phase 1 fixes — CancellationException swallow audit (2026-06-02)

14 pre-existing catch(e: Exception) blocks in suspend contexts fixed across 5 files.
Root issue: SILENT_FAILURE_AUDIT.md had added Diag.swallowed to all catch sites but
did not add the CancellationException rethrow required by CRYPTO-4 and Phase 3 check 5.

Files: ChannelSyncCoordinator.kt (3), NetworkStateCoordinator.kt (1), MeshSyncWorker.kt (2),
ForumViewModel.kt (6), OnboardingViewModel.kt (2).

Most impactful fix: NSC's executeTransition() was converting scope cancellation to
TransitionResult.Failure, potentially triggering incorrect rollback on shutdown.

### Open items (final state for this session)

1. [DEPLOYMENT BLOCKER] Attestation root placeholders (external device/keys required).
2. [ARCH] S1: BLE/WiFi/LAN transports not wired.
3. [ARCH] S2: DHT seed list empty.
4. [MEDIUM] Ratchet desync on out-of-order delivery (Phase 2 item 7 — complex).
5. [LOW] HKDF test vectors determinism-only.
6. [LOW] PostEntity stub encryptedTier0=ByteArray(0) for SYNCING received posts.
7. [LOW] RevocationUpdate: DHT-only peers dropped (null publicIdentity).
8. [LOW] DiscoveredPeerCache: only DHT entries upserted (BLE/LAN unwired).

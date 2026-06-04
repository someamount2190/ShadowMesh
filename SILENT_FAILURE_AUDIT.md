# SHADOWMESH — Silent-Failure Audit & Instrumentation Worklist

Goal: **nothing fails silently.** Every place the code can swallow an exception, mask a
failure with a default, or degrade quietly should report through the `Diag` seam
(`:core:diagnostics`) so it surfaces in the on-device diagnostics event log (debug builds).

## Mechanism (already in place)

- `:core:diagnostics` — `Diag.swallowed / fallback / degraded / invariant / info`. No-op and
  near-free in release (`Diag.enabled == false`); the debug build installs `DiagRecorder`
  and flips it on, so reports appear in the diagnostics screen's event log.
- Pattern to apply at each site below:
  ```kotlin
  } catch (e: Exception) {
      Diag.swallowed("<subsystem>", "<stable-code>", e, "key" to value)   // was: catch (_: Exception) {}
  }
  // or, for a masked failure:
  val x = compute() ?: run { Diag.fallback("<subsystem>", "<code>", "why default"); DEFAULT }
  ```

## Instrumented so far (worked examples)

- [x] core/mesh/.../delivery/StoreAndForwardManager.kt — replicate-to-node, drain-retry-kept, fetch-holder-skip
- [x] core/attestation/.../HardwareAttestation.kt — verifyRootCertificate fail-closed on unconfigured root

## Remaining worklist

Each entry is a swallow/fallback site to convert to a `Diag` report. Do these under a
compiler (Claude Code): the edit is mechanical but each needs the right subsystem tag and
any useful context fields. Triage column: **G** gate/security-relevant (do first),
**A** availability, **L** low-signal/log-only-ok.

## A. Broad/empty catch sites (swallowed exceptions)

*All sites below instrumented with `Diag.swallowed` in v15.*


- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/nudge/NudgeEngine.kt:67
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/nudge/NudgeEngine.kt:85
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/anchor/AnchorHandoffManager.kt:120
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/anchor/AnchorHandoffManager.kt:237
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/FragmentFetcher.kt:161
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/FragmentFetcher.kt:186
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/FragmentFetcher.kt:212
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/FragmentFetcher.kt:276
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/FragmentFetcher.kt:293
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/survival/SurvivalModeEngine.kt:165
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/files/ShadowFilesChunker.kt:221
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/circuit/OnionCircuit.kt:229
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/gossip/GossipEngine.kt:192
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/gossip/GossipEngine.kt:264
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/gossip/GossipEngine.kt:305
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/NatTraversalEngine.kt:72
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/NatTraversalEngine.kt:117
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/wifi/WiFiDirectTransport.kt:162
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/wifi/WiFiDirectTransport.kt:177
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/wifi/WiFiDirectTransport.kt:190
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/wifi/WiFiDirectTransport.kt:208
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/wifi/WiFiDirectTransport.kt:263
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/ble/BleGattTransport.kt:202
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/ble/BleGattTransport.kt:203
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/lan/LanSubnetTransport.kt:91
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/lan/LanSubnetTransport.kt:100
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/lan/LanSubnetTransport.kt:151
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/lan/LanSubnetTransport.kt:202
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/lan/LanSubnetTransport.kt:240
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/privacy/SndpEngine.kt:156
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/privacy/InMeshMixProtocol.kt:135
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/migration/FragmentMigrationManager.kt:86
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/migration/FragmentMigrationManager.kt:96
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/dht/DhtEngine.kt:65
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/dht/DhtEngine.kt:113
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/dht/DhtEngine.kt:166
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/dht/DhtEngine.kt:207
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/dht/DhtEngine.kt:297
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/dht/DhtEngine.kt:317
- [x] core/platform/src/main/kotlin/mesh/shadowmesh/platform/ShadowMeshVpnService.kt:117
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/HardwareAttestation.kt:311
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/HardwareAttestation.kt:366
- [x] core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/AppArtifactDescriptor.kt:113
- [x] core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/visual/VisualFrameProtocol.kt:124
- [x] core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/AppArtifactAcquirer.kt:215
- [x] core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/ApkArtifactVerifier.kt:101
- [x] core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/ApkArtifactVerifier.kt:143
- [x] core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/DistributionConstants.kt:94
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/PanicWipeManager.kt:108
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/PanicWipeManager.kt:120
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/PanicWipeManager.kt:130
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/PanicWipeManager.kt:132
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/PanicWipeManager.kt:145
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/PanicWipeManager.kt:153
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/PanicWipeManager.kt:157
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/PanicWipeManager.kt:159

## B. catch(e:) blocks (verify each logs AND reports via Diag, not just Log.w)

*All sites below instrumented in v15.*


- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/StoreAndForwardManager.kt:110
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/StoreAndForwardManager.kt:144
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/StoreAndForwardManager.kt:195
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/fragment/FragmentationEngine.kt:143
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/circuit/OnionCircuit.kt:185
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/trust/TrustChainValidator.kt:83
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/trust/TrustChainValidator.kt:240
- [x] core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/migration/AnticipatoryReplicationManager.kt:71
- [x] core/platform/src/main/kotlin/mesh/shadowmesh/platform/OemBatteryExemption.kt:160
- [x] core/platform/src/main/kotlin/mesh/shadowmesh/platform/ShadowMeshVpnService.kt:94
- [x] core/platform/src/main/kotlin/mesh/shadowmesh/platform/ShadowMeshVpnService.kt:119
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/nfc/NfcBootstrapCoordinator.kt:234
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/nfc/NfcBootstrapCoordinator.kt:277
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/nfc/NfcBootstrapCoordinator.kt:343
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/HardwareAttestation.kt:148
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/HardwareAttestation.kt:193
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/HardwareAttestation.kt:201
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/KeyboxRevocationCache.kt:158
- [x] core/attestation/src/main/kotlin/mesh/shadowmesh/attestation/KeyboxRevocationCache.kt:207
- [x] core/crypto/src/main/kotlin/mesh/shadowmesh/crypto/CryptoResult.kt:43
- [x] core/nsc/src/main/kotlin/mesh/shadowmesh/nsc/NetworkStateCoordinator.kt:425
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/BiometricKeyManager.kt:100
- [x] core/security/src/main/kotlin/mesh/shadowmesh/security/ApkIntegrityVerifier.kt:66
- [x] feature/forum/src/main/kotlin/mesh/shadowmesh/forum/TtlSweepWorker.kt:50
- [x] feature/forum/src/main/kotlin/mesh/shadowmesh/forum/backend/ChannelSyncCoordinator.kt:91
- [x] feature/forum/src/main/kotlin/mesh/shadowmesh/forum/backend/ChannelSyncCoordinator.kt:134
- [x] feature/forum/src/main/kotlin/mesh/shadowmesh/forum/backend/PostDispatcher.kt:82
- [x] feature/forum/src/main/kotlin/mesh/shadowmesh/forum/ForumViewModel.kt:130
- [x] feature/forum/src/main/kotlin/mesh/shadowmesh/forum/ForumViewModel.kt:208
- [x] feature/forum/src/main/kotlin/mesh/shadowmesh/forum/ForumViewModel.kt:212
- [x] feature/forum/src/main/kotlin/mesh/shadowmesh/forum/ForumViewModel.kt:229
- [x] feature/onboarding/src/main/kotlin/mesh/shadowmesh/onboarding/OnboardingViewModel.kt:130
- [x] feature/onboarding/src/main/kotlin/mesh/shadowmesh/onboarding/OnboardingViewModel.kt:167
- [x] app/src/main/kotlin/mesh/shadowmesh/app/MainActivity.kt:209
- [x] app/src/main/kotlin/mesh/shadowmesh/app/ShadowMeshApplication.kt:85
- [x] app/src/main/kotlin/mesh/shadowmesh/app/ShadowMeshApplication.kt:714
- [x] app/src/main/kotlin/mesh/shadowmesh/app/ShadowMeshApplication.kt:780
- [x] app/src/main/kotlin/mesh/shadowmesh/app/MeshSyncWorker.kt:62
- [x] app/src/main/kotlin/mesh/shadowmesh/app/MeshSyncWorker.kt:79
- [x] app/src/main/kotlin/mesh/shadowmesh/app/ShadowMeshForegroundService.kt:76

## C. Failure-masking fallbacks (?: default, getOrNull, getOrElse) — review each

Count: 124 sites. Many are legitimate (descriptive Outcome.Failed returns in distribution are fine). Flag only those that drop a failure without any signal. Full list:

```
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/StoreAndForwardManager.kt:207
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/delivery/DistributedRetransmissionManager.kt:133
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/files/ShadowFilesReassembler.kt:121
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/files/ShadowFilesReassembler.kt:123
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/files/ShadowFilesReassembler.kt:134
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/files/ShadowFilesReassembler.kt:147
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/files/ShadowFilesReassembler.kt:148
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/circuit/EntryNodeStore.kt:44
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/circuit/EntryNodeStore.kt:218
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/circuit/OnionCircuit.kt:242
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/gossip/GossipEngine.kt:238
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/gossip/HardenedChallengeLayer.kt:81
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/wifi/WiFiDirectTransport.kt:188
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/wifi/WiFiDirectTransport.kt:201
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/transport/lan/LanSubnetTransport.kt:160
core/mesh/src/main/kotlin/mesh/shadowmesh/mesh/migration/AnticipatoryReplicationManager.kt:129
core/crypto/src/main/kotlin/mesh/shadowmesh/crypto/CryptoResult.kt:17
core/crypto/src/main/kotlin/mesh/shadowmesh/crypto/NodeCallsign.kt:177
core/storage/src/main/kotlin/mesh/shadowmesh/storage/RatchetStateStore.kt:123
core/nsc/src/main/kotlin/mesh/shadowmesh/nsc/NetworkStateCoordinator.kt:389
core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/AppArtifactSeeder.kt:57
core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/AppArtifactAcquirer.kt:72
core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/AppArtifactAcquirer.kt:74
core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/AppArtifactAcquirer.kt:87
core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/AppArtifactAcquirer.kt:89
core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/AppArtifactAcquirer.kt:94
core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/AppArtifactAcquirer.kt:114
core/distribution/src/main/kotlin/mesh/shadowmesh/distribution/ApkArtifactVerifier.kt:78
feature/ui/src/main/kotlin/mesh/shadowmesh/ui/detail/PostDetailScreen.kt:150
feature/ui/src/main/kotlin/mesh/shadowmesh/ui/detail/PostDetailScreen.kt:151
feature/ui/src/main/kotlin/mesh/shadowmesh/ui/nav/NavGraph.kt:123
feature/ui/src/main/kotlin/mesh/shadowmesh/ui/nav/NavGraph.kt:128
feature/ui/src/main/kotlin/mesh/shadowmesh/ui/nav/NavGraph.kt:142
feature/ui/src/main/kotlin/mesh/shadowmesh/ui/nav/NavGraph.kt:144
feature/ui/src/main/kotlin/mesh/shadowmesh/ui/nav/NavGraph.kt:148
feature/ui/src/main/kotlin/mesh/shadowmesh/ui/onboarding/OnboardingScreen.kt:648
feature/forum/src/main/kotlin/mesh/shadowmesh/forum/TtlSweepWorker.kt:40
feature/forum/src/main/kotlin/mesh/shadowmesh/forum/backend/PostDispatcher.kt:131
feature/forum/src/main/kotlin/mesh/shadowmesh/forum/KeyOrchestrator.kt:132
feature/forum/src/main/kotlin/mesh/shadowmesh/forum/PostEngine.kt:142
feature/forum/src/main/kotlin/mesh/shadowmesh/forum/PostEngine.kt:216
feature/forum/src/main/kotlin/mesh/shadowmesh/forum/PostEngine.kt:266
feature/forum/src/main/kotlin/mesh/shadowmesh/forum/PostEngine.kt:429
feature/debug-diagnostics/src/main/kotlin/mesh/shadowmesh/debug/SubsystemProbes.kt:25
app/src/main/kotlin/mesh/shadowmesh/app/MainActivity.kt:203
app/src/main/kotlin/mesh/shadowmesh/app/ShadowMeshForegroundService.kt:69
```

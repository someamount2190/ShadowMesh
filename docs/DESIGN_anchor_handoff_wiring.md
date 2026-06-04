# DESIGN — Anchor Handoff Wiring & Concrete `AnchorTransport`

Status: **blocked on design decisions (below), not on implementation effort.**
Audience: implementer of the anchor-handoff path. Cross-ref: `STUB_AUDIT.md` S9, S3.

## Why this doc exists

`AnchorHandoffManager` (`core/mesh/anchor/AnchorHandoffManager.kt`) is fully written and is the
sole emitter of the `RECLAIM_DHT_SLICE` NSC rollback opcode. But it is **never constructed in
production**, and its `AnchorTransport` interface has **no concrete implementation**. So the
entire `P1_DATA_INTEGRITY` "zero data loss" handoff path is dead code, and the `RECLAIM_DHT_SLICE`
replay handler is unreachable (correctly fail-loud per S3).

Wiring it is not a typing task. Three of the five `AnchorTransport` methods require **new protocol
primitives**, and the central concept — a "DHT slice" that a node *owns* and can *hand off* — is
**not implemented by the current DHT**, which is replication-based (`store` → closest-K via
`iterativeFindNode`; `DhtValue` has key+ttl but **no owner field**). This doc pins the decisions
that must be made before any of that code can be correct.

## The core decision: ownership model

The replication DHT has no notion of a node "owning" a key range. Anchor handoff assumes one.
Pick one model; everything else follows.

- **Option A — Replication-only (no ownership).** "Handoff" = ensure the target now also holds
  the slice's values (redundancy), then update *routing* so lookups prefer the new anchor. Source
  keeps its copies. Simplest; matches the existing DHT. `revertSliceTransfer` becomes "re-broadcast
  routing pointing back at source" — **no data movement to undo**. Downside: not a true handoff;
  storage isn't reclaimed from the source.
- **Option B — Authoritative ownership (move).** Introduce an owner/assignment record (new field
  on `DhtValue` or a side table keyed by NodeId range). "Handoff" transfers authority; source may
  drop its copies after commit. `revertSliceTransfer` = restore source authority + re-store any
  dropped values. Truer to the design's intent, but requires an ownership store, a migration, and
  a DHT `remove`/`expire-at-target` RPC that **does not exist today**.

**Recommendation:** Option A for beta (it needs no new at-rest state and no remove RPC), with the
routing-update message (below) as the only new primitive. Revisit B only if storage reclamation
from the old anchor becomes a requirement.

## Slice membership definition (needed for both options)

Define the slice handed from `source` to `target` as the set of local keys closer to `target` than
to `source` in Kademlia space:

```
slice(source, target) = { key ∈ localStore : key.xorDistance(target) < key.xorDistance(source) }
```

`NodeId.xorDistance` exists (`DhtModels.kt:32`). **Blocker:** `localStore` is private and has no
public enumeration — only `getLocal(key)` / `localStoreSize()` (`DhtEngine.kt:238–264`). So step 0
is a small, well-defined new API:

```kotlin
// DhtEngine
/** Snapshot of local values whose key is closer to [target] than to [source]. RAM read, no I/O. */
fun sliceToward(source: NodeId, target: NodeId): List<DhtValue>
```

This is mechanical and unit-testable on the JVM (no Android) — the one piece I could write now
without a decision, but it is inert until the rest is decided, so it is specified here rather than
shipped half-wired.

## Per-method implementation map

| `AnchorTransport` method | Existing primitive | New work |
|---|---|---|
| `transferDhtSlice(s,t)` | `DhtTransport.store(targetContact, value)` per slice entry; resolve `t`→`DhtContact` via `routingTable.findClosest`/`peerContact` | needs `DhtEngine.sliceToward` (above); decide retry/timeout; return false on any push failure |
| `verifySliceMerkle(s,t)` | `hkdf.sha3_256` over sorted `(key‖valueHash)`; `FragmentationEngine` Merkle tree (`FragmentationEngine.kt:87`) | define canonical slice serialization (sort by key bytes) so both sides compute the same root |
| `broadcastRoutingUpdate(old,new)` | gossip fan-out exists for fragments | **new signed control message** `ANCHOR_UPDATE{oldId,newId,seq,sig}` + receiver handler that updates `routingTable`; must be signed (Dilithium+Ed25519 via `HybridSigner`) and anti-replayed (seq) or it is a routing-poisoning vector |
| `revertSliceTransfer(s,t)` | Option A: re-call `broadcastRoutingUpdate(new→old)` | Option B: local re-store + target `remove` RPC (**no remove RPC exists** — would need adding) |
| `reembedHoneyAnchor(new)` | honey registry in `core/security` / `GossipEngine.broadcastHoneyFragment` | wire the new anchor's honey key into the registry; best-effort (already non-blocking in the transition) |

## Wiring plan (after the decision)

1. Implement `DhtEngine.sliceToward` (+ JVM unit test).
2. Implement the chosen `revertSliceTransfer` semantics and, if Option B, the `remove`/expire RPC.
3. Add the `ANCHOR_UPDATE` signed gossip control message + verified receiver handler.
4. Implement `class DhtAnchorTransport(dhtEngine, gossipEngine, signer, scope) : AnchorTransport`.
5. Construct `AnchorHandoffManager` in `ShadowMeshApplication` (inject `nsc`, `dhtEngine`,
   transport, scope). Lifecycle (scan/advertise/timers) owned by `ShadowMeshForegroundService`,
   consistent with the other engines.
6. Route the `RECLAIM_DHT_SLICE` **replay** handler to the *same* `revertSliceTransfer` the
   in-memory checkpoint lambda uses (so persisted-replay and in-memory rollback stay identical),
   replacing the current fail-loud `error(...)`. The handler then needs the transport injected
   into `registerNscRollbackHandlers`.
7. Verification: Phase 6 integration tests already cover handoff + Merkle-mismatch rollback —
   run them on-device; add a process-death-mid-handoff test that exercises the replay path.

## Open decisions for the maintainer

1. **Ownership model: A (replication + routing) or B (authoritative move)?** Everything above forks
   here. Recommend A for beta.
2. **Is storage reclamation from the old anchor a beta requirement?** If yes → B and a remove RPC.
3. **`ANCHOR_UPDATE` trust gate:** which trust level may originate one, and how is it rate-limited?
   (Routing updates are a poisoning surface; this is a security decision, not a wiring one.)

Once 1–3 are answered, steps 1–7 are mechanical and individually verifiable. None of it should be
written before then — guessing the ownership model in a zero-data-loss path is how silent
inconsistency gets shipped.

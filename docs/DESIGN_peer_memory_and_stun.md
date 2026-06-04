# Peer Memory & STUN Metadata-Leak — design notes

## Part 1 — Peer memory (PeerModelEntity / EncounterAbstractor)

The shape you described is right: persist derived abstractions, keep raw events RAM-only,
never let the timestamp touch disk. These files make the implicit decisions explicit.

### What persists (`PeerModelEntity`, SQLCipher table `peer_models`)
Derived abstractions only: delivery weight (+ confidence), a coarse time-of-day profile,
frequency inputs, observed-channel bitset. Survives restart/reboot; gone on panic wipe.

### What doesn't (`ActiveEncounterSession`, RAM)
The live encounter buffer — running counters and `sessionStartMs`. Dropped when the
encounter ends and the snapshot is folded in. `sessionStartMs` is the only wall-clock value
and never persists.

### Decisions made explicit (the things that would otherwise be decided in the DAO)

1. **Time-of-day = integer counts, not floats.** Four `Long` counts per quarter; the
   distribution is derived on read (`count/total`). Floats drift under repeated
   nudge-and-renormalise and never stay `== 1.0`. Counts are exact.

2. **Honest privacy claim.** The four counts ARE a lossy recording of every timestamp ever
   seen, quantised to 6-hour buckets. An adversary who seizes the DB CAN read "morning
   contact." The guarantee is *"timestamp coarsened to a quarter-day bucket and summed,"*
   not *"timestamp is gone."* The KDoc says this in those words.

3. **Delivery weight = EWMA + sample count.** `deliveryWeight` is an EWMA in [0,1];
   `deliverySamples` is the confidence. 0.93-from-one-encounter and 0.93-from-fifty are
   different trust levels, and callers must check `deliverySamples` (the DAO's
   `reliableRelays` enforces a minimum in SQL). EWMA means one bad encounter can't swing a
   long-trusted peer and one lucky encounter can't fake a proven one. Alpha = 0.30.

4. **Frequency derived from mesh-global monotonic sequence, not wall-clock.** Storing the
   bucket would freeze a derived value; storing `encounterCount` + seq window lets the
   bucketing rule change without a migration.

### Crash vs clean-end boundary (the bias trap)
Folding on clean end only means a peer that always disconnects uncleanly never updates —
silently under-counting exactly the unreliable peers. Default mitigation (documented in
`EncounterAbstractor`): **fold the partial snapshot on an unclean teardown too**, so flaky
peers are penalised (low delivery ratio) rather than excused. Optional: checkpoint long
sessions — OFF by default because it reintroduces a timestamp on disk.

### Migration
`peer_models` added as `MIGRATION_9_10` (pure CREATE TABLE, no data transform); DB version
9 → 10. Validate against a Room migration test before deployment.

---

## Part 2 — STUN DNS/IP leak (the "tunnel into onion with IP" item)

### The leak
The mesh is otherwise IP-only (seeders are IP:port). The exception was
`NatTraversalEngine.DEFAULT_STUN_SERVERS`, which used hostnames
(`stun.l.google.com`, `stun.cloudflare.com`, ...). `discoverMappedAddress()` called
`sendStunBindingRequest(stun.host, ...)`, which:

1. **DNS leak** — resolves the STUN hostname via the local/ISP resolver in clear text,
   announcing "this device runs a P2P / NAT-traversal app" *before any tunnelling*. Classic
   DNS-leak-around-the-tunnel.
2. **IP leak** — the binding request shows this node's real source IP to a third-party STUN
   operator (Google/Cloudflare), linking real-IP ↔ "ShadowMesh user."

### The fix
- **IP-pinned STUN servers.** `StunServer` now holds an `ip`, not a `host`. A hostname is
  structurally unrepresentable, so a DNS lookup cannot happen. Rotated via signed gossip,
  like the seed list.
- **`StunPrivacyPolicy`**, default **`CIRCUIT_ONLY`**: the binding request is tunnelled
  through the onion circuit (`CircuitStunSender`, implemented over `CircuitManager`) and
  egresses from the exit hop — neither the local resolver nor the STUN operator sees this
  node. If no circuit is available it **fails closed** (returns null, reports a `Diag`
  degraded event), and the caller falls back to a mesh relay. It NEVER silently drops to
  clear-text. `DIRECT_IP_ONLY` (no DNS, but operator sees IP) and `DISABLED` are opt-in.
- Trade-off, stated in code: under `CIRCUIT_ONLY` the discovered mapped address is the
  circuit egress, not this node's own NAT mapping. Peers reach this node via the
  circuit/relay rather than a directly-punched hole tied to its real IP. That is the
  intended privacy posture, not a regression.

### Honest status
This STUN path was **unwired scaffolding**: there is no concrete `UdpSocketAdapter`
implementation in the tree, and `ShadowMeshApplication` called `NatTraversalEngine()` with
no arguments — a pre-existing build break independent of this change. Rather than fabricate
an untestable socket layer, the fix adds a fail-closed `NoOpUdpSocketAdapter` (sends
dropped, STUN returns null) and wires the constructor correctly, so the build is honest and
the node degrades to mesh-relay connectivity. A real `DatagramSocket`-backed adapter and the
`CircuitStunSender` over `CircuitManager` are the remaining implementation work; the leak
surface is now closed by construction (no hostnames) regardless of when they land.

---

## Part 3 — Hole-punch latency under circuit routing (the timeout question)

**Q: routing STUN through the circuit increases latency — how does that affect the
probability of a successful hole punch before the timeout? Modelled, or adaptive timeout?**

Both, but the first finding reframes the question:

### Circuit STUN and hole punching do not coexist
A STUN request sent through the circuit egresses from the **exit hop**, so the reflexive
address returned is the exit hop's, **not this node's own NAT mapping**. Classic UDP hole
punching requires knowing your *own* mapping, which only a **direct** STUN query reveals. So
`CIRCUIT_ONLY` is a different connectivity mode — peers reach you *through* the circuit/relay,
not via a punched hole — and it feeds the relay path, not `punch()`. Therefore **circuit STUN
adds zero latency to hole punching**: the two are mutually exclusive. Hole punching only runs
under `DIRECT_IP_ONLY`, where STUN is direct and there is no circuit in the path.

### Where latency actually matters, and the model
For the `DIRECT_IP_ONLY` punch path, the latency that matters is **not** STUN discovery and
**not** circuit latency — it is **rendezvous skew**: the two peers learn "punch now" via the
DHT at slightly different times. Model (implemented in `estimateAdaptivePunchPlan`):

- A UDP NAT mapping, once created by an outbound probe, lives for `T_nat` ≈ 30–120 s. STUN
  discovery latency is sub-second — three orders of magnitude below `T_nat` — so it does not
  meaningfully shrink the punch window. **Discovery latency is a non-factor.**
- The binding constraint is that a probe's receive window must stay open while the peer's
  probe is in flight, i.e. the window must exceed the coordination skew Δ ≈ DHT RTT.
- Per attempt whose window covers Δ, success ≈ `p0` (≈0.8 for full-cone/restricted NAT, ≈0
  for symmetric — the latter returns `SymmetricNatFailure`). Over `n` such attempts:
  **P(success) ≈ 1 − (1 − p0)^n.**

### Adaptive schedule (not a fixed timeout)
The old code used a fixed 200 ms first window with `×2` backoff and a 5 s cap — which
**silently fails whenever Δ > 200 ms** (any cross-continent or multi-hop rendezvous), because
even the first probe's window can't cover the skew. The replacement sizes the schedule to the
estimated RTT:

- `firstWindowMs = clamp(max(200ms, 2·Δ), … , 4000ms)` — the **first** attempt already covers
  the skew, instead of relying on luck.
- attempt count grows until the cumulative backoff budget approaches a 20 s ceiling (still ≪
  `T_nat`), keeping `P(success)` high while bounding total time.
- `punch()` takes `coordinationRttMs` (pass the measured DHT RTT) and emits the plan +
  predicted success as a `Diag` event for telemetry.

Net: discovery/circuit latency does not threaten hole punching (mappings outlive it by
orders of magnitude); coordination skew does, and the timeout is now adaptive to it rather
than fixed. Unit-tested in `NatTraversalPunchPlanTest` (pure model, JVM-runnable). The `p0`
value and `T_nat` assumption should be validated against real two-device NAT measurements —
the model gives the schedule, field data gives the constants.

### RTT estimator (the initial-estimator question)
The skew estimate feeds from a Jacobson/Karels estimator (`RttEstimator`, RFC 6298), NOT
from STUN time. STUN RTT measures you ↔ a well-peered public anycast server and systematically
*under*-estimates the mesh rendezvous path — and under-estimation is the dangerous direction
(too-small first window → silent miss). So STUN RTT is only ever a floor, never the estimate.

- **Sample source:** the rendezvous path itself. RTT is harvested around the real DHT round
  trips in `NatAwareDhtTransport` (`ping`, `findNode`), recorded per-peer, and only on a
  successful round trip.
- **Karn's rule:** samples from a retried/duplicated rendezvous are discarded (ambiguous
  attribution). `recordSample(..., retried = true)` drops them.
- **Variance, not just mean:** `rtoMs()` returns `SRTT + K·RTTVAR` (K=4), so a stable LAN path
  converges to a tight window automatically and a jittery relayed path gets a wide one —
  without hand-tuning a flat multiplier. The punch schedule consumes this RTO directly
  (`estimateAdaptivePunchPlanFromRto`), since the variance term already covers the tail.
- **Cold start:** per-transport seed (LAN ≈ 40 ms, INTERNET ≈ 500 ms, UNKNOWN ≈ 800 ms — the
  TCP-style conservative initial RTO), because a WiFi-Direct peer and a relayed peer differ by
  an order of magnitude; one global prior would be wrong for half of cases.
- **Backoff:** `onTimeout` doubles SRTT until the next sample (RFC 6298 §5.5).

Two honest limits. (1) What actually constrains the window is the *one-way* desync between
peers, but measuring one-way delay needs synced clocks (an NTP dependency + leak), so RTT is a
conservative proxy — worst-case relative skew is bounded by ~RTT. A future "punch at timestamp
T" rendezvous would collapse skew to clock-sync error and make this estimator nearly moot, but
that needs clocks we don't have. (2) The estimator is **RAM-only** (per-process, like
`sessionStartMs`) and is never persisted into `PeerModelEntity` — a stored per-peer RTT
distribution is a timing fingerprint, which the peer-memory design keeps off disk.
Unit-tested in `RttEstimatorTest` (convergence, variance widening, Karn discard, clamps).

### Adapting to changing conditions — and why reseed-on-handoff was REJECTED
The estimator adapts continuously within a process (EWMA per nodeId), and the RTTVAR term
widens the window *immediately* on a regime change (e.g. WiFi→cellular: the first surprising
sample spikes |SRTT−R|, so RTO grows that same sample even before SRTT converges). It does
NOT adapt across process restarts (RAM-only, by privacy design — every launch is cold).

A faster "detect the handoff and reseed SRTT to the new path's seed" mechanism was considered
and **deliberately not built**, for a security reason:

- The handoff signal is `pathClass`, derived from `peer.address`, which is NOT cryptographically
  bound to the nodeId (the routing layer accepts addresses from `findNode` responses without a
  per-address signature). So an attacker who can influence routing can FORGE a path-class flip.
- A reseed driven by that signal is therefore an attacker-reachable control input. They cannot
  choose the RTT *value* (the reseed target is a local constant, never peer-supplied — this is
  a hard design rule), but they can force a reset to a known bucket repeatedly: a "reset
  treadmill" that prevents convergence (downgrade-to-baseline), and forcing the LAN bucket
  yields a too-small window that degrades hole-punch success.
- The plain EWMA has a better security property: it is SAMPLE-DRIVEN. Moving SRTT requires
  serving real round trips at a chosen latency — costly and self-limiting. Reseed-on-handoff
  replaces that with a cheap forgeable trigger. The performance upside (shaving a few hundred
  ms off a handful of post-handoff punches) does not justify the new surface.

**If reseed is ever revisited**, only the monotonic-safe-direction form is acceptable: it may
WIDEN (inflate RTTVAR) but never SHRINK SRTT below the learned value, rate-limited per peer,
target always a constant — so the only attacker-reachable effect is benign (wider windows).
The real upstream fix is to authenticate the address↔nodeId binding so the trigger can't be
forged at all.

### Staleness widening (the realistic vanish-and-return case) — IMPLEMENTED
The common real case isn't a clean in-session handoff; it's a peer that goes quiet for minutes
and returns, possibly on a different network. `rtoMs()` now widens the window as a function of
time since the last accepted sample: multiplier 1.0 within a 30 s grace, ramping linearly to
3× by 5 min idle, capped so a long-idle peer behaves like a cold peer on its path rather than
ballooning. This captures most of what reseed was for, in the SAFE direction only — stale state
means "be more cautious," never "use a smaller window" — and is not usefully attackable: the
most an adversary could induce is making you wait longer before reusing a peer, which is not an
attack. RAM-only, like the rest of the estimator. Unit-tested for fresh-not-widened, monotonic
widening, cap, and clock-reset-on-fresh-sample.

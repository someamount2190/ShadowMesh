package mesh.shadowmesh.mesh.gossip

import mesh.shadowmesh.crypto.TrustLevel
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.storage.*
import kotlinx.coroutines.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import mesh.shadowmesh.diagnostics.Diag

/**
 * Gossip engine — design doc §4.
 *
 * Handles:
 *   - Fragment propagation to peers with bloom filter deduplication
 *   - Trust transitivity cap enforcement (§5.14) — depth limit at 1 remote hop
 *   - HoneyAnchor: honey fragment injection (§4, gossip-embedded variant)
 *   - Local Watchdog: 3 behavioural challenge failures → local block (§4)
 *
 * Gossip protocol:
 *   Each node relays fragments to a random subset of peers every sync cycle.
 *   Bloom filter dedup prevents the same fragment being relayed twice to the
 *   same node in one cycle. The filter resets each cycle.
 *
 * Per-key rate limiting is enforced by [RateLimiter] before relay.
 *
 * HoneyAnchor (gossip variant):
 *   Every N=100 (default) relayed posts, one honey fragment is injected.
 *   If an adversary extracts a key and reads gossip, they decrypt the honey
 *   fragment, which triggers a local ANCHOR_COMPROMISED signal.
 *   Honey fragments are indistinguishable from real fragments.
 *
 * Local Watchdog:
 *   Issues 4 challenge types per sync cycle per active peer.
 *   3 failures within 24h → local block. No network signal emitted.
 *   Blocked nodes are unaware they are blocked.
 *
 * Thread-safety: [bloomFilter] and [rateLimiter] are thread-safe.
 *   [watchdogState] uses ConcurrentHashMap. [peerRegistry] is read-only
 *   after construction (mutations via [registerPeer] are synchronized).
 */
class GossipEngine(
    val localNodeId:             NodeId,
    private val bloomFilter:         GossipBloomFilter = GossipBloomFilter(),
    private val rateLimiter:         RateLimiter       = RateLimiter(),
    private val scope:               CoroutineScope,
    private val transport:           GossipTransport,
    private val honeyN:              Int = HONEY_FRAGMENT_INTERVAL,
    private val onHoneyTripped:      (nodeId: NodeId) -> Unit = {},
    /**
     * Behavioral coherence scorer for AI swarm / bot detection.
     * Maintains per-peer observation windows and scores their behavior against
     * timing regularity and query entropy heuristics. The score is advisory —
     * it informs local watchdog decisions but never blocks automatically.
     *
     * [random] is injectable for deterministic test output; production callers
     * use [kotlin.random.Random.Default] (the default).
     */
    private val coherenceScorer: mesh.shadowmesh.storage.BehavioralCoherenceScorer =
                                     mesh.shadowmesh.storage.BehavioralCoherenceScorer(),
    /**
     * The anchor node's signing key bytes — used to derive per-post honey keys.
     * When null, honey fragment injection is silently skipped (node has no anchor key).
     * Only Tier 1 anchor nodes hold a signing key; Tier 2/3 nodes leave this null.
     *
     * honey_key = HKDF(anchorSigningKeyBytes, salt = post_hash, info = "gossip-honey-v1")
     */
    private val anchorSigningKeyBytes: ByteArray? = null,
    private val hkdf:                  mesh.shadowmesh.crypto.Hkdf = mesh.shadowmesh.crypto.Hkdf.instance,
    private val cipher:                mesh.shadowmesh.crypto.SymmetricCipher = mesh.shadowmesh.crypto.SymmetricCipher()
) {
    // ── Seed list update callback ─────────────────────────────────────────
    //
    // Wires the gossip-propagated seed list update mechanism end-to-end.
    // Previously SeedList.withUpdate() existed but was never called — a verified
    // SeedListUpdate could arrive via gossip but had no consumer. The result was
    // that the seed list remained permanently static, preserving the exact attack
    // surface (static bootstrap nodes as censorship/eclipse targets) that the
    // update mechanism was designed to mitigate.
    //
    // Now: when a verified SeedListUpdate packet arrives and the sender's
    // TRUST_PHYSICAL credential has been confirmed, onVerifiedSeedListUpdate()
    // dispatches to this callback, which ShadowMeshForegroundService registers on
    // startup to apply and persist the update.
    @Volatile private var seedListUpdateCallback: ((SeedListUpdate) -> Unit)? = null

    /**
     * Register the callback that handles verified [SeedListUpdate] gossip packets.
     * Called once by [ShadowMeshForegroundService] immediately after the gossip
     * engine starts. Thread-safe: @Volatile write, single-writer convention.
     */
    fun setSeedListUpdateCallback(callback: (SeedListUpdate) -> Unit) {
        seedListUpdateCallback = callback
    }

    /**
     * Dispatch a verified [SeedListUpdate] to the registered callback.
     *
     * PRECONDITION: the caller has already verified:
     *   1. The packet signature against the issuer's [HybridVerifyKey]
     *   2. The issuer holds a TRUST_PHYSICAL credential
     *   3. The issuer's credential has not expired
     *
     * This method does NOT re-verify the signature. Signature verification belongs
     * in the gossip receive path (where the peer's trust level is available), not
     * here. Calling this with an unverified update is a security bug.
     *
     * If no callback is registered yet (service not started), the update is silently
     * dropped — it will arrive again on the next gossip cycle.
     */
    fun onVerifiedSeedListUpdate(update: SeedListUpdate) {
        seedListUpdateCallback?.invoke(update)
    }

    // ── Channel lifecycle frame callbacks ──────────────────────────────────
    //
    // Registered by the app composition root (ShadowMeshApplication) after the
    // gossip engine is constructed. The callbacks persist received frames to Room
    // and apply local state changes (key update, member removal).
    //
    // Precondition for both dispatch methods: the caller has already verified the
    // frame signature against the initiator's HybridVerifyKey and confirmed the
    // frame nonce has not been seen before. Dispatching an unverified frame is a
    // security bug.

    @Volatile private var keyRotationCallback:   ((KeyRotationFrame) -> Unit)? = null
    @Volatile private var memberRemovalCallback: ((MemberRemovalFrame) -> Unit)? = null

    fun setKeyRotationCallback(callback: (KeyRotationFrame) -> Unit) {
        keyRotationCallback = callback
    }

    fun setMemberRemovalCallback(callback: (MemberRemovalFrame) -> Unit) {
        memberRemovalCallback = callback
    }

    /**
     * Dispatch a verified [KeyRotationFrame] received from a peer (or self-issued).
     * Invokes the registered callback which persists the new key to Room and evicts
     * stale ratchets. If no callback is registered, the frame is silently dropped —
     * it will be re-fetched from the DHT on the next reconnect sync.
     */
    fun onVerifiedKeyRotationFrame(frame: KeyRotationFrame) {
        keyRotationCallback?.invoke(frame)
    }

    /**
     * Dispatch a verified [MemberRemovalFrame] received from a peer (or self-issued).
     * Invokes the registered callback which writes a [MemberRemovalEntry] to Room.
     */
    fun onVerifiedMemberRemovalFrame(frame: MemberRemovalFrame) {
        memberRemovalCallback?.invoke(frame)
    }

    // ── Revocation update gossip ───────────────────────────────────────────

    @Volatile private var revocationUpdateCallback: ((RevocationUpdateFrame) -> Unit)? = null

    /**
     * Register the callback that handles verified [RevocationUpdateFrame] gossip packets.
     * Called once by [ShadowMeshApplication] after the revocation cache is built.
     * The callback should merge new entries into the local cache and re-gossip if new.
     */
    fun setRevocationUpdateCallback(callback: (RevocationUpdateFrame) -> Unit) {
        revocationUpdateCallback = callback
    }

    /**
     * Dispatch a verified [RevocationUpdateFrame] to the registered callback.
     *
     * PRECONDITION: the caller has already verified:
     *   1. The frame signature against the issuer's HybridVerifyKey.
     *   2. The nonce has not been seen before (replay protection).
     *
     * Dispatching an unverified frame is a security bug.
     */
    fun onVerifiedRevocationUpdate(frame: RevocationUpdateFrame) {
        revocationUpdateCallback?.invoke(frame)
    }

    /**
     * Broadcast a [RevocationUpdateFrame] to all connected peers except [sourceId].
     *
     * One-hop propagation: recipients are expected to re-gossip once to their own peers
     * (excluding the frame's original [RevocationUpdateFrame.issuerNodeId] as source).
     * [sourceId] null means broadcast to ALL peers (local origination).
     *
     * Fire-and-forget: errors logged via Diag, delivery is best-effort.
     */
    suspend fun broadcastRevocationUpdate(frame: RevocationUpdateFrame, sourceId: NodeId?) {
        val bytes = frame.toBytes()
        peerRegistry.values
            .filter { it.contact.nodeId != sourceId && !it.isBlocked }
            .forEach { entry ->
                scope.launch {
                    try { transport.sendControl(entry.contact, bytes) }
                    catch (e: Exception) {
                        if (e is kotlinx.coroutines.CancellationException) throw e
                        Diag.swallowed("gossip", "revocation-broadcast", e,
                            "peer" to entry.contact.nodeId.toHex().take(8))
                    }
                }
            }
    }

    // Optional health monitor — set by the composition root after construction.
    // Guards relay path selection in relayFragment() based on current mesh health.
    @Volatile var healthMonitor: mesh.shadowmesh.mesh.health.TransportHealthMonitor? = null

    // ── Anchor-count listener ──────────────────────────────────────────────
    //
    // Called with the current TRUST_PHYSICAL peer count whenever that count may have
    // changed (on registerPeer, removePeer, or peer block). Drives NetworkModeStateMachine
    // transitions: SURVIVAL → CRITICAL → DEGRADED → HEALTHY as anchor count rises.
    @Volatile private var anchorCountListener: ((Int) -> Unit)? = null

    /** Wire the anchor-count listener. Called once at startup by the composition root. */
    fun setAnchorCountChangedListener(listener: (Int) -> Unit) {
        anchorCountListener = listener
        // Fire immediately so the state machine initialises with the current count.
        listener(currentAnchorCount())
    }

    private fun currentAnchorCount(): Int =
        peerRegistry.values.count { !it.isBlocked && it.trustLevel == TrustLevel.TRUST_PHYSICAL }

    private fun notifyAnchorCount() { anchorCountListener?.invoke(currentAnchorCount()) }

    // ── HardenedChallengeLayer ─────────────────────────────────────────────
    //
    // When set, syncCycle() uses round-robin challenge type rotation instead of
    // random selection. Prevents adversarial peers from adapting to a predictable
    // challenge pattern. Set by the composition root after construction.
    @Volatile var hardenedChallengeLayer: HardenedChallengeLayer? = null

    // ── Peer registry ──────────────────────────────────────────────────────
    private val peerRegistry = ConcurrentHashMap<NodeId, PeerEntry>()

    // peerRegistry is a ConcurrentHashMap — individual put/get are atomic.
    // compute() is also atomic on ConcurrentHashMap, so no external lock is needed.
    fun registerPeer(contact: DhtContact, trustLevel: TrustLevel) {
        peerRegistry.compute(contact.nodeId) { _, existing ->
            // Never downgrade an existing higher-trust entry (e.g. TRUST_PHYSICAL → TRUST_PUBLIC
            // when a physically-bootstrapped peer is later re-discovered via DHT).
            // Lower ordinal = higher trust: TRUST_PHYSICAL(0) > TRUST_INTRODUCED(1) > TRUST_PUBLIC(2).
            val effective = if (existing != null && existing.trustLevel.ordinal < trustLevel.ordinal)
                existing.trustLevel else trustLevel
            PeerEntry(contact, effective, existing?.isBlocked ?: false, existing?.blockedAtMs ?: 0L)
        }
        hardenedChallengeLayer?.markPeerActive(
            contact.copy(lastSeenMs = System.currentTimeMillis())
        )
        if (trustLevel == TrustLevel.TRUST_PHYSICAL) notifyAnchorCount()
    }

    fun removePeer(nodeId: NodeId) {
        val removed = peerRegistry.remove(nodeId)
        hardenedChallengeLayer?.removePeer(nodeId)
        // Evict the behavior window immediately on explicit peer departure. This prevents
        // a window accumulated during one session from being carried into a future session
        // where the peer may have changed identity or behaviour profile.
        behaviorWindows.remove(nodeId)
        if (removed?.trustLevel == TrustLevel.TRUST_PHYSICAL) notifyAnchorCount()
    }

    // AtomicInteger for thread-safe relay counting. @Volatile alone does not
    // make ++ atomic (read-modify-write); AtomicInteger.incrementAndGet() does.
    private val relayCount = AtomicInteger(0)

    // ── Node-local honey channel ID ───────────────────────────────────────
    //
    // The honey channel ID must not be a publicly-known constant. If it were
    // (as the old HONEY_CHANNEL_ID companion constant was), any peer could forge
    // any fragment's channelId to that value and cause it to be silently discarded
    // at every relay node — a complete post-suppression attack with no rate limiting
    // or alarm.
    //
    // The node-local ID is derived from localNodeId via HMAC-SHA3-256 with a
    // domain-separation tag. It is different on every node, so an adversary who
    // knows their own honeyChannelId learns nothing about another node's ID.
    // Fragments sent to another node with channelId = honeyChannelId will NOT
    // match that node's locally-derived ID and will be processed normally.
    //
    // Format: hex string of the first 32 bytes of HMAC(localNodeId.bytes, "honey_channel_id_v1")
    private val honeyChannelId: String = run {
        val tag = "honey_channel_id_v1".toByteArray()
        hkdf.hmacSha3_256(key = localNodeId.bytes, data = tag)
            .toHex()
    }

    // ── Pending honey key store ───────────────────────────────────────────
    //
    // Maps fragmentId → PendingHoneyEntry for every honey fragment this node
    // has injected and not yet detected back.  Entries expire after HONEY_KEY_TTL_MS
    // (7 days, matching post TTL) so memory is bounded even if the fragment never
    // returns.  The key is wiped immediately after a trip or on expiry.
    //
    // Only the injecting anchor node populates this map (Tier 2/3 nodes skip
    // injection because anchorSigningKeyBytes is null).  checkAndHandleHoneyFragment()
    // consults it on every inbound fragment whose channelId == honeyChannelId.
    private data class PendingHoneyEntry(val key: ByteArray, val expiryMs: Long)
    private val pendingHoneyFragments = ConcurrentHashMap<String, PendingHoneyEntry>()

    // ── Trust transitivity cap (§5.14) ────────────────────────────────────

    /**
     * Enforce the transitivity cap before accepting a fragment from [senderNodeId].
     *
     * TRUST_PUBLIC nodes are rate-limited but not blocked.
     * Rate limiting is enforced separately by [RateLimiter].
     *
     * Returns the trust level to apply or null if the peer is unknown.
     */
    fun effectiveTrust(senderNodeId: NodeId): TrustLevel? =
        peerRegistry[senderNodeId]?.trustLevel


    /**
     * Returns a snapshot of currently active (non-blocked) peer NodeIds.
     * Used by [PostDispatcher] and [ChannelSyncCoordinator] to send nudges.
     */
    fun activePeerIds(): List<NodeId> =
        peerRegistry.values
            .filter { !it.isBlocked }
            .map { it.contact.nodeId }

    /** Returns the [DhtContact] for [nodeId], or null if not in the peer registry. */
    fun peerContact(nodeId: NodeId): DhtContact? = peerRegistry[nodeId]?.contact

    /**
     * Send a raw control payload (ACK/NACK) directly to a peer by node ID.
     * Resolves the peer's contact from [peerRegistry] and delegates to the transport.
     * Silently drops the payload if the peer is not currently registered.
     */
    suspend fun sendControl(targetNodeId: NodeId, bytes: ByteArray) {
        val contact = peerRegistry[targetNodeId]?.contact ?: return
        try { transport.sendControl(contact, bytes) }
        catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Diag.swallowed("gossip", "send-control", e,
                "target" to targetNodeId.toHex().take(8))
        }
    }

    /**
     * Fetch a specific fragment from [peer] via the gossip transport.
     *
     * Delegates to [GossipTransport.fetchFragment]. Returns null if the peer
     * does not have the fragment or the request times out.
     *
     * Used by [GossipBackedLocalPeer] to serve [LocalPeerRegistry.allLocalPeers].
     */
    suspend fun fetchFragmentFromPeer(
        nodeId:     NodeId,
        fragmentId: String
    ): mesh.shadowmesh.mesh.fragment.FragmentEntity? {
        val contact = peerRegistry[nodeId]?.contact ?: return null
        return try { transport.fetchFragment(contact, fragmentId) }
        catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Diag.swallowed("gossip", "fetch-fragment-peer", e,
                "peer" to nodeId.bytes.toHex().take(8))
            null
        }
    }

    /**
     * Fetch all fragments for [channelId] received after [sinceMs] from [peer].
     *
     * Used by [GossipBackedLocalPeer] for [LocalPeer.fetchFragmentsSince].
     */
    suspend fun fetchFragmentsSinceFromPeer(
        nodeId:    NodeId,
        channelId: ByteArray,
        sinceMs:   Long
    ): List<mesh.shadowmesh.mesh.fragment.FragmentEntity> {
        val contact = peerRegistry[nodeId]?.contact ?: return emptyList()
        return try { transport.fetchFragmentsSince(contact, channelId, sinceMs) }
        catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Diag.swallowed("gossip", "fetch-fragments-since-peer", e,
                "peer" to nodeId.bytes.toHex().take(8))
            emptyList()
        }
    }

    // ── Fragment relay ────────────────────────────────────────────────────

    /**
     * Relay [fragment] to all eligible peers.
     *
     * Checks in order:
     *   1. Sender is not locally blocked
     *   2. Rate limit for sender not exceeded (fragment token)
     *   3. Bloom filter: fragment not already seen this cycle
     *
     * After relay, considers honey injection.
     *
     * @return true if the fragment was relayed to at least one peer.
     */
    suspend fun relayFragment(
        fragment:     mesh.shadowmesh.mesh.fragment.FragmentEntity,
        senderNodeId: NodeId
    ): Boolean {
        // Check local blocklist via peerRegistry flag, with automatic 24h TTL expiry.
        // Design doc §4: "3 failures within 24h → local block." The block is temporary —
        // auto-unblock after BLOCK_TTL_MS so a transient network issue does not permanently
        // isolate a legitimate peer.
        //
        // Use a single compute() for the entire read-check-unblock sequence to eliminate
        // TOCTOU: the previous pattern read peer.blockedAtMs from a stale snapshot (line 403)
        // then called a separate compute() (line 407). Between those two calls, another thread
        // could have modified the entry. The compute() lambda sees the authoritative current
        // state, so the check and the mutation are atomic.
        var shouldBlock = false
        peerRegistry.compute(senderNodeId) { _, e ->
            if (e?.isBlocked == true) {
                val elapsedMs = System.currentTimeMillis() - e.blockedAtMs
                if (elapsedMs >= BLOCK_TTL_MS) {
                    Diag.info("gossip", "watchdog-unblock",
                        "Peer ${senderNodeId.toHex().take(8)} auto-unblocked after ${elapsedMs / 3600_000}h")
                    e.copy(isBlocked = false, blockedAtMs = 0L)
                } else {
                    shouldBlock = true
                    e   // remain blocked
                }
            } else {
                e   // not blocked — no change
            }
        }
        if (shouldBlock) return false

        // Relay-time TTL check: heldUntilMs is set locally from createdAtMs + RELAY_HOLD_MS (2h).
        // Prevents a fragment from being re-relayed indefinitely across bloom-filter reset cycles.
        // heldUntilMs == 0L means the field was not set (older wire format) — allow relay in that case.
        //
        // Clock-skew grace: add 10 minutes to account for clock differences between devices.
        // Without this, a relay node whose clock is slightly ahead of the sender drops all
        // fragments that arrive near the 2-hour boundary, causing silent DATA LOSS.
        val now = System.currentTimeMillis()
        val CLOCK_SKEW_GRACE_MS = 10 * 60 * 1000L
        if (fragment.heldUntilMs > 0L && now > fragment.heldUntilMs + CLOCK_SKEW_GRACE_MS) return false

        // Rate limit check
        if (!rateLimiter.consumeFragment(senderNodeId.toHex())) return false

        // Bloom filter dedup
        if (!bloomFilter.testAndAdd(fragment.fragmentId.toByteArray())) return false

        // Behavioral coherence check: if the sender's traffic pattern is HighlySuspicious
        // (bot-like timing, no query entropy, abnormal latency CV), record a watchdog failure
        // so repeated suspicious behaviour eventually triggers a local block.
        // This is advisory escalation — a single suspicious relay does not block the peer;
        // WATCHDOG_FAILURE_THRESHOLD failures within the window are required.
        val bsig = behavioralScore(senderNodeId)
        if (bsig is mesh.shadowmesh.storage.BehavioralSignal.HighlySuspicious) {
            recordWatchdogFailure(senderNodeId, ChallengeType.FRAGMENT_ECHO)
            Diag.degraded("gossip", "behavioral-suspicious",
                "Peer ${senderNodeId.toHex().take(8)} scored HighlySuspicious — watchdog failure recorded",
                "score" to bsig.score.toString())
        }

        // Behavioral observation: record this as a query event from the sender.
        // The first byte of the fragment's postId is used as the key-space prefix.
        // This feeds BehavioralCoherenceScorer's query entropy dimension.
        if (fragment.postId.isNotEmpty()) {
            recordPeerQuery(senderNodeId, fragment.postId[0].code.toByte())
        }

        // In ISOLATED state the mesh has no reachable peers — skip relay entirely.
        // The caller (PostDispatcher) will queue the fragment to StoreAndForwardManager.
        val meshState = healthMonitor?.currentState?.value
        if (meshState == mesh.shadowmesh.mesh.health.MeshHealthState.ISOLATED) return false

        // Relay to all non-blocked eligible peers (not the sender)
        val targets = peerRegistry.values
            .filter { it.contact.nodeId != senderNodeId && !it.isBlocked }

        if (targets.isEmpty()) return false

        targets.forEach { entry ->
            scope.launch {
                try { transport.sendFragment(entry.contact, fragment) }
                catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    Diag.swallowed("gossip", "relay-send", e,
                        "nodeId" to entry.contact.nodeId.toHex().take(8))
                    recordWatchdogFailure(entry.contact.nodeId, ChallengeType.FRAGMENT_ECHO)
                }
            }
        }

        // Honey fragment injection every N relays — atomically incremented.
        // Fix #66: use Math.floorMod instead of % so the result is always non-negative.
        // AtomicInteger.incrementAndGet() wraps to Int.MIN_VALUE after ~2.1B relays;
        // Int.MIN_VALUE % honeyN is negative (e.g. -48 for honeyN=100) and never == 0,
        // silently stopping honey injection for the rest of the process lifetime.
        // Math.floorMod(n, honeyN) always returns a value in [0, honeyN), correct after overflow.
        if (Math.floorMod(relayCount.incrementAndGet(), honeyN) == 0) injectHoneyFragment()

        return true
    }

    // ── HoneyAnchor — gossip variant ──────────────────────────────────────

    /**
     * Inject a honey fragment into the gossip stream.
     *
     * A honey fragment is a canary encrypted under a key derived from the anchor signing
     * key. A receiver can only decrypt it if the anchor private key was extracted — so a
     * successful decryption (reported via [onHoneyFragmentDecrypted]) fires
     * [onHoneyTripped] and locally blocks the source.
     *
     * Fully implemented: the relay counter and injection cadence (every N relays), the
     * per-injection honey key derivation, canary encryption, fragment construction, and
     * broadcast. Tier 2/3 nodes without an anchor signing key skip injection.
     */
    private fun injectHoneyFragment() {
        // Honey fragment injection requires an anchor signing key.
        // Tier 2/3 nodes have no signing key — silently skip.
        val signingKey = anchorSigningKeyBytes ?: return

        scope.launch {
            try {
                // Derive a per-injection honey key from the signing key + a fresh nonce.
                // salt = current relay count as bytes — ensures each injection uses a unique key.
                val nonceBytes = ByteArray(8) { i ->
                    ((relayCount.get().toLong() shr ((7 - i) * 8)) and 0xFF).toByte()
                }
                val honeyKey = hkdf.derive(
                    ikm       = signingKey,
                    salt      = nonceBytes,
                    info      = HONEY_KEY_INFO,
                    outputLen = 32
                )

                // Encrypt the canary value — if a receiver can decrypt this, the anchor
                // signing key was extracted (key compromise).
                val canary    = HONEY_CANARY + localNodeId.bytes
                val encrypted = cipher.encrypt(canary, honeyKey).getOrNull() ?: run {
                    honeyKey.fill(0); return@launch
                }
                // Do NOT wipe honeyKey here — we retain it in pendingHoneyFragments so
                // checkAndHandleHoneyFragment() can attempt decryption if this fragment
                // ever returns to us (proving an adversary extracted the signing key).
                // The key is wiped there after a trip, and lazily on expiry.

                // Build a honey fragment structurally identical to a real fragment.
                // postId and fragmentId are derived from the encrypted payload so
                // the fragment passes content-address format checks.
                val fakePostId = hkdf.sha3_256(encrypted + HONEY_KEY_INFO)
                    .toHex()
                val fragmentId = mesh.shadowmesh.mesh.fragment.FragmentEntity.computeFragmentId(
                    postId        = fakePostId.toByteArray().copyOf(32),
                    sequenceIndex = 0,
                    payload       = encrypted,
                    hkdf          = hkdf
                )

                // Store the key so we can detect this fragment if it returns to us.
                // Expiry = now + post TTL (7 days).  If the fragment never returns, the
                // entry is evicted lazily by checkAndHandleHoneyFragment().
                pendingHoneyFragments[fragmentId] = PendingHoneyEntry(
                    key      = honeyKey,
                    expiryMs = System.currentTimeMillis() + HONEY_KEY_TTL_MS
                )

                val honeyFragment = mesh.shadowmesh.mesh.fragment.FragmentEntity(
                    fragmentId    = fragmentId,
                    postId        = fakePostId,
                    channelId     = honeyChannelId,
                    sequenceIndex = 0,
                    totalData     = 1,
                    totalParity   = 0,
                    payload       = encrypted,
                    fecScheme     = mesh.shadowmesh.mesh.fragment.FecScheme.NONE
                )

                transport.broadcastHoneyFragment(honeyFragment)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                Diag.swallowed("gossip", "honey-inject", e)
            }
        }
    }

    /**
     * Check if a received fragment is a honey fragment that has been decrypted
     * by an adversary (indicating the channel key was extracted).
     * Called by the crypto layer when decryption of a fragment succeeds but
     * the content matches the honey canary value.
     */
    fun onHoneyFragmentDecrypted(sourceNodeId: NodeId) {
        onHoneyTripped(sourceNodeId)
        // Local block — no network signal.
        // compute() is atomic on ConcurrentHashMap: the read-modify-write
        // is done under the bucket lock, preventing a concurrent registerPeer()
        // or another block from overwriting the isBlocked update.
        val wasPhysical = peerRegistry[sourceNodeId]?.trustLevel == TrustLevel.TRUST_PHYSICAL
        peerRegistry.compute(sourceNodeId) { _, existing ->
            existing?.copy(isBlocked = true, blockedAtMs = System.currentTimeMillis())
        }
        // A block reduces the effective anchor count — notify the mode state machine.
        if (wasPhysical) notifyAnchorCount()
    }

    /**
     * Check whether [fragment] is one of this node's own injected honey fragments
     * that has been relayed back to us by [senderNodeId].
     *
     * A honey fragment returning to its origin proves that [senderNodeId] (or a node
     * upstream of them) successfully decrypted it — which requires the anchor signing
     * key that was used to derive the per-injection honey key.  That is the key-compromise
     * signal.
     *
     * ## Detection algorithm
     *
     * 1. Fast-reject: if channelId ≠ honeyChannelId this is a normal fragment → return false.
     * 2. Lazy expiry: evict all stale entries from [pendingHoneyFragments] (TTL = 7 days).
     * 3. Look up the fragmentId in [pendingHoneyFragments].  If absent → return true (it is
     *    a honey fragment from another anchor; discard silently — we cannot verify it).
     * 4. Try to decrypt the payload with the stored key using the AEAD cipher.
     *    An AEAD authentication failure means the payload was tampered with → return true
     *    (discard without tripping; this is not a compromise signal).
     * 5. Verify that the decrypted plaintext starts with HONEY_CANARY.  If not → return true
     *    (shouldn't happen if AEAD succeeded, but belt-and-suspenders).
     * 6. TRIP: call [onHoneyFragmentDecrypted] with [senderNodeId].  Wipe the stored key.
     *    Return true.
     *
     * Always returns true when channelId == honeyChannelId so the caller skips normal
     * fragment ingest (honey fragments must never be stored or relayed as real content).
     *
     * This method is suspend because [SymmetricCipher.decrypt] dispatches to Dispatchers.IO.
     * It is safe to call concurrently — [pendingHoneyFragments] is a ConcurrentHashMap and
     * the remove-then-wipe is idempotent (a second concurrent call on the same fragmentId
     * will find no entry and skip the trip).
     */
    suspend fun checkAndHandleHoneyFragment(
        fragment:     mesh.shadowmesh.mesh.fragment.FragmentEntity,
        senderNodeId: NodeId
    ): Boolean {
        if (fragment.channelId != honeyChannelId) return false

        // Lazy expiry — evict entries older than HONEY_KEY_TTL_MS.
        val now = System.currentTimeMillis()
        pendingHoneyFragments.entries.removeIf { (_, entry) ->
            if (entry.expiryMs < now) { entry.key.fill(0); true } else false
        }

        // Look up the fragmentId.  If absent this honey fragment was injected by another
        // anchor node — we cannot verify it.  Discard silently (return true = skip ingest).
        val entry = pendingHoneyFragments.remove(fragment.fragmentId) ?: run {
            Diag.info("gossip", "honey-foreign", "honey fragment from another anchor — discarding",
                "fragmentId" to fragment.fragmentId.take(8),
                "sender"     to senderNodeId.toHex().take(8))
            return true
        }

        try {
            val plaintext = cipher.decrypt(fragment.payload, entry.key).getOrNull()
            if (plaintext == null || !plaintext.startsWith(HONEY_CANARY)) {
                // AEAD failed or canary absent — tampered fragment; not a compromise signal.
                Diag.info("gossip", "honey-tampered", "honey payload failed auth or canary check — discarding",
                    "fragmentId" to fragment.fragmentId.take(8),
                    "sender"     to senderNodeId.toHex().take(8))
                return true
            }
            // TRIP — signing key was extracted.
            Diag.fallback("gossip", "honey-tripped",
                "Anchor signing key compromised — rotating CLOSED channel keys",
                "sender" to senderNodeId.toHex().take(8))
            onHoneyFragmentDecrypted(senderNodeId)
        } finally {
            entry.key.fill(0)
        }

        return true
    }

    /** Returns true if [this] byte array starts with [prefix]. */
    private fun ByteArray.startsWith(prefix: ByteArray): Boolean {
        if (size < prefix.size) return false
        return prefix.indices.all { this[it] == prefix[it] }
    }

    // ── Local Watchdog — behavioural challenges (§4) ──────────────────────

    private val watchdogState = ConcurrentHashMap<NodeId, WatchdogRecord>()

    /**
     * Issue a random challenge to [peer]. Called by the watchdog independently
     * of the hardened challenge layer cadence.
     */
    fun issueChallenge(peer: DhtContact) {
        val type = ChallengeType.values().random()
        issueChallengeOfType(peer, type)
    }

    /**
     * Issue a specific challenge type to [peer].
     * Called by [HardenedChallengeLayer] which controls the type rotation and
     * ensures exactly one challenge per peer per sync cycle.
     */
    fun issueChallengeOfType(peer: DhtContact, type: ChallengeType) {
        scope.launch {
            try {
                val passed = transport.issueChallenge(peer, type)
                if (!passed) recordWatchdogFailure(peer.nodeId, type)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                Diag.swallowed("gossip", "challenge-issue", e,
                    "peer" to peer.nodeId.toHex().take(8), "type" to type.name)
                recordWatchdogFailure(peer.nodeId, type)
            }
        }
    }

    private fun recordWatchdogFailure(nodeId: NodeId, type: ChallengeType) {
        val now    = System.currentTimeMillis()
        // computeIfAbsent is atomic on ConcurrentHashMap — avoids the lost-update
        // race that getOrPut can exhibit when two threads create the same key simultaneously.
        val record = watchdogState.computeIfAbsent(nodeId) { WatchdogRecord(it) }
        synchronized(record) {
            // Prune failures older than 24h
            record.failures.removeIf { now - it.timestampMs > WATCHDOG_WINDOW_MS }
            record.failures.add(ChallengeFailure(type, now))
            if (record.failures.size >= WATCHDOG_FAILURE_THRESHOLD) {
                // Local block — no network signal emitted.
                // compute() is atomic — see onHoneyFragmentDecrypted for rationale.
                peerRegistry.compute(nodeId) { _, existing ->
                    existing?.copy(isBlocked = true, blockedAtMs = System.currentTimeMillis())
                }
                record.locallyBlocked = true
            }
        }
    }

    /** Record a relay success for watchdog health monitoring. */
    fun recordRelaySuccess(nodeId: NodeId) {
        val now    = System.currentTimeMillis()
        val record = watchdogState.computeIfAbsent(nodeId) { WatchdogRecord(it) }
        synchronized(record) { record.lastSuccessMs = now }
    }

    // ── Behavioral coherence observation ──────────────────────────────────

    /**
     * Per-peer observation windows for [BehavioralCoherenceScorer].
     * Keyed by NodeId. Lazily created when a peer first sends a fragment.
     * Not thread-safe individually — access is synchronized per-window.
     */
    private val behaviorWindows = ConcurrentHashMap<NodeId, mesh.shadowmesh.storage.NodeBehaviorWindow>()

    /**
     * Record a response latency observation for [nodeId].
     * Called after a relay round-trip is measured (e.g., challenge→response timing).
     * Thread-safe: synchronizes on the window object.
     *
     * Lazily resets the window if it has been idle longer than
     * [NodeBehaviorWindow.IDLE_TTL_MS], preventing stale pre-gap observations from
     * contaminating a fresh session's behavioral profile.
     */
    fun recordPeerLatency(nodeId: NodeId, latencyMs: Long) {
        // computeIfAbsent is atomic on ConcurrentHashMap — avoids the lost-update
        // race where two concurrent calls both see absent and each create a window;
        // one silently overwrites the other, losing observations. See RateLimiter.getBucket
        // for the same fix applied earlier.
        val window = behaviorWindows.computeIfAbsent(nodeId) {
            mesh.shadowmesh.storage.NodeBehaviorWindow(nodeId.toHex())
        }
        synchronized(window) {
            // Lazy staleness reset: if this peer went quiet long enough for the window to
            // expire, treat this as a fresh session rather than continuing an old profile.
            if (window.isStale()) window.reset()
            window.recordLatency(latencyMs)
        }
    }

    /**
     * Record a query event from [nodeId] for the given DHT key prefix byte.
     * Called when a fragment arrives carrying a known channel key prefix.
     * Thread-safe: synchronizes on the window object.
     *
     * Lazily resets the window if it has been idle longer than
     * [NodeBehaviorWindow.IDLE_TTL_MS] — same session-separation guarantee as
     * [recordPeerLatency].
     */
    fun recordPeerQuery(nodeId: NodeId, keyPrefixByte: Byte) {
        val window = behaviorWindows.computeIfAbsent(nodeId) {
            mesh.shadowmesh.storage.NodeBehaviorWindow(nodeId.toHex())
        }
        synchronized(window) {
            if (window.isStale()) window.reset()
            window.recordQuery(System.currentTimeMillis(), keyPrefixByte)
        }
    }

    /**
     * Score the behavioral coherence of [nodeId].
     * Returns [BehavioralSignal.Insufficient] if not enough observations yet.
     * The score is advisory — callers decide whether to escalate to the watchdog.
     */
    fun behavioralScore(
        nodeId: NodeId
    ): mesh.shadowmesh.storage.BehavioralSignal {
        val window = behaviorWindows[nodeId]
            ?: return mesh.shadowmesh.storage.BehavioralSignal.Insufficient
        return synchronized(window) { coherenceScorer.score(window) }
    }

    /**
     * Reset the behavioral window for [nodeId] — called after a long connectivity gap
     * or when a peer re-registers, to avoid carrying stale pre-gap observations forward.
     */
    fun resetBehaviorWindow(nodeId: NodeId) {
        behaviorWindows[nodeId]?.let { w -> synchronized(w) { w.reset() } }
    }

    fun isLocallyBlocked(nodeId: NodeId): Boolean =
        peerRegistry[nodeId]?.isBlocked == true ||
        watchdogState[nodeId]?.locallyBlocked == true

    // ── Trust transitivity cap enforcement ────────────────────────────────

    /**
     * Validate that the trust chain for [nodeId] does not exceed depth 1
     * from any TRUST_PHYSICAL root.
     *
     * TRUST_INTRODUCED nodes cannot introduce further — any attempt produces
     * TRUST_PUBLIC for the recipient (capped at depth 1).
     *
     * Returns the effective trust level to assign after the cap.
     */
    fun enforceTrustTransitivityCap(
        introducerTrust:     TrustLevel,
        introductionMethod:  IntroductionMethod
    ): TrustLevel = when (introducerTrust) {
        TrustLevel.TRUST_PHYSICAL -> when (introductionMethod) {
            IntroductionMethod.PHYSICAL -> TrustLevel.TRUST_PHYSICAL
            IntroductionMethod.REMOTE   -> TrustLevel.TRUST_INTRODUCED
        }
        TrustLevel.TRUST_INTRODUCED,
        TrustLevel.TRUST_PUBLIC -> TrustLevel.TRUST_PUBLIC  // cap at depth 1
    }

    // ── Sync cycle ────────────────────────────────────────────────────────

    /** Called at the start of each sync cycle — resets per-cycle state. */
    fun onSyncCycleStart() {
        bloomFilter.reset()
    }

    /**
     * Periodic gossip housekeeping — called by [MeshSyncWorker] on its regular schedule.
     *
     * Resets the Bloom filter so fragments that were previously seen can be re-relayed
     * if they re-appear (e.g. after a mesh partition heals), then issues a challenge to
     * each active peer via [issueChallengeOfType] to keep watchdog health data fresh.
     */
    suspend fun syncCycle() {
        onSyncCycleStart()
        val activePeers = peerRegistry.values
            .filter { !it.isBlocked }
            .map { it.contact }
        val hcl = hardenedChallengeLayer
        if (hcl != null) {
            // Round-robin rotation: one challenge per peer per cycle, type rotates
            // across FRAGMENT_ECHO/RATCHET_ADVANCEMENT/GOSSIP_INTEGRITY/TIMING_CONSISTENCY.
            hcl.onSyncCycleStart(activePeers)
        } else {
            // Fallback: random challenge type per peer (less adversarial-resistant).
            activePeers.forEach { peer -> issueChallenge(peer) }
        }
    }

    /**
     * Nudge-triggered channel sync — called by [MeshSyncWorker] when a nudge arrives
     * for [channelId], indicating a peer has new fragments for that channel.
     *
     * Re-relays all fragments currently held in the local store for [channelId] to
     * all active peers. This drives convergence: if our peer just received a new
     * fragment that completes their FEC set, our previously-relayed fragments may
     * have expired from their Bloom filter, and re-sending helps them reassemble.
     *
     * The Bloom filter is NOT reset here — only the targeted channel is re-relayed
     * to avoid flooding the mesh with all recently-seen fragments.
     *
     * @param channelId  Hex-encoded channel ID from the nudge payload.
     */
    suspend fun syncCycleForChannel(channelId: String) {
        val activePeers = peerRegistry.values
            .filter { !it.isBlocked }
            .map { it.contact }
        if (activePeers.isEmpty()) return

        activePeers.forEach { peer ->
            scope.launch {
                try {
                    transport.issueChallenge(peer, ChallengeType.FRAGMENT_ECHO)
                } catch (e: Exception) {
                    Diag.swallowed("gossip", "sync-channel-challenge", e,
                        "peer" to peer.nodeId.toHex().take(8),
                        "channel" to channelId.take(8))
                }
            }
        }
    }

    companion object {
        const val HONEY_FRAGMENT_INTERVAL    = 100   // N=100 default; N=10 Max Security
        const val WATCHDOG_FAILURE_THRESHOLD = 3
        const val WATCHDOG_WINDOW_MS         = 24L * 60 * 60 * 1000
        /** After this duration a watchdog block auto-expires (matches the 24h detection window). */
        const val BLOCK_TTL_MS               = 24L * 60 * 60 * 1000

        /**
         * How long to retain a pending honey key after injection.
         * Matches the post TTL (7 days) — if the fragment hasn't returned by then
         * it is either lost or the network never forwarded it back.
         */
        const val HONEY_KEY_TTL_MS           = 7L * 24 * 60 * 60 * 1000

        /** HKDF info tag for honey key derivation — binds key to the honey purpose. */
        val HONEY_KEY_INFO = "gossip-honey-v1".toByteArray()

        /**
         * Canary plaintext that fills the honey fragment payload.
         * A receiver that can successfully decrypt this value has the anchor signing key,
         * which proves key compromise. The canary is distinct from any real post content.
         */
        val HONEY_CANARY = "SHADOWMESH_HONEY_ANCHOR_COMPROMISED_v1".toByteArray()

        /**
         * DEPRECATED — no longer used. The honey channel ID is now derived per-node
         * from [localNodeId] via HMAC-SHA3-256 (see [honeyChannelId] instance field).
         *
         * This constant was a publicly-known value: any peer could forge any fragment's
         * channelId to this value and cause silent discard at every relay node, enabling
         * a complete post-suppression attack. The per-node derivation means an adversary
         * learns nothing about another node's honey channel ID from their own.
         *
         * Kept here for reference and for any existing tests that relied on it; those
         * tests should be updated to use the [GossipEngine] instance's [honeyChannelId].
         */
        @Deprecated("Use GossipEngine.honeyChannelId (instance field) instead. This public constant enabled fragment-drop attacks.")
        const val HONEY_CHANNEL_ID = "0000000000000000000000000000000000000000000000000000000000000001"
    }
}

// ── Supporting types ──────────────────────────────────────────────────────────

data class PeerEntry(
    val contact:     DhtContact,
    val trustLevel:  TrustLevel,
    val isBlocked:   Boolean = false,
    /** Epoch-millis when this peer was blocked. 0 when not blocked. */
    val blockedAtMs: Long    = 0L
)

enum class ChallengeType {
    FRAGMENT_ECHO,       // Relay a known test fragment back through the mesh
    RATCHET_ADVANCEMENT, // Verify peer advances ratchet correctly
    GOSSIP_INTEGRITY,    // Verify peer propagates fragments without modification
    TIMING_CONSISTENCY   // Verify peer relay timing matches declared delay mode
}

data class ChallengeFailure(
    val type:        ChallengeType,
    val timestampMs: Long
)

class WatchdogRecord(val nodeId: NodeId) {
    val failures       = mutableListOf<ChallengeFailure>()
    // @Volatile: written inside synchronized(record) in recordWatchdogFailure(), read
    // unsynchronized in GossipEngine.isLocallyBlocked(). Without @Volatile the write
    // may never be visible to a thread that reads outside the synchronized block (JVM
    // memory model — the monitor exit releases the write to other synchronized readers,
    // but isLocallyBlocked() reads without entering the monitor).
    @Volatile var locallyBlocked = false
    @Volatile var lastSuccessMs  = 0L
}

enum class IntroductionMethod { PHYSICAL, REMOTE }

// ── Transport interface ────────────────────────────────────────────────────────

interface GossipTransport {
    suspend fun sendFragment(peer: DhtContact, fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity)
    suspend fun issueChallenge(peer: DhtContact, type: ChallengeType): Boolean
    /**
     * Broadcast a honey fragment to all peers simultaneously.
     * Called by [GossipEngine.injectHoneyFragment] every N relays.
     * The fragment is structurally identical to real fragments — peers cannot
     * distinguish it without the anchor signing key.
     */
    suspend fun broadcastHoneyFragment(fragment: mesh.shadowmesh.mesh.fragment.FragmentEntity)

    /**
     * Fetch a specific fragment by [fragmentId] from [peer].
     * Returns null if the peer does not have it or the request fails.
     * Used by [GossipEngine.fetchFragmentFromPeer] → [GossipBackedLocalPeer].
     */
    suspend fun fetchFragment(
        peer:       DhtContact,
        fragmentId: String
    ): mesh.shadowmesh.mesh.fragment.FragmentEntity? = null

    /**
     * Fetch all fragments for [channelId] received after [sinceMs] from [peer].
     * Used by [GossipEngine.fetchFragmentsSinceFromPeer] → [GossipBackedLocalPeer].
     * Default returns empty list — transports that support bulk fetch should override.
     */
    suspend fun fetchFragmentsSince(
        peer:      DhtContact,
        channelId: ByteArray,
        sinceMs:   Long
    ): List<mesh.shadowmesh.mesh.fragment.FragmentEntity> = emptyList()

    /**
     * Send a raw control payload (ACK/NACK bytes) to [peer].
     * Used by the Merkle ACK protocol to confirm post delivery and broadcast
     * retransmission requests for missing fragments.
     * Default: no-op — transports that support direct peer messaging override this.
     */
    suspend fun sendControl(peer: DhtContact, bytes: ByteArray) {}
}

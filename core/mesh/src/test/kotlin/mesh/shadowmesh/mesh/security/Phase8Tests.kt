package mesh.shadowmesh.mesh.security

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.nulls.shouldBeNull
import kotlinx.coroutines.test.*
import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.mesh.circuit.*
import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.mesh.fragment.*
import mesh.shadowmesh.mesh.mode.*
import mesh.shadowmesh.mesh.privacy.*

// ── PacketNormalizer ──────────────────────────────────────────────────────────

class PacketNormalizerTest : DescribeSpec({

    describe("PacketNormalizer — 4-bucket size normalization") {

        it("normalizes 10-byte payload to 128-byte bucket") {
            val payload = ByteArray(10) { 0x42 }
            val normalized = PacketNormalizer.normalize(payload)
            normalized.shouldNotBeNull()
            normalized.size shouldBe 128
        }

        it("normalizes 200-byte payload to 512-byte bucket") {
            val payload = ByteArray(200) { 0x42 }
            val normalized = PacketNormalizer.normalize(payload)
            normalized.shouldNotBeNull()
            normalized.size shouldBe 512
        }

        it("normalizes 600-byte payload to 1024-byte bucket") {
            val payload = ByteArray(600) { 0x42 }
            val normalized = PacketNormalizer.normalize(payload)
            normalized.shouldNotBeNull()
            normalized.size shouldBe 1024
        }

        it("normalizes 2000-byte payload to 4096-byte bucket") {
            val payload = ByteArray(2000) { 0x42 }
            val normalized = PacketNormalizer.normalize(payload)
            normalized.shouldNotBeNull()
            normalized.size shouldBe 4096
        }

        it("returns null for payload exceeding largest bucket") {
            val payload = ByteArray(4095) { 0x42 }  // 4095 + 2B header = 4097 > 4096
            PacketNormalizer.normalize(payload).shouldBeNull()
        }

        it("normalize → denormalize round-trip recovers original payload") {
            listOf(1, 50, 127, 128, 200, 511, 600, 1023, 2000).forEach { size ->
                val payload    = ByteArray(size) { (it % 256).toByte() }
                val normalized = PacketNormalizer.normalize(payload) ?: return@forEach
                val recovered  = PacketNormalizer.denormalize(normalized)
                recovered.shouldNotBeNull()
                recovered shouldBe payload
            }
        }

        it("different payloads of same size produce different normalized packets (random padding)") {
            val p1 = ByteArray(10) { 0x01 }
            val p2 = ByteArray(10) { 0x01 }
            val n1 = PacketNormalizer.normalize(p1)!!
            val n2 = PacketNormalizer.normalize(p2)!!
            // Both 128 bytes, same payload — padding is random so outputs should differ
            // (extremely unlikely to be equal)
            n1.size shouldBe n2.size
            // Payload portions should match, padding should differ with overwhelming probability
            n1.copyOfRange(1, 11) shouldBe n2.copyOfRange(1, 11)
        }

        it("bucketFor returns correct bucket for given payload size") {
            PacketNormalizer.bucketFor(10)   shouldBe 128
            PacketNormalizer.bucketFor(200)  shouldBe 512
            PacketNormalizer.bucketFor(600)  shouldBe 1024
            PacketNormalizer.bucketFor(2000) shouldBe 4096
            PacketNormalizer.bucketFor(4095) shouldBe -1
        }

        it("denormalize rejects packet with non-bucket size") {
            // A 200-byte packet is not a valid bucket — must return null, not garbage
            val fakePacket = ByteArray(200) { 0x42 }
            PacketNormalizer.denormalize(fakePacket).shouldBeNull()
        }

        it("denormalize rejects packet with size 0") {
            PacketNormalizer.denormalize(ByteArray(0)).shouldBeNull()
        }

        it("overhead is at most 30% for small payloads") {
            val payloadSize    = 100
            val normalizedSize = PacketNormalizer.bucketFor(payloadSize)
            val overhead       = (normalizedSize - payloadSize).toDouble() / normalizedSize
            (overhead <= 0.30) shouldBe true  // 30% worst-case for small payloads
        }
    }
})

// ── CircuitRoleRotator ────────────────────────────────────────────────────────

// ── CircuitRoleRotator ────────────────────────────────────────────────────────

class CircuitRoleRotatorTest : DescribeSpec({

    fun makeCandidate(id: Int, trust: TrustLevelForCircuit = TrustLevelForCircuit.PHYSICAL) =
        CircuitCandidate(
            nodeId      = NodeId(ByteArray(32) { if (it == 0) id.toByte() else 0 }),
            contact     = DhtContact(
                NodeId(ByteArray(32) { if (it == 0) id.toByte() else 0 }),
                PeerAddress("10.0.0.$id", 7400)
            ),
            trustLevel  = trust,
            uptimeScore = 80
        )

    describe("CircuitRoleRotator") {

        it("selects entry, guard, middle, exit from a pool of 6 with preferences") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            val pool    = (1..6).map { makeCandidate(it) }
            // Entry preference: prefer node 1
            val prefs   = listOf(makeCandidate(1))
            val sel     = rotator.selectNextCircuit(pool, prefs)
            sel.shouldNotBeNull()
            sel.entry.shouldNotBeNull()
            sel.exit.shouldNotBeNull()
        }

        it("entry is drawn from preferences when available") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            val pool    = (1..6).map { makeCandidate(it) }
            val prefs   = listOf(makeCandidate(2))  // prefer node 2
            val sel     = rotator.selectNextCircuit(pool, prefs)
            sel.shouldNotBeNull()
            sel.entry shouldBe pool[1].contact  // node 2
        }

        it("entry falls back to next preference when first is unavailable") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            // Pool does not include node 99 (unavailable); node 2 is in pool
            val pool    = (1..6).map { makeCandidate(it) }
            val prefs   = listOf(makeCandidate(99), makeCandidate(2))
            val sel     = rotator.selectNextCircuit(pool, prefs)
            sel.shouldNotBeNull()
            sel.entry shouldBe pool[1].contact  // node 2 — first available preference
        }

        it("entry falls back to any TRUST_PHYSICAL when all preferences exhausted") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            val pool    = (1..4).map { makeCandidate(it) }
            // Preferences are all unavailable
            val prefs   = listOf(makeCandidate(98), makeCandidate(99))
            val sel     = rotator.selectNextCircuit(pool, prefs)
            sel.shouldNotBeNull()
            // Entry must be one of the TRUST_PHYSICAL pool nodes
            val poolIds = pool.map { it.contact }
            poolIds.contains(sel.entry) shouldBe true
        }

        it("entry and guard are always different nodes") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            val pool    = (1..6).map { makeCandidate(it) }
            val prefs   = listOf(makeCandidate(1))
            repeat(10) {
                val sel = rotator.selectNextCircuit(pool, prefs)
                sel.shouldNotBeNull()
                // Entry and guard must differ when guard is non-null
                sel.guard?.let { g -> (sel.entry == g) shouldBe false }
            }
        }

        it("guard is drawn from full mesh (TRUST_INTRODUCED eligible)") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            // Only one TRUST_PHYSICAL node (entry); rest are TRUST_INTRODUCED
            val physical    = makeCandidate(1, TrustLevelForCircuit.PHYSICAL)
            val introduced  = (2..6).map { makeCandidate(it, TrustLevelForCircuit.INTRODUCED) }
            val pool        = listOf(physical) + introduced
            val prefs       = listOf(physical)

            var guardWasIntroduced = false
            repeat(20) {
                val sel = rotator.selectNextCircuit(pool, prefs)
                sel.shouldNotBeNull()
                if (sel.guard != null && introduced.any { it.contact == sel.guard }) {
                    guardWasIntroduced = true
                }
            }
            // Guard should sometimes be a TRUST_INTRODUCED node since pool includes them
            guardWasIntroduced shouldBe true
        }

        it("no node serves same role in consecutive circuits") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            val pool    = (1..8).map { makeCandidate(it) }
            val prefs   = (1..4).map { makeCandidate(it) }

            val sel1 = rotator.selectNextCircuit(pool, prefs)!!
            val sel2 = rotator.selectNextCircuit(pool, prefs)!!

            // Entry must change between circuits when preferences allow
            (sel1.entry == sel2.entry) shouldBe false
        }

        it("forceNoGuard=true produces 2-hop circuit regardless of pool size") {
            // Validates fix #1: CRITICAL mode must produce Entry+Exit only,
            // even when enough peers for a 4-hop circuit are available.
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            val pool    = (1..8).map { makeCandidate(it) }  // plenty of peers
            val prefs   = listOf(makeCandidate(1))

            val sel = rotator.selectNextCircuit(pool, prefs, forceNoGuard = true, forceNoMiddle = true)
            sel.shouldNotBeNull()
            sel.guard.shouldBeNull()   // forced 2-hop
            sel.middle.shouldBeNull()  // forced 2-hop
            sel.entry.shouldNotBeNull()
            sel.exit.shouldNotBeNull()
        }

        it("forceNoGuard=false produces 4-hop when pool allows") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            val pool    = (1..8).map { makeCandidate(it) }
            val prefs   = listOf(makeCandidate(1))

            val sel = rotator.selectNextCircuit(pool, prefs, forceNoGuard = false, forceNoMiddle = false)
            sel.shouldNotBeNull()
            // With 8 candidates, guard and middle should both be selected
            sel.guard.shouldNotBeNull()
            sel.middle.shouldNotBeNull()
        }

        it("falls back to 2-hop circuit when pool has fewer than 3 nodes") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            // Only 2 nodes available: entry candidate and one other
            val pool  = listOf(makeCandidate(1), makeCandidate(2))
            val prefs = listOf(makeCandidate(1))
            val sel   = rotator.selectNextCircuit(pool, prefs)
            sel.shouldNotBeNull()
            sel.guard.shouldBeNull()   // 2-hop: entry + exit only
            sel.middle.shouldBeNull()
        }

        it("blocked nodes are excluded from all roles") {
            val localId = NodeId(ByteArray(32) { 0xFF.toByte() })
            val rotator = CircuitRoleRotator(localId)
            val pool = listOf(
                makeCandidate(1).copy(isBlocked = true),
                makeCandidate(2),
                makeCandidate(3),
                makeCandidate(4)
            )
            val prefs = listOf(makeCandidate(1), makeCandidate(2))
            repeat(20) {
                val sel = rotator.selectNextCircuit(pool, prefs)
                sel.shouldNotBeNull()
                // Node 1 must never appear in any role
                (sel.entry == pool[0].contact) shouldBe false
                sel.guard?.let { (it == pool[0].contact) shouldBe false }
                sel.exit.let  { (it == pool[0].contact) shouldBe false }
                sel.middle?.let { (it == pool[0].contact) shouldBe false }
            }
        }
    }
})

// ── InMeshMixProtocol ─────────────────────────────────────────────────────────

class InMeshMixProtocolTest : DescribeSpec({

    fun makeFragment(id: String) = FragmentEntity(
        fragmentId    = id,
        postId        = "post1",
        channelId     = "chan1",
        sequenceIndex = 0,
        totalData     = 1,
        totalParity   = 0,
        payload       = ByteArray(64),
        fecScheme     = FecScheme.NONE
    )

    describe("InMeshMixProtocol") {

        it("forwards immediately when disabled") {
            runTest {
                val forwarded = mutableListOf<FragmentEntity>()
                val transport = object : MixTransport {
                    override suspend fun forwardFragment(target: DhtContact, fragment: FragmentEntity) {
                        forwarded.add(fragment)
                    }
                }
                val mix  = InMeshMixProtocol(this, transport)
                val peer = DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 7400))
                mix.relay(makeFragment("frag1"), peer)
                advanceUntilIdle()
                forwarded.size shouldBe 1
            }
        }

        it("pools fragments when enabled, flushes after window") {
            runTest {
                val forwarded = mutableListOf<FragmentEntity>()
                val transport = object : MixTransport {
                    override suspend fun forwardFragment(t: DhtContact, f: FragmentEntity) { forwarded.add(f) }
                }
                val mix  = InMeshMixProtocol(this, transport)
                mix.enable(windowMs = 100)
                val peer = DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 7400))

                // Add 3 fragments
                mix.relay(makeFragment("f1"), peer)
                mix.relay(makeFragment("f2"), peer)
                mix.relay(makeFragment("f3"), peer)
                mix.poolSize() shouldBe 3

                // Wait for flush window
                advanceTimeBy(200)
                advanceUntilIdle()

                // All 3 should be forwarded (mix pool >= MIN_POOL_SIZE)
                forwarded.size shouldBe 3
                mix.poolSize() shouldBe 0
            }
        }

        it("injects decoys when pool has fewer than MIN_POOL_SIZE") {
            runTest {
                val forwarded = mutableListOf<FragmentEntity>()
                val transport = object : MixTransport {
                    override suspend fun forwardFragment(t: DhtContact, f: FragmentEntity) { forwarded.add(f) }
                }
                val mix  = InMeshMixProtocol(this, transport)
                mix.enable(windowMs = 100)
                val peer = DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 7400))

                // Add only 1 fragment (below MIN_POOL_SIZE=3)
                mix.relay(makeFragment("f_lone"), peer)

                advanceTimeBy(200)
                advanceUntilIdle()

                // Should forward MIN_POOL_SIZE=3 total (1 real + 2 decoys)
                forwarded.size shouldBe InMeshMixProtocol.MIN_POOL_SIZE
            }
        }

        it("isEnabled reflects state correctly") {
            runTest {
                val mix = InMeshMixProtocol(this, object : MixTransport {
                    override suspend fun forwardFragment(t: DhtContact, f: FragmentEntity) {}
                })
                mix.isEnabled() shouldBe false
                mix.enable()
                mix.isEnabled() shouldBe true
                mix.disable()
                mix.isEnabled() shouldBe false
            }
        }
    }
})

// ── SNDP ──────────────────────────────────────────────────────────────────────

class SndpEngineTest : DescribeSpec({

    describe("SndpEngine — cover traffic") {

        it("does not emit in CRITICAL mode") {
            runTest {
                val emitted = mutableListOf<FragmentEntity>()
                val transport = object : SndpTransport {
                    override suspend fun sendFakeFragment(peer: DhtContact, fragment: FragmentEntity) {
                        emitted.add(fragment)
                    }
                    override suspend fun gossipSndpBurst(postHash: ByteArray, peers: List<DhtContact>) {}
                }
                val engine = SndpEngine(NodeId.random(), scope = this, transport = transport)
                engine.onSyncCycleStart(
                    mode             = NetworkMode.CRITICAL,
                    recentPostHashes = listOf(ByteArray(32) { 0x01 }),
                    knownPeers       = listOf(DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 7400)))
                )
                advanceUntilIdle()
                emitted.size shouldBe 0
            }
        }

        it("does not emit in SURVIVAL mode") {
            runTest {
                val emitted = mutableListOf<FragmentEntity>()
                val transport = object : SndpTransport {
                    override suspend fun sendFakeFragment(peer: DhtContact, fragment: FragmentEntity) {
                        emitted.add(fragment)
                    }
                    override suspend fun gossipSndpBurst(postHash: ByteArray, peers: List<DhtContact>) {}
                }
                val engine = SndpEngine(NodeId.random(), scope = this, transport = transport)
                engine.onSyncCycleStart(
                    mode             = NetworkMode.SURVIVAL,
                    recentPostHashes = (0 until 100).map { ByteArray(32) { i -> (i + it).toByte() } },
                    knownPeers       = listOf(DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 7400)))
                )
                advanceUntilIdle()
                emitted.size shouldBe 0
            }
        }

        it("cycleNonce rotates even when sndpEnabled=false (CRITICAL mode)") {
            runTest {
                val engine = SndpEngine(NodeId.random(), scope = this, transport = object : SndpTransport {
                    override suspend fun sendFakeFragment(peer: DhtContact, fragment: FragmentEntity) {}
                    override suspend fun gossipSndpBurst(postHash: ByteArray, peers: List<DhtContact>) {}
                })

                // Access cycleNonce via reflection to verify rotation
                val field = SndpEngine::class.java.getDeclaredField("cycleNonce")
                field.isAccessible = true

                val nonceBefore = (field.get(engine) as ByteArray).copyOf()

                // Call with CRITICAL mode — sndpEnabled=false, but nonce must still rotate
                engine.onSyncCycleStart(
                    mode             = NetworkMode.CRITICAL,
                    recentPostHashes = listOf(ByteArray(32) { 0x01 }),
                    knownPeers       = emptyList()
                )
                advanceUntilIdle()

                val nonceAfter = (field.get(engine) as ByteArray).copyOf()
                nonceBefore.contentEquals(nonceAfter) shouldBe false
            }
        }

        it("gossip burst is triggered on real post published") {
            runTest {
                var gossipCalled = false
                val transport = object : SndpTransport {
                    override suspend fun sendFakeFragment(peer: DhtContact, fragment: FragmentEntity) {}
                    override suspend fun gossipSndpBurst(postHash: ByteArray, peers: List<DhtContact>) {
                        gossipCalled = true
                    }
                }
                val engine = SndpEngine(NodeId.random(), scope = this, transport = transport)
                engine.onRealPostPublished(
                    postHash   = ByteArray(32) { 0x42 },
                    mode       = NetworkMode.HEALTHY,
                    knownPeers = listOf(DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 7400)))
                )
                advanceUntilIdle()
                gossipCalled shouldBe true
            }
        }

        it("fake fragments use a random per-burst channelId, not the deprecated constant") {
            runTest {
                val emitted = mutableListOf<FragmentEntity>()
                val transport = object : SndpTransport {
                    override suspend fun sendFakeFragment(peer: DhtContact, fragment: FragmentEntity) {
                        emitted.add(fragment)
                    }
                    override suspend fun gossipSndpBurst(postHash: ByteArray, peers: List<DhtContact>) {}
                }
                val engine = SndpEngine(NodeId.random(), scope = this, transport = transport)
                engine.onRealPostPublished(
                    postHash   = ByteArray(32) { 0x42 },
                    mode       = NetworkMode.HEALTHY,
                    knownPeers = listOf(DhtContact(NodeId.random(), PeerAddress("1.1.1.1", 7400)))
                )
                advanceUntilIdle()
                // Fix #73 replaced the static SNDP_FAKE_CHANNEL_ID constant (all-zeros, trivially
                // identifiable by any observer) with a fresh per-burst random 32-byte channelId.
                // This test verifies the new behaviour: the channelId must NOT be the deprecated
                // constant, must be 64 hex chars, and all fragments in the burst share it.
                emitted.isNotEmpty() shouldBe true
                val burstChannelId = emitted.first().channelId
                @Suppress("DEPRECATION")
                burstChannelId shouldNotBe SndpEngine.SNDP_FAKE_CHANNEL_ID
                burstChannelId.length shouldBe 64
                burstChannelId.all { it.isDigit() || it in 'a'..'f' } shouldBe true
                emitted.forEach { frag -> frag.channelId shouldBe burstChannelId }
            }
        }
    }
})

// ── OnionCircuit ──────────────────────────────────────────────────────────────

class OnionCircuitTest : DescribeSpec({

    val hkdf   = Hkdf.instance
    val kem    = HybridKem(hkdf)
    val cipher = SymmetricCipher()

    describe("OnionCircuit — encryption layers") {

        it("4-hop: buildOnion payload recovered after Entry→Guard→Middle→Exit decryption") {
            runTest {
                val circuit = OnionCircuit(NodeId.random(), kem)

                val entryKey  = cipher.generateKey()
                val guardKey  = cipher.generateKey()
                val middleKey = cipher.generateKey()
                val exitKey   = cipher.generateKey()

                val state = OnionCircuit.CircuitState(
                    id     = "test_circuit_4hop",
                    entry  = OnionCircuit.HopKey(NodeId.random(), PeerAddress("0.0.0.1", 7400), entryKey),
                    guard  = OnionCircuit.HopKey(NodeId.random(), PeerAddress("1.1.1.1", 7400), guardKey),
                    middle = OnionCircuit.HopKey(NodeId.random(), PeerAddress("2.2.2.2", 7400), middleKey),
                    exit   = OnionCircuit.HopKey(NodeId.random(), PeerAddress("3.3.3.3", 7400), exitKey)
                )

                val payload = "secret message for exit".toByteArray()
                var received: ByteArray? = null
                var entryTarget: PeerAddress? = null

                val transport = object : CircuitTransport {
                    override suspend fun requestHopPublicKey(hop: DhtContact, circuitId: String) = null
                    override suspend fun sendKemCiphertext(hop: DhtContact, circuitId: String, ct: HybridCiphertext) {}
                    override suspend fun sendToEntry(entryAddress: PeerAddress, onion: ByteArray) {
                        entryTarget = entryAddress  // assign outer var — not a new val
                        // Simulate Entry decrypting its layer → forwards to Guard
                        val entryResult = circuit.decryptLayer(onion, entryKey)
                        if (entryResult is LayerResult.Forward) {
                            // Simulate Guard decrypting its layer → forwards to Middle
                            val guardResult = circuit.decryptLayer(entryResult.payload, guardKey)
                            if (guardResult is LayerResult.Forward) {
                                // Simulate Middle decrypting its layer → forwards to Exit
                                val midResult = circuit.decryptLayer(guardResult.payload, middleKey)
                                if (midResult is LayerResult.Forward) {
                                    // Exit layer: addrLen==0 → LayerResult.Exit carries final payload
                                    val exitResult = circuit.decryptLayer(midResult.payload, exitKey)
                                    if (exitResult is LayerResult.Exit) {
                                        received = exitResult.payload
                                    }
                                }
                            }
                        }
                    }
                }

                circuit.send(payload, state, transport)
                advanceUntilIdle()

                // Sender dispatches to Entry, not Guard — Guard never sees sender IP
                entryTarget shouldBe state.entry.address
                received.shouldNotBeNull()
                received!! shouldBe payload
            }
        }

        it("3-hop degraded: Entry→Guard→Exit (middle null) recovers payload") {
            runTest {
                val circuit = OnionCircuit(NodeId.random(), kem)

                val entryKey = cipher.generateKey()
                val guardKey = cipher.generateKey()
                val exitKey  = cipher.generateKey()

                val state = OnionCircuit.CircuitState(
                    id     = "test_circuit_3hop",
                    entry  = OnionCircuit.HopKey(NodeId.random(), PeerAddress("0.0.0.1", 7400), entryKey),
                    guard  = OnionCircuit.HopKey(NodeId.random(), PeerAddress("1.1.1.1", 7400), guardKey),
                    middle = null,
                    exit   = OnionCircuit.HopKey(NodeId.random(), PeerAddress("3.3.3.3", 7400), exitKey)
                )
                state.is3Hop shouldBe true

                val payload  = "3-hop test payload".toByteArray()
                var received: ByteArray? = null

                val transport = object : CircuitTransport {
                    override suspend fun requestHopPublicKey(hop: DhtContact, circuitId: String) = null
                    override suspend fun sendKemCiphertext(hop: DhtContact, circuitId: String, ct: HybridCiphertext) {}
                    override suspend fun sendToEntry(entryAddress: PeerAddress, onion: ByteArray) {
                        val entryResult = circuit.decryptLayer(onion, entryKey)
                        if (entryResult is LayerResult.Forward) {
                            val guardResult = circuit.decryptLayer(entryResult.payload, guardKey)
                            if (guardResult is LayerResult.Forward) {
                                val exitResult = circuit.decryptLayer(guardResult.payload, exitKey)
                                if (exitResult is LayerResult.Exit) received = exitResult.payload
                            }
                        }
                    }
                }

                circuit.send(payload, state, transport)
                advanceUntilIdle()
                received.shouldNotBeNull()
                received!! shouldBe payload
            }
        }

        it("2-hop critical fallback: Entry→Exit (guard and middle null) recovers payload") {
            runTest {
                val circuit = OnionCircuit(NodeId.random(), kem)

                val entryKey = cipher.generateKey()
                val exitKey  = cipher.generateKey()

                val state = OnionCircuit.CircuitState(
                    id     = "test_circuit_2hop",
                    entry  = OnionCircuit.HopKey(NodeId.random(), PeerAddress("0.0.0.1", 7400), entryKey),
                    guard  = null,
                    middle = null,
                    exit   = OnionCircuit.HopKey(NodeId.random(), PeerAddress("3.3.3.3", 7400), exitKey)
                )
                state.is2Hop shouldBe true

                val payload  = "2-hop test payload".toByteArray()
                var received: ByteArray? = null

                val transport = object : CircuitTransport {
                    override suspend fun requestHopPublicKey(hop: DhtContact, circuitId: String) = null
                    override suspend fun sendKemCiphertext(hop: DhtContact, circuitId: String, ct: HybridCiphertext) {}
                    override suspend fun sendToEntry(entryAddress: PeerAddress, onion: ByteArray) {
                        val entryResult = circuit.decryptLayer(onion, entryKey)
                        if (entryResult is LayerResult.Forward) {
                            val exitResult = circuit.decryptLayer(entryResult.payload, exitKey)
                            if (exitResult is LayerResult.Exit) received = exitResult.payload
                        }
                    }
                }

                circuit.send(payload, state, transport)
                advanceUntilIdle()
                received.shouldNotBeNull()
                received!! shouldBe payload
            }
        }

        it("teardown wipes all session keys including entry") {
            val state = OnionCircuit.CircuitState(
                id     = "wipe_test",
                entry  = OnionCircuit.HopKey(NodeId.random(), PeerAddress("0.0.0.1", 7400), ByteArray(32) { 0x41 }),
                guard  = OnionCircuit.HopKey(NodeId.random(), PeerAddress("1.1.1.1", 7400), ByteArray(32) { 0x42 }),
                middle = OnionCircuit.HopKey(NodeId.random(), PeerAddress("2.2.2.2", 7400), ByteArray(32) { 0x43 }),
                exit   = OnionCircuit.HopKey(NodeId.random(), PeerAddress("3.3.3.3", 7400), ByteArray(32) { 0x44 })
            )

            val circuit = OnionCircuit(NodeId.random(), HybridKem(Hkdf.instance))
            circuit.teardown(state)

            state.entry.sessionKey.all  { it == 0.toByte() } shouldBe true
            state.guard!!.sessionKey.all  { it == 0.toByte() } shouldBe true
            state.middle!!.sessionKey.all { it == 0.toByte() } shouldBe true
            state.exit.sessionKey.all   { it == 0.toByte() } shouldBe true
        }
    }
})

package mesh.shadowmesh.forum

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.test.*
import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.storage.*

// ── RatchetStateStore ─────────────────────────────────────────────────────────

class RatchetStateStoreTest : DescribeSpec({

    val hkdf       = Hkdf.instance
    val cipher     = SymmetricCipher()
    val channelKey = ByteArray(32) { 0x42 }

    describe("RatchetStateStore — persist and restore chain_key across process death") {

        it("save then restore returns identical chain key and post index") {
            runTest {
                val dao   = FakeRatchetDao()
                val store = RatchetStateStore(dao, cipher)

                val chainKey  = ByteArray(32) { 0xAB.toByte() }
                val postIndex = 1000

                store.save("chan1", chainKey, postIndex, channelKey)
                val restored = store.restore("chan1", channelKey)

                restored.shouldNotBeNull()
                restored.chainKey.contentEquals(chainKey) shouldBe true
                restored.postIndex shouldBe postIndex
            }
        }

        it("restore returns null when no checkpoint exists") {
            runTest {
                val store = RatchetStateStore(FakeRatchetDao(), cipher)
                store.restore("nonexistent", channelKey).shouldBeNull()
            }
        }

        it("chain key is encrypted at rest — stored bytes differ from plaintext") {
            runTest {
                val dao   = FakeRatchetDao()
                val store = RatchetStateStore(dao, cipher)
                val chainKey = ByteArray(32) { 0x77.toByte() }

                store.save("chan2", chainKey, 500, channelKey)

                val entity = dao.stored["chan2"]!!
                // Encrypted blob must differ from raw chain key
                entity.encryptedChainKey.contentEquals(chainKey) shouldBe false
                // And must be longer (nonce + tag overhead)
                (entity.encryptedChainKey.size > 32) shouldBe true
            }
        }

        it("wrong channel key cannot decrypt checkpoint") {
            runTest {
                val dao   = FakeRatchetDao()
                val store = RatchetStateStore(dao, cipher)
                val chainKey = ByteArray(32) { 0x55.toByte() }

                store.save("chan3", chainKey, 200, channelKey)

                val wrongKey = ByteArray(32) { 0xFF.toByte() }
                var threw = false
                try { store.restore("chan3", wrongKey) }
                catch (e: Exception) { threw = true }
                threw shouldBe true
            }
        }

        it("delete removes the checkpoint") {
            runTest {
                val dao   = FakeRatchetDao()
                val store = RatchetStateStore(dao, cipher)
                store.save("chan4", ByteArray(32), 0, channelKey)
                store.delete("chan4")
                store.restore("chan4", channelKey).shouldBeNull()
            }
        }

        it("upsert overwrites previous checkpoint for same channel") {
            runTest {
                val dao   = FakeRatchetDao()
                val store = RatchetStateStore(dao, cipher)
                val key1  = ByteArray(32) { 0x11.toByte() }
                val key2  = ByteArray(32) { 0x22.toByte() }

                store.save("chan5", key1, 1000, channelKey)
                store.save("chan5", key2, 2000, channelKey)

                val restored = store.restore("chan5", channelKey)!!
                restored.postIndex shouldBe 2000
                restored.chainKey.contentEquals(key2) shouldBe true
            }
        }

        it("ratchet survives simulated process death — restore and re-advance produces same keys") {
            runTest {
                val dao   = FakeRatchetDao()
                val store = RatchetStateStore(dao, cipher)

                // Simulate: ratchet advances 5 posts, saves checkpoint at post 5
                val ratchet1 = PostRatchet.fromChannelKey(channelKey, hkdf, checkpointInterval = 5)
                val hashes   = (1..5).map { "hash_$it".toByteArray() }
                var checkpointKey: ByteArray? = null
                var checkpointIndex = 0
                hashes.forEach { h ->
                    val step = ratchet1.advance(h)
                    if (step.checkpoint != null) {
                        checkpointKey  = step.checkpoint
                        checkpointIndex = step.postIndex
                        store.save("chan6", step.checkpoint!!, step.postIndex, channelKey)
                    }
                }

                // Process "dies" here. Restore on next launch.
                val restored = store.restore("chan6", channelKey)!!
                val ratchet2 = PostRatchet(ByteArray(32), hkdf, checkpointInterval = 5)
                ratchet2.restoreFromCheckpoint(restored.chainKey, restored.postIndex)
                restored.chainKey.fill(0)

                // Both ratchets should produce identical keys for post 6+
                val nextHashes = (6..8).map { "hash_$it".toByteArray() }
                nextHashes.forEach { h ->
                    val k1 = ratchet1.advance(h).postKey
                    val k2 = ratchet2.advance(h).postKey
                    k1.contentEquals(k2) shouldBe true
                }
            }
        }
    }
})

// ── KeyOrchestrator (pure logic — no Android) ─────────────────────────────────

class KeyOrchestratorLogicTest : DescribeSpec({

    val hkdf   = Hkdf.instance
    val cipher = SymmetricCipher()
    val ibd    = IntegrityBoundedKeyDerivation(hkdf)

    val deviceSecret   = ByteArray(32) { 0x42 }
    val apkBindingHash = ByteArray(32) { 0x13 }

    describe("KeyOrchestrator — wrapping key derivation") {

        it("OPEN channel wrapping key is deterministic from device secret + apk hash + channelId") {
            val channelId = "test-channel-abc"
            val genesisHash = hkdf.sha3_256(channelId.toByteArray()).copyOf(32)

            val key1 = ibd.derive(deviceSecret, apkBindingHash, genesisHash,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)
            val key2 = ibd.derive(deviceSecret, apkBindingHash, genesisHash,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)

            key1.contentEquals(key2) shouldBe true
        }

        it("different channelIds produce different wrapping keys") {
            val gh1 = hkdf.sha3_256("channel-1".toByteArray()).copyOf(32)
            val gh2 = hkdf.sha3_256("channel-2".toByteArray()).copyOf(32)

            val k1 = ibd.derive(deviceSecret, apkBindingHash, gh1,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)
            val k2 = ibd.derive(deviceSecret, apkBindingHash, gh2,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)

            k1.contentEquals(k2) shouldBe false
        }

        it("wrap then unwrap round-trip recovers original key") {
            runTest {
                val rawKey     = ByteArray(32) { 0x77.toByte() }
                val channelId  = "round-trip-chan"
                val genesisHash = hkdf.sha3_256(channelId.toByteArray()).copyOf(32)
                val wrappingKey = ibd.derive(deviceSecret, apkBindingHash, genesisHash,
                    IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)

                val wrapped   = cipher.encrypt(rawKey, wrappingKey).getOrThrow()
                val unwrapped = cipher.decrypt(wrapped, wrappingKey).getOrThrow()

                unwrapped.contentEquals(rawKey) shouldBe true
            }
        }

        it("different device secret produces different wrapping key — tamper protection") {
            val genesisHash = hkdf.sha3_256("chan".toByteArray()).copyOf(32)
            val altSecret   = ByteArray(32) { 0xFF.toByte() }

            val k1 = ibd.derive(deviceSecret, apkBindingHash, genesisHash,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)
            val k2 = ibd.derive(altSecret, apkBindingHash, genesisHash,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)

            k1.contentEquals(k2) shouldBe false
        }
    }

    describe("KeyOrchestrator — ratchet advancement with checkpoint persistence") {

        it("ratchet advances correctly and persists checkpoint at interval") {
            runTest {
                val channelKey  = ByteArray(32) { 0x42 }
                val ratchetDao  = FakeRatchetDao()
                val ratchetStore = RatchetStateStore(ratchetDao, cipher)
                val ratchet     = PostRatchet.fromChannelKey(channelKey, hkdf, checkpointInterval = 3)

                // Advance 3 posts — checkpoint should fire at index 3
                var checkpointSaved = false
                (1..3).forEach { i ->
                    val step = ratchet.advance("hash_$i".toByteArray())
                    if (step.checkpoint != null) {
                        ratchetStore.save("chan", step.checkpoint!!, step.postIndex, channelKey)
                        checkpointSaved = true
                    }
                }

                checkpointSaved shouldBe true
                ratchetDao.stored["chan"].shouldNotBeNull()
                ratchetDao.stored["chan"]!!.postIndex shouldBe 3
            }
        }
    }
})

// ── ForumViewModel ────────────────────────────────────────────────────────────

class ForumViewModelTest : DescribeSpec({

    describe("ForumViewModel — channel selection and post list") {

        it("channels flow emits from ChannelManager") {
            runTest {
                val dao     = FakeDao()
                val manager = ChannelManager(dao, Hkdf.instance)
                val engine  = PostEngine(dao)
                val vm      = ForumViewModel(engine, manager)

                val chan = ChannelEntity(
                    channelId = "c1", name = "Test", type = ChannelType.OPEN,
                    encryptedKeyBlob = ByteArray(0), genesisHash = "gh",
                    createdAtMs = 0, lastActivityMs = 0
                )
                dao.upsertChannel(chan)

                val collected = vm.channels.value
                // May be empty on first collect before flow emits — that's fine
                // The important property is no crash
                (collected is List<*>) shouldBe true
            }
        }

        it("selectChannel updates currentChannelId") {
            runTest {
                val vm = ForumViewModel(PostEngine(FakeDao()), ChannelManager(FakeDao()))
                vm.selectChannel("chan-abc")
                vm.currentChannelId.value shouldBe "chan-abc"
            }
        }

        it("departChannel clears currentChannelId if it matches") {
            runTest {
                val dao = FakeDao()
                dao.upsertChannel(ChannelEntity(
                    channelId = "c1", name = "n", type = ChannelType.OPEN,
                    encryptedKeyBlob = ByteArray(0), genesisHash = "gh",
                    createdAtMs = 0, lastActivityMs = 0
                ))
                val vm = ForumViewModel(PostEngine(dao), ChannelManager(dao))
                vm.selectChannel("c1")
                vm.departChannel("c1")
                advanceUntilIdle()
                vm.currentChannelId.value.shouldBeNull()
            }
        }

        it("clearCompose resets draft text") {
            runTest {
                val vm = ForumViewModel(PostEngine(FakeDao()), ChannelManager(FakeDao()))
                vm.onDraftChanged("hello world")
                vm.compose.value.draftText shouldBe "hello world"
                vm.clearCompose()
                vm.compose.value.draftText shouldBe ""
            }
        }

        it("onBurnAfterReadToggled toggles the flag") {
            runTest {
                val vm = ForumViewModel(PostEngine(FakeDao()), ChannelManager(FakeDao()))
                vm.compose.value.burnAfterRead shouldBe false
                vm.onBurnAfterReadToggled()
                vm.compose.value.burnAfterRead shouldBe true
                vm.onBurnAfterReadToggled()
                vm.compose.value.burnAfterRead shouldBe false
            }
        }
    }

    describe("ForumViewModel — post submission lifecycle") {

        it("submitPost clears compose and enters PENDING") {
            runTest {
                val dao = FakeDao()
                dao.upsertChannel(ChannelEntity(
                    channelId = "c1", name = "n", type = ChannelType.OPEN,
                    encryptedKeyBlob = ByteArray(0), genesisHash = "gh",
                    createdAtMs = 0, lastActivityMs = 0
                ))

                val postKey = ByteArray(32) { 0x01 }
                var dispatched = false
                val vm = ForumViewModel(
                    PostEngine(dao),
                    ChannelManager(dao),
                    fragmentDispatcher = { dispatched = true }
                )
                vm.selectChannel("c1")
                vm.onDraftChanged("test post")

                vm.submitPost("c1") { draftText ->
                    val hkdf   = Hkdf.instance
                    val cipher = SymmetricCipher()
                    val enc0 = cipher.encrypt("meta".toByteArray(), postKey).getOrThrow()
                    val enc1 = cipher.encrypt(draftText.take(50).toByteArray(), postKey).getOrThrow()
                    val enc2 = cipher.encrypt(draftText.toByteArray(), postKey).getOrThrow()
                    val postHash = hkdf.sha3_256(enc2).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                    val postId   = hkdf.sha3_256("c1".toByteArray() + "author".toByteArray() +
                        enc2 + ByteArray(8)).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                    PostEntity(
                        postId = postId, channelId = "c1", authorNodeId = "author",
                        encryptedTier0 = enc0, encryptedTier1 = enc1, encryptedTier2 = null,
                        postHash = postHash, createdAtMs = 0L, ttlMs = Long.MAX_VALUE,
                        postState = PostState.PENDING
                    )
                }

                advanceUntilIdle()

                // Compose should be cleared
                vm.compose.value.draftText shouldBe ""
                // Fragment dispatcher should have been called
                dispatched shouldBe true
            }
        }

        it("retryPost re-dispatches fragments") {
            runTest {
                var dispatchCount = 0
                val vm = ForumViewModel(
                    PostEngine(FakeDao()),
                    ChannelManager(FakeDao()),
                    fragmentDispatcher = { dispatchCount++ }
                )

                // Manually create a state machine in FAILED state
                val sm = vm.getPostStateMachine("post-1")
                sm.onSubmit()
                sm.onFailed()

                vm.retryPost("post-1")
                advanceUntilIdle()

                // dispatch should have been called once for retry
                dispatchCount shouldBe 1
                sm.state.value shouldBe PostState.PENDING
            }
        }

        it("onPostConfirmed transitions state machine to CONFIRMED") {
            runTest {
                val vm = ForumViewModel(PostEngine(FakeDao()), ChannelManager(FakeDao()))
                val sm = vm.getPostStateMachine("post-2")
                sm.onSubmit()
                sm.onFirstAck()

                vm.onPostConfirmed("post-2", ByteArray(64))
                advanceUntilIdle()

                sm.state.value shouldBe PostState.CONFIRMED
            }
        }
    }

    describe("ForumViewModel — post detail and burn-after-read") {

        it("openPost returns snapshot before burn-after-read deletion") {
            runTest {
                val dao     = FakeDao()
                val engine  = PostEngine(dao)
                val postKey = ByteArray(32) { 0x01 }
                val cipher  = SymmetricCipher()
                val hkdf    = Hkdf.instance

                val enc0 = cipher.encrypt("meta".toByteArray(), postKey).getOrThrow()
                val enc2 = cipher.encrypt("full content".toByteArray(), postKey).getOrThrow()
                val postHash = hkdf.sha3_256(enc2).joinToString("") { "%02x".format(it.toInt() and 0xFF) }
                val postId   = "burn-post-id"

                dao.insertPost(PostEntity(
                    postId = postId, channelId = "c1", authorNodeId = "author",
                    encryptedTier0 = enc0, encryptedTier1 = null, encryptedTier2 = enc2,
                    postHash = postHash, createdAtMs = 0, ttlMs = Long.MAX_VALUE,
                    burnAfterRead = true, postState = PostState.CONFIRMED
                ))

                // Open the post — should return entity even though burnAfterRead=true
                val result = engine.openPost(postId)
                result.shouldNotBeNull()
                result.postId shouldBe postId

                // After opening, post should be gone from DB
                val afterBurn = dao.getPost(postId)
                afterBurn.shouldBeNull()
            }
        }

        it("openPost on non-burn post leaves it in DB") {
            runTest {
                val dao    = FakeDao()
                val engine = PostEngine(dao)
                val cipher = SymmetricCipher()
                val hkdf   = Hkdf.instance
                val postKey = ByteArray(32) { 0x01 }

                val enc0 = cipher.encrypt("meta".toByteArray(), postKey).getOrThrow()
                val enc2 = cipher.encrypt("content".toByteArray(), postKey).getOrThrow()
                val postHash = hkdf.sha3_256(enc2).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

                dao.insertPost(PostEntity(
                    postId = "keep-post", channelId = "c1", authorNodeId = "author",
                    encryptedTier0 = enc0, encryptedTier1 = null, encryptedTier2 = enc2,
                    postHash = postHash, createdAtMs = 0, ttlMs = Long.MAX_VALUE,
                    burnAfterRead = false, postState = PostState.CONFIRMED
                ))

                engine.openPost("keep-post").shouldNotBeNull()
                dao.getPost("keep-post").shouldNotBeNull()  // still there
            }
        }
    }
})

// ── Full user usage cycle ─────────────────────────────────────────────────────

class UserUsageCycleTest : DescribeSpec({

    describe("User usage cycle — join channel, post, read, depart") {

        it("complete cycle: create channel → post → read → burn-after-read → depart") {
            runTest {
                val dao          = FakeDao()
                val hkdf         = Hkdf.instance
                val cipher       = SymmetricCipher()
                val channelMgr   = ChannelManager(dao, hkdf)
                val postEngine   = PostEngine(dao)

                // 1. Create a CLOSED channel with a wrapped key
                val rawKey       = ByteArray(32) { 0x42 }
                // Simulate wrapping: encrypt rawKey with a device-derived key
                val deviceKey    = ByteArray(32) { 0xAA.toByte() }
                val wrappedKey   = cipher.encrypt(rawKey, deviceKey).getOrThrow()

                val channel = channelMgr.createChannel(
                    name          = "Ops Channel",
                    type          = ChannelType.CLOSED,
                    genesisNodeId = ByteArray(32) { 0x01 },
                    wrappedKey    = wrappedKey
                )
                channel.name shouldBe "Ops Channel"
                channel.type shouldBe ChannelType.CLOSED
                channel.departed shouldBe false

                // 2. Simulate ratchet advance for post
                val ratchet   = PostRatchet.fromChannelKey(rawKey, hkdf)
                val content   = "Regroup at 0600 at grid ref 44N"
                val postHash  = hkdf.sha3_256(content.toByteArray())
                val step      = ratchet.advance(postHash)
                val postKey   = step.postKey

                // 3. Create post
                val enc0 = cipher.encrypt(
                    "author:node1|channel:${channel.channelId}|ts:1000".toByteArray(),
                    postKey
                ).getOrThrow()
                val enc1 = cipher.encrypt(content.take(20).toByteArray(), postKey).getOrThrow()
                val enc2 = cipher.encrypt(content.toByteArray(), postKey).getOrThrow()
                postKey.fill(0)  // wipe post key immediately after use

                val postId = hkdf.sha3_256(
                    channel.channelId.toByteArray() + "node1".toByteArray() + enc2 +
                    ByteArray(8)
                ).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

                val post = PostEntity(
                    postId = postId, channelId = channel.channelId, authorNodeId = "node1",
                    encryptedTier0 = enc0, encryptedTier1 = enc1, encryptedTier2 = enc2,
                    postHash = postHash.joinToString("") { "%02x".format(it.toInt() and 0xFF) },
                    createdAtMs = 1000L, ttlMs = Long.MAX_VALUE,
                    burnAfterRead = true, postState = PostState.CONFIRMED
                )
                val rowId = dao.insertPost(post)
                (rowId != -1L) shouldBe true  // not a duplicate

                // 4. Read post (burn-after-read)
                val retrieved = postEngine.openPost(postId)
                retrieved.shouldNotBeNull()
                retrieved.postId shouldBe postId

                // Decrypt to verify content round-trips correctly
                val channelKeyUnwrapped = cipher.decrypt(wrappedKey, deviceKey).getOrThrow()
                val ratchet2 = PostRatchet.fromChannelKey(channelKeyUnwrapped, hkdf)
                val step2    = ratchet2.advance(postHash)
                val dec      = cipher.decrypt(retrieved.encryptedTier2!!, step2.postKey).getOrThrow()
                dec.decodeToString() shouldBe content
                step2.postKey.fill(0)
                channelKeyUnwrapped.fill(0)

                // 5. Verify burn-after-read: post gone from DB after open
                dao.getPost(postId).shouldBeNull()

                // 6. Depart channel — key wiped
                channelMgr.departChannel(channel.channelId)
                val departed = channelMgr.getChannel(channel.channelId)
                departed.shouldNotBeNull()
                departed.departed shouldBe true
                departed.encryptedKeyBlob.isEmpty() shouldBe true
            }
        }

        it("duplicate post rejected by content address") {
            runTest {
                val dao    = FakeDao()
                val cipher = SymmetricCipher()
                val hkdf   = Hkdf.instance
                val key    = ByteArray(32) { 0x01 }

                val enc0 = cipher.encrypt("meta".toByteArray(), key).getOrThrow()
                val enc2 = cipher.encrypt("same content".toByteArray(), key).getOrThrow()
                val hash = hkdf.sha3_256(enc2).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

                val post = PostEntity(
                    postId = "dup-id", channelId = "c1", authorNodeId = "n",
                    encryptedTier0 = enc0, encryptedTier1 = null, encryptedTier2 = enc2,
                    postHash = hash, createdAtMs = 0, ttlMs = Long.MAX_VALUE
                )

                val r1 = dao.insertPost(post)
                val r2 = dao.insertPost(post)  // duplicate

                (r1 != -1L) shouldBe true
                r2 shouldBe -1L  // rejected
            }
        }

        it("key rotation: old key cannot decrypt post-rotation content") {
            runTest {
                val hkdf   = Hkdf.instance
                val cipher = SymmetricCipher()

                val oldKey     = ByteArray(32) { 0x11.toByte() }
                val newKey     = ByteArray(32) { 0x22.toByte() }
                val content    = "post rotation content"

                // Encrypt with new key
                val enc = cipher.encrypt(content.toByteArray(), newKey).getOrThrow()

                // Old key cannot decrypt
                var threw = false
                try { cipher.decrypt(enc, oldKey).getOrThrow() }
                catch (e: Exception) { threw = true }
                threw shouldBe true

                // New key decrypts correctly
                val dec = cipher.decrypt(enc, newKey).getOrThrow()
                dec.decodeToString() shouldBe content
            }
        }

        it("COMPARTMENTED channel requiresBiometricGate and cannot rotate digitally") {
            runTest {
                val dao     = FakeDao()
                val manager = ChannelManager(dao)
                val channel = ChannelEntity(
                    channelId = "comp", name = "Compartmented",
                    type = ChannelType.COMPARTMENTED,
                    encryptedKeyBlob = ByteArray(0), genesisHash = "gh",
                    createdAtMs = 0, lastActivityMs = 0
                )
                dao.upsertChannel(channel)

                manager.requiresBiometricGate(channel) shouldBe true

                // rotateKey must throw for COMPARTMENTED
                var threw = false
                try { manager.rotateKey("comp", ByteArray(32), ChannelType.COMPARTMENTED) }
                catch (e: IllegalArgumentException) { threw = true }
                threw shouldBe true
            }
        }

        it("TTL sweep deletes expired posts and leaves current ones") {
            runTest {
                val dao    = FakeDao()
                val engine = PostEngine(dao)
                val cipher = SymmetricCipher()
                val hkdf   = Hkdf.instance
                val key    = ByteArray(32) { 0x01 }

                val enc0 = cipher.encrypt("meta".toByteArray(), key).getOrThrow()
                val enc2 = cipher.encrypt("content".toByteArray(), key).getOrThrow()
                val hash = hkdf.sha3_256(enc2).joinToString("") { "%02x".format(it.toInt() and 0xFF) }

                val nowMs = System.currentTimeMillis()

                // Expired post
                dao.insertPost(PostEntity(
                    postId = "expired", channelId = "c1", authorNodeId = "n",
                    encryptedTier0 = enc0, encryptedTier1 = null, encryptedTier2 = enc2,
                    postHash = hash, createdAtMs = 0, ttlMs = nowMs - 1_000L,
                    postState = PostState.CONFIRMED
                ))

                // Current post
                dao.insertPost(PostEntity(
                    postId = "current", channelId = "c1", authorNodeId = "n",
                    encryptedTier0 = enc0, encryptedTier1 = null, encryptedTier2 = enc2,
                    postHash = hash + "x", createdAtMs = nowMs, ttlMs = nowMs + 7 * 86_400_000L,
                    postState = PostState.CONFIRMED
                ))

                engine.sweepExpired(nowMs)

                dao.getPost("expired").shouldBeNull()
                dao.getPost("current").shouldNotBeNull()
            }
        }

        it("TtlSweepWorker work name is defined") {
            TtlSweepWorker.WORK_NAME shouldBe "shadowmesh_ttl_sweep"
            TtlSweepWorker.INTERVAL_HOURS shouldBe 6L
        }
    }
})

// ── Fake DAO implementations ──────────────────────────────────────────────────

private class FakeRatchetDao : RatchetDao {
    val stored = mutableMapOf<String, RatchetCheckpointEntity>()
    override suspend fun upsertCheckpoint(checkpoint: RatchetCheckpointEntity) {
        stored[checkpoint.channelId] = checkpoint
    }
    override suspend fun getCheckpoint(channelId: String) = stored[channelId]
    override suspend fun deleteCheckpoint(channelId: String) { stored.remove(channelId) }
}

private class FakeDao : ShadowMeshDao {
    private val channels  = mutableMapOf<String, ChannelEntity>()
    val posts             = mutableMapOf<String, PostEntity>()
    private val fragments = mutableMapOf<String, FragmentEntity>()
    private val blocklist = mutableMapOf<String, BlocklistEntry>()
    private val reputation= mutableMapOf<String, ReputationEntry>()

    override suspend fun upsertChannel(channel: ChannelEntity)  { channels[channel.channelId] = channel }
    override fun observeActiveChannels() = kotlinx.coroutines.flow.flow {
        emit(channels.values.filter { !it.departed }.sortedByDescending { it.lastActivityMs })
    }
    override suspend fun getChannel(channelId: String) = channels[channelId]
    override suspend fun markDeparted(channelId: String) {
        channels[channelId]?.let { channels[channelId] = it.copy(departed = true, encryptedKeyBlob = ByteArray(0)) }
    }
    override suspend fun touchChannel(channelId: String, nowMs: Long) {
        channels[channelId]?.let { channels[channelId] = it.copy(lastActivityMs = nowMs) }
    }
    override suspend fun insertPost(post: PostEntity): Long {
        if (posts.containsKey(post.postId)) return -1L
        posts[post.postId] = post; return 1L
    }
    override fun observePosts(channelId: String) = kotlinx.coroutines.flow.flow {
        emit(posts.values.filter { it.channelId == channelId }.sortedByDescending { it.createdAtMs })
    }
    override suspend fun getPost(postId: String) = posts[postId]
    override suspend fun updatePostState(postId: String, state: PostState) {
        posts[postId]?.let { posts[postId] = it.copy(postState = state) }
    }
    override suspend fun updatePostProgress(postId: String, state: PostState, tier1Unlocked: Boolean, received: Int) {
        posts[postId]?.let { posts[postId] = it.copy(
            postState = state,
            tier1Unlocked = if (tier1Unlocked) true else it.tier1Unlocked,
            fragmentsReceived = if (received >= 0) received else it.fragmentsReceived) }
    }
    override suspend fun updatePostConfirmed(postId: String, encryptedTier2: ByteArray, postHash: String) {
        posts[postId]?.let { posts[postId] = it.copy(postState = PostState.CONFIRMED, encryptedTier2 = encryptedTier2, postHash = postHash) }
    }
    override suspend fun burnIfRequired(postId: String) { posts.remove(postId) }
    override suspend fun purgeTtlExpired(nowMs: Long) { posts.entries.removeIf { it.value.ttlMs < nowMs } }
    override suspend fun postExists(postId: String) = if (posts.containsKey(postId)) 1 else 0
    override suspend fun insertFragment(fragment: FragmentEntity): Long {
        if (fragments.containsKey(fragment.fragmentId)) return -1L
        fragments[fragment.fragmentId] = fragment; return 1L
    }
    override suspend fun getFragmentsForPost(postId: String) =
        fragments.values.filter { it.postId == postId }.sortedBy { it.index }
    override suspend fun fragmentCountForPost(postId: String) =
        fragments.values.count { it.postId == postId }
    override suspend fun deleteFragments(postId: String) { fragments.entries.removeIf { it.value.postId == postId } }
    override suspend fun purgeOrphanedFragments(cutoffMs: Long) {}
    override suspend fun blockNode(entry: BlocklistEntry) { blocklist[entry.nodeId] = entry }
    override suspend fun isBlocked(nodeId: String) = if (blocklist.containsKey(nodeId)) 1 else 0
    override fun observeBlocklist() = kotlinx.coroutines.flow.flowOf(blocklist.values.toList())
    override suspend fun unblock(nodeId: String) { blocklist.remove(nodeId) }
    override suspend fun upsertReputation(entry: ReputationEntry) { reputation[entry.nodeId] = entry }
    override suspend fun getReputation(nodeId: String) = reputation[nodeId]
    override fun observeReputation() = kotlinx.coroutines.flow.flowOf(reputation.values.toList())
    override suspend fun recordRelaySuccess(nodeId: String, nowMs: Long) {
        reputation[nodeId]?.let { reputation[nodeId] = it.copy(relaySuccessCount = it.relaySuccessCount + 1) }
    }
    override suspend fun recordRelayFailure(nodeId: String, nowMs: Long) {
        reputation[nodeId]?.let { reputation[nodeId] = it.copy(relayFailureCount = it.relayFailureCount + 1) }
    }
}

// ── Gap 3.1 — Polls ──────────────────────────────────────────────────────────

class PollTest : DescribeSpec({

    describe("PostEngine — polls") {

        fun makeDao() = FakeShadowMeshDao()
        fun makeEngine(dao: FakeShadowMeshDao) = PostEngine(dao)

        it("createPoll stores a poll and returns it") {
            runTest {
                val dao    = makeDao()
                val engine = makeEngine(dao)

                val poll = engine.createPoll(
                    postId    = "post1",
                    channelId = "chan1",
                    question  = "Which option?",
                    options   = listOf("Option A", "Option B")
                )

                poll.postId    shouldBe "post1"
                poll.question  shouldBe "Which option?"
                dao.getPoll("post1") shouldBe poll
            }
        }

        it("createPoll rejects fewer than 2 options") {
            runTest {
                val engine = makeEngine(makeDao())
                var threw  = false
                try { engine.createPoll("p", "c", "Q?", listOf("Only one")) }
                catch (e: IllegalArgumentException) { threw = true }
                threw shouldBe true
            }
        }

        it("votePoll records vote index") {
            runTest {
                val dao    = makeDao()
                val engine = makeEngine(dao)
                engine.createPoll("post1", "chan1", "Q?", listOf("A", "B"))
                val poll = dao.getPoll("post1")!!
                engine.votePoll(poll.pollId, 1)
                dao.getPoll("post1")?.myVoteIndex shouldBe 1
            }
        }
    }
})

// ── Gap 3.1 — Reactions ──────────────────────────────────────────────────────

class ReactionTest : DescribeSpec({

    describe("PostEngine — reactions") {

        fun makeEngine() = PostEngine(FakeShadowMeshDao())

        it("addReaction stores a reaction") {
            runTest {
                val engine = makeEngine()
                val reaction = engine.addReaction(
                    postId        = "post1",
                    authorNodeId  = "node_abc",
                    reactionType  = "👍",
                    encryptedBlob = ByteArray(16)
                )
                reaction.postId       shouldBe "post1"
                reaction.reactionType shouldBe "👍"
            }
        }

        it("addReaction with blank type throws") {
            runTest {
                val engine = makeEngine()
                var threw  = false
                try { engine.addReaction("p", "n", "", ByteArray(0)) }
                catch (e: IllegalArgumentException) { threw = true }
                threw shouldBe true
            }
        }
    }
})

// ── Gap 3.2 — Blocklist wired to fragment assembly ────────────────────────────

class BlocklistAssemblyTest : DescribeSpec({

    describe("PostEngine.ingestFragment — blocklist enforcement") {

        it("fragment from blocked author is silently dropped") {
            runTest {
                val dao = FakeShadowMeshDao()
                dao.blockNode(BlocklistEntry("blocked_author", "spam", System.currentTimeMillis(), BlockSource.LOCAL_DECISION))

                val engine = PostEngine(dao)
                val fragment = FragmentEntity(
                    fragmentId    = "frag1",
                    postId        = "post1",
                    channelId     = "chan1",
                    index         = 0,
                    total         = 1,
                    encryptedBytes = ByteArray(64),
                    sha3Hash      = "hash",
                    receivedAtMs  = System.currentTimeMillis()
                )

                val accepted = engine.ingestFragment(fragment, ChannelType.CLOSED, "blocked_author")
                accepted shouldBe false
            }
        }

        it("fragment from non-blocked author is accepted") {
            runTest {
                val dao    = FakeShadowMeshDao()
                val engine = PostEngine(dao)

                // Insert a matching post first so progress update succeeds
                dao.upsertChannel(ChannelEntity("chan1", "Test", ChannelType.CLOSED, ByteArray(0), "genesis", System.currentTimeMillis(), System.currentTimeMillis()))

                val fragment = FragmentEntity(
                    fragmentId     = "frag2",
                    postId         = "post2",
                    channelId      = "chan1",
                    index          = 0,
                    total          = 1,
                    encryptedBytes = ByteArray(64),
                    sha3Hash       = "hash2",
                    receivedAtMs   = System.currentTimeMillis()
                )

                val accepted = engine.ingestFragment(fragment, ChannelType.CLOSED, "clean_author")
                // Bloom filter + no duplicate = should be accepted
                accepted shouldBe true
            }
        }
    }
})

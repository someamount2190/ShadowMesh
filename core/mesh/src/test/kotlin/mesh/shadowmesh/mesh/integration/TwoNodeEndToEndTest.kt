// TODO: [Integration Test] JVM-only, no Android Context required.
// ASSUMPTION: liboqs-java native library is on java.library.path at test time.
//   All existing core/crypto JVM tests (HybridKemTest, etc.) share this requirement.
//   If those pass, this test passes.
// ASSUMPTION: PostRatchet.fromChannelKeyAndSender with the same senderNodeId produces
//   identical chain key sequences on both nodes — this is the per-sender ratchet model.
// ASSUMPTION: SymmetricCipher.encrypt/decrypt can be called from runTest coroutine scope;
//   it dispatches to Dispatchers.IO internally, which runs on real threads under runTest.

package mesh.shadowmesh.mesh.integration

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import kotlinx.coroutines.test.runTest
import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.mesh.fragment.*
import org.junit.jupiter.api.Assumptions
import java.security.SecureRandom

class TwoNodeEndToEndTest : DescribeSpec({

    val kem    = HybridKem(Hkdf.instance)
    val signer = HybridSigner()
    val hkdf   = Hkdf.instance
    val cipher = SymmetricCipher()
    val engine = FragmentationEngine(hkdf)
    val rng    = SecureRandom()

    describe("two-node fragmented encrypted message") {

        it("A sends fragmented encrypted post to B; B reassembles and decrypts correctly") {
            runTest {
                // Skip gracefully if the liboqs JNI native library is not on java.library.path.
                val kemAvailable = runCatching { kem.encapsulate(HybridPublicKey(ByteArray(1), ByteArray(1))) }
                    .fold(onSuccess = { true }, onFailure = { e ->
                        (e !is ExceptionInInitializerError && e !is UnsatisfiedLinkError && e !is NoClassDefFoundError)
                    })
                Assumptions.assumeTrue(kemAvailable, "liboqs native library not available on this JVM — skipping KEM test")

                // ── 1. Node identity generation ────────────────────────────────────
                val generator = NodeIdentityGenerator(kem = kem, signer = signer, hkdf = hkdf)
                val nodeA = generator.generate().getOrThrow()
                val nodeB = generator.generate().getOrThrow()

                nodeA.nodeId.contentEquals(nodeB.nodeId) shouldBe false
                nodeA.nodeId.size shouldBe 32
                nodeB.nodeId.size shouldBe 32

                // ── 2. KEM key exchange: A encapsulates to B's public key ───────────
                val kemResult = kem.encapsulate(nodeB.publicPart.kemPublicKey).getOrThrow()

                val sharedSecretB = kem.decapsulate(
                    ciphertext       = kemResult.ciphertext,
                    recipientPrivKey = nodeB.privatePart.kemPrivateKey
                ).getOrThrow()

                // Both sides must derive the same 32-byte shared secret
                kemResult.sharedSecret.contentEquals(sharedSecretB) shouldBe true
                kemResult.sharedSecret.size shouldBe 32

                // ── 3. Derive shared channel key from KEM shared secret ────────────
                val channelId = hkdf.sha3_256(
                    nodeA.nodeId + nodeB.nodeId + "ch_v1".toByteArray()
                )
                val channelKeyA = hkdf.derive(
                    ikm       = kemResult.sharedSecret,
                    salt      = channelId,
                    info      = "shadowmesh_channel_key_v1".toByteArray(),
                    outputLen = 32
                )
                val channelKeyB = hkdf.derive(
                    ikm       = sharedSecretB,
                    salt      = channelId,
                    info      = "shadowmesh_channel_key_v1".toByteArray(),
                    outputLen = 32
                )
                kemResult.sharedSecret.fill(0)
                sharedSecretB.fill(0)

                channelKeyA.contentEquals(channelKeyB) shouldBe true

                // ── 4. Both nodes build per-sender ratchets for A's posts ──────────
                // Per-sender ratchet: B tracks A's ratchet using A's nodeId as the salt.
                val ratchetA = PostRatchet.fromChannelKeyAndSender(
                    channelKey          = channelKeyA,
                    senderNodeId        = nodeA.nodeId,
                    hkdf                = hkdf,
                    checkpointInterval  = 5  // low for testability
                )
                val ratchetB = PostRatchet.fromChannelKeyAndSender(
                    channelKey          = channelKeyB,
                    senderNodeId        = nodeA.nodeId,
                    hkdf                = hkdf,
                    checkpointInterval  = 5
                )

                // ── 5. Sender (A): encrypt post 0 and fragment it ─────────────────
                val plaintext = "SHADOWMESH: offline P2P mesh message — post index 0. "
                    .repeat(40).toByteArray()

                val postId   = ByteArray(32).also { rng.nextBytes(it) }
                val postHash = hkdf.sha3_256(postId)

                val stepA     = ratchetA.advance(postHash)
                val postKey0A = stepA.postKey

                val encryptedPost = cipher.encrypt(plaintext, postKey0A).getOrThrow()
                postKey0A.fill(0)

                // Encrypted post is [24B nonce][ciphertext + 16B tag] — larger than plaintext
                (encryptedPost.size > plaintext.size) shouldBe true

                val fragmentSet = engine.fragment(postId, channelId, encryptedPost, FecScheme.RS_10_7)

                fragmentSet.fragments.size shouldBe
                    (FecScheme.RS_10_7.dataShards + FecScheme.RS_10_7.parityShards)
                fragmentSet.originalLength shouldBe encryptedPost.size
                fragmentSet.scheme shouldBe FecScheme.RS_10_7

                // Every fragment's content-addressed ID must verify
                fragmentSet.fragments.all { engine.verifyFragment(it) } shouldBe true

                // ── 6. Wire round-trip: serialize all fragments ────────────────────
                val wireBytes    = fragmentSet.fragments.map { it.toWire() }
                val deserialised = wireBytes.map { FragmentEntity.fromWire(it) }

                deserialised.all { it != null } shouldBe true

                // channelId on wire is obfuscated — verify obfuscation is consistent
                val expectedObfuscated = FragmentEntity.obfuscateChannelId(channelId)
                deserialised.all { it!!.channelId == expectedObfuscated } shouldBe true

                // postId is NOT obfuscated — must round-trip faithfully
                val postIdHex = postId.toHex()
                deserialised.all { it!!.postId == postIdHex } shouldBe true

                // ── 7. Network simulation: drop 2 fragments (RS_10_7 tolerates up to 7) ─
                val receivedFragments = deserialised
                    .filterIndexed { i, _ -> i != 2 && i != 11 }  // drop fragment indices 2, 11
                    .filterNotNull()

                receivedFragments.size shouldBe fragmentSet.fragments.size - 2

                // ── 8. Receiver (B): reassemble ────────────────────────────────────
                val reassembled = engine.reassemble(
                    fragments      = receivedFragments,
                    originalLength = fragmentSet.originalLength,
                    scheme         = FecScheme.RS_10_7
                )
                reassembled.shouldNotBeNull()
                reassembled.contentEquals(encryptedPost) shouldBe true

                // ── 9. Receiver (B): derive post key from ratchet and decrypt ───────
                // B extracts postId from a received fragment (it's in plaintext on wire)
                val postIdFromWire = hexToBytes(receivedFragments.first().postId)
                val postHashB      = hkdf.sha3_256(postIdFromWire)

                val stepB     = ratchetB.advance(postHashB)
                val postKey0B = stepB.postKey

                val decrypted = cipher.decrypt(reassembled, postKey0B).getOrThrow()
                postKey0B.fill(0)

                decrypted.contentEquals(plaintext) shouldBe true
            }
        }

        it("Merkle root computed by receiver from data-only shards matches sender's root") {
            runTest {
                val postId    = ByteArray(32) { it.toByte() }
                val channelId = ByteArray(32) { (it + 1).toByte() }
                val payload   = ByteArray(3000) { (it % 127).toByte() }

                val set = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)

                val receiverTree = FragmentMerkleTree.build(
                    set.dataFragments.sortedBy { it.sequenceIndex }.map { it.payload },
                    hkdf
                )
                set.merkleRoot.contentEquals(receiverTree.root) shouldBe true
            }
        }

        it("forward secrecy: post N key is computationally independent of post N+1 key") {
            runTest {
                val channelKey   = ByteArray(32).also { rng.nextBytes(it) }
                val senderNodeId = ByteArray(32).also { rng.nextBytes(it) }

                val ratchet = PostRatchet.fromChannelKeyAndSender(channelKey, senderNodeId)

                val hash0 = hkdf.sha3_256("post0".toByteArray())
                val hash1 = hkdf.sha3_256("post1".toByteArray())

                val key0 = ratchet.advance(hash0).postKey.copyOf()
                val key1 = ratchet.advance(hash1).postKey.copyOf()

                key0.contentEquals(key1) shouldBe false

                // Encrypt with key1; verify key0 cannot authenticate/decrypt it
                val msg = "secret content for post 1".toByteArray()
                val ct  = cipher.encrypt(msg, key1).getOrThrow()

                val result = cipher.decrypt(ct, key0)
                (result is CryptoResult.Failure) shouldBe true
            }
        }

        it("FEC: reassemble from exactly N data shards with all parity discarded") {
            runTest {
                val postId    = ByteArray(32).also { rng.nextBytes(it) }
                val channelId = ByteArray(32).also { rng.nextBytes(it) }
                val payload   = ByteArray(1024) { it.toByte() }

                val set      = engine.fragment(postId, channelId, payload, FecScheme.RS_10_8)
                val dataOnly = set.dataFragments  // exactly 10 data shards, 0 parity

                dataOnly.size shouldBe FecScheme.RS_10_8.dataShards

                val result = engine.reassemble(dataOnly, set.originalLength, FecScheme.RS_10_8)
                result.shouldNotBeNull()
                result.contentEquals(payload) shouldBe true
            }
        }

        it("FEC: reassemble fails when below threshold") {
            runTest {
                val postId    = ByteArray(32).also { rng.nextBytes(it) }
                val channelId = ByteArray(32).also { rng.nextBytes(it) }
                val payload   = ByteArray(512) { it.toByte() }

                val set   = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
                val tooFew = set.fragments.take(FecScheme.RS_10_7.dataShards - 1)  // need 10, have 9

                engine.reassemble(tooFew, set.originalLength, FecScheme.RS_10_7).shouldBeNull()
            }
        }

        it("ratchet checkpoint: restore from checkpoint and advance to same key") {
            runTest {
                val channelKey   = ByteArray(32).also { rng.nextBytes(it) }
                val senderNodeId = ByteArray(32).also { rng.nextBytes(it) }

                // Ratchet with checkpoint every 3 posts
                val ratchetFull = PostRatchet.fromChannelKeyAndSender(
                    channelKey = channelKey,
                    senderNodeId = senderNodeId,
                    checkpointInterval = 3
                )

                val hash0 = hkdf.sha3_256("p0".toByteArray())
                val hash1 = hkdf.sha3_256("p1".toByteArray())
                val hash2 = hkdf.sha3_256("p2".toByteArray())
                val hash3 = hkdf.sha3_256("p3".toByteArray())

                ratchetFull.advance(hash0)
                ratchetFull.advance(hash1)
                val step2 = ratchetFull.advance(hash2)

                // Checkpoint must be non-null at post index 3 (= interval)
                step2.checkpoint.shouldNotBeNull()
                val checkpointKey = step2.checkpoint!!.copyOf()
                val checkpointIdx = step2.postIndex

                // Advance one more step on the original ratchet
                val key3Original = ratchetFull.advance(hash3).postKey.copyOf()

                // Restore from checkpoint on a fresh ratchet and advance to same step
                val ratchetRestored = PostRatchet.fromCheckpoint(
                    checkpointKey   = checkpointKey,
                    checkpointIndex = checkpointIdx,
                    hkdf            = hkdf,
                    checkpointInterval = 3
                )
                val key3Restored = ratchetRestored.advance(hash3).postKey.copyOf()

                key3Original.contentEquals(key3Restored) shouldBe true
            }
        }
    }
})

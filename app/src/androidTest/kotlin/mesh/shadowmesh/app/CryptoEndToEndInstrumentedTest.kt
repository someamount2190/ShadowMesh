package mesh.shadowmesh.app

import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import mesh.shadowmesh.crypto.*
import mesh.shadowmesh.mesh.fragment.*
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import org.openquantumsafe.KeyEncapsulation
import java.security.SecureRandom

/**
 * On-device instrumented test for the full ShadowMesh crypto stack.
 *
 * Runs on the emulator/device so liboqs-jni.so is properly loaded for the target ABI.
 * Covers the path that the JVM unit test (TwoNodeEndToEndTest) skips when the desktop
 * native library is absent.
 *
 * Test plan:
 *   1. HybridKem key exchange: encapsulate + decapsulate → same shared secret
 *   2. Channel key derivation via HKDF
 *   3. PostRatchet: advance produces distinct post keys; forward secrecy holds
 *   4. SymmetricCipher: encrypt → decrypt round-trip
 *   5. FragmentationEngine: fragment + FEC round-trip (drop 2 of 17 shards, reassemble)
 *   6. Full two-node path: NodeA encrypts, fragments; NodeB reassembles, decrypts
 */
@RunWith(AndroidJUnit4::class)
class CryptoEndToEndInstrumentedTest {

    private val kem    = HybridKem(Hkdf.instance)
    private val signer = HybridSigner()
    private val hkdf   = Hkdf.instance
    private val cipher = SymmetricCipher()
    private val engine = FragmentationEngine(hkdf)
    private val rng    = SecureRandom()

    // ── 1. KEM key exchange ───────────────────────────────────────────────────

    @Test
    fun hybridKem_encapsulateDecapsulate_sameSharedSecret() = runBlocking {
        val generator = NodeIdentityGenerator(kem = kem, signer = signer, hkdf = hkdf)
        val nodeB     = generator.generate().getOrThrow()

        val kemResult     = kem.encapsulate(nodeB.publicPart.kemPublicKey).getOrThrow()
        val sharedSecretB = kem.decapsulate(
            ciphertext       = kemResult.ciphertext,
            recipientPrivKey = nodeB.privatePart.kemPrivateKey
        ).getOrThrow()

        assertEquals("Shared secret must be 32 bytes", 32, kemResult.sharedSecret.size)
        assertEquals("Shared secret must be 32 bytes", 32, sharedSecretB.size)
        assertTrue(
            "Both sides must derive the same 32-byte shared secret",
            kemResult.sharedSecret.contentEquals(sharedSecretB)
        )
    }

    // ── 2. PostRatchet forward secrecy ────────────────────────────────────────

    @Test
    fun postRatchet_forwardSecrecy_keyNCannotDecryptKeyN1() = runBlocking {
        val channelKey   = ByteArray(32).also { rng.nextBytes(it) }
        val senderNodeId = ByteArray(32).also { rng.nextBytes(it) }
        val ratchet      = PostRatchet.fromChannelKeyAndSender(channelKey, senderNodeId)

        val key0 = ratchet.advance(hkdf.sha3_256("post0".toByteArray())).postKey.copyOf()
        val key1 = ratchet.advance(hkdf.sha3_256("post1".toByteArray())).postKey.copyOf()

        assertFalse("key0 and key1 must differ", key0.contentEquals(key1))

        val ct     = cipher.encrypt("secret".toByteArray(), key1).getOrThrow()
        val result = cipher.decrypt(ct, key0)
        assertTrue("key0 must not decrypt a key1 ciphertext", result is CryptoResult.Failure)
    }

    // ── 3. SymmetricCipher round-trip ─────────────────────────────────────────

    @Test
    fun symmetricCipher_roundTrip() = runBlocking {
        val key       = ByteArray(32).also { rng.nextBytes(it) }
        val plaintext = "ShadowMesh XChaCha20-Poly1305 round-trip test".toByteArray()

        val ct        = cipher.encrypt(plaintext, key).getOrThrow()
        val recovered = cipher.decrypt(ct, key).getOrThrow()

        assertTrue("Decrypted bytes must equal original plaintext", recovered.contentEquals(plaintext))
        assertTrue("Ciphertext is larger (nonce + tag overhead)", ct.size > plaintext.size)
    }

    // ── 4. FEC fragment + reassemble ──────────────────────────────────────────

    @Test
    fun fec_fragmentAndReassemble_drop2Shards() {
        val postId    = ByteArray(32).also { rng.nextBytes(it) }
        val channelId = ByteArray(32).also { rng.nextBytes(it) }
        val payload   = ByteArray(2048) { it.toByte() }

        val set = engine.fragment(postId, channelId, payload, FecScheme.RS_10_7)
        assertEquals(17, set.fragments.size)  // 10 data + 7 parity

        // Drop 2 shards — RS_10_7 tolerates up to 7 losses
        val received = set.fragments.filterIndexed { i, _ -> i != 1 && i != 13 }
        assertEquals(15, received.size)

        val reassembled = engine.reassemble(received, set.originalLength, FecScheme.RS_10_7)
        assertNotNull("Reassembly must succeed with 15 of 17 shards", reassembled)
        assertTrue("Reassembled payload must match original", reassembled!!.contentEquals(payload))
    }

    // ── 4b. Kyber direct JNI diagnostic ──────────────────────────────────────

    @Test
    fun kyber_directJni_sameObject_encapDecapMatch() {
        // Standard liboqs pattern: generate keypair in kem_B, encapsulate from kem_A,
        // decapsulate in kem_B (no import_secret_key — private key lives in the JNI object).
        val kemB = KeyEncapsulation("Kyber1024")
        val pubKeyB = kemB.generate_keypair()

        val encapSs: ByteArray
        val ct: ByteArray
        KeyEncapsulation("Kyber1024").use { kemA ->
            encapSs = kemA.encap_secret(pubKeyB.copyOf())
            ct = kemA.get_ciphertext() ?: throw AssertionError("liboqs returned null ciphertext")
        }

        val decapSs = kemB.decap_secret(ct)
        kemB.close()

        assertEquals("Kyber shared secret length", encapSs.size, decapSs.size)
        assertTrue(
            "Kyber same-JNI-object: encap and decap shared secrets must match",
            encapSs.contentEquals(decapSs)
        )
    }

    @Test
    fun kyber_directJni_importSecretKey_encapDecapMatch() {
        // Tests import_secret_key path specifically.
        val kemB = KeyEncapsulation("Kyber1024")
        val pubKeyB   = kemB.generate_keypair()
        // Must copy before close() — dispose_KEM() calls Common.wipe() which zeroes
        // the internal secret_key_ array that export_secret_key() exposes by reference.
        val secretKey = kemB.export_secret_key().copyOf()
        kemB.close()

        val encapSs: ByteArray
        val ct: ByteArray
        KeyEncapsulation("Kyber1024").use { kemA ->
            encapSs = kemA.encap_secret(pubKeyB.copyOf())
            ct = kemA.get_ciphertext() ?: throw AssertionError("liboqs returned null ciphertext")
        }

        val decapSs: ByteArray
        KeyEncapsulation("Kyber1024").use { kemB2 ->
            kemB2.import_secret_key(secretKey)
            decapSs = kemB2.decap_secret(ct)
        }

        assertEquals("Kyber secret key size", 3168, secretKey.size)
        assertTrue(
            "Kyber import_secret_key path: encap and decap shared secrets must match",
            encapSs.contentEquals(decapSs)
        )
    }

    @Test
    fun hybridKem_directKeyPair_noNodeIdentity() = runBlocking {
        val kemKp    = kem.generateKeyPair().getOrThrow()
        val kemResult = kem.encapsulate(kemKp.publicKey).getOrThrow()
        val recovered = kem.decapsulate(kemResult.ciphertext, kemKp.privateKey).getOrThrow()
        assertTrue(
            "HybridKem direct keypair round-trip must match",
            kemResult.sharedSecret.contentEquals(recovered)
        )
    }

    // ── 5. Full two-node encrypted fragmented post ────────────────────────────

    @Test
    fun twoNode_fullStack_kemExchangeFragmentEncryptDecrypt() = runBlocking {
        val generator = NodeIdentityGenerator(kem = kem, signer = signer, hkdf = hkdf)
        val nodeA     = generator.generate().getOrThrow()
        val nodeB     = generator.generate().getOrThrow()

        assertFalse("Node IDs must differ", nodeA.nodeId.contentEquals(nodeB.nodeId))

        // KEM exchange: A encapsulates to B's public key
        val kemResult     = kem.encapsulate(nodeB.publicPart.kemPublicKey).getOrThrow()
        val sharedSecretB = kem.decapsulate(kemResult.ciphertext, nodeB.privatePart.kemPrivateKey).getOrThrow()
        assertTrue(kemResult.sharedSecret.contentEquals(sharedSecretB))

        // Derive channel key
        val channelId   = hkdf.sha3_256(nodeA.nodeId + nodeB.nodeId + "ch_v1".toByteArray())
        val channelKeyA = hkdf.derive(kemResult.sharedSecret, channelId, "shadowmesh_channel_key_v1".toByteArray(), 32)
        val channelKeyB = hkdf.derive(sharedSecretB,          channelId, "shadowmesh_channel_key_v1".toByteArray(), 32)
        assertTrue("Channel keys must match", channelKeyA.contentEquals(channelKeyB))
        kemResult.sharedSecret.fill(0); sharedSecretB.fill(0)

        // Per-sender ratchets (both seeded identically from channelKey + senderNodeId)
        val ratchetA = PostRatchet.fromChannelKeyAndSender(channelKeyA, nodeA.nodeId, hkdf, 5)
        val ratchetB = PostRatchet.fromChannelKeyAndSender(channelKeyB, nodeA.nodeId, hkdf, 5)

        // A: encrypt and fragment
        val plaintext = "SHADOWMESH two-node on-device integration test ".repeat(30).toByteArray()
        val postId    = ByteArray(32).also { rng.nextBytes(it) }
        val postHash  = hkdf.sha3_256(postId)
        val stepA     = ratchetA.advance(postHash)
        val encrypted = cipher.encrypt(plaintext, stepA.postKey).getOrThrow()
        stepA.postKey.fill(0)

        val set = engine.fragment(postId, channelId, encrypted, FecScheme.RS_10_7)
        assertTrue("All fragment IDs must verify", set.fragments.all { engine.verifyFragment(it) })

        // Wire round-trip + drop 2 shards
        val wire         = set.fragments.map { it.toWire() }
        val deserialized = wire.map { FragmentEntity.fromWire(it) }.filterNotNull()
        assertEquals(17, deserialized.size)
        val received     = deserialized.filterIndexed { i, _ -> i != 3 && i != 9 }

        // B: reassemble
        val reassembled = engine.reassemble(received, set.originalLength, FecScheme.RS_10_7)
        assertNotNull("Reassembly must succeed", reassembled)
        assertTrue("Reassembled bytes match encrypted post", reassembled!!.contentEquals(encrypted))

        // B: decrypt using own ratchet
        val postIdFromWire = hexToBytes(received.first().postId)
        val stepB          = ratchetB.advance(hkdf.sha3_256(postIdFromWire))
        val decrypted      = cipher.decrypt(reassembled, stepB.postKey).getOrThrow()
        stepB.postKey.fill(0)

        assertTrue("Decrypted plaintext must match original", decrypted.contentEquals(plaintext))
    }
}

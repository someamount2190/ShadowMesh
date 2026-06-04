package mesh.shadowmesh.security

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.IntegrityBoundedKeyDerivation

/**
 * Tests for the pure-JVM parts of ApkIntegrityVerifier.
 *
 * The Android-specific parts (PackageManager, WorkManager) are not tested here —
 * they require instrumented tests on a real device or emulator. This class covers:
 *   - buildApkBindingHash correctness (delegated to IntegrityBoundedKeyDerivation)
 *   - Key derivation changes when APK hash changes
 *   - WrappedKey serialisation round-trip
 *
 * The full verify() flow is covered by instrumented tests in the androidTest source set.
 */
class ApkIntegrityVerifierTest : DescribeSpec({

    val hkdf = Hkdf()
    val ibd  = IntegrityBoundedKeyDerivation(hkdf)

    val signingCert = ByteArray(512) { it.toByte() }
    val criticalBytecodes = listOf(
        ByteArray(1024) { 0x01 },   // NSC
        ByteArray(2048) { 0x02 },   // GossipEngine
        ByteArray(512)  { 0x03 },   // DhtClient
        ByteArray(256)  { 0x04 },   // HybridKem
        ByteArray(128)  { 0x05 }    // FragmentAssembler
    )

    describe("APK binding hash") {

        it("is deterministic for the same inputs") {
            val h1 = ibd.buildApkBindingHash(signingCert, criticalBytecodes)
            val h2 = ibd.buildApkBindingHash(signingCert, criticalBytecodes)
            h1.contentEquals(h2) shouldBe true
        }

        it("changes when signing certificate changes — repackaged APK breaks identity") {
            val altCert = ByteArray(512) { 0xFF.toByte() }
            val h1 = ibd.buildApkBindingHash(signingCert, criticalBytecodes)
            val h2 = ibd.buildApkBindingHash(altCert, criticalBytecodes)
            h1.contentEquals(h2) shouldBe false
        }

        it("changes when any critical class bytecode changes") {
            val modifiedBytecodes = criticalBytecodes.toMutableList().also {
                it[0] = ByteArray(1024) { 0xAA.toByte() }  // NSC modified
            }
            val h1 = ibd.buildApkBindingHash(signingCert, criticalBytecodes)
            val h2 = ibd.buildApkBindingHash(signingCert, modifiedBytecodes)
            h1.contentEquals(h2) shouldBe false
        }

        it("changes when a critical class is added") {
            val extended = criticalBytecodes + listOf(ByteArray(64) { 0x06 })
            val h1 = ibd.buildApkBindingHash(signingCert, criticalBytecodes)
            val h2 = ibd.buildApkBindingHash(signingCert, extended)
            h1.contentEquals(h2) shouldBe false
        }

        it("produces 32-byte hash") {
            val h = ibd.buildApkBindingHash(signingCert, criticalBytecodes)
            h.size shouldBe 32
        }
    }

    describe("Key derivation breaks when APK hash changes") {

        val deviceSecret = ByteArray(32) { 0x42 }

        it("identity key is different when APK hash changes") {
            val hash1 = ibd.buildApkBindingHash(signingCert, criticalBytecodes)
            val altCert = ByteArray(512) { 0xFF.toByte() }
            val hash2 = ibd.buildApkBindingHash(altCert, criticalBytecodes)

            val key1 = ibd.derive(deviceSecret, hash1,
                purpose = IntegrityBoundedKeyDerivation.KeyPurpose.IDENTITY)
            val key2 = ibd.derive(deviceSecret, hash2,
                purpose = IntegrityBoundedKeyDerivation.KeyPurpose.IDENTITY)

            key1.contentEquals(key2) shouldBe false
        }

        it("channel key is different when APK hash changes") {
            val channelGenesis = ByteArray(32) { 0x77 }
            val hash1 = ibd.buildApkBindingHash(signingCert, criticalBytecodes)
            val modifiedBytecodes = criticalBytecodes.toMutableList().also {
                it[2] = ByteArray(512) { 0xBB.toByte() }
            }
            val hash2 = ibd.buildApkBindingHash(signingCert, modifiedBytecodes)

            val key1 = ibd.derive(deviceSecret, hash1, channelGenesis,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)
            val key2 = ibd.derive(deviceSecret, hash2, channelGenesis,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)

            key1.contentEquals(key2) shouldBe false
        }
    }

    describe("WrappedKey serialisation") {

        it("round-trip toBytes / fromBytes") {
            val ciphertext = ByteArray(48) { it.toByte() }
            val iv         = ByteArray(12) { (it + 100).toByte() }
            val wrapped    = WrappedKey(ciphertext, iv)

            val bytes     = wrapped.toBytes()
            val recovered = WrappedKey.fromBytes(bytes)

            recovered.ciphertext.contentEquals(ciphertext) shouldBe true
            recovered.iv.contentEquals(iv) shouldBe true
        }

        it("different iv produces different bytes") {
            val ct  = ByteArray(48) { 0x01 }
            val iv1 = ByteArray(12) { 0x01 }
            val iv2 = ByteArray(12) { 0x02 }

            WrappedKey(ct, iv1).toBytes().contentEquals(
                WrappedKey(ct, iv2).toBytes()
            ) shouldBe false
        }

        it("fromBytes rejects truncated input") {
            var threw = false
            try { WrappedKey.fromBytes(ByteArray(2)) }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }
    }
})

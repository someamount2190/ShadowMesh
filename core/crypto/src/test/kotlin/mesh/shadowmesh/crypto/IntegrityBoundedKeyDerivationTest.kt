package mesh.shadowmesh.crypto

import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe

class IntegrityBoundedKeyDerivationTest : DescribeSpec({

    val hkdf = Hkdf()
    val ibd  = IntegrityBoundedKeyDerivation(hkdf)

    val deviceSecret   = ByteArray(32) { 0x42 }
    val apkHash        = ByteArray(32) { 0x13 }
    val channelGenesis = ByteArray(32) { 0x77 }

    describe("IntegrityBoundedKeyDerivation") {

        it("produces a 32-byte key") {
            val key = ibd.derive(deviceSecret, apkHash)
            key.size shouldBe 32
        }

        it("is deterministic — same inputs produce same key") {
            val k1 = ibd.derive(deviceSecret, apkHash, channelGenesis)
            val k2 = ibd.derive(deviceSecret, apkHash, channelGenesis)
            k1.contentEquals(k2) shouldBe true
        }

        it("different APK hash produces different key — modification breaks identity") {
            val k1 = ibd.derive(deviceSecret, apkHash)
            val k2 = ibd.derive(deviceSecret, ByteArray(32) { 0xFF.toByte() })
            k1.contentEquals(k2) shouldBe false
        }

        it("different device secret produces different key") {
            val k1 = ibd.derive(deviceSecret, apkHash)
            val k2 = ibd.derive(ByteArray(32) { 0x99.toByte() }, apkHash)
            k1.contentEquals(k2) shouldBe false
        }

        it("different channel genesis produces different channel key") {
            val k1 = ibd.derive(deviceSecret, apkHash, channelGenesis,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)
            val k2 = ibd.derive(deviceSecret, apkHash, ByteArray(32) { 0x01 },
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)
            k1.contentEquals(k2) shouldBe false
        }

        it("different KeyPurpose produces different key") {
            val identity = ibd.derive(deviceSecret, apkHash, channelGenesis,
                IntegrityBoundedKeyDerivation.KeyPurpose.IDENTITY)
            val channel  = ibd.derive(deviceSecret, apkHash, channelGenesis,
                IntegrityBoundedKeyDerivation.KeyPurpose.CHANNEL)
            identity.contentEquals(channel) shouldBe false
        }

        it("rejects deviceSecret shorter than 32 bytes") {
            var threw = false
            try { ibd.derive(ByteArray(16), apkHash) }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }

        it("rejects apkBindingHash not exactly 32 bytes") {
            var threw = false
            try { ibd.derive(deviceSecret, ByteArray(16)) }
            catch (e: IllegalArgumentException) { threw = true }
            threw shouldBe true
        }

        it("buildApkBindingHash is deterministic") {
            val cert     = ByteArray(512) { it.toByte() }
            val bytecode = listOf(ByteArray(1024) { 0x01 }, ByteArray(2048) { 0x02 })
            val h1 = ibd.buildApkBindingHash(cert, bytecode)
            val h2 = ibd.buildApkBindingHash(cert, bytecode)
            h1.contentEquals(h2) shouldBe true
        }

        it("buildApkBindingHash differs when signing cert changes") {
            val cert1    = ByteArray(512) { 0x01 }
            val cert2    = ByteArray(512) { 0x02 }
            val bytecode = listOf(ByteArray(1024) { 0x01 })
            ibd.buildApkBindingHash(cert1, bytecode)
                .contentEquals(ibd.buildApkBindingHash(cert2, bytecode)) shouldBe false
        }

        it("buildApkBindingHash differs when critical bytecode changes") {
            val cert     = ByteArray(512) { 0x01 }
            val code1    = listOf(ByteArray(1024) { 0x01 })
            val code2    = listOf(ByteArray(1024) { 0x02 })
            ibd.buildApkBindingHash(cert, code1)
                .contentEquals(ibd.buildApkBindingHash(cert, code2)) shouldBe false
        }
    }
})

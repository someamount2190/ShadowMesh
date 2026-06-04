package mesh.shadowmesh.distribution

import android.content.Context
import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import io.kotest.core.spec.style.DescribeSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import java.io.File
import java.security.MessageDigest

/**
 * Pure-logic tests for app self-distribution (design Features 1–3).
 * Covers descriptor + bootstrap-QR serialization round-trips and the ApkArtifactVerifier gate
 * (content hash, signing-cert agreement, descriptor signature, downgrade floor) using a fake
 * cert-hash provider so no real APK/PackageManager is needed.
 */
class DistributionTest : DescribeSpec({

    val sodium = LazySodiumJava(SodiumJava())

    // Fixed test release keypair.
    val relPub  = ByteArray(com.goterl.lazysodium.interfaces.Sign.PUBLICKEYBYTES)
    val relPriv = ByteArray(com.goterl.lazysodium.interfaces.Sign.SECRETKEYBYTES)
    sodium.cryptoSignKeypair(relPub, relPriv)

    fun sign(msg: ByteArray): ByteArray {
        val s = ByteArray(com.goterl.lazysodium.interfaces.Sign.BYTES)
        sodium.cryptoSignDetached(s, null, msg, msg.size.toLong(), relPriv)
        return s
    }

    fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    val certHash = "a".repeat(64)   // pretend signing-cert SHA-256 hex

    fun descriptorFor(apkBytes: ByteArray, versionCode: Int = 10): AppArtifactDescriptor {
        val unsigned = AppArtifactDescriptor(
            versionCode     = versionCode,
            versionName     = "1.2.3",
            manifestHash    = ByteArray(32) { 7 },
            apkSha256       = sha256(apkBytes),
            signingCertHash = certHash,
            minSdk          = 29,
            signature       = ByteArray(0)
        )
        return unsigned.copy(signature = sign(unsigned.signedBytes()))
    }

    describe("AppArtifactDescriptor round-trip") {
        it("serializes and parses back identically") {
            val d = descriptorFor(byteArrayOf(1, 2, 3))
            val parsed = AppArtifactDescriptor.fromBytes(d.toBytes())
            parsed shouldBe d
        }
        it("rejects malformed bytes") {
            AppArtifactDescriptor.fromBytes(byteArrayOf(0, 1, 2)) shouldBe null
        }
    }

    describe("AppArtifactDescriptor — manifestHash is a stable key derivation seed") {
        it("createAndSignDescriptor manifestHash is reproducible for the same APK+versionCode") {
            runTest {
                val apk = File.createTempFile("test", ".apk").apply {
                    writeBytes(ByteArray(2048) { (it % 251).toByte() }); deleteOnExit()
                }
                val chunker = ShadowFilesChunker()
                val d1 = AppArtifactSeeder.createAndSignDescriptor(
                    apkFile = apk, versionCode = 10, versionName = "1.0",
                    minSdk = 29, signingCertHash = certHash,
                    releasePrivateKey = relPriv, chunker = chunker
                )
                val d2 = AppArtifactSeeder.createAndSignDescriptor(
                    apkFile = apk, versionCode = 10, versionName = "1.0",
                    minSdk = 29, signingCertHash = certHash,
                    releasePrivateKey = relPriv, chunker = chunker
                )
                // Same APK + versionCode → same key derivation seed → same manifestHash
                d1.manifestHash.contentEquals(d2.manifestHash) shouldBe true
            }
        }

        it("different versionCode produces different manifestHash") {
            runTest {
                val apk = File.createTempFile("test", ".apk").apply {
                    writeBytes(ByteArray(1024) { 0x42 }); deleteOnExit()
                }
                val chunker = ShadowFilesChunker()
                val d1 = AppArtifactSeeder.createAndSignDescriptor(
                    apkFile = apk, versionCode = 10, versionName = "1.0",
                    minSdk = 29, signingCertHash = certHash, releasePrivateKey = relPriv, chunker = chunker
                )
                val d2 = AppArtifactSeeder.createAndSignDescriptor(
                    apkFile = apk, versionCode = 11, versionName = "1.1",
                    minSdk = 29, signingCertHash = certHash, releasePrivateKey = relPriv, chunker = chunker
                )
                // Different versionCode → different postId in chunking → different manifestHash
                d1.manifestHash.contentEquals(d2.manifestHash) shouldBe false
            }
        }
    }
        it("serializes and parses back identically") {
            val qr = AppBootstrapQr(
                versionCode = 10,
                manifestHash = ByteArray(32) { 7 },
                seederHint = ByteArray(6) { 9 },
                descriptorSig8 = ByteArray(8) { 3 }
            )
            AppBootstrapQr.fromBytes(qr.toBytes()) shouldBe qr
        }
        it("derives from a descriptor with matching fields") {
            val d = descriptorFor(byteArrayOf(5))
            val qr = AppBootstrapQr.forDescriptor(d, ByteArray(6) { 1 })
            qr.versionCode shouldBe d.versionCode
            qr.descriptorSig8.contentEquals(d.signature.copyOf(8)) shouldBe true
        }
    }

    describe("ApkArtifactVerifier gate") {
        val ctx = mockk<Context>(relaxed = true)
        val apkBytes = ByteArray(2048) { (it % 251).toByte() }

        fun verifier(floor: Int = 0, archiveCert: String? = certHash) =
            ApkArtifactVerifier(
                context = ctx,
                expectedSigningCertHash = certHash,
                releasePublicKey = relPub,
                downgradeFloor = floor,
                archiveCertHashProvider = { archiveCert }
            )

        fun tmpApk(bytes: ByteArray): File =
            File.createTempFile("test", ".apk").apply { writeBytes(bytes); deleteOnExit() }

        it("accepts a genuine descriptor + matching APK") {
            runTest {
                val d = descriptorFor(apkBytes)
                val res = verifier().verify(tmpApk(apkBytes), d)
                res.shouldBeInstanceOf<ApkArtifactVerifier.Result.Verified>()
                (res as ApkArtifactVerifier.Result.Verified).versionCode shouldBe 10
            }
        }
        it("rejects a forged descriptor signature") {
            runTest {
                val d = descriptorFor(apkBytes).copy(signature = ByteArray(64) { 0 })
                verifier().verify(tmpApk(apkBytes), d)
                    .shouldBeInstanceOf<ApkArtifactVerifier.Result.Rejected>()
            }
        }
        it("rejects content-hash mismatch (tampered APK)") {
            runTest {
                val d = descriptorFor(apkBytes)
                val tampered = apkBytes.copyOf().also { it[0] = (it[0] + 1).toByte() }
                verifier().verify(tmpApk(tampered), d)
                    .shouldBeInstanceOf<ApkArtifactVerifier.Result.Rejected>()
            }
        }
        it("rejects when archive signing cert is not the genuine release key") {
            runTest {
                val d = descriptorFor(apkBytes)
                verifier(archiveCert = "b".repeat(64)).verify(tmpApk(apkBytes), d)
                    .shouldBeInstanceOf<ApkArtifactVerifier.Result.Rejected>()
            }
        }
        it("rejects a downgrade below the floor") {
            runTest {
                val d = descriptorFor(apkBytes, versionCode = 5)
                verifier(floor = 10).verify(tmpApk(apkBytes), d)
                    .shouldBeInstanceOf<ApkArtifactVerifier.Result.Rejected>()
            }
        }
    }
})

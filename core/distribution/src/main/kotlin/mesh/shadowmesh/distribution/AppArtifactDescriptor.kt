package mesh.shadowmesh.distribution
import mesh.shadowmesh.diagnostics.Diag

import mesh.shadowmesh.crypto.Hkdf
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Signed record that designates a SHADOWMESH build as a mesh-hosted artifact
 * (design: Self-Distribution, Feature 1 + 3).
 *
 * The descriptor binds, under one Ed25519 release signature:
 *   versionCode ↔ manifestHash ↔ apkSha256 ↔ signingCertHash
 *
 * That binding is what closes the downgrade/confusion gap: an attacker cannot lift a
 * genuine-but-old APK's hash into a descriptor for a different version, because the
 * signature covers all four fields together.
 *
 * Wire format (signed bytes = everything except the signature):
 *   magic[4]="SMAD" | version:byte | versionCode:int | versionNameLen:byte | versionName
 *   | manifestHash[32] | apkSha256[32] | minSdk:int | signingCertHashLen:byte | signingCertHash
 *   ── then ──  signatureLen:short | signature
 */
data class AppArtifactDescriptor(
    val versionCode:     Int,
    val versionName:     String,
    val manifestHash:    ByteArray,   // identifies the SHADOWFILES TransferManifest (32)
    val apkSha256:       ByteArray,   // SHA-256 of the assembled, decrypted APK bytes (32)
    val signingCertHash: String,      // SHA-256 hex of the APK signing certificate
    val minSdk:          Int,
    val signature:       ByteArray    // Ed25519 over signedBytes(), by the release key
) {
    /** Exact bytes the signature covers (everything except the signature itself). */
    fun signedBytes(): ByteArray = buildSignedBytes(
        versionCode, versionName, manifestHash, apkSha256, signingCertHash, minSdk
    )

    fun toBytes(): ByteArray {
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            val body = signedBytes()
            d.write(body)
            d.writeShort(signature.size)
            d.write(signature)
        }
        return out.toByteArray()
    }

    override fun equals(other: Any?) = other is AppArtifactDescriptor &&
        versionCode == other.versionCode &&
        manifestHash.contentEquals(other.manifestHash) &&
        apkSha256.contentEquals(other.apkSha256) &&
        signingCertHash.equals(other.signingCertHash, ignoreCase = true) &&
        signature.contentEquals(other.signature)

    override fun hashCode(): Int {
        var r = versionCode
        r = 31 * r + manifestHash.contentHashCode()
        r = 31 * r + apkSha256.contentHashCode()
        r = 31 * r + signingCertHash.lowercase().hashCode()
        return r
    }

    companion object {
        const val MAGIC   = "SMAD"          // SHADOWMESH App Descriptor
        const val VERSION: Byte = 1

        private fun buildSignedBytes(
            versionCode: Int, versionName: String, manifestHash: ByteArray,
            apkSha256: ByteArray, signingCertHash: String, minSdk: Int
        ): ByteArray {
            require(manifestHash.size == 32) { "manifestHash must be 32 bytes" }
            require(apkSha256.size == 32)    { "apkSha256 must be 32 bytes" }
            val out = ByteArrayOutputStream()
            DataOutputStream(out).use { d ->
                d.writeBytes(MAGIC)
                d.writeByte(VERSION.toInt())
                d.writeInt(versionCode)
                val vn = versionName.toByteArray()
                require(vn.size <= 255) { "versionName too long" }
                d.writeByte(vn.size); d.write(vn)
                d.write(manifestHash)
                d.write(apkSha256)
                d.writeInt(minSdk)
                val ch = signingCertHash.toByteArray()
                require(ch.size <= 255) { "signingCertHash too long" }
                d.writeByte(ch.size); d.write(ch)
            }
            return out.toByteArray()
        }

        /** Parse a full descriptor (body + signature). Returns null on malformed input. */
        fun fromBytes(bytes: ByteArray): AppArtifactDescriptor? = try {
            val dis = DataInputStream(ByteArrayInputStream(bytes))
            val magic = ByteArray(4).also { dis.readFully(it) }
            require(String(magic) == MAGIC) { "bad magic" }
            val ver = dis.readByte(); require(ver == VERSION) { "bad version" }
            val versionCode = dis.readInt()
            val vnLen = dis.readUnsignedByte()
            val versionName = ByteArray(vnLen).also { dis.readFully(it) }.let(::String)
            val manifestHash = ByteArray(32).also { dis.readFully(it) }
            val apkSha256 = ByteArray(32).also { dis.readFully(it) }
            val minSdk = dis.readInt()
            val chLen = dis.readUnsignedByte()
            val signingCertHash = ByteArray(chLen).also { dis.readFully(it) }.let(::String)
            val sigLen = dis.readUnsignedShort()
            val signature = ByteArray(sigLen).also { dis.readFully(it) }
            AppArtifactDescriptor(
                versionCode, versionName, manifestHash, apkSha256,
                signingCertHash, minSdk, signature
            )
        } catch (_: Exception) {
            null
        }
    }
}

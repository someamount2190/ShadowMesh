package mesh.shadowmesh.distribution
import mesh.shadowmesh.diagnostics.Diag

import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.intTo4Bytes
import mesh.shadowmesh.mesh.fragment.FragmentEntity
import mesh.shadowmesh.mesh.files.TransferManifest
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Reserved, well-known identifiers for the app-distribution channel (design Feature 1).
 *
 * CHANNEL_KEY is PUBLIC by design — see [AppArtifactSeeder]. It provides traffic-shape
 * uniformity (app pulls are indistinguishable from private SHADOWFILES pulls), not secrecy.
 */
object DistributionConstants {
    private val hkdf = Hkdf.instance

    /** 32-byte reserved channel id for app distribution (SHA3 of a fixed label). */
    val CHANNEL_ID: ByteArray = hkdf.sha3_256("shadowmesh.app.distribution.channel".toByteArray()).copyOf(32)

    /** 32-byte PUBLIC channel key (fixed). Not a secret; uniformity only. */
    val CHANNEL_KEY: ByteArray = hkdf.sha3_256("shadowmesh.app.distribution.publickey.v1".toByteArray()).copyOf(32)

    /** Per-version base postId for the transfer (each build is its own SHADOWFILES transfer). */
    fun distributionPostId(versionCode: Int): ByteArray =
        hkdf.sha3_256("shadowmesh.app.dist.post".toByteArray() + intTo4Bytes(versionCode)).copyOf(32)

    /** Stable transferId string the reassembler keys checkpoints by. */
    fun transferId(versionCode: Int): String = "appdist_v$versionCode"

    const val SEED_TTL_MS = 30L * 24 * 60 * 60 * 1000   // 30 days — apps are long-lived seeds

}

/**
 * Bootstrap QR payload (design Feature 2). A QR cannot hold an APK, so it carries a small
 * trigger: which build, where to find a seeder, and the transfer-key seed.
 *
 * The transfer key is NOT secret here (public distribution channel), so the QR carries the
 * version + manifestHash + a seeder hint + a short release-signature prefix for fast reject.
 * The acquirer re-derives the real transfer key from CHANNEL_KEY + manifestHash exactly as the
 * seeder did — the QR only needs to convey manifestHash and version, not the key itself.
 *
 * Wire format:
 *   magic[4]="SMBP" | version:byte | versionCode:int | manifestHash[32]
 *   | seederHint[6] | descriptorSig8[8]
 */
data class AppBootstrapQr(
    val versionCode:    Int,
    val manifestHash:   ByteArray,    // 32
    val seederHint:     ByteArray,    // 6 — BLE manufacturer-data tag of the advertising seeder
    val descriptorSig8: ByteArray     // 8 — first 8 bytes of the release signature, fast reject
) {
    fun toBytes(): ByteArray {
        require(manifestHash.size == 32) { "manifestHash must be 32" }
        require(seederHint.size == 6)    { "seederHint must be 6" }
        require(descriptorSig8.size == 8){ "descriptorSig8 must be 8" }
        val out = ByteArrayOutputStream()
        DataOutputStream(out).use { d ->
            d.writeBytes(MAGIC)
            d.writeByte(VERSION.toInt())
            d.writeInt(versionCode)
            d.write(manifestHash)
            d.write(seederHint)
            d.write(descriptorSig8)
        }
        return out.toByteArray()
    }

    override fun equals(other: Any?) = other is AppBootstrapQr &&
        versionCode == other.versionCode && manifestHash.contentEquals(other.manifestHash) &&
        seederHint.contentEquals(other.seederHint) && descriptorSig8.contentEquals(other.descriptorSig8)
    override fun hashCode() = 31 * versionCode + manifestHash.contentHashCode()

    companion object {
        const val MAGIC = "SMBP"           // SHADOWMESH BootstraP
        const val VERSION: Byte = 1

        fun fromBytes(bytes: ByteArray): AppBootstrapQr? = try {
            val dis = DataInputStream(ByteArrayInputStream(bytes))
            val magic = ByteArray(4).also { dis.readFully(it) }
            require(String(magic) == MAGIC) { "bad magic" }
            require(dis.readByte() == VERSION) { "bad version" }
            val versionCode = dis.readInt()
            val manifestHash = ByteArray(32).also { dis.readFully(it) }
            val seederHint = ByteArray(6).also { dis.readFully(it) }
            val sig8 = ByteArray(8).also { dis.readFully(it) }
            AppBootstrapQr(versionCode, manifestHash, seederHint, sig8)
        } catch (_: Exception) { null }

        /** Build the bootstrap QR for a seeded artifact. [seederHint] is this seeder's BLE tag. */
        fun forDescriptor(descriptor: AppArtifactDescriptor, seederHint: ByteArray): AppBootstrapQr =
            AppBootstrapQr(
                versionCode    = descriptor.versionCode,
                manifestHash   = descriptor.manifestHash,
                seederHint     = seederHint,
                descriptorSig8 = descriptor.signature.copyOf(8)
            )
    }
}

/**
 * Abstraction over "fetch SHADOWFILES bytes from a seeder" so the acquirer logic is
 * transport-agnostic and unit-testable. The concrete implementation (in the app / bootstrap
 * stub) wires this to BleGattTransport / WiFiDirectTransport fragment requests.
 */
interface ArtifactFetcher {
    /** Fetch the signed descriptor bytes from the seeder identified by [seederHint]. */
    suspend fun fetchDescriptor(seederHint: ByteArray, versionCode: Int): ByteArray?

    /** Fetch the SHADOWFILES TransferManifest bytes for [manifestHash]. */
    suspend fun fetchManifest(seederHint: ByteArray, manifestHash: ByteArray): ByteArray?

    /**
     * Fetch the [AppArtifactAcquirer.ChunkIndex] sidecar for the transfer identified by
     * [merkleRoot] (the Merkle root of the production chunk tree, from [TransferManifest]).
     *
     * This is a distinct method from [fetchManifest] to make the protocol contract explicit.
     * The earlier implementation reused [fetchManifest] with [merkleRoot] as a sentinel value,
     * creating an implicit convention that any [ArtifactFetcher] implementer could not know
     * about from the interface alone. Implementers map this to a dedicated request to the seeder
     * (e.g. a separate BLE characteristic write or a well-known fragment postId derived from the
     * merkleRoot). Returns null if the index cannot be fetched.
     */
    suspend fun fetchChunkIndex(seederHint: ByteArray, merkleRoot: ByteArray): ByteArray?

    /**
     * Fetch all fragments for a given chunk (content-addressed by per-chunk postId). The
     * acquirer feeds these to ShadowFilesReassembler. Returns null if the chunk can't be fetched.
     */
    suspend fun fetchChunkFragments(
        seederHint: ByteArray,
        chunkPostId: ByteArray
    ): List<FragmentEntity>?
}

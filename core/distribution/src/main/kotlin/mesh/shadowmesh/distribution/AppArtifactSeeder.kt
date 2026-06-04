package mesh.shadowmesh.distribution

import android.content.Context
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import mesh.shadowmesh.crypto.intTo4Bytes
import mesh.shadowmesh.mesh.files.ChunkResult
import mesh.shadowmesh.mesh.files.ShadowFilesChunker
import java.io.File
import java.security.MessageDigest

/**
 * Publish side of app self-distribution (design Feature 1).
 *
 * Chunks the device's own installed base APK into a SHADOWFILES transfer on the reserved
 * public distribution channel, and produces a signed [AppArtifactDescriptor] that names the
 * build and binds its hashes.
 *
 * The distribution channel key is PUBLIC and compiled in ([DistributionConstants.CHANNEL_KEY]):
 * the APK is not a secret, so this key buys traffic-shape uniformity (app pulls look like any
 * private SHADOWFILES pull on the wire), not confidentiality.
 *
 * Signing the descriptor requires the release Ed25519 PRIVATE key, which only the build/release
 * pipeline holds — so [signDescriptor] is normally run at release time, the resulting descriptor
 * bytes are shipped inside the APK (or distributed alongside it), and a running seeder simply
 * re-serves that pre-signed descriptor via [loadBundledDescriptor]. [createAndSignDescriptor] is
 * provided for the release tool / tests; a normal device never holds the private key.
 */
class AppArtifactSeeder(
    private val context: Context,
    private val chunker: ShadowFilesChunker = ShadowFilesChunker()
) {

    /** The assembled chunk result for the installed APK, ready to serve to acquirers. */
    data class SeedingState(
        val descriptor: AppArtifactDescriptor,
        val chunkResult: ChunkResult,
        val apkBytes:   ByteArray
    )

    /**
     * Prepare to seed: read the installed APK, chunk it on the distribution channel, and pair
     * it with the bundled (pre-signed) descriptor.
     *
     * The transfer key is derived from the descriptor's [AppArtifactDescriptor.manifestHash],
     * which is the **key derivation seed** (a provisional-key Merkle root computed at release
     * time). This is the same seed the acquirer uses, so both sides arrive at the same key.
     *
     * Integrity check: the installed APK is required to hash to [AppArtifactDescriptor.apkSha256].
     * This prevents a tampered installed APK from being seeded under a genuine descriptor.
     * The chunk-tree Merkle root is NOT compared against descriptor.manifestHash — they are
     * semantically different values (key seed vs production tree root).
     */
    suspend fun prepareSeeding(bundledDescriptor: AppArtifactDescriptor): SeedingState? =
        withContext(Dispatchers.IO) {
            val apkFile = installedApkFile() ?: return@withContext null
            val apkBytes = apkFile.readBytes()

            // APK content integrity: ensure the installed APK matches what was signed.
            if (!sha256(apkBytes).contentEquals(bundledDescriptor.apkSha256)) return@withContext null

            // Derive the same key the acquirer will use.
            val transferKey = chunker.deriveKeyFromChannel(
                DistributionConstants.CHANNEL_KEY, bundledDescriptor.manifestHash
            )
            val result = chunker.chunk(
                fileBytes   = apkBytes,
                transferKey = transferKey,
                postId      = DistributionConstants.distributionPostId(bundledDescriptor.versionCode),
                channelId   = DistributionConstants.CHANNEL_ID,
                filename    = null,   // do not leak "this is the apk" in the manifest
                ttlMs       = System.currentTimeMillis() + DistributionConstants.SEED_TTL_MS
            )
            // Note: result.manifestHash is the production chunk tree root (different from
            // bundledDescriptor.manifestHash which is the key derivation seed). This is correct.
            // The per-chunk hashes in the ChunkIndex are derived from result and verified by the
            // acquirer's Merkle check independently of the descriptor.manifestHash field.

            SeedingState(bundledDescriptor, result, apkBytes)
        }

    /**
     * Publish a prepared [SeedingState] into the DHT so acquirers can fetch via the DHT-backed
     * [ArtifactFetcher]. Uses the same key-derivation as [buildArtifactFetcher] in the app module.
     *
     * Stored records (all with [DistributionConstants.SEED_TTL_MS] = 30-day TTL):
     *   1. Descriptor bytes         → key = SHA3-256(distributionPostId(v) || "desc_v1")
     *   2. Manifest bytes           → key = SHA3-256(manifestHash          || "manifest_v1")
     *   3. Chunk index bytes        → key = SHA3-256(merkleRoot            || "chunkidx_v1")
     *   4. Per-chunk fragment list  → key = SHA3-256(chunkPostId)
     *      Wire: [4B count][count × [4B fragLen][frag bytes]]
     *
     * The chunk index format is [4B count][count × [32B chunkHash][4B encLen]].
     * This is the format [AppArtifactAcquirer.parseChunkIndex] expects.
     */
    suspend fun publishToDht(
        seedingState: SeedingState,
        dhtEngine:    mesh.shadowmesh.mesh.dht.DhtEngine
    ) = withContext(Dispatchers.IO) {
        val hkdf   = mesh.shadowmesh.crypto.Hkdf.instance
        val desc   = seedingState.descriptor
        val result = seedingState.chunkResult
        val ttlMs  = System.currentTimeMillis() + DistributionConstants.SEED_TTL_MS

        // 1. Descriptor
        val descKey = mesh.shadowmesh.mesh.dht.NodeId(
            hkdf.sha3_256(DistributionConstants.distributionPostId(desc.versionCode) + "desc_v1".toByteArray())
        )
        dhtEngine.store(mesh.shadowmesh.mesh.dht.DhtValue(descKey, desc.toBytes(), ttlMs))

        // 2. Manifest
        val manifestBytes = chunker.serializeManifest(result.manifest)
        val manifestKey = mesh.shadowmesh.mesh.dht.NodeId(
            hkdf.sha3_256(result.manifestHash + "manifest_v1".toByteArray())
        )
        dhtEngine.store(mesh.shadowmesh.mesh.dht.DhtValue(manifestKey, manifestBytes, ttlMs))

        // 3. Chunk index: [4B chunkCount][count × [32B chunkHash][4B encLen]]
        //    AppArtifactAcquirer.parseChunkIndex expects exactly this layout.
        val indexOut = java.io.ByteArrayOutputStream()
        val indexDos = java.io.DataOutputStream(indexOut)
        indexDos.writeInt(result.chunkHashes.size)
        result.chunkHashes.forEachIndexed { i, hash ->
            indexDos.write(hash)
            // encryptedChunkLen: payload bytes of the first fragment × totalData shards
            // (RS padding to shard boundary). Use fragmentSets[i].fragments[0].payload.size × totalData.
            val fragmentSet = result.fragmentSets.getOrNull(i)
            val encLen = if (fragmentSet != null && fragmentSet.fragments.isNotEmpty())
                fragmentSet.fragments[0].payload.size * fragmentSet.fragments[0].totalData
            else 0
            indexDos.writeInt(encLen)
        }
        indexDos.flush()
        val indexKey = mesh.shadowmesh.mesh.dht.NodeId(
            hkdf.sha3_256(result.manifest.merkleRoot + "chunkidx_v1".toByteArray())
        )
        dhtEngine.store(mesh.shadowmesh.mesh.dht.DhtValue(indexKey, indexOut.toByteArray(), ttlMs))

        // 4. Per-chunk fragment lists: [4B count][count × [4B fragLen][frag bytes]]
        result.fragmentSets.forEachIndexed { chunkIdx, fragmentSet ->
            val chunkPostId = DistributionConstants.distributionPostId(desc.versionCode).let { base ->
                hkdf.sha3_256(base + mesh.shadowmesh.crypto.intTo4Bytes(chunkIdx))
            }
            val fragOut = java.io.ByteArrayOutputStream()
            val fragDos = java.io.DataOutputStream(fragOut)
            fragDos.writeInt(fragmentSet.fragments.size)
            fragmentSet.fragments.forEach { frag ->
                val fragBytes = serializeFragment(frag)
                fragDos.writeInt(fragBytes.size)
                fragDos.write(fragBytes)
            }
            fragDos.flush()
            val fragKey = mesh.shadowmesh.mesh.dht.NodeId(hkdf.sha3_256(chunkPostId))
            dhtEngine.store(mesh.shadowmesh.mesh.dht.DhtValue(fragKey, fragOut.toByteArray(), ttlMs))
        }
    }

    /**
     * Serialize a [FragmentEntity] to the DHT wire format used by [AppArtifactAcquirer]'s
     * deserialize path in [ShadowMeshApplication.deserializeFragment]:
     *   [64B fragmentId][64B postId][64B channelId]
     *   [2B seqIdx][2B totalData][2B totalParity][4B payloadLen][payload][1B fecWire]
     */
    private fun serializeFragment(frag: mesh.shadowmesh.mesh.fragment.FragmentEntity): ByteArray {
        val baos = java.io.ByteArrayOutputStream()
        val dos  = java.io.DataOutputStream(baos)
        dos.writeBytes(frag.fragmentId.padEnd(64).take(64))
        dos.writeBytes(frag.postId.padEnd(64).take(64))
        dos.writeBytes(frag.channelId.padEnd(64).take(64))
        dos.writeShort(frag.sequenceIndex)
        dos.writeShort(frag.totalData)
        dos.writeShort(frag.totalParity)
        dos.writeInt(frag.payload.size)
        dos.write(frag.payload)
        dos.writeByte(frag.fecScheme.wire.toInt())
        dos.flush()
        return baos.toByteArray()
    }

    /** Path to this app's installed base APK. */
    private fun installedApkFile(): File? =
        context.applicationInfo.sourceDir?.let { File(it) }?.takeIf { it.exists() }

    private fun sha256(b: ByteArray) = MessageDigest.getInstance("SHA-256").digest(b)

    companion object {
        /**
         * RELEASE-TIME ONLY. Build the signed descriptor for an APK file using the release
         * Ed25519 private key. Run by the release pipeline / tests — never on an end-user
         * device (which does not hold the private key). The result is bundled into the APK and
         * re-served at runtime via [prepareSeeding].
         *
         * Key-derivation semantics of [AppArtifactDescriptor.manifestHash]:
         *   The field is a **key derivation seed**, not the Merkle root of the production
         *   encrypted chunk tree. It is derived once at release time by chunking the APK with a
         *   provisional zero-seed key; the resulting Merkle root is stable (same APK + versionCode
         *   → same value) and is used by both the seeder and the acquirer to derive the real
         *   transfer key via [ShadowFilesChunker.deriveKeyFromChannel]. The production chunk tree
         *   (encrypted under the real key) has its own Merkle root, which is NOT stored in the
         *   descriptor — it is checked internally by [ShadowFilesReassembler] per-chunk. The
         *   descriptor's [AppArtifactDescriptor.apkSha256] is the end-to-end integrity anchor.
         */
        suspend fun createAndSignDescriptor(
            apkFile:            File,
            versionCode:        Int,
            versionName:        String,
            minSdk:             Int,
            signingCertHash:    String,
            releasePrivateKey:  ByteArray,
            chunker:            ShadowFilesChunker = ShadowFilesChunker()
        ): AppArtifactDescriptor = withContext(Dispatchers.IO) {
            val apkBytes = apkFile.readBytes()
            val apkSha   = MessageDigest.getInstance("SHA-256").digest(apkBytes)

            // Derive a stable key derivation seed by chunking once with a provisional zero key.
            // The resulting Merkle root (manifestHash) is deterministic for this APK+versionCode
            // and is embedded in the descriptor. Both the seeder (prepareSeeding) and the
            // acquirer (AppArtifactAcquirer) independently derive the real transfer key from
            // this seed via deriveKeyFromChannel(CHANNEL_KEY, descriptor.manifestHash).
            val provisionalKey = chunker.deriveKeyFromChannel(
                DistributionConstants.CHANNEL_KEY, ByteArray(32)
            )
            val provisionalResult = chunker.chunk(
                fileBytes   = apkBytes,
                transferKey = provisionalKey,
                postId      = DistributionConstants.distributionPostId(versionCode),
                channelId   = DistributionConstants.CHANNEL_ID,
                filename    = null
            )
            // provisionalResult.manifestHash is the key derivation seed — stored in the descriptor.
            val descriptor = AppArtifactDescriptor(
                versionCode     = versionCode,
                versionName     = versionName,
                manifestHash    = provisionalResult.manifestHash,   // key seed, not production tree root
                apkSha256       = apkSha,
                signingCertHash = signingCertHash,
                minSdk          = minSdk,
                signature       = ByteArray(0)
            )
            val sig = signEd25519(descriptor.signedBytes(), releasePrivateKey)
            descriptor.copy(signature = sig)
        }

        private fun signEd25519(message: ByteArray, privateKey: ByteArray): ByteArray {
            val signer = Ed25519Signer()
            signer.init(true, Ed25519PrivateKeyParameters(privateKey, 0))
            signer.update(message, 0, message.size)
            return signer.generateSignature()
        }
    }
}

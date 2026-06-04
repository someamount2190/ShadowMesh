package mesh.shadowmesh.distribution

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import kotlinx.coroutines.Dispatchers
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.diagnostics.Diag
import kotlinx.coroutines.withContext
import java.io.File
import java.security.MessageDigest

/**
 * Distribution trust gate — design Feature 3. The same signing-certificate hash the app
 * checks at runtime ([mesh.shadowmesh.security.ApkIntegrityVerifier]) becomes the anchor
 * for verifying an APK acquired through ANY channel (mesh pull, Bluetooth share, SD card).
 *
 * All four checks must pass before an acquired APK is offered for install:
 *   1. Content   — SHA-256(file) == descriptor.apkSha256
 *   2. Authentic — archive signing-cert hash == EXPECTED_SIGNATURE_HASH (compiled in)
 *   2b. Agreement — that same cert hash == descriptor.signingCertHash
 *   3. Descriptor — Ed25519(descriptor.signedBytes, descriptor.signature, RELEASE_PUBKEY)
 *
 * Trust anchor: the release signing-key fingerprint compiled into every installed copy
 * (`expectedSigningCertHash`) plus `releasePublicKey`. This is a SOFTWARE anchor — a device
 * already running genuine SHADOWMESH carries the correct values and can vet any candidate.
 * The first copy a person ever obtains has no on-device anchor; they must compare the
 * fingerprint out-of-band (printed/spoken/second source). See THREAT_MODEL.md §3 and the
 * self-distribution design doc.
 *
 * `downgradeFloor`: refuse descriptors below a minimum versionCode, so a verified-but-old
 * build cannot be pushed as an "update". Defaults to 0 (no floor).
 *
 * Pure logic aside from one PackageManager call to read the candidate archive's cert; the
 * hashing and signature steps are unit-testable with a fake [archiveCertHashProvider].
 */
class ApkArtifactVerifier(
    private val context:                 Context,
    private val expectedSigningCertHash: String,        // BuildConfig.EXPECTED_SIGNATURE_HASH
    private val releasePublicKey:        ByteArray,      // Ed25519 release pubkey (32 bytes)
    private val downgradeFloor:          Int = 0,
    /** Override for tests; production reads the archive via PackageManager. */
    private val archiveCertHashProvider: ((File) -> String?)? = null
) {

    sealed class Result {
        data class Verified(val versionCode: Int, val versionName: String) : Result()
        data class Rejected(val reason: String) : Result()
    }

    /**
     * Verify an acquired APK against its signed descriptor.
     * [apkFile] is the fully-assembled candidate; [descriptor] arrived alongside it.
     */
    suspend fun verify(apkFile: File, descriptor: AppArtifactDescriptor): Result =
        withContext(Dispatchers.IO) {
            // (3) Descriptor signature first — cheapest reject, and everything else trusts
            //     descriptor fields, so they must be authenticated before use.
            if (!verifyDescriptorSignature(descriptor)) {
                return@withContext Result.Rejected("Descriptor signature invalid")
            }
            // Downgrade floor
            if (descriptor.versionCode < downgradeFloor) {
                return@withContext Result.Rejected(
                    "Descriptor versionCode ${descriptor.versionCode} below floor $downgradeFloor"
                )
            }
            if (!apkFile.exists() || apkFile.length() == 0L) {
                return@withContext Result.Rejected("APK file missing or empty")
            }
            // (1) Content hash
            val actualSha = sha256(apkFile)
            if (!actualSha.contentEquals(descriptor.apkSha256)) {
                return@withContext Result.Rejected("APK content hash mismatch")
            }
            // (2) Authenticity: signing cert of the archive == compiled-in expected hash
            val archiveCertHash = archiveSigningCertHash(apkFile)
                ?: return@withContext Result.Rejected("Could not read archive signing certificate")
            if (!archiveCertHash.equals(expectedSigningCertHash, ignoreCase = true)) {
                return@withContext Result.Rejected(
                    "Signing certificate does not match the genuine SHADOWMESH release key"
                )
            }
            // (2b) Descriptor agrees with the archive's cert hash
            if (!archiveCertHash.equals(descriptor.signingCertHash, ignoreCase = true)) {
                return@withContext Result.Rejected(
                    "Descriptor signing-cert hash disagrees with the archive"
                )
            }
            Result.Verified(descriptor.versionCode, descriptor.versionName)
        }

    // ── checks ────────────────────────────────────────────────────────────

    private fun verifyDescriptorSignature(d: AppArtifactDescriptor): Boolean {
        if (releasePublicKey.size != 32) return false
        return try {
            val msg      = d.signedBytes()
            val verifier = Ed25519Signer()
            verifier.init(false, Ed25519PublicKeyParameters(releasePublicKey, 0))
            verifier.update(msg, 0, msg.size)
            verifier.verifySignature(d.signature)
        } catch (_: Exception) {
            false
        }
    }

    private fun sha256(file: File): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest()
    }

    /**
     * SHA-256 hex of the candidate archive's signing certificate. Uses
     * [PackageManager.getPackageArchiveInfo] with signing flags — the archive-file analogue
     * of the installed-package path in ApkIntegrityVerifier.
     */
    @Suppress("DEPRECATION")
    private fun archiveSigningCertHash(apkFile: File): String? {
        archiveCertHashProvider?.let { return it(apkFile) }
        return try {
            val pm = context.packageManager
            val path = apkFile.absolutePath
            val certBytes: ByteArray = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val info = pm.getPackageArchiveInfo(path, PackageManager.GET_SIGNING_CERTIFICATES)
                    ?: return null
                val signingInfo = info.signingInfo ?: return null
                signingInfo.apkContentsSigners.firstOrNull()?.toByteArray() ?: return null
            } else {
                val info = pm.getPackageArchiveInfo(path, PackageManager.GET_SIGNATURES)
                    ?: return null
                @Suppress("DEPRECATION")
                info.signatures?.firstOrNull()?.toByteArray() ?: return null
            }
            MessageDigest.getInstance("SHA-256").digest(certBytes)
                .toHex()
        } catch (_: Exception) {
            null
        }
    }
}

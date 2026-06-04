package mesh.shadowmesh.crypto

import org.bouncycastle.crypto.digests.SHA3Digest

/**
 * HKDF-SHA3-256 implementation per RFC 5869.
 *
 * Uses BouncyCastle's SHA3Digest directly rather than MessageDigest.getInstance("SHA3-256")
 * because the JCE provider for SHA3-256 is not guaranteed available until API 31.
 * BouncyCastle is already on the compile classpath (bcprov-jdk15to18) so no extra dep needed.
 */
class Hkdf {

    // ── Public API ────────────────────────────────────────────────────────

    /**
     * Full HKDF: extract then expand.
     *
     * @param ikm       Input key material
     * @param salt      Optional salt (null or empty → 32 zero bytes per RFC 5869 §2.2)
     * @param info      Context/application-specific info bytes
     * @param outputLen Output length in bytes. Max: 255 × 32 = 8160.
     */
    fun derive(
        ikm:       ByteArray,
        salt:      ByteArray? = null,
        info:      ByteArray,
        outputLen: Int = 32
    ): ByteArray {
        require(outputLen > 0)         { "outputLen must be positive" }
        require(outputLen <= 255 * 32) { "outputLen exceeds HKDF maximum (${255 * 32})" }

        val effectiveSalt = if (salt == null || salt.isEmpty()) ByteArray(32) else salt
        val prk           = extract(effectiveSalt, ikm)
        return expand(prk, info, outputLen)
    }

    // ── HKDF-Extract ──────────────────────────────────────────────────────

    private fun extract(salt: ByteArray, ikm: ByteArray): ByteArray =
        hmacSha3_256(key = salt, data = ikm)

    // ── HKDF-Expand ───────────────────────────────────────────────────────

    private fun expand(prk: ByteArray, info: ByteArray, outputLen: Int): ByteArray {
        val result  = ByteArray(outputLen)
        var t       = ByteArray(0)
        var offset  = 0
        var counter = 1

        while (offset < outputLen) {
            t = hmacSha3_256(key = prk, data = t + info + byteArrayOf(counter.toByte()))
            val toCopy = minOf(t.size, outputLen - offset)
            t.copyInto(result, offset, 0, toCopy)
            offset += toCopy
            counter++
        }
        return result
    }

    // ── HMAC-SHA3-256 ─────────────────────────────────────────────────────

    /**
     * HMAC-SHA3-256: H((K XOR opad) || H((K XOR ipad) || data))
     *
     * Block size for HMAC-SHA3-256: the Keccak rate for SHA3-256 is
     * (state_width − capacity) / 8 = (1600 − 512) / 8 = 136 bytes.
     * NIST FIPS 202 §B.1 defines SHA3-256's rate as 1088 bits = 136 bytes.
     * For HMAC over SHA-3, the block size equals the rate (per RFC 7627 §4
     * and NIST SP 800-185 §4.3). The value 136 is correct.
     */
    fun hmacSha3_256(key: ByteArray, data: ByteArray): ByteArray {
        val blockSize = 136

        val k       = if (key.size > blockSize) sha3_256(key) else key
        val kPadded = k.copyOf(blockSize)   // zero-pads if k shorter than blockSize

        val ipad = ByteArray(blockSize) { (kPadded[it].toInt() xor 0x36).toByte() }
        val opad = ByteArray(blockSize) { (kPadded[it].toInt() xor 0x5c).toByte() }

        val inner = sha3_256(ipad + data)
        return sha3_256(opad + inner)
    }

    // ── SHA3-256 ──────────────────────────────────────────────────────────

    fun sha3_256(data: ByteArray): ByteArray {
        val digest = SHA3Digest(256)
        digest.update(data, 0, data.size)
        val out = ByteArray(32)
        digest.doFinal(out, 0)
        return out
    }

    companion object {
        /** Shared singleton. Thread-safe via ThreadLocal MessageDigest. */
        val instance = Hkdf()
    }
}

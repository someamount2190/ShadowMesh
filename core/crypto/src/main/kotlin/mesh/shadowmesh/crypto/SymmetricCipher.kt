package mesh.shadowmesh.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.ChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import java.security.SecureRandom

/**
 * XChaCha20-Poly1305 AEAD symmetric encryption.
 *
 * - Key size:   32 bytes
 * - Nonce size: 24 bytes (XChaCha20 extended nonce — random nonce collision negligible)
 * - Tag size:   16 bytes (Poly1305 MAC)
 *
 * Wire format: [24-byte nonce][ciphertext + 16-byte tag]
 *
 * Implemented via BouncyCastle ChaCha20Poly1305 (RFC 8439) with HChaCha20
 * subkey derivation per the XChaCha20-Poly1305 IETF draft. This produces
 * the same wire format as libsodium's crypto_aead_xchacha20poly1305_ietf_*.
 */
class SymmetricCipher {

    private val rng = SecureRandom()

    // ── Encrypt ───────────────────────────────────────────────────────────

    /**
     * Encrypt [plaintext] with [key] using a caller-supplied [nonce].
     *
     * Internal: used by known-answer tests to produce deterministic output.
     * Production code always uses [encrypt] which generates a random nonce.
     * [nonce] must be exactly [NONCE_BYTES] (24) bytes.
     */
    internal suspend fun encryptWithNonce(
        plaintext: ByteArray,
        key:       ByteArray,
        nonce:     ByteArray,
        aad:       ByteArray? = null
    ): CryptoResult<ByteArray> =
        withContext(Dispatchers.IO) {
            cryptoRunCatching {
                require(key.size == KEY_BYTES)     { "Key must be $KEY_BYTES bytes" }
                require(nonce.size == NONCE_BYTES) { "Nonce must be $NONCE_BYTES bytes" }
                nonce + xchacha20poly1305Encrypt(key, nonce, plaintext, aad)
            }
        }

    /**
     * Encrypt [plaintext] with [key], optionally binding to [aad] (additional authenticated data).
     *
     * When [aad] is non-null, it is included in the Poly1305 MAC but is NOT stored in the
     * wire output — the receiver must supply the same [aad] to [decrypt].
     *
     * Wire format: [24-byte nonce][ciphertext + 16-byte tag].
     */
    suspend fun encrypt(
        plaintext: ByteArray,
        key:       ByteArray,
        aad:       ByteArray? = null
    ): CryptoResult<ByteArray> =
        withContext(Dispatchers.IO) {
            cryptoRunCatching {
                require(key.size == KEY_BYTES) {
                    "Key must be $KEY_BYTES bytes, got ${key.size}"
                }
                val nonce = ByteArray(NONCE_BYTES).also { rng.nextBytes(it) }
                nonce + xchacha20poly1305Encrypt(key, nonce, plaintext, aad)
            }
        }

    // ── Decrypt ───────────────────────────────────────────────────────────

    /**
     * Decrypt [noncePlusCiphertext] with [key].
     * Input must be in [nonce || ciphertext+tag] format as produced by [encrypt].
     *
     * When [aad] is non-null, decryption is first attempted with the AAD (new format).
     * If authentication fails and [aad] was provided, decryption is retried without AAD
     * (backward-compatible fallback for messages encrypted before AAD was enabled).
     */
    suspend fun decrypt(
        noncePlusCiphertext: ByteArray,
        key:                 ByteArray,
        aad:                 ByteArray? = null
    ): CryptoResult<ByteArray> =
        withContext(Dispatchers.IO) {
            cryptoRunCatching {
                require(key.size == KEY_BYTES) {
                    "Key must be $KEY_BYTES bytes, got ${key.size}"
                }
                require(noncePlusCiphertext.size >= NONCE_BYTES + MAC_BYTES) {
                    "Input too short: ${noncePlusCiphertext.size} bytes"
                }

                val nonce      = noncePlusCiphertext.copyOfRange(0, NONCE_BYTES)
                val ciphertext = noncePlusCiphertext.copyOfRange(NONCE_BYTES, noncePlusCiphertext.size)

                try {
                    xchacha20poly1305Decrypt(key, nonce, ciphertext, aad)
                } catch (e: Exception) {
                    if (aad == null) throw e
                    // Backward-compatible fallback for messages encrypted before AAD was added
                    xchacha20poly1305Decrypt(key, nonce, ciphertext, null)
                }
            }
        }

    fun generateKey(): ByteArray = ByteArray(KEY_BYTES).also { rng.nextBytes(it) }

    // ── XChaCha20-Poly1305 internals ──────────────────────────────────────

    private fun xchacha20poly1305Encrypt(
        key:       ByteArray,
        nonce24:   ByteArray,
        plaintext: ByteArray,
        aad:       ByteArray?
    ): ByteArray {
        val subkey  = hChaCha20(key, nonce24.copyOfRange(0, 16))
        val nonce12 = ByteArray(12).also { System.arraycopy(nonce24, 16, it, 4, 8) }
        val cipher  = ChaCha20Poly1305()
        cipher.init(true, AEADParameters(KeyParameter(subkey), 128, nonce12, aad))
        val out = ByteArray(cipher.getOutputSize(plaintext.size))
        var off = cipher.processBytes(plaintext, 0, plaintext.size, out, 0)
        off += cipher.doFinal(out, off)
        return out
    }

    private fun xchacha20poly1305Decrypt(
        key:        ByteArray,
        nonce24:    ByteArray,
        ciphertext: ByteArray,
        aad:        ByteArray?
    ): ByteArray {
        val subkey  = hChaCha20(key, nonce24.copyOfRange(0, 16))
        val nonce12 = ByteArray(12).also { System.arraycopy(nonce24, 16, it, 4, 8) }
        val cipher  = ChaCha20Poly1305()
        cipher.init(false, AEADParameters(KeyParameter(subkey), 128, nonce12, aad))
        val out = ByteArray(cipher.getOutputSize(ciphertext.size))
        var off = cipher.processBytes(ciphertext, 0, ciphertext.size, out, 0)
        try {
            off += cipher.doFinal(out, off)
        } catch (e: InvalidCipherTextException) {
            throw IllegalStateException("XChaCha20-Poly1305 decryption failed — authentication tag mismatch", e)
        }
        return out.copyOf(off)
    }

    // HChaCha20: derives a 32-byte subkey from a 32-byte key and 16-byte nonce prefix.
    // Runs 20 ChaCha20 rounds and returns words[0..3] || words[12..15] without adding
    // back the initial state (unlike regular ChaCha20 which adds the original state).
    private fun hChaCha20(key: ByteArray, nonce16: ByteArray): ByteArray {
        fun toLE(b: ByteArray, i: Int) =
            (b[i].toInt() and 0xFF) or
            ((b[i+1].toInt() and 0xFF) shl 8) or
            ((b[i+2].toInt() and 0xFF) shl 16) or
            ((b[i+3].toInt() and 0xFF) shl 24)

        val s = IntArray(16)
        s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574
        for (i in 0..7) s[4+i] = toLE(key, i*4)
        for (i in 0..3) s[12+i] = toLE(nonce16, i*4)

        fun qr(a: Int, b: Int, c: Int, d: Int) {
            s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] xor s[a], 16)
            s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] xor s[c], 12)
            s[a] += s[b]; s[d] = Integer.rotateLeft(s[d] xor s[a],  8)
            s[c] += s[d]; s[b] = Integer.rotateLeft(s[b] xor s[c],  7)
        }

        repeat(10) {
            qr(0,4,8,12); qr(1,5,9,13); qr(2,6,10,14); qr(3,7,11,15)
            qr(0,5,10,15); qr(1,6,11,12); qr(2,7,8,13); qr(3,4,9,14)
        }

        fun fromLE(v: Int, b: ByteArray, i: Int) {
            b[i] = v.toByte(); b[i+1] = (v shr 8).toByte()
            b[i+2] = (v shr 16).toByte(); b[i+3] = (v shr 24).toByte()
        }
        val out = ByteArray(32)
        fromLE(s[0], out, 0); fromLE(s[1], out, 4); fromLE(s[2], out, 8); fromLE(s[3], out, 12)
        fromLE(s[12], out, 16); fromLE(s[13], out, 20); fromLE(s[14], out, 24); fromLE(s[15], out, 28)
        return out
    }

    companion object {
        const val KEY_BYTES   = 32
        const val NONCE_BYTES = 24  // XChaCha20 extended nonce
        const val MAC_BYTES   = 16  // Poly1305 tag
    }
}

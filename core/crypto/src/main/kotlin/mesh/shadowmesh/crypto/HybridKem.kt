package mesh.shadowmesh.crypto

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.openquantumsafe.KeyEncapsulation
import java.security.SecureRandom

/**
 * Kyber-1024 + X25519 hybrid Key Encapsulation Mechanism.
 * Both KEM schemes run independently; combined shared secret is derived via
 * HKDF-SHA3-256. Adversary must break BOTH to recover the shared secret.
 *
 * FIX (Issue 4): HybridPrivateKey.fromKeyPairs() factory method added to
 * guarantee kyberPublicKeyForSalt is always the correct companion public key.
 */
class HybridKem(private val hkdf: Hkdf) {

    private val rng = SecureRandom()

    suspend fun generateKyberKeyPair(): CryptoResult<KyberKeyPair> =
        withContext(Dispatchers.IO) {
            cryptoRunCatching {
                KeyEncapsulation(KYBER_ALGORITHM).use { kem ->
                    val pubKey = kem.generate_keypair()
                    // export_secret_key() returns the internal array reference.
                    // close() → dispose_KEM() → Common.wipe() zeroes that same array,
                    // so we must copy before the use-block ends.
                    KyberKeyPair(publicKey = pubKey.copyOf(), privateKey = kem.export_secret_key().copyOf())
                }
            }
        }

    suspend fun generateX25519KeyPair(): CryptoResult<X25519KeyPair> =
        withContext(Dispatchers.IO) {
            cryptoRunCatching {
                val privParams = X25519PrivateKeyParameters(rng)
                val pubParams  = privParams.generatePublicKey()
                X25519KeyPair(publicKey = pubParams.encoded, privateKey = privParams.encoded)
            }
        }

    suspend fun generateKeyPair(): CryptoResult<HybridFullKeyPair> =
        withContext(Dispatchers.IO) {
            cryptoRunCatching {
                val kyberKp  = generateKyberKeyPair().getOrThrow()
                val x25519Kp = generateX25519KeyPair().getOrThrow()
                HybridFullKeyPair(
                    publicKey  = HybridPublicKey(kyberKp.publicKey, x25519Kp.publicKey),
                    privateKey = HybridPrivateKey.fromKeyPairs(kyberKp, x25519Kp)
                )
            }
        }

    suspend fun encapsulate(recipientPublicKey: HybridPublicKey): CryptoResult<HybridKemResult> =
        withContext(Dispatchers.IO) {
            cryptoRunCatching {
                val kyberSharedSs: ByteArray
                val kyberCiphertext: ByteArray
                KeyEncapsulation(KYBER_ALGORITHM).use { kem ->
                    kyberSharedSs   = kem.encap_secret(recipientPublicKey.kyberPublicKey)
                    kyberCiphertext = kem.get_ciphertext()
                        ?: throw IllegalStateException("liboqs returned null ciphertext after encap_secret")
                }

                val ephPrivParams = X25519PrivateKeyParameters(rng)
                val ephPubParams  = ephPrivParams.generatePublicKey()
                val ephPub        = ephPubParams.encoded
                val ephPriv       = ephPrivParams.encoded

                val x25519Ss = x25519ScalarMult(ephPriv, recipientPublicKey.x25519PublicKey)

                val combinedIkm = kyberSharedSs + x25519Ss
                kyberSharedSs.fill(0)
                x25519Ss.fill(0)
                ephPriv.fill(0)

                // Bind both ciphertexts into the HKDF info field to prevent MITM substitution.
                // info = LABEL || kyberCiphertext || x25519EphPublicKey
                val infoWithTranscript = INFO_ENCAP + kyberCiphertext + ephPub

                val sharedSecret = hkdf.derive(
                    ikm       = combinedIkm,
                    salt      = hkdf.sha3_256(recipientPublicKey.kyberPublicKey),
                    info      = infoWithTranscript,
                    outputLen = 32
                )
                combinedIkm.fill(0)

                HybridKemResult(
                    sharedSecret = sharedSecret,
                    ciphertext   = HybridCiphertext(
                        kyberCiphertext    = kyberCiphertext,
                        x25519EphPublicKey = ephPub
                    )
                )
            }
        }

    suspend fun decapsulate(
        ciphertext:       HybridCiphertext,
        recipientPrivKey: HybridPrivateKey
    ): CryptoResult<ByteArray> =
        withContext(Dispatchers.IO) {
            cryptoRunCatching {
                var kyberSs:     ByteArray? = null
                var x25519Ss:    ByteArray? = null
                var combinedIkm: ByteArray? = null
                try {
                    KeyEncapsulation(KYBER_ALGORITHM).use { kem ->
                        kem.import_secret_key(recipientPrivKey.kyberPrivateKey)
                        kyberSs = kem.decap_secret(ciphertext.kyberCiphertext)
                    }

                    x25519Ss = x25519ScalarMult(
                        recipientPrivKey.x25519PrivateKey,
                        ciphertext.x25519EphPublicKey
                    )

                    combinedIkm = kyberSs!! + x25519Ss!!

                    val infoWithTranscript = INFO_ENCAP + ciphertext.kyberCiphertext + ciphertext.x25519EphPublicKey

                    hkdf.derive(
                        ikm       = combinedIkm!!,
                        salt      = hkdf.sha3_256(recipientPrivKey.kyberPublicKeyForSalt),
                        info      = infoWithTranscript,
                        outputLen = 32
                    )
                } finally {
                    kyberSs?.fill(0)
                    x25519Ss?.fill(0)
                    combinedIkm?.fill(0)
                }
            }
        }

    // X25519 scalar multiplication via BouncyCastle.
    // Throws if the output is the all-zero point (small subgroup / low-order key attack).
    private fun x25519ScalarMult(privKey: ByteArray, pubKey: ByteArray): ByteArray {
        val agreement = X25519Agreement()
        agreement.init(X25519PrivateKeyParameters(privKey, 0))
        val out = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(pubKey, 0), out, 0)
        check(!out.all { it == 0.toByte() }) { "X25519 scalar multiplication produced all-zero output" }
        return out
    }

    companion object {
        private const val KYBER_ALGORITHM = "Kyber1024"
        private val INFO_ENCAP = "shadowmesh_kem_v1".toByteArray()
    }
}

// ── Data classes ──────────────────────────────────────────────────────────────

data class KyberKeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
    override fun equals(other: Any?) = other is KyberKeyPair &&
        publicKey.contentEquals(other.publicKey) && privateKey.contentEquals(other.privateKey)
    override fun hashCode() = 31 * publicKey.contentHashCode() + privateKey.contentHashCode()
}

data class X25519KeyPair(val publicKey: ByteArray, val privateKey: ByteArray) {
    override fun equals(other: Any?) = other is X25519KeyPair &&
        publicKey.contentEquals(other.publicKey) && privateKey.contentEquals(other.privateKey)
    override fun hashCode() = 31 * publicKey.contentHashCode() + privateKey.contentHashCode()
}

/** Combined public key: Kyber-1024 + X25519. Wire: [4B kyber len][kyber key][x25519 key 32B] */
data class HybridPublicKey(
    val kyberPublicKey:  ByteArray,
    val x25519PublicKey: ByteArray
) {
    fun toBytes(): ByteArray {
        val kLen = kyberPublicKey.size
        return intTo4Bytes(kLen) + kyberPublicKey + x25519PublicKey
    }

    companion object {
        fun fromBytes(bytes: ByteArray): HybridPublicKey {
            require(bytes.size >= 4) { "HybridPublicKey: too short (${bytes.size})" }
            val kLen = fourBytesToInt(bytes, 0)
            require(kLen >= 0) { "HybridPublicKey: negative Kyber key length ($kLen)" }
            require(bytes.size == 4 + kLen + 32) {
                "HybridPublicKey: wrong total length — expected ${4 + kLen + 32}, got ${bytes.size}"
            }
            return HybridPublicKey(
                kyberPublicKey  = bytes.copyOfRange(4, 4 + kLen),
                x25519PublicKey = bytes.copyOfRange(4 + kLen, 4 + kLen + 32)
            )
        }
    }

    override fun equals(other: Any?) = other is HybridPublicKey &&
        kyberPublicKey.contentEquals(other.kyberPublicKey) &&
        x25519PublicKey.contentEquals(other.x25519PublicKey)
    override fun hashCode() = 31 * kyberPublicKey.contentHashCode() + x25519PublicKey.contentHashCode()
}

/**
 * Hybrid private key.
 * Use [fromKeyPairs] factory to guarantee kyberPublicKeyForSalt is the correct companion key.
 */
data class HybridPrivateKey(
    val kyberPrivateKey:       ByteArray,
    val kyberPublicKeyForSalt: ByteArray,
    val x25519PrivateKey:      ByteArray
) {
    companion object {
        fun fromKeyPairs(kyberKp: KyberKeyPair, x25519Kp: X25519KeyPair) = HybridPrivateKey(
            kyberPrivateKey       = kyberKp.privateKey,
            kyberPublicKeyForSalt = kyberKp.publicKey,
            x25519PrivateKey      = x25519Kp.privateKey
        )
    }

    override fun equals(other: Any?) = other is HybridPrivateKey &&
        kyberPrivateKey.contentEquals(other.kyberPrivateKey) &&
        kyberPublicKeyForSalt.contentEquals(other.kyberPublicKeyForSalt) &&
        x25519PrivateKey.contentEquals(other.x25519PrivateKey)
    override fun hashCode(): Int {
        var r = kyberPrivateKey.contentHashCode()
        r = 31 * r + kyberPublicKeyForSalt.contentHashCode()
        r = 31 * r + x25519PrivateKey.contentHashCode()
        return r
    }
}

data class HybridFullKeyPair(
    val publicKey:  HybridPublicKey,
    val privateKey: HybridPrivateKey
)

/** Wire: [4B kyber ct len][kyber ct][x25519 eph pub 32B] */
data class HybridCiphertext(
    val kyberCiphertext:    ByteArray,
    val x25519EphPublicKey: ByteArray
) {
    fun toBytes(): ByteArray =
        intTo4Bytes(kyberCiphertext.size) + kyberCiphertext + x25519EphPublicKey

    companion object {
        fun fromBytes(bytes: ByteArray): HybridCiphertext {
            require(bytes.size >= 4) { "HybridCiphertext: too short (${bytes.size})" }
            val kLen = fourBytesToInt(bytes, 0)
            require(kLen >= 0) { "HybridCiphertext: negative Kyber ciphertext length ($kLen)" }
            require(bytes.size == 4 + kLen + 32) {
                "HybridCiphertext: wrong total length — expected ${4 + kLen + 32}, got ${bytes.size}"
            }
            return HybridCiphertext(
                kyberCiphertext    = bytes.copyOfRange(4, 4 + kLen),
                x25519EphPublicKey = bytes.copyOfRange(4 + kLen, 4 + kLen + 32)
            )
        }
    }

    override fun equals(other: Any?) = other is HybridCiphertext &&
        kyberCiphertext.contentEquals(other.kyberCiphertext) &&
        x25519EphPublicKey.contentEquals(other.x25519EphPublicKey)
    override fun hashCode() = 31 * kyberCiphertext.contentHashCode() + x25519EphPublicKey.contentHashCode()
}

data class HybridKemResult(
    val sharedSecret: ByteArray,
    val ciphertext:   HybridCiphertext
) {
    override fun equals(other: Any?) = other is HybridKemResult &&
        sharedSecret.contentEquals(other.sharedSecret)
    override fun hashCode() = sharedSecret.contentHashCode()
}

// ── Byte utilities ────────────────────────────────────────────────────────────

internal fun fourBytesToInt(b: ByteArray, off: Int) =
    ((b[off].toInt() and 0xFF) shl 24) or
    ((b[off+1].toInt() and 0xFF) shl 16) or
    ((b[off+2].toInt() and 0xFF) shl  8) or
     (b[off+3].toInt() and 0xFF)

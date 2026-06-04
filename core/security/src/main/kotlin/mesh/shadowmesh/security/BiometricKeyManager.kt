package mesh.shadowmesh.security

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX
import android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
import android.util.Log
import mesh.shadowmesh.diagnostics.Diag
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.security.KeyFactory
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import mesh.shadowmesh.crypto.toHex
import mesh.shadowmesh.crypto.intTo4Bytes

/**
 * Biometric-bound key wrapping — design doc §5.11.
 *
 * A 256-bit AES-GCM wrapping key is stored in the Android Keystore, bound to
 * biometric authentication (fingerprint / face / PIN fallback). The wrapping key
 * never leaves the Keystore in plaintext; it is used in-place via [Cipher].
 *
 * Caller-provided key material (e.g. channel keys, ratchet seed) is wrapped
 * (encrypted) and unwrapped (decrypted) through BiometricPrompt, which enforces
 * user presence before the Keystore releases the key for cipher use.
 *
 * Keystore tier detection:
 *   HARDWARE_STRONGBOX  — dedicated secure element (best)
 *   HARDWARE_TEE        — ARM TrustZone (good)
 *   SOFTWARE_ONLY       — no hardware isolation (warn user)
 *
 * Auth window:
 *   COMPARTMENTED channels: 30 seconds (§5.11 design requirement)
 *   OPEN / CLOSED channels: 300 seconds (5 minutes)
 *
 * Thread-safety: [wrapKey] and [unwrapKey] MUST be called from the Main
 * dispatcher — BiometricPrompt requires the Main thread for UI presentation.
 * [detectKeystoreTier] is safe on any thread.
 *
 * Key alias: each channel uses its own alias derived from the channel ID,
 * so compromise of one channel's wrapping key does not affect others.
 */
class BiometricKeyManager(
    private val context: Context
) {

    // ── Keystore tier ─────────────────────────────────────────────────────

    enum class KeystoreTier {
        HARDWARE_STRONGBOX,
        HARDWARE_TEE,
        SOFTWARE_ONLY
    }

    /**
     * Detect the security tier of the Android Keystore on this device.
     * Called on setup to show the appropriate security warning in the UI.
     */
    fun detectKeystoreTier(keyAlias: String = PROBE_KEY_ALIAS): KeystoreTier {
        return try {
            ensureProbeKeyExists()
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
            val key      = keyStore.getKey(PROBE_KEY_ALIAS, null) as? SecretKey
                ?: return KeystoreTier.SOFTWARE_ONLY

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
                val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
                return when (keyInfo.securityLevel) {
                    SECURITY_LEVEL_STRONGBOX          -> KeystoreTier.HARDWARE_STRONGBOX
                    SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeystoreTier.HARDWARE_TEE
                    else                               -> KeystoreTier.SOFTWARE_ONLY
                }
            }

            // Pre-API 31 fallback: use isInsideSecureHardware
            @Suppress("DEPRECATION")
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            @Suppress("DEPRECATION")
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            @Suppress("DEPRECATION")
            if (keyInfo.isInsideSecureHardware) KeystoreTier.HARDWARE_TEE
            else KeystoreTier.SOFTWARE_ONLY
        } catch (e: Exception) {
            Log.w(TAG, "Keystore tier detection failed — assuming SOFTWARE_ONLY", e)
            Diag.swallowed("biometric-key", "tier-detect", e)
            KeystoreTier.SOFTWARE_ONLY
        }
    }

    /**
     * User-facing message for the keystore tier. Displayed during setup.
     */
    fun keystoreTierMessage(tier: KeystoreTier): String = when (tier) {
        KeystoreTier.HARDWARE_STRONGBOX ->
            "Keys are protected by a dedicated secure element (StrongBox). Maximum hardware security."
        KeystoreTier.HARDWARE_TEE ->
            "Keys are protected by hardware (TrustZone). Strong security on this device."
        KeystoreTier.SOFTWARE_ONLY ->
            "⚠ This device has no hardware key protection. Keys are stored in software only. " +
            "Consider using a device with a hardware security module for sensitive operations."
    }

    // ── Auth window ───────────────────────────────────────────────────────

    enum class ChannelSensitivity { COMPARTMENTED, OPEN_OR_CLOSED }

    fun authWindowSeconds(sensitivity: ChannelSensitivity): Int = when (sensitivity) {
        ChannelSensitivity.COMPARTMENTED  -> AUTH_WINDOW_COMPARTMENTED_SEC
        ChannelSensitivity.OPEN_OR_CLOSED -> AUTH_WINDOW_OPEN_SEC
    }

    // ── Key wrapping ──────────────────────────────────────────────────────

    /**
     * Wrap (encrypt) [keyBytes] under the Keystore wrapping key for [keyAlias].
     * Presents a BiometricPrompt to the user before the Keystore releases the key.
     *
     * @param activity   FragmentActivity hosting the BiometricPrompt UI.
     * @param keyAlias   Channel-specific alias (e.g. "shadowmesh_channel_<channelId>").
     * @param keyBytes   Plaintext key material to protect (e.g. 32-byte channel key).
     * @param sensitivity Determines the auth validity window.
     *
     * @return [WrappedKey] containing the AES-GCM ciphertext and IV.
     *         Store this in SQLCipher — it is useless without a fresh biometric auth.
     *
     * MUST be called from Main dispatcher.
     */
    suspend fun wrapKey(
        activity:    FragmentActivity,
        keyAlias:    String,
        keyBytes:    ByteArray,
        sensitivity: ChannelSensitivity = ChannelSensitivity.OPEN_OR_CLOSED
    ): WrappedKey = withContext(Dispatchers.Main) {
        require(keyBytes.isNotEmpty()) { "keyBytes must not be empty" }

        ensureWrappingKeyExists(keyAlias, authWindowSeconds(sensitivity))

        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        val wrappingKey = keyStore.getKey(keyAlias, null) as SecretKey
        cipher.init(Cipher.ENCRYPT_MODE, wrappingKey)

        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        val authenticatedCipher = presentBiometricPrompt(activity, cryptoObject, "Wrap key")

        val ciphertext = authenticatedCipher.cipher!!.doFinal(keyBytes)
        val iv         = authenticatedCipher.cipher!!.iv
        WrappedKey(ciphertext = ciphertext, iv = iv)
    }

    /**
     * Unwrap (decrypt) a previously wrapped key.
     * Presents a BiometricPrompt to the user before the Keystore releases the key.
     *
     * @return The plaintext key bytes. Caller must wipe with fill(0) after use.
     *
     * MUST be called from Main dispatcher.
     */
    suspend fun unwrapKey(
        activity:   FragmentActivity,
        keyAlias:   String,
        wrapped:    WrappedKey,
        sensitivity: ChannelSensitivity = ChannelSensitivity.OPEN_OR_CLOSED
    ): ByteArray = withContext(Dispatchers.Main) {
        ensureWrappingKeyExists(keyAlias, authWindowSeconds(sensitivity))

        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        val wrappingKey = keyStore.getKey(keyAlias, null) as SecretKey
        val spec = GCMParameterSpec(GCM_TAG_BITS, wrapped.iv)
        cipher.init(Cipher.DECRYPT_MODE, wrappingKey, spec)

        val cryptoObject = BiometricPrompt.CryptoObject(cipher)
        val authenticatedCipher = presentBiometricPrompt(activity, cryptoObject, "Unwrap key")

        authenticatedCipher.cipher!!.doFinal(wrapped.ciphertext)
    }

    // ── BiometricPrompt ───────────────────────────────────────────────────

    private suspend fun presentBiometricPrompt(
        activity:     FragmentActivity,
        cryptoObject: BiometricPrompt.CryptoObject,
        subtitle:     String
    ): BiometricPrompt.CryptoObject = suspendCancellableCoroutine { cont ->

        val executor = ContextCompat.getMainExecutor(activity)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                val obj = result.cryptoObject
                if (obj != null) cont.resume(obj)
                else cont.resumeWithException(
                    SecurityException("BiometricPrompt succeeded but returned null CryptoObject")
                )
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                cont.resumeWithException(
                    BiometricAuthException(errorCode, errString.toString())
                )
            }

            override fun onAuthenticationFailed() {
                // Single failed attempt — prompt retries automatically; don't cancel coroutine.
                Log.d(TAG, "Biometric attempt failed — retrying")
            }
        }

        val prompt = BiometricPrompt(activity, executor, callback)

        // setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL) was introduced
        // in androidx.biometric 1.1.0 but the DEVICE_CREDENTIAL authenticator type as a
        // combined flag requires API 30 (R) on the platform side. On API 29, this call
        // throws IllegalArgumentException on some OEMs ("DEVICE_CREDENTIAL is not a
        // supported authenticator on API <30"). Use the deprecated setDeviceCredentialAllowed
        // on API 29 — it is deprecated but correct and stable on that API level.
        val info = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("SHADOWMESH")
                .setSubtitle(subtitle)
                .setDescription("Authenticate to access encrypted key material")
                .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
                .build()
        } else {
            // API 29: use setNegativeButtonText (no device-credential combined flow) or
            // setDeviceCredentialAllowed. setDeviceCredentialAllowed is the correct
            // equivalent — it allows PIN/pattern/password fallback identical to DEVICE_CREDENTIAL.
            @Suppress("DEPRECATION")
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("SHADOWMESH")
                .setSubtitle(subtitle)
                .setDescription("Authenticate to access encrypted key material")
                .setDeviceCredentialAllowed(true)
                .build()
        }

        cont.invokeOnCancellation {
            // B14 fix: dismiss the biometric prompt when the calling coroutine is
            // cancelled (e.g. ViewModel cleared, user navigates away, timeout).
            // Without this, the prompt remains visible as a zombie dialog after the
            // coroutine that presented it has been cancelled.
            prompt.cancelAuthentication()
        }
        prompt.authenticate(info, cryptoObject)
    }

    // ── Keystore key management ───────────────────────────────────────────

    private fun ensureWrappingKeyExists(keyAlias: String, authValiditySeconds: Int) {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        if (keyStore.containsAlias(keyAlias)) return
        generateWrappingKey(keyAlias, authValiditySeconds)
    }

    private fun generateWrappingKey(keyAlias: String, authValiditySeconds: Int) {
        val specBuilder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            // Invalidate the key if a new biometric (fingerprint/face) is enrolled.
            // Without this, an attacker with brief physical access who enrolls their own
            // biometric retains permanent key access even after the device is reclaimed.
            .setInvalidatedByBiometricEnrollment(true)
            .apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    setUserAuthenticationParameters(
                        authValiditySeconds,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                    )
                } else {
                    @Suppress("DEPRECATION")
                    setUserAuthenticationValidityDurationSeconds(authValiditySeconds)
                }
            }

        // Attempt StrongBox first (Pixel 3+, Galaxy S10+ and later have dedicated secure
        // element hardware). StrongBox keys cannot be extracted even if TEE firmware is
        // compromised. Fall back to TEE on devices without StrongBox support.
        fun buildAndGenerate(useStrongBox: Boolean) {
            val spec = specBuilder.setIsStrongBoxBacked(useStrongBox).build()
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                .also { it.init(spec) }
                .generateKey()
        }

        try {
            buildAndGenerate(true)
            Log.d(TAG, "Wrapping key backed by StrongBox for alias=$keyAlias")
        } catch (e: android.security.keystore.StrongBoxUnavailableException) {
            Diag.degraded("biometric-key", "strongbox-unavailable",
                "StrongBox unavailable on this device — falling back to TEE for alias=$keyAlias")
            buildAndGenerate(false)
        }
    }

    private fun ensureProbeKeyExists() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        if (keyStore.containsAlias(PROBE_KEY_ALIAS)) return
        val spec = KeyGenParameterSpec.Builder(
            PROBE_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .also { it.init(spec) }
            .generateKey()
    }

    // ── Device secret (hardware-backed, no auth required at startup) ──────────

    /**
     * Get or create a 32-byte hardware-protected device secret.
     *
     * First call: generates 32 bytes of [SecureRandom] output, wraps them under a
     * non-auth-gated AES-GCM AndroidKeyStore key (TEE/StrongBox, no UI prompt required),
     * and stores the encrypted blob in [DEVICE_SECRET_PREFS].
     *
     * Subsequent calls: decrypts the stored blob using the same Keystore key.
     *
     * Hardware binding: the Keystore key lives in TEE or StrongBox and is never exported.
     * Moving the SharedPreferences blob to another device without the Keystore key causes
     * decryption to fail — a fresh secret is generated and all derived keys change.
     *
     * No user authentication required — called from Application.onCreate() before any UI.
     * Per-channel and per-ratchet keys are user-gated via [wrapKey]/[unwrapKey].
     *
     * [synchronized] prevents a race where two concurrent callers both observe no stored
     * secret and each generate an independent fresh secret — the second write would make
     * the first secret permanently inaccessible.
     */
    @Synchronized
    fun getOrCreateDeviceSecret(): ByteArray {
        ensureDeviceSecretKeyExists()
        val prefs  = context.getSharedPreferences(DEVICE_SECRET_PREFS, Context.MODE_PRIVATE)
        val stored = prefs.getString(DEVICE_SECRET_PREF_KEY, null)

        if (stored != null) {
            return try {
                val blob = android.util.Base64.decode(stored, android.util.Base64.NO_WRAP)
                decryptWithDeviceKey(blob)
            } catch (e: Exception) {
                // Keystore key lost (factory reset, key deletion, or TEE fault).
                // All derived keys — database key, channel keys, node identity — will
                // differ after re-generation. Log at WARN so the event is observable.
                Log.w(TAG, "Device secret decryption failed — regenerating (derived keys will change). Cause: ${e.message}")
                Diag.degraded("biometric-key", "device-secret-key-lost",
                    "Device secret Keystore key lost — identity and database reset required. " +
                    "Cause: ${e.message}")
                generateAndPersistDeviceSecret(prefs)
            }
        }
        return generateAndPersistDeviceSecret(prefs)
    }

    private fun generateAndPersistDeviceSecret(
        prefs: android.content.SharedPreferences
    ): ByteArray {
        val secret = ByteArray(DEVICE_SECRET_BYTES).also { java.security.SecureRandom().nextBytes(it) }
        val blob   = encryptWithDeviceKey(secret)
        prefs.edit()
            .putString(DEVICE_SECRET_PREF_KEY,
                android.util.Base64.encodeToString(blob, android.util.Base64.NO_WRAP))
            .commit()
        return secret
    }

    private fun ensureDeviceSecretKeyExists() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        if (ks.containsAlias(DEVICE_SECRET_KEY_ALIAS)) return

        fun build(useStrongBox: Boolean): KeyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                DEVICE_SECRET_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .setIsStrongBoxBacked(useStrongBox)
                .build()

        try {
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                .also { it.init(build(true)) }.generateKey()
            Log.d(TAG, "Device secret key backed by StrongBox")
        } catch (e: android.security.keystore.StrongBoxUnavailableException) {
            Diag.degraded("biometric-key", "device-secret-strongbox-unavailable",
                "StrongBox unavailable — device secret key stored in TEE")
            KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                .also { it.init(build(false)) }.generateKey()
        }
    }

    private fun encryptWithDeviceKey(plaintext: ByteArray): ByteArray {
        val ks     = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        val key    = ks.getKey(DEVICE_SECRET_KEY_ALIAS, null) as SecretKey
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val ct = cipher.doFinal(plaintext)
        val iv = cipher.iv
        // Wire: [1B ivLen][iv bytes][AES-GCM ciphertext + 16B tag]
        return byteArrayOf(iv.size.toByte()) + iv + ct
    }

    private fun decryptWithDeviceKey(blob: ByteArray): ByteArray {
        require(blob.size > 1) { "Device secret blob too short (${blob.size}B)" }
        val ivLen = blob[0].toInt() and 0xFF
        require(blob.size > 1 + ivLen) { "Device secret blob malformed (ivLen=$ivLen, blobLen=${blob.size})" }
        val iv = blob.copyOfRange(1, 1 + ivLen)
        val ct = blob.copyOfRange(1 + ivLen, blob.size)
        val ks     = KeyStore.getInstance(ANDROID_KEYSTORE).also { it.load(null) }
        val key    = ks.getKey(DEVICE_SECRET_KEY_ALIAS, null) as SecretKey
        val cipher = Cipher.getInstance(AES_GCM_NOPADDING)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(ct)
    }

    // ── Constants ─────────────────────────────────────────────────────────

    companion object {
        private const val TAG               = "BiometricKeyManager"
        private const val ANDROID_KEYSTORE  = "AndroidKeyStore"
        private const val AES_GCM_NOPADDING = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS      = 128
        private const val PROBE_KEY_ALIAS          = "shadowmesh_keystore_probe"
        private const val DEVICE_SECRET_KEY_ALIAS  = "shadowmesh_device_secret_v1"
        private const val DEVICE_SECRET_PREFS      = "shadowmesh_device_prefs"
        private const val DEVICE_SECRET_PREF_KEY   = "device_secret_blob"
        private const val DEVICE_SECRET_BYTES      = 32

        /**
         * Biometric authentication window for COMPARTMENTED channels.
         * Design doc §5.11: 30 seconds. After this window, a new biometric
         * challenge is required before the Keystore releases the wrapping key.
         */
        const val AUTH_WINDOW_COMPARTMENTED_SEC = 30

        /**
         * Biometric authentication window for OPEN/CLOSED channels.
         * Design doc §5.11: 300 seconds (5 minutes). Less sensitive channels
         * tolerate a longer window to reduce authentication friction.
         */
        const val AUTH_WINDOW_OPEN_SEC = 300

        /**
         * Canonical alias format for a channel's wrapping key.
         * Using a per-channel alias ensures key rotation is scoped.
         */
        fun channelKeyAlias(channelId: String): String = "shadowmesh_channel_$channelId"
    }
}

// ── Data classes ──────────────────────────────────────────────────────────────

/**
 * AES-GCM wrapped key. Safe to store in SQLCipher.
 * Useless without a successful biometric authentication on the same device.
 */
data class WrappedKey(
    val ciphertext: ByteArray,   // AES-GCM encrypted key bytes
    val iv:         ByteArray    // 12-byte GCM IV
) {
    fun toBytes(): ByteArray = intTo4Bytes(iv.size) + iv + ciphertext

    companion object {
        fun fromBytes(bytes: ByteArray): WrappedKey {
            require(bytes.size >= 4) { "WrappedKey: too short" }
            val ivLen = fourBytesToIntBiometric(bytes, 0)
            require(ivLen > 0 && bytes.size > 4 + ivLen) { "WrappedKey: malformed" }
            val iv         = bytes.copyOfRange(4, 4 + ivLen)
            val ciphertext = bytes.copyOfRange(4 + ivLen, bytes.size)
            return WrappedKey(ciphertext, iv)
        }
    }

    override fun equals(other: Any?) = other is WrappedKey &&
        ciphertext.contentEquals(other.ciphertext) && iv.contentEquals(other.iv)
    override fun hashCode() = 31 * ciphertext.contentHashCode() + iv.contentHashCode()
}

class BiometricAuthException(val errorCode: Int, message: String) : Exception(message)

// Local int ↔ bytes helpers (avoid depending on crypto package internals)
private fun fourBytesToIntBiometric(b: ByteArray, off: Int): Int =
    ((b[off].toInt()   and 0xFF) shl 24) or
    ((b[off+1].toInt() and 0xFF) shl 16) or
    ((b[off+2].toInt() and 0xFF) shl 8) or
     (b[off+3].toInt() and 0xFF)

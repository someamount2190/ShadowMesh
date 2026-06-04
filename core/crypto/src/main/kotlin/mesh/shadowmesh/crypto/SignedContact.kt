package mesh.shadowmesh.crypto

/**
 * A DHT contact whose identity and address are cryptographically authenticated.
 *
 * ## What this proves
 *
 * A [SignedContact] binds three things together under a single Dilithium-3 + Ed25519
 * signature:
 *
 *   1. **Identity binding**: `nodeId == SHA3-256(kemPublicKey.toBytes() || signingPublicKey.toBytes())`
 *      — the 32-byte node ID is a hash commitment to the node's public keys. A peer cannot
 *      claim a nodeId that does not derive from their actual keys.
 *
 *   2. **Address binding**: the signature covers `nodeId || addressBytes || seq` — a node
 *      cannot forge a signed contact for a nodeId they don't control and bind it to an
 *      arbitrary address. Address changes require a new signature with an incremented seq.
 *
 *   3. **Replay protection**: [seq] is a monotonic counter. A routing table that tracks the
 *      highest seq seen per nodeId can reject replayed contacts from a previous address.
 *
 * ## What this does NOT prove
 *
 * A valid [SignedContact] proves the node controls the keypair — it does NOT prove the node
 * is trustworthy, is Tier 1, or has been introduced via NFC. Those properties come from the
 * [TrustCredential] system. [SignedContact] is a lower-level primitive: it prevents Sybil
 * attacks where an adversary fabricates contacts with arbitrary nodeIds, but it does not
 * replace the physical-trust bootstrap.
 *
 * ## Wire format
 *
 * Length-prefixed binary, no JSON. All integers big-endian. All length prefixes 4 bytes.
 *
 *   [4B] kemPublicKey length
 *   [?B] kemPublicKey bytes (HybridPublicKey.toBytes())
 *   [4B] signingPublicKey length
 *   [?B] signingPublicKey bytes (HybridVerifyKey.toBytes())
 *   [4B] addressBytes length
 *   [?B] addressBytes (PeerAddress wire encoding)
 *   [8B] seq (big-endian long)
 *   [4B] signature length
 *   [?B] signature bytes (HybridSigner hybrid sig)
 *
 * Note: nodeId is NOT stored in the wire format. It is always derived from the public keys
 * on deserialization and verified — storing it separately would create a redundancy that a
 * tampered payload could exploit (claim one nodeId in the header, use different keys).
 *
 * ## Size
 *
 * ~7KB per contact (dominated by Kyber-1024 pubkey ~1568B + Dilithium-3 pubkey ~1952B +
 * Dilithium-3 sig ~3293B). This is too large for UDP DHT datagrams (MTU 1400B). SignedContacts
 * are exchanged out-of-band: at NFC bootstrap (where NodePublicIdentity is already transmitted)
 * and via gossip. The UDP DHT wire format carries compact DhtContact (nodeId + address, 38B);
 * trust is established before DHT routing, not during it.
 *
 * @param nodeId          32-byte SHA3-256(kemPub || sigPub). Derived on deserialization.
 * @param kemPublicKey    Node's Kyber-1024 + X25519 public key (for key encapsulation).
 * @param signingPublicKey Node's Dilithium-3 + Ed25519 public key (for signature verification).
 * @param addressBytes    Canonical wire encoding of the node's current network address.
 * @param seq             Monotonic address-change counter. Starts at 0, incremented on address change.
 * @param signature       Hybrid signature over [signedPayload]. Verified by [verifyIdentityAndSignature].
 */
data class SignedContact(
    val nodeId:           ByteArray,
    val kemPublicKey:     HybridPublicKey,
    val signingPublicKey: HybridVerifyKey,
    val addressBytes:     ByteArray,
    val seq:              Long,
    val signature:        ByteArray
) {
    // ── Verification ─────────────────────────────────────────────────────

    /**
     * Verify this contact's identity binding and address signature.
     *
     * This is a synchronous operation — Dilithium verification is CPU-bound (~1ms)
     * with no I/O. Do not call from the main thread if you are verifying many contacts.
     *
     * Returns [VerifyResult.Ok] with the derived nodeId on success.
     *
     * Two checks run in order — both must pass:
     *   1. nodeId == SHA3-256(kemPub || sigPub) — identity binding.
     *   2. HybridSigner.verifySync(signedPayload, signature, signingPublicKey) — address binding.
     */
    fun verifyIdentityAndSignature(): VerifyResult {
        // ── Check 1: nodeId is committed to the public keys ───────────────
        val expected = Hkdf.instance.sha3_256(
            kemPublicKey.toBytes() + signingPublicKey.toBytes()
        )
        if (!expected.contentEquals(nodeId)) {
            return VerifyResult.IdentityMismatch(
                "nodeId does not match SHA3-256(kemPub || sigPub)"
            )
        }

        // ── Check 2: signature covers nodeId || address || seq ────────────
        // Reuse a shared signer instance rather than allocating one per call —
        // HybridSigner() loads LazySodiumJava(SodiumJava()) which, while cheap after
        // the first JNI load, is unnecessary allocation on a hot verification path.
        val payload = signedPayload()
        val ok = sharedSigner.verifySync(payload, signature, signingPublicKey)
        return if (ok) VerifyResult.Ok(nodeId) else VerifyResult.InvalidSignature
    }

    /**
     * The canonical byte sequence that the signature covers.
     * Stable: all callers (signer and verifier) use this method.
     */
    fun signedPayload(): ByteArray =
        nodeId + addressBytes + longToBytes(seq)

    // ── Serialization ─────────────────────────────────────────────────────

    fun toBytes(): ByteArray {
        val kemBytes = kemPublicKey.toBytes()
        val sigPubBytes = signingPublicKey.toBytes()
        return intTo4Bytes(kemBytes.size) + kemBytes +
               intTo4Bytes(sigPubBytes.size) + sigPubBytes +
               intTo4Bytes(addressBytes.size) + addressBytes +
               longToBytes(seq) +
               intTo4Bytes(signature.size) + signature
    }

    // ── Equality ──────────────────────────────────────────────────────────

    override fun equals(other: Any?): Boolean {
        if (other !is SignedContact) return false
        return nodeId.contentEquals(other.nodeId) &&
               seq == other.seq &&
               addressBytes.contentEquals(other.addressBytes)
    }

    override fun hashCode(): Int = nodeId.contentHashCode() * 31 + seq.hashCode()

    companion object {
        /**
         * Shared [HybridSigner] for [verifyIdentityAndSignature]. Thread-safe: [HybridSigner]
         * is stateless (all state is in the key arguments). Avoids allocating
         * `LazySodiumJava(SodiumJava())` on every verification call.
         */
        private val sharedSigner = HybridSigner()
        /**
         * Deserialise a [SignedContact] from [bytes].
         *
         * The nodeId is NOT read from the wire — it is always computed from the public keys
         * after parsing. This means a tampered nodeId in transit has no effect; the result
         * always carries the nodeId that is cryptographically committed to the deserialized keys.
         *
         * This method validates wire structure (length prefixes, field bounds) but does NOT
         * verify the address signature. Call [verifyIdentityAndSignature] after deserialization
         * for full verification.
         *
         * @param hkdf   HKDF instance for SHA3-256. Defaults to [Hkdf.instance].
         * @throws IllegalArgumentException if the bytes are structurally malformed (truncated
         *         fields, negative length prefixes, etc.).
         */
        fun fromBytes(bytes: ByteArray, hkdf: Hkdf = Hkdf.instance): SignedContact {
            var off = 0

            fun readLenPrefixed(): ByteArray {
                require(off + 4 <= bytes.size) { "SignedContact: truncated at length prefix (off=$off)" }
                val len = fourBytesToInt(bytes, off); off += 4
                // Explicit positive-bounds check before arithmetic: if len is near Int.MAX_VALUE,
                // `off + len` overflows to negative, making `off + len <= bytes.size` vacuously
                // true (negative <= non-negative). The copyOfRange then throws, which is the
                // correct exception path — but the explicit cap makes the intent clear and
                // prevents any future refactoring from accidentally admitting large allocations.
                require(len >= 0 && len <= bytes.size - off) {
                    "SignedContact: invalid field length $len at off=${off - 4} (remaining=${bytes.size - off})"
                }
                return bytes.copyOfRange(off, off + len).also { off += len }
            }

            val kemBytes    = readLenPrefixed()
            // Wrap HybridPublicKey/HybridVerifyKey parse failures as IllegalArgumentException.
            // These factories may throw IllegalStateException or other types; callers catch
            // IllegalArgumentException per the KDoc contract, so they would miss other types.
            val kemPub      = try { HybridPublicKey.fromBytes(kemBytes) }
                              catch (e: Exception) {
                                  throw IllegalArgumentException("SignedContact: invalid KEM public key: ${e.message}", e)
                              }

            val sigPubBytes = readLenPrefixed()
            val sigPub      = try { HybridVerifyKey.fromBytes(sigPubBytes) }
                              catch (e: Exception) {
                                  throw IllegalArgumentException("SignedContact: invalid signing public key: ${e.message}", e)
                              }

            val addrBytes   = readLenPrefixed()

            require(off + 8 <= bytes.size) { "SignedContact: truncated before seq" }
            val seq = bytesToLong(bytes, off); off += 8

            val sig = readLenPrefixed()

            // Derive nodeId from the public keys — never trust a wire-transmitted nodeId
            val nodeId = hkdf.sha3_256(kemPub.toBytes() + sigPub.toBytes())

            return SignedContact(
                nodeId           = nodeId,
                kemPublicKey     = kemPub,
                signingPublicKey = sigPub,
                addressBytes     = addrBytes,
                seq              = seq,
                signature        = sig
            )
        }

        /**
         * Create and sign a [SignedContact] for the local node.
         *
         * @param identity    Local node identity — provides public keys and the signing key.
         * @param addressBytes  Canonical wire encoding of this node's current address.
         * @param seq           Current monotonic counter (from [ContactSeqCounter]).
         * @param signer        HybridSigner instance.
         */
        fun sign(
            identity:     NodePublicIdentity,
            privateKey:   HybridSigningKey,
            addressBytes: ByteArray,
            seq:          Long,
            signer:       HybridSigner = HybridSigner()
        ): SignedContact {
            val nodeId  = identity.nodeId
            val payload = nodeId + addressBytes + longToBytes(seq)
            val sig     = signer.signSync(payload, privateKey)
            return SignedContact(
                nodeId           = nodeId,
                kemPublicKey     = identity.kemPublicKey,
                signingPublicKey = identity.signingPublicKey,
                addressBytes     = addressBytes,
                seq              = seq,
                signature        = sig
            )
        }
    }
}

/** Result of [SignedContact.verifyIdentityAndSignature]. */
sealed class VerifyResult {
    /** Both checks passed. [nodeId] is the verified 32-byte node identity. */
    data class Ok(val nodeId: ByteArray)           : VerifyResult()
    /** nodeId does not match SHA3-256(kemPub || sigPub). */
    data class IdentityMismatch(val reason: String) : VerifyResult()
    /** Signature verification failed (address or seq was tampered). */
    object InvalidSignature                         : VerifyResult()
}

/**
 * Monotonic sequence number for signed contacts.
 *
 * Starts at 0 on every process start. Incrementing on address change ensures that
 * a replayed contact from a previous session with a lower seq is rejected by routing tables
 * that have seen the higher seq. Persistence across restarts is optional — restarting from
 * 0 is safe because the seq only needs to be monotonic within a routing table's observation
 * window, and a restarted node will typically advertise its new address quickly.
 */
class ContactSeqCounter {
    private val counter = java.util.concurrent.atomic.AtomicLong(0L)

    /** Current sequence number — use for the next signed contact. */
    fun current(): Long = counter.get()

    /** Increment and return the new sequence number (call on address change). */
    fun increment(): Long = counter.incrementAndGet()
}

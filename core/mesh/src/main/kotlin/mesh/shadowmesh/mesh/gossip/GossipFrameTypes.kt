package mesh.shadowmesh.mesh.gossip

import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.hexToBytes

/**
 * Wire types for channel lifecycle gossip frames.
 *
 * Both frame types are:
 *   1. Gossiped immediately to all connected peers when issued.
 *   2. Stored in the DHT under a deterministic key so offline peers
 *      retrieve them via findValue() on reconnect.
 *
 * DHT key derivation — channelId is obfuscated before hashing:
 *   obfChan = SHA3-256(channelId_bytes || "shadowmesh_gossip_dhtkey_v1")
 *   KeyRotationFrame:   SHA3-256("key_rotation"   || obfChan || newKeyVersionNumber)
 *   MemberRemovalFrame: SHA3-256("member_removal"  || obfChan || removedNodeId)
 *
 * Obfuscation prevents a passive observer who knows a channel's identifier from
 * pre-computing the DHT keys and suppressing retrieval (eclipse attack on channel
 * key rotations or member removals). The 32-byte obfChan is computationally
 * indistinguishable from random without the 256-bit channelId.
 *
 * Replay protection: every frame carries a random 16-byte nonce.
 * Receivers track seen nonces via the used_bootstrap_nonces table (reused for
 * all one-time frame nonces) and drop any frame whose nonce has been seen before.
 */

/**
 * Announces a channel key rotation to all members, including those currently offline.
 *
 * [wrappedNewKey] is the new channel key wrapped with the same IBD derivation
 * used at channel creation — any device with a valid install unwraps it locally
 * using their [deviceSecret] and [apkBindingHash].
 *
 * Receivers must:
 *   1. Verify [signature] over [signedPayload].
 *   2. Check [newKeyVersionNumber] > current channel keyVersionNumber (reject replays).
 *   3. Unwrap [wrappedNewKey] via local IBD derivation.
 *   4. Persist the new keyBlob and increment keyVersionNumber in ChannelEntity.
 *   5. Evict all in-memory ratchets for [channelId].
 */
data class KeyRotationFrame(
    val channelId:           String,    // hex channelId (64 chars)
    val newKeyVersionNumber: Int,       // must be > receiver's current keyVersionNumber
    val wrappedNewKey:       ByteArray, // new key — same wrap format as ChannelEntity.encryptedKeyBlob
    val rotatedAtMs:         Long,
    val initiatorNodeId:     String,    // hex nodeId of the rotating device
    val nonce:               ByteArray, // 16-byte random — replay protection
    val signature:           ByteArray  // HybridSigner over signedPayload()
) {
    /** Bytes committed by the signature. */
    fun signedPayload(): ByteArray =
        channelId.toByteArray() +
        frameIntToBytes(newKeyVersionNumber) +
        wrappedNewKey +
        frameLongToBytes(rotatedAtMs) +
        nonce

    /**
     * DHT key under which this frame is stored for offline peers.
     *
     * channelId is obfuscated before hashing so observers who know the channelId cannot
     * pre-compute this key and suppress retrieval. See module KDoc for the full derivation.
     */
    fun dhtKey(hkdf: Hkdf): ByteArray {
        val obfChan = hkdf.sha3_256(
            hexToBytes(channelId) + "shadowmesh_gossip_dhtkey_v1".toByteArray(Charsets.UTF_8)
        )
        return hkdf.sha3_256(
            "key_rotation".toByteArray() + obfChan + frameIntToBytes(newKeyVersionNumber)
        )
    }
}

/**
 * Announces that [removedNodeId] has been removed from [channelId].
 *
 * Receiving nodes must:
 *   1. Verify [signature] over [signedPayload].
 *   2. Write a [MemberRemovalEntry] to the local database.
 *   3. Stop relaying fragments from [removedNodeId] for this channel.
 *   4. If [removedNodeId] == localNodeId: mark channel as departed.
 */
data class MemberRemovalFrame(
    val channelId:       String,    // hex channelId
    val removedNodeId:   String,    // hex nodeId of removed member
    val removedAtMs:     Long,
    val initiatorNodeId: String,    // hex nodeId of the remover
    val nonce:           ByteArray, // 16-byte random — replay protection
    val signature:       ByteArray  // HybridSigner over signedPayload()
) {
    fun signedPayload(): ByteArray =
        channelId.toByteArray() +
        removedNodeId.toByteArray() +
        frameLongToBytes(removedAtMs) +
        nonce

    /**
     * DHT key under which this frame is stored for offline peers.
     * channelId is obfuscated — see [KeyRotationFrame.dhtKey] and module KDoc.
     */
    fun dhtKey(hkdf: Hkdf): ByteArray {
        val obfChan = hkdf.sha3_256(
            hexToBytes(channelId) + "shadowmesh_gossip_dhtkey_v1".toByteArray(Charsets.UTF_8)
        )
        return hkdf.sha3_256(
            "member_removal".toByteArray() + obfChan + removedNodeId.toByteArray()
        )
    }
}

/**
 * Announces newly discovered keybox revocations to mesh peers.
 *
 * When a node fetches a fresh revocation list and finds entries not in its cache,
 * it signs and gossips this frame to all connected peers. Peers verify, merge into
 * their local cache, and re-gossip to their peers exactly once (one-hop propagation).
 *
 * Wire format (version 1):
 *   [4B magic: 0x52564B55 "RVKU"]
 *   [2B serials_count, big-endian unsigned]
 *   for each serial:  [2B len_BE][len bytes UTF-8 hex string]
 *   [2B hashes_count, big-endian unsigned]
 *   for each hash:    [2B len_BE][len bytes UTF-8 hex string]
 *   [8B fetchedAtMs, big-endian]
 *   [64 bytes issuerNodeId, UTF-8 hex ASCII]
 *   [16B nonce — replay protection]
 *   [4B sig_len, big-endian][sig_len bytes HybridSigner hybrid signature]
 *
 * Security properties:
 *   - Signature covers all semantically significant fields via [signedPayload].
 *   - Nonce prevents replay of the same update across gossip reset cycles.
 *   - One-hop propagation (sourceId excluded on re-gossip) prevents amplification loops.
 *   - mergeUpdate() is idempotent — a re-gossiped frame produces no second gossip.
 */
data class RevocationUpdateFrame(
    val revokedSerials:   List<String>,  // normalized hex serial numbers (no leading zeros)
    val revokedKeyHashes: List<String>,  // lowercase hex SHA-256 of public keys
    val fetchedAtMs:      Long,
    val issuerNodeId:     String,        // 64-char hex NodeId
    val nonce:            ByteArray,     // 16 bytes
    val signature:        ByteArray      // HybridSigner hybrid signature
) {
    /**
     * Bytes committed by the signature. Domain-separated to prevent cross-protocol reuse.
     */
    fun signedPayload(): ByteArray =
        DOMAIN_PREFIX.toByteArray() +
        revokedSerials.joinToString("\n").toByteArray() +
        byteArrayOf(0x00) +
        revokedKeyHashes.joinToString("\n").toByteArray() +
        byteArrayOf(0x00) +
        frameLongToBytes(fetchedAtMs) +
        issuerNodeId.toByteArray() +
        nonce

    fun toBytes(): ByteArray {
        require(revokedSerials.size   <= MAX_ENTRIES) { "Too many serial entries" }
        require(revokedKeyHashes.size <= MAX_ENTRIES) { "Too many hash entries" }
        require(nonce.size == 16) { "Nonce must be 16 bytes" }
        require(issuerNodeId.length == 64) { "issuerNodeId must be 64-char hex" }

        val out = java.io.ByteArrayOutputStream()
        val dos = java.io.DataOutputStream(out)
        dos.writeInt(MAGIC)
        dos.writeShort(revokedSerials.size)
        for (s in revokedSerials) {
            val b = s.toByteArray()
            require(b.size <= 128) { "Serial too long: ${b.size}" }
            dos.writeShort(b.size)
            dos.write(b)
        }
        dos.writeShort(revokedKeyHashes.size)
        for (h in revokedKeyHashes) {
            val b = h.toByteArray()
            require(b.size <= 128) { "Hash too long: ${b.size}" }
            dos.writeShort(b.size)
            dos.write(b)
        }
        dos.writeLong(fetchedAtMs)
        dos.write(issuerNodeId.toByteArray())   // exactly 64 bytes
        dos.write(nonce)                         // exactly 16 bytes
        dos.writeInt(signature.size)
        dos.write(signature)
        dos.flush()
        return out.toByteArray()
    }

    companion object {
        const val MAGIC       = 0x52564B55   // "RVKU" — Int literal, no sign-extension risk (MSB=0)
        const val MAX_ENTRIES = 1000
        private const val DOMAIN_PREFIX = "shadowmesh_revoc_update_v1 "

        // Static field (not a getter) — avoids ByteArray allocation on every packet check.
        val MAGIC_BYTES: ByteArray = byteArrayOf(
            0x52.toByte(), 0x56.toByte(), 0x4B.toByte(), 0x55.toByte()
        )

        fun fromBytes(bytes: ByteArray): RevocationUpdateFrame? { return try {
            val dis = java.io.DataInputStream(java.io.ByteArrayInputStream(bytes))
            val magic = dis.readInt()
            if (magic != MAGIC) return null

            val serialsCount = dis.readShort().toInt() and 0xFFFF
            if (serialsCount > MAX_ENTRIES) return null
            val serials = (0 until serialsCount).map {
                val len = dis.readShort().toInt() and 0xFFFF
                if (len > 128) return null
                ByteArray(len).also { dis.readFully(it) }.decodeToString()
            }

            val hashesCount = dis.readShort().toInt() and 0xFFFF
            if (hashesCount > MAX_ENTRIES) return null
            val hashes = (0 until hashesCount).map {
                val len = dis.readShort().toInt() and 0xFFFF
                if (len > 128) return null
                ByteArray(len).also { dis.readFully(it) }.decodeToString()
            }

            val fetchedAtMs = dis.readLong()
            val issuerIdBytes = ByteArray(64).also { dis.readFully(it) }
            val nonce = ByteArray(16).also { dis.readFully(it) }
            val sigLen = dis.readInt()
            if (sigLen < 0 || sigLen > 8192) return null
            val signature = ByteArray(sigLen).also { dis.readFully(it) }

            RevocationUpdateFrame(serials, hashes, fetchedAtMs,
                issuerIdBytes.decodeToString(), nonce, signature)
        } catch (_: Exception) { null } }
    }
}

// ── Wire helpers — file-private to avoid collisions with other modules ────────

internal fun frameIntToBytes(v: Int): ByteArray = byteArrayOf(
    (v shr 24).toByte(), (v shr 16).toByte(), (v shr 8).toByte(), v.toByte()
)

internal fun frameLongToBytes(v: Long): ByteArray = byteArrayOf(
    (v shr 56).toByte(), (v shr 48).toByte(), (v shr 40).toByte(), (v shr 32).toByte(),
    (v shr 24).toByte(), (v shr 16).toByte(), (v shr  8).toByte(), v.toByte()
)

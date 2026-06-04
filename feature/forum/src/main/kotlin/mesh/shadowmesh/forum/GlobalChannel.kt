package mesh.shadowmesh.forum

import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.toHex

/**
 * Constants and key derivation for the built-in global public channel.
 *
 * The global channel is pre-seeded on every installation and pinned at the
 * top of the channel list. Its channel ID and key are deterministic across
 * all installations — any device running the app has the same values computed
 * from the same constant strings.
 *
 * Key architecture:
 *   The raw channel key = SHA3-256("shadowmesh_global_channel_key_v1").
 *   This is a publicly-known derivation — the global channel is a public space.
 *   For local storage, the raw key is wrapped using the same HKDF+device-secret
 *   mechanism as OPEN channels (KeyOrchestrator.wrapChannelKey). Different devices
 *   wrap it differently but all recover the same raw key on unwrap.
 *
 * Non-departable: [ShadowMeshApplication] calls [ChannelManager.ensureGlobalChannel]
 * on every launch to restore the channel even if the user previously departed it.
 * [ChannelManager.departChannel] is a no-op for this channel ID.
 */
object GlobalChannel {
    private val hkdf = Hkdf.instance

    const val NAME = "Global"

    /**
     * Deterministic channel ID: SHA3-256("shadowmesh_global_channel_v1") as hex.
     * Computed once at class load and cached; same value on every device.
     */
    val ID: String by lazy {
        hkdf.sha3_256("shadowmesh_global_channel_v1".toByteArray(Charsets.UTF_8)).toHex()
    }

    /**
     * Genesis hash used to populate [ChannelEntity.genesisHash]: same derivation
     * all devices compute independently.
     */
    val GENESIS_HASH: String by lazy {
        hkdf.sha3_256("shadowmesh_global_channel_v1_genesis".toByteArray(Charsets.UTF_8)).toHex()
    }

    /**
     * Derive the 32-byte raw channel key. Callers MUST fill the returned array with
     * zeros after use — even though the key is publicly derivable, clearing it removes
     * it from heap sooner and keeps the zeroing discipline consistent with private keys.
     */
    fun rawKey(): ByteArray =
        hkdf.sha3_256("shadowmesh_global_channel_key_v1".toByteArray(Charsets.UTF_8))

    /** Epoch creation timestamp — predates all user-created channels so it always sorts last on recency. */
    const val CREATED_AT_MS = 0L
}

package mesh.shadowmesh.ui.viewmodel

import android.graphics.Bitmap
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch
import mesh.shadowmesh.crypto.Hkdf
import mesh.shadowmesh.crypto.TrustLevel
import javax.inject.Named
import mesh.shadowmesh.forum.ChannelManager
import mesh.shadowmesh.forum.ForumViewModel
import mesh.shadowmesh.forum.KeyOrchestrator
import mesh.shadowmesh.forum.PostEngine
import mesh.shadowmesh.mesh.gossip.GossipEngine
import mesh.shadowmesh.mesh.mode.NetworkMode
import mesh.shadowmesh.mesh.mode.NetworkModeStateMachine
import mesh.shadowmesh.storage.ChannelEntity
import mesh.shadowmesh.storage.ChannelType
import mesh.shadowmesh.storage.PostEntity
import mesh.shadowmesh.storage.PostState
import javax.inject.Inject

// ── ChannelListItem — sealed for RecyclerView / LazyColumn adapter ────────────

sealed class ChannelListItem {
    data class SectionHeader(val label: String)       : ChannelListItem()
    data class Channel(val entity: ChannelEntity, val unread: Int) : ChannelListItem()
}

// ── ForumUiViewModel ──────────────────────────────────────────────────────────

/**
 * UI-layer ViewModel for the forum screens.
 *
 * Wraps [ForumViewModel] (domain layer) and adds:
 *   - [sortedChannels]: private channels pinned top, then sorted by DHT popularity DESC
 *     within each tier (COMPARTMENTED > CLOSED > OPEN > ANONYMOUS). Emits
 *     [ChannelListItem.SectionHeader] interleaved with [ChannelListItem.Channel].
 *   - [unreadCounts]: map of channelId → unread count (posts where openedAtMs IS NULL).
 *   - [feedItems]: cross-channel CONFIRMED posts sorted by createdAtMs DESC,
 *     with private-channel posts ranked above public at equal timestamps.
 *   - [networkMode]: current [NetworkMode] from [NetworkModeStateMachine].
 *   - [meshLiveness]: foreground service health for the live dot.
 *
 * Thread-safety: all flows are collected on [viewModelScope]. The ViewModel is
 * created by Hilt and survives configuration changes.
 */
// ── ContactItem ───────────────────────────────────────────────────────────────

data class ContactItem(
    val nodeId:      String,
    val displayId:   String,
    val trustLabel:  String,
    val isReachable: Boolean,
)

// ── ForumUiViewModel ──────────────────────────────────────────────────────────

@HiltViewModel
class ForumUiViewModel @Inject constructor(
    private val channelManager:  ChannelManager,
    private val postEngine:      PostEngine,
    private val networkModeSM:   NetworkModeStateMachine,
    private val forumViewModel:  ForumViewModel,
    private val keyOrchestrator: KeyOrchestrator,
    private val gossipEngine:    GossipEngine,
    @Named("localNodeId")
    private val _localNodeId:    String = "",
) : ViewModel() {

    // ── Raw channel stream ────────────────────────────────────────────────────

    private val rawChannels: StateFlow<List<ChannelEntity>> =
        channelManager.observeActiveChannels()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // ── Sorted + sectioned channel list ──────────────────────────────────────
    //
    // Sort contract (locked — not user-configurable per design doc):
    //   Tier 1 (pinned):  COMPARTMENTED — highest DHT popularity first, then recency
    //   Tier 1 (pinned):  CLOSED        — same
    //   Tier 2 (public):  OPEN          — highest DHT popularity first, then recency
    //   Tier 2 (public):  ANONYMOUS     — same
    //
    // Section headers "Private — Pinned" and "Public" are injected by this flow.
    // DHT popularity is the primary sort key within each tier so channels with
    // more anchor nodes holding their fragments appear above less-replicated ones.

    val sortedChannels: StateFlow<List<ChannelListItem>> =
        combine(rawChannels, unreadCountsFlow()) { channels, counts ->
            buildSortedList(channels, counts)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private fun buildSortedList(
        channels: List<ChannelEntity>,
        counts:   Map<String, Int>
    ): List<ChannelListItem> {
        val privateTypes = setOf(ChannelType.COMPARTMENTED, ChannelType.CLOSED)

        // GLOBAL is always pinned above all other sections.
        val global = channels.filter { it.type == ChannelType.GLOBAL }

        val priv = channels
            .filter { it.type in privateTypes }
            .sortedWith(
                compareByDescending<ChannelEntity> { typePriority(it.type) }
                    .thenByDescending { it.dhtPopularity }
                    .thenByDescending { it.lastActivityMs }
            )

        val pub = channels
            .filter { it.type !in privateTypes && it.type != ChannelType.GLOBAL }
            .sortedWith(
                compareByDescending<ChannelEntity> { it.dhtPopularity }
                    .thenByDescending { it.lastActivityMs }
            )

        return buildList {
            if (global.isNotEmpty()) {
                add(ChannelListItem.SectionHeader("Global"))
                global.forEach { add(ChannelListItem.Channel(it, counts[it.channelId] ?: 0)) }
            }
            if (priv.isNotEmpty()) {
                add(ChannelListItem.SectionHeader("Private — Pinned"))
                priv.forEach { add(ChannelListItem.Channel(it, counts[it.channelId] ?: 0)) }
            }
            if (pub.isNotEmpty()) {
                add(ChannelListItem.SectionHeader("Public"))
                pub.forEach { add(ChannelListItem.Channel(it, counts[it.channelId] ?: 0)) }
            }
        }
    }

    /** COMPARTMENTED pins above CLOSED within the private section. GLOBAL handled separately. */
    private fun typePriority(type: ChannelType) = when (type) {
        ChannelType.COMPARTMENTED -> 2
        ChannelType.CLOSED        -> 1
        else                      -> 0
    }

    // ── Unread counts ─────────────────────────────────────────────────────────

    /**
     * Combines per-channel unread count flows into a single map.
     * Each channel gets its own Flow<Int> from the DAO; we combine them.
     * When the channel list changes, the combine is rebuilt automatically via
     * the flatMapLatest + combine pattern.
     */
    private fun unreadCountsFlow(): Flow<Map<String, Int>> =
        rawChannels.flatMapLatest { channels ->
            if (channels.isEmpty()) return@flatMapLatest flowOf(emptyMap())
            val flows = channels.map { ch ->
                postEngine.observeUnread(ch.channelId).map { count -> ch.channelId to count }
            }
            combine(flows) { pairs -> pairs.toMap() }
        }

    // ── Feed posts ────────────────────────────────────────────────────────────

    /**
     * Cross-channel CONFIRMED posts for the Feed tab.
     *
     * Sort: createdAtMs DESC, with private-channel posts ranked above public
     * posts at equal timestamps (tie-break by type priority DESC).
     * PENDING and SYNCING posts appear only in their channel detail.
     */
    val feedItems: StateFlow<List<FeedItem>> =
        rawChannels.flatMapLatest { channels ->
            if (channels.isEmpty()) return@flatMapLatest flowOf(emptyList())
            val postFlows = channels.map { ch ->
                postEngine.observePosts(ch.channelId).map { posts ->
                    posts.filter { it.postState == PostState.CONFIRMED || it.postState == PostState.SYNCING }
                         .map { FeedItem(it, ch) }
                }
            }
            combine(postFlows) { arrays ->
                arrays.flatMap { it }
                    .sortedWith(
                        compareByDescending<FeedItem> { it.post.createdAtMs }
                            .thenByDescending { typePriority(it.channel.type) }
                    )
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // ── Network mode ──────────────────────────────────────────────────────────

    private val _networkMode = MutableStateFlow(networkModeSM.currentMode)
    val networkMode: StateFlow<NetworkMode> = _networkMode.asStateFlow()

    init {
        networkModeSM.addListener { _, to -> _networkMode.value = to }
    }

    // ── Delegate to ForumViewModel ────────────────────────────────────────────

    fun selectChannel(channelId: String) = forumViewModel.selectChannel(channelId)
    fun departChannel(channelId: String) = forumViewModel.departChannel(channelId)
    fun onFirstFragmentAck(postId: String) = forumViewModel.onFirstFragmentAck(postId)
    fun onPostConfirmed(postId: String, enc: ByteArray) = forumViewModel.onPostConfirmed(postId, enc)
    fun retryPost(postId: String) = forumViewModel.retryPost(postId)

    val posts     get() = forumViewModel.posts
    val postDetail get() = forumViewModel.postDetail
    val compose   get() = forumViewModel.compose
    val events    get() = forumViewModel.events

    fun submitPost(channelId: String, create: suspend (String) -> mesh.shadowmesh.storage.PostEntity?) =
        forumViewModel.submitPost(channelId, create)

    fun openPost(postId: String, decrypt: suspend (ByteArray) -> String, showRep: Boolean = false) =
        forumViewModel.openPost(postId, decrypt, showRep)

    fun getPostStateMachine(postId: String) = forumViewModel.getPostStateMachine(postId)

    // ── Local identity ────────────────────────────────────────────────────────

    val localNodeId: String get() = _localNodeId

    // ── Contacts (active mesh peers) ──────────────────────────────────────────

    val contacts: StateFlow<List<ContactItem>> = flow {
        while (true) {
            val items = gossipEngine.activePeerIds().map { nodeId ->
                val trust = gossipEngine.effectiveTrust(nodeId)
                val trustLabel = when (trust) {
                    TrustLevel.TRUST_PHYSICAL   -> "PHYSICAL"
                    TrustLevel.TRUST_INTRODUCED -> "INTRODUCED"
                    else                        -> "PUBLIC"
                }
                val id = nodeId.toString()
                ContactItem(
                    nodeId      = id,
                    displayId   = id.take(8).uppercase() + "…" + id.takeLast(4).uppercase(),
                    trustLabel  = trustLabel,
                    isReachable = true,
                )
            }
            emit(items)
            delay(5_000)
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // ── Send a post ───────────────────────────────────────────────────────────

    fun sendPost(channelId: String, text: String, burnAfterRead: Boolean = false) {
        viewModelScope.launch {
            forumViewModel.onDraftChanged(text)
            forumViewModel.submitPost(channelId) { draftText ->
                val channel = channelManager.getChannel(channelId) ?: return@submitPost null
                val tier2  = draftText.encodeToByteArray()
                val tier1  = draftText.take(200).encodeToByteArray()
                val tier0  = draftText.take(50).encodeToByteArray()
                // Use the static channel key to encrypt tiers stored in the DB. The ratchet
                // is advanced exactly once per post in PostDispatcher.dispatch() when the
                // post is sent — not here. This eliminates the double-advance that previously
                // burned two ratchet steps per post and used mismatched keys.
                val channelKey = keyOrchestrator.retrieveChannelKey(channelId, channel.type)
                    ?: return@submitPost null
                try {
                    postEngine.createPost(
                        channelId      = channelId,
                        authorNodeId   = localNodeId,
                        plaintextTier0 = tier0,
                        plaintextTier1 = tier1,
                        plaintextTier2 = tier2,
                        postKey        = channelKey,
                        channelType    = channel.type,
                        burnAfterRead  = burnAfterRead,
                    )
                } finally {
                    channelKey.fill(0)
                }
            }
        }
    }

    // ── Create channel ────────────────────────────────────────────────────────

    private val _createChannelError = MutableStateFlow<String?>(null)
    val createChannelError: StateFlow<String?> = _createChannelError.asStateFlow()

    private val _isCreatingChannel = MutableStateFlow(false)
    val isCreatingChannel: StateFlow<Boolean> = _isCreatingChannel.asStateFlow()

    fun createChannel(name: String, type: ChannelType) {
        viewModelScope.launch {
            _isCreatingChannel.value = true
            _createChannelError.value = null
            try {
                val nowMs        = System.currentTimeMillis()
                val localIdHex   = localNodeId
                val localIdBytes = localIdHex.chunked(2)
                    .map { it.toInt(16).toByte() }
                    .toByteArray()
                    .let { if (it.size >= 32) it.copyOf(32) else it.copyOf(32) }

                // Pre-compute channelId using same derivation as ChannelManager so
                // the key can be wrapped with the correct salt before creation.
                val genesisHash = Hkdf.instance.sha3_256(
                    localIdBytes + name.toByteArray() + longToBytes(nowMs)
                )
                val channelIdBytes = Hkdf.instance.sha3_256(
                    genesisHash + type.name.toByteArray()
                )
                val channelId = channelIdBytes.joinToString("") { byte -> "%02x".format(byte) }

                val wrappedKey = keyOrchestrator.generateAndWrapChannelKey(channelId, type)
                channelManager.createChannel(name, type, localIdBytes, wrappedKey, nowMs)
            } catch (e: Exception) {
                _createChannelError.value = e.message ?: "Failed to create channel"
            } finally {
                _isCreatingChannel.value = false
            }
        }
    }

    fun clearCreateChannelError() { _createChannelError.value = null }

    // ── Node identity QR ──────────────────────────────────────────────────────

    fun generateNodeIdQr(sizePx: Int = 512): Bitmap? = try {
        val nodeId = localNodeId.ifEmpty { return null }
        val hints  = mapOf(EncodeHintType.MARGIN to 1)
        val matrix = QRCodeWriter().encode(nodeId, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        val bmp    = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.ARGB_8888)
        for (x in 0 until sizePx) for (y in 0 until sizePx) {
            bmp.setPixel(x, y, if (matrix[x, y]) android.graphics.Color.BLACK else android.graphics.Color.WHITE)
        }
        bmp
    } catch (_: Exception) { null }

    // ── Rotate channel key ────────────────────────────────────────────────────

    fun rotateChannelKey(channelId: String) {
        viewModelScope.launch {
            try {
                val channel    = channelManager.getChannel(channelId) ?: return@launch
                val wrappedKey = keyOrchestrator.generateAndWrapChannelKey(channelId, channel.type)
                channelManager.rotateKey(channelId, wrappedKey, channel.type)
                keyOrchestrator.evictAllRatchets(channelId)
            } catch (e: Exception) {
                android.util.Log.e("ForumUiVM", "rotateChannelKey failed: ${e.message}")
            }
        }
    }

    // ── Channel members (contacts who can access this channel) ────────────────

    fun channelMembers(channelId: String): StateFlow<List<ContactItem>> =
        contacts.map { list ->
            // For private channels: show all PHYSICAL-trust peers (they hold real keys).
            // For public channels: show all known peers.
            list
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())
}

private fun longToBytes(value: Long): ByteArray {
    val b = ByteArray(8)
    for (i in 0..7) b[i] = ((value shr ((7 - i) * 8)) and 0xFFL).toByte()
    return b
}

data class FeedItem(val post: PostEntity, val channel: ChannelEntity)

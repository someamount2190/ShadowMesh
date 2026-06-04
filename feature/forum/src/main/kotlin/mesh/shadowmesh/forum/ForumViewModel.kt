package mesh.shadowmesh.forum
import mesh.shadowmesh.diagnostics.Diag
import mesh.shadowmesh.storage.PostState

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import mesh.shadowmesh.storage.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

/**
 * Forum ViewModel — Phase 3 gap.
 *
 * Exposes StateFlows and SharedFlows the UI observes. Owns:
 *   - Channel list (active, non-departed channels)
 *   - Per-channel post list
 *   - Per-post detail (decrypt and expose plain text to UI)
 *   - Compose state (draft text, attachment type, send lifecycle)
 *   - Post state machine registry for optimistic UI
 *   - One-tap retry wiring (re-dispatches fragments via [fragmentDispatcher])
 *
 * The ViewModel does NOT touch cryptographic key material directly — that
 * is [KeyOrchestrator]'s job. The ViewModel calls PostEngine and ChannelManager
 * and receives already-encrypted entities. Decryption for display happens in
 * [PostDetailState] via a caller-supplied decrypt lambda (injected at open time).
 *
 * Fragment dispatch:
 *   The mesh layer (Phase 4+) will implement the actual gossip dispatch.
 *   Until then, [fragmentDispatcher] is an injectable suspend function so the
 *   ViewModel can be fully tested without the mesh layer.
 *
 * @param postEngine          Post storage and lifecycle.
 * @param channelManager      Channel storage and lifecycle.
 * @param fragmentDispatcher  Suspend function that dispatches post fragments to
 *                            the mesh. Injected so Phase 4 mesh can wire in.
 *                            Signature: (postId: String) -> Unit
 */
class ForumViewModel(
    private val postEngine:         PostEngine,
    private val channelManager:     ChannelManager,
    private val fragmentDispatcher: suspend (postId: String) -> Unit = { },
    /**
     * Scope used for PENDING timeout jobs.
     *
     * The PENDING→FAILED timeout must survive ViewModel clearance (e.g. user
     * navigates away while a post is in PENDING — the timeout job must still fire
     * so the post is marked FAILED on next open, not stuck in PENDING forever).
     * [viewModelScope] is cancelled on [onCleared], so it cannot host these jobs.
     *
     * Pass an application-lifetime scope (e.g. [ShadowMeshApplication.applicationScope]).
     * Defaults to [viewModelScope] in tests where the distinction does not matter.
     */
    private val backgroundScope:    CoroutineScope? = null
) : ViewModel() {

    // ── Channel list ──────────────────────────────────────────────────────

    val channels: StateFlow<List<ChannelEntity>> =
        channelManager.observeActiveChannels()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // ── Current channel selection ─────────────────────────────────────────

    private val _currentChannelId = MutableStateFlow<String?>(null)
    val currentChannelId: StateFlow<String?> = _currentChannelId.asStateFlow()

    fun selectChannel(channelId: String) { _currentChannelId.value = channelId }

    // ── Post list for selected channel ────────────────────────────────────

    val posts: StateFlow<List<PostEntity>> =
        _currentChannelId.flatMapLatest { channelId ->
            if (channelId == null) flowOf(emptyList())
            else postEngine.observePosts(channelId)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // ── Post detail ───────────────────────────────────────────────────────

    private val _postDetail = MutableStateFlow<PostDetailState>(PostDetailState.Idle)
    val postDetail: StateFlow<PostDetailState> = _postDetail.asStateFlow()

    /**
     * Open a post for reading. Handles burn-after-read.
     *
     * [decrypt] is a suspend lambda supplied by the caller that decrypts the
     * encrypted tier bytes into displayable text. This keeps key material out
     * of the ViewModel.
     *
     * Pattern:
     *   viewModel.openPost(postId) { encBytes ->
     *       keyOrchestrator.retrieveChannelKey(...).use { key ->
     *           cipher.decrypt(encBytes, key).getOrThrow().decodeToString()
     *       }
     *   }
     */
    fun openPost(
        postId:          String,
        decrypt:         suspend (encryptedBytes: ByteArray) -> String,
        showReputation:  Boolean = false   // pass true when reputation data is surfaced in the UI
    ) {
        viewModelScope.launch {
            _postDetail.value = PostDetailState.Loading
            try {
                val post = postEngine.openPost(postId)
                if (post == null) {
                    _postDetail.value = PostDetailState.NotFound
                    return@launch
                }
                // Decrypt the highest available tier for display.
                //
                // Fix: use tier1Unlocked as the gate for partial content display,
                // not null-check on encryptedTier1. For non-COMPARTMENTED channels,
                // encryptedTier1 is stored at post creation (never null), so the
                // null check always passed even with 0 fragments received. The correct
                // gate is tier1Unlocked, which is set by PostEngine.ingestFragment()
                // only after ≥10% of fragments arrive.
                val postTier2 = post.encryptedTier2
                val postTier1 = post.encryptedTier1
                val displayText = when {
                    // Gate full content on CONFIRMED — encryptedTier2 is stored from creation
                    // but must not be displayed until all fragments are received and verified.
                    post.postState == PostState.CONFIRMED && postTier2 != null ->
                        decrypt(postTier2)
                    post.tier1Unlocked && postTier1 != null ->
                        decrypt(postTier1) + "\u2026"  // partial — more arriving
                    post.encryptedTier0.isEmpty() ->
                        "Receiving post…"  // stub for received-only posts — encryptedTier0 not yet known
                    else ->
                        decrypt(post.encryptedTier0)
                }
                // reputationWarningVisible: mandatory warning required by design doc when
                // reputation data is shown — reputation is heuristic, not cryptographic.
                _postDetail.value = PostDetailState.Loaded(
                    post                     = post,
                    displayText              = displayText,
                    reputationWarningVisible = showReputation
                )
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                _postDetail.value = PostDetailState.Error(e.message ?: "Decrypt failed")
            }
        }
    }

    fun clearPostDetail() { _postDetail.value = PostDetailState.Idle }

    // ── Compose state ─────────────────────────────────────────────────────

    private val _compose = MutableStateFlow(ComposeState())
    val compose: StateFlow<ComposeState> = _compose.asStateFlow()

    fun onDraftChanged(text: String) {
        _compose.update { it.copy(draftText = text) }
    }

    fun onBurnAfterReadToggled() {
        _compose.update { it.copy(burnAfterRead = !it.burnAfterRead) }
    }

    fun clearCompose() { _compose.value = ComposeState() }

    // ── Post submission ───────────────────────────────────────────────────

    // Registry of in-flight post state machines
    private val stateMachines = PostStateMachineRegistry(
        // Timeout jobs must outlive ViewModel navigation — use backgroundScope when provided.
        // viewModelScope is cancelled on onCleared(), which would silently drop the PENDING
        // timeout before it fires if the user navigates away during a send attempt.
        scope     = backgroundScope ?: viewModelScope,
        onTimeout = { postId -> onPostTimeout(postId) }
    )

    /**
     * Submit a composed post.
     *
     * [createPost] is a suspend lambda that does the actual encryption and DB insert.
     * This keeps the ViewModel free of key material — the caller supplies the lambda.
     *
     * Pattern:
     *   viewModel.submitPost(channelId) { draftText ->
     *       keyOrchestrator.advanceRatchet(...) { step ->
     *           postEngine.createPost(channelId, nodeId, ..., step.postKey, ...)
     *       }
     *   }
     *
     * Returns the postId of the newly created post, or null if duplicate/failed.
     */
    fun submitPost(
        channelId:  String,
        createPost: suspend (draftText: String) -> PostEntity?
    ) {
        viewModelScope.launch {
            val draft = _compose.value.draftText
            if (draft.isBlank()) return@launch

            // Signal that async work is in progress so the UI can disable the send
            // button during the encryption + DB write. Without this, rapid taps can
            // trigger multiple concurrent createPost calls before the first completes.
            _compose.update { it.copy(isSubmitting = true) }

            try {
                val post = createPost(draft) ?: run {
                    _compose.update { it.copy(isSubmitting = false) }
                    return@launch  // duplicate — silently ignore
                }

                // Acquire state machine and enter PENDING
                val sm = stateMachines.getOrCreate(post.postId)
                sm.onSubmit()

                // Clear compose immediately — optimistic UI (isSubmitting also cleared)
                clearCompose()

                // Dispatch fragments to mesh
                try {
                    fragmentDispatcher(post.postId)
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) throw e
                    sm.onFailed("Fragment dispatch failed: ${e.message}")
                    postEngine.onDeliveryFailed(post.postId)
                }
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                _compose.update { it.copy(isSubmitting = false) }
                _events.tryEmit(ForumEvent.PostCreateFailed(e.message ?: "Unknown error"))
            }
        }
    }

    /**
     * Mark an OFFLINE_LOCAL post as PENDING_ONLINE so it can be submitted to the online
     * channel on the next manual send. Enforces at most one pending post per channel.
     * No-op if another post is already queued for this channel.
     */
    fun queueForOnline(postId: String) {
        viewModelScope.launch {
            val post = postEngine.loadForDispatch(postId) ?: return@launch
            val existing = postEngine.getPendingOnlineForChannel(post.channelId)
            if (existing != null && existing.postId != postId) return@launch
            postEngine.setPostState(postId, PostState.PENDING_ONLINE)
            _compose.update { it.copy(pendingOnlinePostId = postId) }
        }
    }

    /**
     * Create an online endorsement of an OFFLINE_LOCAL post.
     *
     * Decrypts the original post via [decrypt], formats the endorsement payload
     * (author + timestamp + original content), then calls [createEndorsement] to
     * encrypt and persist it as a new PostEntity with [endorsedPostId] set.
     * The new post is dispatched through the normal fragment pipeline.
     *
     * [decrypt]           — caller-supplied lambda; keeps key material out of ViewModel.
     * [createEndorsement] — suspend lambda: (formattedContent, originalPostId) → PostEntity?
     */
    fun endorseOfflineMessage(
        postId:            String,
        decrypt:           suspend (ByteArray) -> String,
        createEndorsement: suspend (content: String, endorsedPostId: String) -> PostEntity?,
    ) {
        viewModelScope.launch {
            val original = postEngine.loadForDispatch(postId) ?: return@launch
            val encBytes = original.encryptedTier2 ?: original.encryptedTier1 ?: original.encryptedTier0
            val originalText = try {
                decrypt(encBytes)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                _events.tryEmit(ForumEvent.PostCreateFailed("Could not decrypt original: ${e.message}"))
                return@launch
            }
            val author  = original.authorNodeId.take(8).uppercase()
            val timeFmt = java.text.SimpleDateFormat("HH:mm dd/MM", java.util.Locale.getDefault())
            val time    = timeFmt.format(java.util.Date(original.createdAtMs))
            val content = buildString {
                appendLine("[ENDORSED OFFLINE MSG]")
                appendLine("─────────────────────")
                appendLine("From : $author")
                appendLine("At   : $time")
                appendLine("─────────────────────")
                append(originalText)
            }
            val newPost = try {
                createEndorsement(content, postId)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                _events.tryEmit(ForumEvent.PostCreateFailed(e.message ?: "Endorsement create failed"))
                return@launch
            } ?: return@launch

            val sm = stateMachines.getOrCreate(newPost.postId)
            sm.onSubmit()
            try {
                fragmentDispatcher(newPost.postId)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                sm.onFailed(e.message ?: "dispatch failed")
                postEngine.onDeliveryFailed(newPost.postId)
            }
        }
    }

    /**
     * Cancel a pending online submission, reverting the post to OFFLINE_LOCAL.
     */
    fun cancelPendingOnline(postId: String) {
        viewModelScope.launch {
            postEngine.setPostState(postId, PostState.OFFLINE_LOCAL)
            _compose.update { it.copy(pendingOnlinePostId = null) }
        }
    }

    /**
     * Retry a failed post. Re-dispatches fragments to the mesh.
     * The post entity already exists in the DB — we just re-send.
     */
    fun retryPost(postId: String) {
        val sm = stateMachines.get(postId) ?: return
        sm.onRetry()
        viewModelScope.launch {
            try {
                fragmentDispatcher(postId)
            } catch (e: Exception) {
                if (e is kotlinx.coroutines.CancellationException) throw e
                sm.onFailed("Retry failed: ${e.message}")
                postEngine.onDeliveryFailed(postId)
            }
        }
    }

    /**
     * Get the [PostStateMachine] for [postId], creating one if needed.
     * The UI observes [PostStateMachine.state] to show spinner / lock / retry.
     */
    fun getPostStateMachine(postId: String): PostStateMachine =
        stateMachines.getOrCreate(postId)

    // ── Mesh delivery callbacks (called by mesh layer in Phase 4+) ────────

    /** Called by mesh layer when first fragment ACK arrives for [postId]. */
    fun onFirstFragmentAck(postId: String) {
        stateMachines.get(postId)?.onFirstAck()
        viewModelScope.launch { postEngine.onFirstFragmentAck(postId) }
    }

    /** Called by mesh layer when Merkle root ACK confirms full delivery. */
    fun onPostConfirmed(postId: String, encryptedTier2: ByteArray) {
        stateMachines.get(postId)?.onConfirmed()
        viewModelScope.launch {
            // postEngine.onConfirmed() handles both confirmation write and
            // channel activity touch internally — no need to call
            // channelManager.touchActivity() here as well.
            postEngine.onConfirmed(postId, encryptedTier2)
            stateMachines.remove(postId)
        }
    }

    // ── Channel actions ───────────────────────────────────────────────────

    fun departChannel(channelId: String) {
        viewModelScope.launch {
            channelManager.departChannel(channelId)
            if (_currentChannelId.value == channelId) {
                _currentChannelId.value = null
                _postDetail.value = PostDetailState.Idle
            }
            _events.tryEmit(ForumEvent.ChannelDeparted(channelId))
        }
    }

    // ── One-off events ────────────────────────────────────────────────────

    private val _events = MutableSharedFlow<ForumEvent>(extraBufferCapacity = 8)
    val events: SharedFlow<ForumEvent> = _events.asSharedFlow()

    // ── Internal ──────────────────────────────────────────────────────────

    private fun onPostTimeout(postId: String) {
        viewModelScope.launch {
            postEngine.onDeliveryFailed(postId)
            _events.tryEmit(ForumEvent.PostDeliveryFailed(postId))
        }
    }
}

// ── UI state types ────────────────────────────────────────────────────────────

sealed class PostDetailState {
    object Idle      : PostDetailState()
    object Loading   : PostDetailState()
    object NotFound  : PostDetailState()
    /** [reputationWarningVisible]: the UI MUST display a mandatory warning when true.
     *  Reputation is a local heuristic — not a cryptographic guarantee.
     *  Design doc Phase 3 exit gate requirement. */
    data class Loaded(
        val post:                     PostEntity,
        val displayText:              String,
        val reputationWarningVisible: Boolean = false
    ) : PostDetailState()
    data class Error(val message: String) : PostDetailState()
}

data class ComposeState(
    val draftText:    String  = "",
    /**
     * When true, this message will delete itself from **each device** after it is
     * read on that device — including the sender's own device on first open.
     *
     * This is a per-device local flag. The sender has no special control over
     * other devices: the flag is transmitted in the post metadata and each
     * recipient honors it independently when they open the post. Replicas held
     * by relay nodes expire on their normal TTL regardless of read state.
     *
     * UI copy: "Deletes from each device after reading"
     * NOT: "Only you can see this" (incorrect — all channel members can read it)
     * NOT: "Will be deleted everywhere" (incorrect — only local reads trigger deletion)
     */
    val burnAfterRead:Boolean = false,
    /**
     * True while the async encryption + DB write is in progress (between send tap
     * and the post entering the state machine). The send button is disabled while
     * this is true to prevent duplicate submissions.
     * Cleared by [clearCompose] on success or by error handlers on failure.
     */
    val isSubmitting: Boolean = false,
    /**
     * The postId of the OFFLINE_LOCAL post the user has queued for online submission.
     * At most one per channel. Null when no pending online submission exists.
     * The post state in DB is PENDING_ONLINE while this is set.
     */
    val pendingOnlinePostId: String? = null,
)

sealed class ForumEvent {
    data class PostDeliveryFailed(val postId: String)     : ForumEvent()
    data class PostCreateFailed(val reason: String)       : ForumEvent()
    data class ChannelDeparted(val channelId: String)     : ForumEvent()
}

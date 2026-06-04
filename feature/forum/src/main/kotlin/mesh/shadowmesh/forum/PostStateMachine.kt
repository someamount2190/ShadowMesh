package mesh.shadowmesh.forum

import mesh.shadowmesh.storage.PostState
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*

/**
 * Optimistic UI post state machine — design doc Phase 3.
 *
 * Manages the per-post UI state:
 *
 *   DRAFT     — user typing, not yet submitted
 *   PENDING   — send initiated, awaiting first fragment ACK from ANY relay
 *   SYNCING   — at least one relay accepted a fragment; propagating through the mesh
 *   CONFIRMED — Merkle root ACK received; post fully replicated
 *   FAILED    — PENDING timed out with zero relay contact (no mesh reachability)
 *
 * ## Async forum model — why locking is scoped to PENDING only
 *
 * SHADOWMESH is a P2P gossip-propagated message store, not a chat protocol.
 * Delivery from sender to all recipients can take seconds in HEALTHY mode
 * or minutes in DEGRADED/SURVIVAL mode. Locking the compose input for the
 * full propagation window would make the forum unusable.
 *
 * The PENDING timeout (30s) covers only the case where the device cannot
 * reach even a single relay node — i.e., no mesh connectivity at all. Once
 * any relay accepts a fragment (SYNCING), the post is in the mesh and will
 * propagate. The user can immediately compose the next post.
 *
 * Input locking semantics:
 *   - PENDING: compose input LOCKED (no relay accepted yet — post may be stuck)
 *   - SYNCING: compose input UNLOCKED (post is in-flight — user can write next)
 *   - CONFIRMED: compose input UNLOCKED (post confirmed)
 *   - FAILED: compose input UNLOCKED (retry available, but user can also write new)
 *
 * Per-post display:
 *   - PENDING: spinner + "Sending…"
 *   - SYNCING: spinner + "In mesh…" (not locked — just an indicator)
 *   - CONFIRMED: delivery ticks ✓✓
 *   - FAILED: "No relay reached · [Retry]"
 *
 * Timeout: 30 seconds for PENDING only. SYNCING has no timeout — propagation
 * time is unbounded and dependent on network conditions. A post in SYNCING
 * that never confirms stays in SYNCING until the TTL expires and is swept.
 *
 * Thread-safety: StateFlow is thread-safe. The timeout Job is cancelled
 * correctly on state transitions.
 */
class PostStateMachine(
    private val postId:    String,
    private val scope:     CoroutineScope,
    private val onTimeout: suspend (postId: String) -> Unit,
    private val timeoutMs: Long = PENDING_TIMEOUT_MS
) {
    private val _state   = MutableStateFlow(PostState.DRAFT)
    val state: StateFlow<PostState> = _state.asStateFlow()

    private var timeoutJob: Job? = null

    // ── Transitions ───────────────────────────────────────────────────────

    /** User submits the post — enters PENDING, starts relay-contact timeout. */
    fun onSubmit() {
        if (_state.value != PostState.DRAFT && _state.value != PostState.FAILED) return
        _state.value = PostState.PENDING
        startPendingTimeout()
    }

    /**
     * First fragment ACK received from any relay — transition to SYNCING.
     * Cancels the PENDING timeout: the post is now in the mesh.
     * The compose input unlocks at this point.
     */
    fun onFirstAck() {
        if (_state.value != PostState.PENDING) return
        timeoutJob?.cancel()   // cancel PENDING timeout — relay contact made
        _state.value = PostState.SYNCING
        // No timeout started for SYNCING — propagation time is unbounded.
    }

    /** Merkle root ACK received — post fully replicated, confirmed. */
    fun onConfirmed() {
        timeoutJob?.cancel()
        _state.value = PostState.CONFIRMED
    }

    /** Explicit delivery failure reported by mesh layer (e.g. hash mismatch on confirm). */
    fun onFailed(reason: String = "Delivery failed") {
        timeoutJob?.cancel()
        _state.value = PostState.FAILED
    }

    /** User initiates retry — re-enters PENDING with a fresh relay-contact timeout. */
    fun onRetry() {
        if (_state.value != PostState.FAILED) return
        _state.value = PostState.PENDING
        startPendingTimeout()
    }

    // ── UI helpers ────────────────────────────────────────────────────────

    /**
     * Returns true when the compose input should be locked.
     *
     * Locked ONLY in PENDING — the post has not yet reached any relay and
     * the user should wait before composing a follow-up (the network may be
     * unreachable and a new send would also fail).
     *
     * SYNCING is NOT locked: the post is in the mesh and propagating normally.
     * Multiple unconfirmed posts co-existing in SYNCING is expected and correct
     * for an async forum.
     */
    val isInputLocked: Boolean
        get() = _state.value == PostState.PENDING

    /**
     * Returns true when a per-post spinner should be shown.
     * Both PENDING and SYNCING show a spinner — the difference is in the label:
     * PENDING = "Sending…", SYNCING = "In mesh…"
     */
    val isSpinning: Boolean
        get() = _state.value == PostState.PENDING || _state.value == PostState.SYNCING

    /** Returns true when the retry button should be shown on the post item. */
    val showRetry: Boolean
        get() = _state.value == PostState.FAILED

    /** Label for the spinner, differentiating relay-contact from propagation. */
    val statusLabel: String
        get() = when (_state.value) {
            PostState.PENDING        -> "Sending…"
            PostState.SYNCING        -> "In mesh…"
            PostState.CONFIRMED      -> ""
            PostState.FAILED         -> "No relay reached"
            PostState.DRAFT          -> ""
            PostState.OFFLINE_LOCAL  -> "Offline"
            PostState.PENDING_ONLINE -> "Queued for online"
        }

    // ── Internal ──────────────────────────────────────────────────────────

    /**
     * Timeout applies only to PENDING — if no relay responds within [PENDING_TIMEOUT_MS],
     * the device has no mesh connectivity and the post is unlikely to propagate.
     * Once SYNCING, no timeout: the mesh will propagate when it can.
     */
    private fun startPendingTimeout() {
        timeoutJob?.cancel()
        timeoutJob = scope.launch {
            delay(timeoutMs)
            if (_state.value == PostState.PENDING) {
                _state.value = PostState.FAILED
                onTimeout(postId)
            }
            // If state has advanced to SYNCING or beyond by the time delay completes,
            // do nothing — the transition was handled by onFirstAck().
        }
    }

    companion object {
        /**
         * Timeout for PENDING state only: how long to wait for any relay to
         * accept the first fragment. 30 seconds is generous — relay contact on
         * a live mesh takes milliseconds. Failure here means no connectivity.
         *
         * Not applied to SYNCING: propagation time is unbounded and governed
         * by the mesh's retransmission and store-and-forward mechanisms.
         */
        const val PENDING_TIMEOUT_MS = 30_000L

        /** Kept for binary compatibility with existing callers. */
        @Deprecated("Use PENDING_TIMEOUT_MS", replaceWith = ReplaceWith("PENDING_TIMEOUT_MS"))
        const val LOCK_TIMEOUT_MS = PENDING_TIMEOUT_MS
    }
}

// ── Registry ──────────────────────────────────────────────────────────────────

/**
 * Manages per-post state machines for all in-flight posts in a channel.
 *
 * The channel UI holds one registry; posts are added on submission and removed
 * on CONFIRMED (delivery indicator cleared after a short delay) or after
 * FAILED + no retry within a reasonable window.
 *
 * Thread-safety: [machines] is a plain [LinkedHashMap] — NOT thread-safe.
 * All methods on this class MUST be called from the main thread. In practice,
 * [PostStateMachineRegistry] is owned by [ForumViewModel] and all call sites
 * in [ForumViewModel] run on [viewModelScope] which dispatches to Main.
 * If this changes (e.g., a background scope calls [getOrCreate]), switch
 * [machines] to [java.util.concurrent.ConcurrentHashMap].
 */
class PostStateMachineRegistry(
    private val scope:     CoroutineScope,
    private val onTimeout: suspend (postId: String) -> Unit
) {
    private val machines = LinkedHashMap<String, PostStateMachine>()

    fun getOrCreate(postId: String): PostStateMachine =
        machines.getOrPut(postId) {
            PostStateMachine(postId, scope, onTimeout)
        }

    fun get(postId: String): PostStateMachine? = machines[postId]

    fun remove(postId: String) { machines.remove(postId) }

    /**
     * Returns true if any post is in PENDING state — the one condition where
     * the compose input should be locked.
     *
     * Posts in SYNCING do NOT contribute to locking: they are propagating normally
     * and the user can compose the next post while they are in transit.
     */
    fun anyPendingLocked(): Boolean = machines.values.any { it.isInputLocked }

    /**
     * @deprecated Use [anyPendingLocked]. The old name implied SYNCING also locked
     *             input, which contradicts the async forum model.
     */
    @Deprecated("Use anyPendingLocked", replaceWith = ReplaceWith("anyPendingLocked()"))
    fun anyLocked(): Boolean = anyPendingLocked()
}

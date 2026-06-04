package mesh.shadowmesh.forum

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import mesh.shadowmesh.mesh.circuit.*
import mesh.shadowmesh.storage.*
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.launch

/**
 * ViewModel for Settings → Privacy → Entry Node.
 *
 * Surfaces the user's Entry Node configuration to the UI:
 *   - Current [EntryNodeMode] (AUTOMATIC or ASK_EACH_TIME)
 *   - Global ranked preference list
 *   - Per-channel override list (keyed by channelId)
 *   - The list of TRUST_PHYSICAL contacts available for selection
 *     (sourced from [trustedContactsProvider] — injected to keep this VM
 *     decoupled from the peer/trust layer)
 *
 * UI contract:
 *   The settings screen shows:
 *     1. A mode selector (radio buttons: Automatic / Ask each time)
 *     2. The global preference list as a drag-reorderable list of contact cards
 *        Each card shows: displayName, short nodeId, online indicator
 *     3. An "Add" button that opens the TRUST_PHYSICAL contact picker
 *     4. Per-channel overrides section (collapsed by default)
 *
 *   The privacy trade-off string is always visible at the top:
 *     "Your Entry Node will know your IP address and that you are active on the mesh.
 *      They will not know who you are communicating with, what you are saying,
 *      or any other details about your activity."
 *
 * Entry offline notification:
 *   When [EntryNodeEvent.EntryOffline] or [EntryNodeEvent.NoEntryAvailable] arrives
 *   (injected via [notifyEvent]), the ViewModel emits it on [events] so the UI can
 *   surface an appropriate notification or dialog.
 *
 * @param store                   Entry Node preference persistence.
 * @param trustedContactsProvider Returns the current list of TRUST_PHYSICAL contacts
 *                                as [EntryNodePreference] candidates (display name +
 *                                nodeId). Injected to keep this ViewModel decoupled
 *                                from the mesh trust layer.
 */
class EntryNodeViewModel(
    private val store:                   EntryNodeStore,
    private val trustedContactsProvider: suspend () -> List<EntryNodePreference>
) : ViewModel() {

    // ── Mode ──────────────────────────────────────────────────────────────

    private val _mode = MutableStateFlow(EntryNodeMode.AUTOMATIC)
    val mode: StateFlow<EntryNodeMode> = _mode.asStateFlow()

    init {
        viewModelScope.launch {
            _mode.value = store.getMode()
        }
    }

    fun setMode(mode: EntryNodeMode) {
        _mode.value = mode
        viewModelScope.launch { store.setMode(mode) }
    }

    // ── Global preference list ────────────────────────────────────────────

    val globalPreferences: StateFlow<List<EntryNodePreference>> =
        store.observeGlobalPreferences()
            .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // ── Available TRUST_PHYSICAL contacts for the picker ──────────────────

    private val _availableContacts = MutableStateFlow<List<EntryNodePreference>>(emptyList())
    val availableContacts: StateFlow<List<EntryNodePreference>> =
        _availableContacts.asStateFlow()

    /** Refresh the list of TRUST_PHYSICAL contacts available for selection.
     *  Call when the picker is opened. */
    fun refreshAvailableContacts() {
        viewModelScope.launch {
            _availableContacts.value = trustedContactsProvider()
        }
    }

    // ── Preference mutations ──────────────────────────────────────────────

    /**
     * Add a contact to the global preference list.
     * [nodeId] and [displayName] come from the contact picker.
     */
    fun addGlobalPreference(nodeId: String, displayName: String) {
        viewModelScope.launch {
            store.addPreference(nodeId, displayName, channelId = null)
        }
    }

    /**
     * Add a per-channel override for [channelId].
     * When this channel is active, the circuit uses this Entry Node instead of
     * the global list. Appropriate for COMPARTMENTED channels.
     */
    fun addChannelOverride(channelId: String, nodeId: String, displayName: String) {
        viewModelScope.launch {
            store.addPreference(nodeId, displayName, channelId = channelId)
        }
    }

    fun removePreference(id: Long) {
        viewModelScope.launch { store.removePreference(id) }
    }

    /**
     * Reorder global preferences after a drag-and-drop gesture.
     * [orderedIds] is the complete list of preference IDs in the new order.
     */
    fun reorderGlobalPreferences(orderedIds: List<Long>) {
        viewModelScope.launch { store.reorderPreferences(orderedIds) }
    }

    // ── Per-channel overrides ─────────────────────────────────────────────

    private val _selectedChannelId = MutableStateFlow<String?>(null)

    fun selectChannelForOverride(channelId: String) {
        _selectedChannelId.value = channelId
    }

    val channelOverrides: StateFlow<List<EntryNodePreference>> =
        _selectedChannelId.flatMapLatest { channelId ->
            if (channelId == null) flowOf(emptyList())
            else store.observeChannelPreferences(channelId)
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    // ── Entry Node picker for ASK_EACH_TIME mode ──────────────────────────

    /**
     * The user has picked an Entry Node in the one-shot picker dialog.
     * Stores it as a temporary selection; [EntryNodeStore.consumeTemporarySelection]
     * will return it to CircuitManager on the next circuit build.
     *
     * After calling this, emit [EntryNodeEvent.PickRequired] as resolved so the UI
     * can dismiss the dialog and proceed with sending.
     */
    fun confirmTemporarySelection(candidate: CircuitCandidate) {
        store.setTemporarySelection(candidate)
        _events.tryEmit(EntryNodePickerResult.SelectionConfirmed)
    }

    fun cancelTemporarySelection() {
        _events.tryEmit(EntryNodePickerResult.SelectionCancelled)
    }

    // ── Events ────────────────────────────────────────────────────────────

    private val _events = MutableSharedFlow<EntryNodePickerResult>(extraBufferCapacity = 4)
    val pickerResults: SharedFlow<EntryNodePickerResult> = _events.asSharedFlow()

    private val _entryEvents = MutableSharedFlow<EntryNodeEvent>(extraBufferCapacity = 4)
    val entryEvents: SharedFlow<EntryNodeEvent> = _entryEvents.asSharedFlow()

    /**
     * Called by the circuit layer (via an injected callback) when an entry-node
     * lifecycle event occurs that the UI should surface:
     *   [EntryNodeEvent.EntryOffline]    → show a notification toast
     *   [EntryNodeEvent.NoEntryAvailable] → show a blocking dialog
     *   [EntryNodeEvent.PickRequired]    → open the Entry Node picker dialog
     */
    fun notifyEvent(event: EntryNodeEvent) {
        viewModelScope.launch { _entryEvents.emit(event) }
    }

    // ── UI state: summary string for the Settings screen ──────────────────

    /**
     * A human-readable summary of the current Entry Node configuration,
     * suitable for display on the Settings screen as a subtitle.
     *
     * Examples:
     *   "Alice (automatic)"
     *   "Alice → Bob → Charlie (automatic)"
     *   "Ask before each post"
     *   "Not configured — IP exposed to a random Guard"
     */
    val configSummary: StateFlow<String> =
        combine(globalPreferences, mode) { prefs, mode ->
            when {
                mode == EntryNodeMode.ASK_EACH_TIME ->
                    "Ask before each post"
                prefs.isEmpty() ->
                    "Not configured — IP exposed to a random Guard"
                prefs.size == 1 ->
                    "${prefs[0].displayName} (automatic)"
                else -> {
                    val names = prefs.take(3).joinToString(" → ") { it.displayName }
                    val suffix = if (prefs.size > 3) " +${prefs.size - 3} more" else ""
                    "$names$suffix (automatic)"
                }
            }
        }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), "Loading…")
}

// ── Picker result ──────────────────────────────────────────────────────────────

sealed class EntryNodePickerResult {
    object SelectionConfirmed : EntryNodePickerResult()
    object SelectionCancelled : EntryNodePickerResult()
}

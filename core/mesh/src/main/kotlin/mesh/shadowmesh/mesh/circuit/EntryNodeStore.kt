package mesh.shadowmesh.mesh.circuit

import mesh.shadowmesh.mesh.dht.*
import mesh.shadowmesh.storage.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.*
import kotlinx.coroutines.withContext

/**
 * Entry Node preference store — manages the user's ranked list of TRUST_PHYSICAL
 * contacts they are willing to use as Entry Nodes.
 *
 * Responsibilities:
 *   - Persist global and per-channel Entry Node preferences to the database.
 *   - Resolve the effective preference list for a given channel:
 *       if a per-channel override exists → use it;
 *       otherwise → use the global list.
 *   - Convert stored preferences to [CircuitCandidate] objects the rotator
 *     can consume, joined against the live peer list for online/blocked status.
 *   - Surface the current [EntryNodeMode] (AUTOMATIC vs ASK_EACH_TIME).
 *   - Expose a Flow for the Settings UI to observe preference changes.
 *
 * Offline fallback resolution:
 *   The store returns all stored preferences in rank order. [CircuitRoleRotator]
 *   then walks the list and applies its own fallback chain — the store does not
 *   pre-filter for online status because online status is known only at circuit
 *   build time. If the rotator finds no available preferred Entry, it falls back
 *   to any TRUST_PHYSICAL peer in the full candidate pool.
 *
 * "Ask each time" mode:
 *   When [getMode] returns [EntryNodeMode.ASK_EACH_TIME], the caller (CircuitManager
 *   or the post-submit path) must surface [EntryNodeEvent.PickRequired] to the UI
 *   before proceeding. The UI calls [setTemporarySelection] with the chosen node,
 *   which is used for one circuit build and then cleared.
 *
 * Thread-safety: all DAO operations dispatched to Dispatchers.IO.
 */
class EntryNodeStore(private val dao: ShadowMeshDao) {

    // ── Mode ──────────────────────────────────────────────────────────────

    /** Current global Entry Node mode. Defaults to AUTOMATIC if not configured. */
    suspend fun getMode(): EntryNodeMode = withContext(Dispatchers.IO) {
        val raw = dao.getEntryNodeMode() ?: return@withContext EntryNodeMode.AUTOMATIC
        runCatching { EntryNodeMode.valueOf(raw) }.getOrDefault(EntryNodeMode.AUTOMATIC)
    }

    suspend fun setMode(mode: EntryNodeMode) = withContext(Dispatchers.IO) {
        dao.setEntryNodeMode(mode.name)
    }

    // ── Preferences — observe ─────────────────────────────────────────────

    /** Live global preference list for the Settings UI. */
    fun observeGlobalPreferences(): Flow<List<EntryNodePreference>> =
        dao.observeGlobalPreferences()

    /** Live per-channel preference list for the per-channel override screen. */
    fun observeChannelPreferences(channelId: String): Flow<List<EntryNodePreference>> =
        dao.observeChannelPreferences(channelId)

    // ── Preferences — mutate ──────────────────────────────────────────────

    /**
     * Add or update a preference entry.
     *
     * [nodeId] must be a TRUST_PHYSICAL contact — this is enforced by the caller
     * (the UI only surfaces TRUST_PHYSICAL contacts in the picker).
     *
     * If [channelId] is null, the entry goes into the global list.
     * If [channelId] is non-null, it creates or replaces a per-channel override entry.
     *
     * New entries are appended at the end of the current list (rank = current max + 1).
     * Use [reorderPreferences] to change rank after insertion.
     */
    suspend fun addPreference(
        nodeId:      String,
        displayName: String,
        channelId:   String? = null
    ): EntryNodePreference = withContext(Dispatchers.IO) {
        val existing = if (channelId != null)
            dao.getChannelPreferences(channelId)
        else
            dao.getGlobalPreferences()

        val nextRank = (existing.maxOfOrNull { it.rank } ?: -1) + 1
        val pref = EntryNodePreference(
            nodeId            = nodeId,
            displayName       = displayName,
            rank              = nextRank,
            channelOverrideId = channelId
        )
        val insertedId = dao.upsertEntryPreference(pref)
        pref.copy(id = insertedId)
    }

    suspend fun removePreference(id: Long) = withContext(Dispatchers.IO) {
        dao.deleteEntryPreference(id)
    }

    /** Remove a TRUST_PHYSICAL contact from all preference lists (global + all channels). */
    suspend fun removeAllPreferencesForNode(nodeId: String) = withContext(Dispatchers.IO) {
        dao.deleteAllPreferencesForNode(nodeId)
    }

    /**
     * Reorder the global or per-channel preference list atomically.
     *
     * [orderedIds] is the complete list of preference IDs in the new desired order.
     * All rank updates are wrapped in a single @Transaction so a process kill
     * mid-reorder never leaves a partial ordering in the database.
     */
    suspend fun reorderPreferences(orderedIds: List<Long>) = withContext(Dispatchers.IO) {
        dao.reorderPreferencesTransactional(orderedIds)
    }

    // ── Effective list for circuit building ───────────────────────────────

    /**
     * Returns the effective ranked [EntryNodePreference] list for [channelId]
     * directly from the database, preserving stored display names.
     *
     * Used when the caller needs the human-readable display names from the DB
     * (e.g. [EntryNodeEvent.PickRequired]) rather than CircuitCandidate objects.
     * Resolution: per-channel override if entries exist, otherwise global list.
     */
    suspend fun effectiveStoredPreferencesForChannel(
        channelId: String?
    ): List<EntryNodePreference> = withContext(Dispatchers.IO) {
        if (channelId != null) {
            val channelPrefs = dao.getChannelPreferences(channelId)
            channelPrefs.ifEmpty { dao.getGlobalPreferences() }
        } else {
            dao.getGlobalPreferences()
        }
    }

    /**
     * Returns the effective ranked preference list for [channelId] as a
     * [CircuitCandidate] list, joined against [onlinePeers] for reachability.
     *
     * Resolution:
     *   1. If per-channel entries exist for [channelId], use them.
     *   2. Otherwise use the global list.
     *
     * The returned list is in rank order (index 0 = highest preference).
     * Nodes not present in [onlinePeers] are included in the list — the rotator
     * skips unavailable nodes in its fallback chain. This avoids a race where a
     * node comes online between the preference resolution and circuit build.
     *
     * [onlinePeers] maps nodeId hex → CircuitCandidate from the live peer table.
     * Nodes absent from [onlinePeers] get a placeholder CircuitCandidate with
     * uptimeScore=0 and isBlocked=true — the rotator skips them via its block
     * filter. This preserves the ranked order so the node is used when it comes
     * online (it will appear in [onlinePeers] and receive a real candidate then).
     */
    suspend fun effectivePreferencesForChannel(
        channelId:    String?,
        onlinePeers:  Map<String, CircuitCandidate>
    ): List<CircuitCandidate> = withContext(Dispatchers.IO) {
        val stored = if (channelId != null) {
            val channelPrefs = dao.getChannelPreferences(channelId)
            channelPrefs.ifEmpty { dao.getGlobalPreferences() }
        } else {
            dao.getGlobalPreferences()
        }

        stored.map { pref ->
            onlinePeers[pref.nodeId] ?: placeholderCandidate(pref)
        }
    }

    // ── Ask-each-time: temporary one-shot selection ───────────────────────

    // AtomicReference: setTemporarySelection and consumeTemporarySelection form
    // a set/getAndSet pair. @Volatile alone does not make the read-then-clear
    // in consumeTemporarySelection atomic — two concurrent callers could both
    // read the same non-null value and both consume the selection, causing it
    // to be used for two simultaneous circuit builds.
    private val temporarySelection = java.util.concurrent.atomic.AtomicReference<CircuitCandidate?>(null)

    /**
     * Set the user's one-shot Entry Node choice (ASK_EACH_TIME mode).
     * This selection is used for a single circuit build and then cleared.
     */
    fun setTemporarySelection(candidate: CircuitCandidate) {
        temporarySelection.set(candidate)
    }

    /**
     * Atomically consume the temporary selection — returns it and clears
     * the field in a single atomic operation (getAndSet).
     * Returns null if no selection is pending.
     */
    fun consumeTemporarySelection(): CircuitCandidate? =
        temporarySelection.getAndSet(null)

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Construct a placeholder CircuitCandidate for a preference whose node is
     * not currently in the live peer list.
     *
     * [isBlocked] is set to true so [CircuitRoleRotator] skips this node via
     * its existing block filter rather than selecting it and failing at the
     * KEM handshake step. The KDoc comment on the sentinel address said
     * "rotator detects 0.0.0.0 as unreachable" but the rotator has no such
     * check — using isBlocked=true is the correct and consistent mechanism.
     *
     * The preference order is preserved in the ranked list; when the node
     * comes online it will appear in [onlinePeers] and get a real candidate.
     */
    private fun placeholderCandidate(pref: EntryNodePreference): CircuitCandidate {
        val nodeIdBytes = runCatching {
            ByteArray(pref.nodeId.length / 2) { i ->
                pref.nodeId.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        }.getOrElse { ByteArray(32) }

        return CircuitCandidate(
            nodeId      = NodeId(nodeIdBytes),
            contact     = DhtContact(
                NodeId(nodeIdBytes),
                PeerAddress("0.0.0.0", 0)
            ),
            trustLevel  = TrustLevelForCircuit.PHYSICAL,
            uptimeScore = 0,
            isBlocked   = true   // offline placeholder — skip in rotator's block filter
        )
    }
}

// ── Entry Node events (for the ViewModel / UI layer) ─────────────────────────

/**
 * Events emitted by [EntryNodeViewModel] that require UI action.
 *
 *   [PickRequired]   — emitted when mode is ASK_EACH_TIME and a circuit needs
 *                      building. UI must show the Entry Node picker and call
 *                      [EntryNodeStore.setTemporarySelection] with the result.
 *   [EntryOffline]   — emitted when all preferred Entry Nodes are offline and
 *                      the rotator has fallen back to an arbitrary TRUST_PHYSICAL
 *                      peer. UI may show a notification.
 *   [NoEntryAvailable] — emitted when no TRUST_PHYSICAL peer exists and circuit
 *                        construction failed entirely. UI must inform the user.
 */
sealed class EntryNodeEvent {
    /** User must pick an Entry Node before the pending post can be sent. */
    data class PickRequired(val availableCandidates: List<EntryNodePreference>) : EntryNodeEvent()
    /** All preferred Entry Nodes were offline; fallback was used. */
    data class EntryOffline(val fallbackDisplayName: String)                    : EntryNodeEvent()
    /** Circuit build failed — no TRUST_PHYSICAL peer is reachable at all. */
    object NoEntryAvailable                                                      : EntryNodeEvent()
}

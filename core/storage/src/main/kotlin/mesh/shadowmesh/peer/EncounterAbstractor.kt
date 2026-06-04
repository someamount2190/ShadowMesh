package mesh.shadowmesh.peer

import mesh.shadowmesh.storage.PeerModelEntity
import mesh.shadowmesh.storage.TimeQuarter
import java.util.concurrent.atomic.AtomicInteger

/**
 * Live, RAM-ONLY buffer for the CURRENT encounter with one peer. This is the only place a
 * wall-clock timestamp ([sessionStartMs]) exists, and it never touches disk: it is read to
 * pick a time-of-day quarter at fold time, then dropped with the session object.
 *
 * Lifecycle:
 *   open(peer)  → counters accumulate during the live connection
 *   end()       → EncounterAbstractor folds the session into PeerModelEntity, session dropped
 *   (crash)     → process dies; this session is lost. See the crash boundary note below.
 */
class ActiveEncounterSession(
    val nodeId:        String,
    val sessionStartMs: Long,             // RAM-only wall-clock; never persisted
    val globalSeqAtStart: Long            // mesh-global monotonic sequence snapshot
) {
    private val fragmentsSent      = AtomicInteger(0)
    private val fragmentsDelivered = AtomicInteger(0)
    @Volatile private var channelsMask: Long = 0

    fun recordFragmentSent()      { fragmentsSent.incrementAndGet() }
    fun recordFragmentDelivered() { fragmentsDelivered.incrementAndGet() }
    fun recordChannelSlot(slot: Int) {
        if (slot in 0..63) channelsMask = channelsMask or (1L shl slot)
    }

    fun snapshot(endMs: Long, globalSeqAtEnd: Long) = EncounterSnapshot(
        nodeId            = nodeId,
        sessionStartMs    = sessionStartMs,
        fragmentsSent     = fragmentsSent.get(),
        fragmentsDelivered= fragmentsDelivered.get(),
        channelsMask      = channelsMask,
        globalSeqAtEnd    = globalSeqAtEnd
    )
}

/** Immutable result of ending a session — the only thing handed to the abstractor. */
data class EncounterSnapshot(
    val nodeId:             String,
    val sessionStartMs:     Long,
    val fragmentsSent:      Int,
    val fragmentsDelivered: Int,
    val channelsMask:       Long,
    val globalSeqAtEnd:     Long
)

/**
 * Folds a completed [EncounterSnapshot] into the durable [PeerModelEntity]. Pure function of
 * (old model, snapshot) → new model, so it is trivially testable and has no I/O. The DAO
 * upsert is the caller's job.
 *
 * CRASH BOUNDARY (the question worth deciding explicitly):
 *   This abstractor runs on a CLEAN encounter end. A process death mid-encounter loses that
 *   one session. The subtle risk is BIAS, not just a lost point: if "clean end" and "crash"
 *   are indistinguishable, a peer that consistently disconnects uncleanly (or whose link
 *   always drops the process) would systematically never fold in — under-counting exactly
 *   the unreliable peers. Two mitigations, pick per deployment:
 *     (a) Treat an unclean transport teardown as a NEGATIVE delivery sample (fold a snapshot
 *         with fragmentsDelivered < fragmentsSent) rather than skipping it — so flaky peers
 *         are penalised, not silently excused. This is the default below: callers should
 *         still call fold() on an unclean end, with the partial counters.
 *     (b) Periodically checkpoint long-running sessions. This reintroduces a timestamp on
 *         disk and is OFF by default; only enable if losing long encounters matters more
 *         than the metadata cost.
 */
object EncounterAbstractor {

    /**
     * @param old      existing model, or null for a first encounter.
     * @param snap     the completed (or unclean-ended) encounter.
     * @param hourOfDay local hour [0,23] derived from snap.sessionStartMs by the caller
     *                  (kept out of here so this stays a pure function and no Clock leaks in).
     */
    fun fold(old: PeerModelEntity?, snap: EncounterSnapshot, hourOfDay: Int): PeerModelEntity {
        val base = old ?: PeerModelEntity(
            nodeId             = snap.nodeId,
            globalSeqFirstSeen = snap.globalSeqAtEnd
        )

        // ── Delivery weight: EWMA fold with an explicit sample of this encounter ──
        // Per-encounter success ratio in [0,1]; an encounter with zero sends contributes a
        // neutral sample (0.0 successes of 0 sends would be undefined, so skip the ratio but
        // still advance nothing — guarded below).
        val sampleRatio = if (snap.fragmentsSent > 0)
            snap.fragmentsDelivered.toDouble() / snap.fragmentsSent
        else null

        val (newWeight, newSamples) = if (sampleRatio == null) {
            base.deliveryWeight to base.deliverySamples
        } else if (base.deliverySamples == 0) {
            // First real sample seeds the EWMA directly (no prior to blend with).
            sampleRatio to 1
        } else {
            val a = PeerModelEntity.DELIVERY_EWMA_ALPHA
            (a * sampleRatio + (1 - a) * base.deliveryWeight) to (base.deliverySamples + 1)
        }

        // ── Time-of-day: increment the integer count for this encounter's quarter ──
        val q = TimeQuarter.fromHourOfDay(hourOfDay)
        var night = base.todNightCount; var morning = base.todMorningCount
        var afternoon = base.todAfternoonCount; var evening = base.todEveningCount
        when (q) {
            TimeQuarter.NIGHT     -> night     += 1
            TimeQuarter.MORNING   -> morning   += 1
            TimeQuarter.AFTERNOON -> afternoon += 1
            TimeQuarter.EVENING   -> evening   += 1
        }

        // ── Channel co-membership mask: sliding window, not lifetime accumulation ──
        // When the window has expired (current encounterCount is far enough past the epoch),
        // start a fresh window rather than continuing to OR into the old one. This prevents
        // the mask from becoming a permanent record of all channel co-membership over the
        // lifetime of the relationship.
        val nextEncounterCount = base.encounterCount + 1
        val windowAge = nextEncounterCount - base.channelsMaskEpochEncounterCount
        val (freshMask, freshEpoch) = if (windowAge > PeerModelEntity.CHANNEL_MASK_WINDOW_ENCOUNTERS) {
            // Window expired — open a new one seeded only with this encounter's channels.
            snap.channelsMask to nextEncounterCount
        } else {
            // Still within the current window — accumulate.
            (base.channelsMaskRecentWindow or snap.channelsMask) to base.channelsMaskEpochEncounterCount
        }

        return base.copy(
            deliveryWeight                  = newWeight,
            deliverySamples                 = newSamples,
            todNightCount                   = night,
            todMorningCount                 = morning,
            todAfternoonCount               = afternoon,
            todEveningCount                 = evening,
            encounterCount                  = nextEncounterCount,
            globalSeqLastSeen               = snap.globalSeqAtEnd,
            channelsMaskRecentWindow        = freshMask,
            channelsMaskEpochEncounterCount = freshEpoch
        )
        // snap.sessionStartMs is read (as hourOfDay) and then discarded with the snapshot.
    }
}

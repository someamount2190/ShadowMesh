package mesh.shadowmesh.storage

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Persistent, derived model of a peer's observed behaviour. The memory.
 *
 * DESIGN: this table stores ONLY abstractions, never raw events. No timestamp ever lands
 * here. Per-encounter raw data lives in [mesh.shadowmesh.peer.ActiveEncounterSession] in
 * RAM and is dropped when the encounter ends (see EncounterAbstractor). What survives a
 * restart is "this peer is a reliable morning relay seen regularly", not "8:23 AM Tuesday".
 *
 * Representation decisions (made explicit so the DAO doesn't decide them implicitly):
 *
 *  1. TIME-OF-DAY is stored as four INTEGER COUNTS, not four floats summing to 1.0.
 *     Floats drift under repeated nudge-and-renormalise and never stay == 1.0; integer
 *     counts are exact and the distribution is derived on read (count / total). The counts
 *     are a deliberately COARSE record — quarter-day buckets, not timestamps — which is the
 *     metadata-minimisation property. Be honest in the threat model: this is a quantised,
 *     aggregated time profile that an adversary seizing the DB CAN read (it reveals "morning
 *     contact"); it is not "the timestamp is gone", it is "the timestamp is coarsened to a
 *     6-hour bucket and summed". That is the actual guarantee.
 *
 *  2. DELIVERY WEIGHT is an EWMA in [0,1] PLUS [deliverySamples], the number of encounters
 *     that have contributed. A weight of 0.93 from one 15-fragment encounter and 0.93 from
 *     fifty encounters are NOT the same confidence; callers must consult [deliverySamples]
 *     before trusting the weight (e.g. require >= MIN_SAMPLES_FOR_RELAY). The EWMA means a
 *     single bad encounter cannot swing a long-trusted peer, and a lucky first encounter
 *     does not masquerade as a proven one.
 *
 *  3. FREQUENCY is derived on read from [encounterCount] and [globalSeqFirstSeen] /
 *     [globalSeqLastSeen] (monotonic mesh-wide sequence counters, NOT wall-clock). Storing
 *     the bucket as a column would freeze a derived value; storing the inputs lets the
 *     bucketing rule change without a migration.
 */
@Entity(tableName = "peer_models")
data class PeerModelEntity(
    @PrimaryKey val nodeId: String,            // 64 hex — the peer

    // ── Delivery reliability (EWMA + confidence) ──────────────────────────
    val deliveryWeight:      Double = 0.0,     // EWMA of per-encounter delivery success in [0,1]
    val deliverySamples:     Int    = 0,       // encounters contributing to deliveryWeight (confidence)

    // ── Time-of-day profile (integer counts, derived to a distribution on read) ──
    val todNightCount:       Long   = 0,       // encounters whose start fell in 00:00–05:59
    val todMorningCount:     Long   = 0,       //                                 06:00–11:59
    val todAfternoonCount:   Long   = 0,       //                                 12:00–17:59
    val todEveningCount:     Long   = 0,       //                                 18:00–23:59

    // ── Frequency inputs (mesh-global monotonic sequence, never wall-clock) ──
    val encounterCount:      Long   = 0,       // total completed encounters folded in
    val globalSeqFirstSeen:  Long   = 0,       // mesh sequence at first encounter
    val globalSeqLastSeen:   Long   = 0,       // mesh sequence at most recent encounter

    // ── Observed channels (sliding window bitset — NOT a lifetime accumulation) ──
    //
    // PRIVACY NOTE: a lifetime OR-accumulation of channel co-membership across all
    // encounters is a durable intersection-attack surface: an adversary seizing the DB
    // learns every channel slot this peer ever shared with us, regardless of how long ago.
    // Instead we maintain a window over the last CHANNEL_MASK_WINDOW_ENCOUNTERS encounters.
    // When the window expires (encounterCount has advanced far enough past the epoch),
    // the mask resets before folding in the new snapshot — so the DB reveals only recent
    // co-membership, not lifetime co-membership.
    //
    // [channelsMaskEpochEncounterCount] is the value of [encounterCount] at the time the
    // current window was opened. When (encounterCount − channelsMaskEpochEncounterCount)
    // exceeds CHANNEL_MASK_WINDOW_ENCOUNTERS, EncounterAbstractor resets the window.
    //
    // Default 0 for both: on the first fold into a new row the epoch is 0, encounterCount
    // becomes 1, so the gap is 1 < CHANNEL_MASK_WINDOW_ENCOUNTERS — window stays open.
    // For existing rows migrated from v10, encounterCount may already be > window size,
    // which means the window expires immediately on the next fold, clearing the old
    // cumulative mask. This is the correct migration behavior: don't carry the old
    // cumulative mask forward under the new windowed semantics.
    val channelsMaskRecentWindow:        Long = 0,
    val channelsMaskEpochEncounterCount: Long = 0,

    // ── Bookkeeping (coarse, for staleness eviction; NOT a raw timestamp record) ──
    val modelVersion:        Int    = 1
) {
    /** Total time-of-day observations (denominator for the derived distribution). */
    fun todTotal(): Long = todNightCount + todMorningCount + todAfternoonCount + todEveningCount

    /**
     * Derived time-of-day distribution as four fractions summing to ~1.0 (computed on read,
     * never stored). Returns a uniform prior when no observations exist.
     */
    fun timeOfDayDistribution(): DoubleArray {
        val t = todTotal()
        if (t == 0L) return doubleArrayOf(0.25, 0.25, 0.25, 0.25)
        return doubleArrayOf(
            todNightCount.toDouble()     / t,
            todMorningCount.toDouble()   / t,
            todAfternoonCount.toDouble() / t,
            todEveningCount.toDouble()   / t
        )
    }

    /** Frequency bucket derived from encounter density over the observed sequence window. */
    fun frequencyBucket(): EncounterFrequency {
        if (encounterCount <= 1) return EncounterFrequency.NEW
        val span = (globalSeqLastSeen - globalSeqFirstSeen).coerceAtLeast(1)
        // encounters per unit of mesh sequence — higher = more frequent
        val density = encounterCount.toDouble() / span
        return when {
            density >= 0.50 -> EncounterFrequency.FREQUENT
            density >= 0.10 -> EncounterFrequency.REGULAR
            else            -> EncounterFrequency.RARE
        }
    }

    /** A peer is trustworthy as a relay only with enough samples behind the weight. */
    fun isReliableRelay(): Boolean =
        deliverySamples >= MIN_SAMPLES_FOR_RELAY && deliveryWeight >= RELIABLE_WEIGHT_THRESHOLD

    companion object {
        const val MIN_SAMPLES_FOR_RELAY    = 3
        const val RELIABLE_WEIGHT_THRESHOLD = 0.80
        /** EWMA smoothing factor — higher reacts faster, lower is more stable. */
        const val DELIVERY_EWMA_ALPHA      = 0.30

        /**
         * Window size for the channel co-membership bitset, in encounters.
         * When encounterCount advances this many steps past [channelsMaskEpochEncounterCount],
         * the mask is reset before folding in new channel observations. This bounds the
         * intersection-attack surface to recent co-membership rather than lifetime history.
         *
         * 50 encounters: at one encounter per day, this is ~7 weeks. At one encounter per
         * hour of heavy use, this is ~2 days. Tune lower to shrink the window, higher to
         * keep more history for routing decisions.
         */
        const val CHANNEL_MASK_WINDOW_ENCOUNTERS = 50
    }
}

enum class EncounterFrequency { NEW, RARE, REGULAR, FREQUENT }

enum class TimeQuarter(val index: Int) {
    NIGHT(0), MORNING(1), AFTERNOON(2), EVENING(3);
    companion object {
        /** Map a millis-of-day (0..86_399_999) to a quarter. Wall-clock never persists. */
        fun fromHourOfDay(hour: Int): TimeQuarter = when (hour) {
            in 0..5   -> NIGHT
            in 6..11  -> MORNING
            in 12..17 -> AFTERNOON
            else      -> EVENING
        }
    }
}

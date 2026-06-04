package mesh.shadowmesh.mesh.health

import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicLong

/**
 * Mesh connectivity health states, ordered from best to worst.
 *
 * Transitions DOWN immediately on confirmed failure.
 * Transitions UP only on successful probe (attempted every 2 minutes).
 */
enum class MeshHealthState {
    FULL_MESH,       // Internet DHT reachable + at least one local transport
    LOCAL_MESH,      // LAN or WiFi Direct reachable, no internet DHT
    PROXIMITY_MESH,  // WiFi Direct reachable, no LAN, no internet DHT
    BLE_ONLY,        // Only BLE reachable
    ISOLATED         // No transports reachable — store-and-forward only
}

/** Which physical/logical transport layer a probe targets. */
enum class TransportType { BLE, WIFI_DIRECT, LAN, INTERNET_DHT }

/**
 * Per-transport health snapshot, updated after every probe.
 *
 * @param lastProbeMs         Wall-clock time of the most recent probe attempt (ms since epoch).
 * @param lastSuccessMs       Wall-clock time of the most recent successful probe.
 * @param consecutiveFailures Number of consecutive probe failures (resets to 0 on success).
 * @param averageLatencyMs    Exponential moving average of successful round-trip latencies (ms).
 * @param isHealthy           True iff the most recent probe succeeded within [PROBE_TIMEOUT_MS].
 */
data class TransportHealthEntry(
    val lastProbeMs:         Long    = 0L,
    val lastSuccessMs:       Long    = 0L,
    val consecutiveFailures: Int     = 0,
    val averageLatencyMs:    Long    = 0L,
    val isHealthy:           Boolean = false
)

/** One recorded state transition, kept in the last-20 transition history. */
data class HealthTransition(
    val fromState:   MeshHealthState,
    val toState:     MeshHealthState,
    val timestampMs: Long,
    val reason:      String
)

/**
 * Background coroutine service that probes each transport type periodically
 * and maintains the aggregate [MeshHealthState].
 *
 * Probe lambdas return the measured round-trip latency in ms on success,
 * or null on failure / timeout. The composition root provides real implementations;
 * null entries (missing probe for a type) are treated as permanently unhealthy.
 *
 * Lifecycle: call [start] when mesh engines are up, [stop] on service destroy.
 * All coroutines run on [scope]; cancellation is handled automatically.
 */
class TransportHealthMonitor(
    private val scope:  CoroutineScope,
    private val probes: Map<TransportType, suspend () -> Long?>
) {
    // ── Public state ──────────────────────────────────────────────────────────

    private val _currentState = MutableStateFlow(MeshHealthState.ISOLATED)
    val currentState: StateFlow<MeshHealthState> = _currentState.asStateFlow()

    private val _perTransportHealth = MutableStateFlow(
        TransportType.values().associateWith { TransportHealthEntry() }
    )
    val perTransportHealth: StateFlow<Map<TransportType, TransportHealthEntry>> =
        _perTransportHealth.asStateFlow()

    // Ring-buffer of last 20 state transitions
    private val _transitionHistory = ConcurrentLinkedDeque<HealthTransition>()
    val transitionHistory: List<HealthTransition> get() = _transitionHistory.toList()

    private val stateEnteredMs = AtomicLong(System.currentTimeMillis())
    val timeInCurrentStateMs: Long get() = System.currentTimeMillis() - stateEnteredMs.get()

    // ── Mutable internal state ────────────────────────────────────────────────
    //
    // ConcurrentHashMap (not toMutableMap/LinkedHashMap): onSendFailure() and
    // attemptUpgrade() both call scope.launch { probeSingle(...) }, which can run
    // concurrently with the periodic probeAll() loop. HashMap is not safe for
    // concurrent access — structural corruption is possible under concurrent puts
    // even for disjoint keys. ConcurrentHashMap makes individual reads and writes
    // thread-safe without requiring external locking around probeSingle.

    private val healthMap: ConcurrentHashMap<TransportType, TransportHealthEntry> =
        TransportType.values().associateWithTo(ConcurrentHashMap()) { TransportHealthEntry() }

    // EMA latency per transport: ema = alpha * sample + (1-alpha) * ema
    private val emaLatency: ConcurrentHashMap<TransportType, Long> =
        TransportType.values().associateWithTo(ConcurrentHashMap()) { 0L }

    private var probeJob:   Job? = null
    private var upgradeJob: Job? = null

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    fun start() {
        probeJob = scope.launch {
            while (isActive) {
                probeAll("periodic")
                delay(PROBE_INTERVAL_MS)
            }
        }
        upgradeJob = scope.launch {
            delay(UPGRADE_ATTEMPT_MS)   // wait before first upgrade attempt
            while (isActive) {
                attemptUpgrade()
                delay(UPGRADE_ATTEMPT_MS)
            }
        }
    }

    fun stop() {
        probeJob?.cancel()
        upgradeJob?.cancel()
    }

    // ── Event hooks ───────────────────────────────────────────────────────────

    /** Called by the transport layer on a confirmed send failure. */
    fun onSendFailure(type: TransportType) {
        scope.launch {
            probeSingle(type, "send-failure")
            recomputeState("send-failure:$type")
        }
    }

    // ── Debug API (debug builds only) ─────────────────────────────────────────

    /** Manually trigger a probe for one transport (exposed to Debug Console). */
    suspend fun probeNow(type: TransportType) {
        probeSingle(type, "manual")
        recomputeState("manual-probe:$type")
    }

    /** Force a specific state for testing. Recorded in history as "forced-override". */
    fun forceState(state: MeshHealthState) {
        transitionTo(state, "forced-override")
    }

    // ── Internal probe logic ──────────────────────────────────────────────────

    private suspend fun probeAll(reason: String) {
        TransportType.values().forEach { probeSingle(it, reason) }
        recomputeState(reason)
    }

    private suspend fun probeSingle(type: TransportType, reason: String) {
        val probe = probes[type]
        val now   = System.currentTimeMillis()
        val latency: Long? = if (probe == null) null else {
            try {
                withTimeout(PROBE_TIMEOUT_MS) { probe() }
            } catch (_: TimeoutCancellationException) {
                null
            } catch (_: Exception) {
                null
            }
        }

        val old     = healthMap[type] ?: TransportHealthEntry()
        val healthy = latency != null

        val newEma: Long = if (latency != null) {
            val prev = emaLatency[type] ?: 0L
            if (prev == 0L) latency
            else (EMA_ALPHA_NUM * latency + (EMA_ALPHA_DEN - EMA_ALPHA_NUM) * prev) / EMA_ALPHA_DEN
        } else {
            emaLatency[type] ?: 0L
        }
        if (latency != null) emaLatency[type] = newEma

        healthMap[type] = TransportHealthEntry(
            lastProbeMs         = now,
            lastSuccessMs       = if (healthy) now else old.lastSuccessMs,
            consecutiveFailures = if (healthy) 0 else old.consecutiveFailures + 1,
            averageLatencyMs    = newEma,
            isHealthy           = healthy
        )
        _perTransportHealth.value = healthMap.toMap()
    }

    private fun recomputeState(reason: String) {
        val dht  = healthMap[TransportType.INTERNET_DHT]?.isHealthy == true
        val lan  = healthMap[TransportType.LAN]?.isHealthy == true
        val wifi = healthMap[TransportType.WIFI_DIRECT]?.isHealthy == true
        val ble  = healthMap[TransportType.BLE]?.isHealthy == true

        val new = when {
            dht                     -> MeshHealthState.FULL_MESH
            lan                     -> MeshHealthState.LOCAL_MESH
            wifi                    -> MeshHealthState.PROXIMITY_MESH
            ble                     -> MeshHealthState.BLE_ONLY
            else                    -> MeshHealthState.ISOLATED
        }
        if (new != _currentState.value) transitionTo(new, reason)
    }

    private fun attemptUpgrade() {
        // Try the next transport up from our current degraded state.
        val target: TransportType = when (_currentState.value) {
            MeshHealthState.ISOLATED       -> TransportType.BLE
            MeshHealthState.BLE_ONLY       -> TransportType.WIFI_DIRECT
            MeshHealthState.PROXIMITY_MESH -> TransportType.LAN
            MeshHealthState.LOCAL_MESH     -> TransportType.INTERNET_DHT
            MeshHealthState.FULL_MESH      -> return
        }
        scope.launch {
            probeSingle(target, "upgrade-attempt")
            recomputeState("upgrade-attempt")
        }
    }

    private fun transitionTo(newState: MeshHealthState, reason: String) {
        val old = _currentState.value
        if (old == newState) return
        _currentState.value = newState
        stateEnteredMs.set(System.currentTimeMillis())
        _transitionHistory.addFirst(HealthTransition(old, newState, System.currentTimeMillis(), reason))
        while (_transitionHistory.size > MAX_HISTORY) _transitionHistory.pollLast()
    }

    companion object {
        const val PROBE_INTERVAL_MS   = 30_000L   // 30 s between periodic probes
        const val PROBE_TIMEOUT_MS    = 3_000L    // 3 s probe round-trip timeout
        const val UPGRADE_ATTEMPT_MS  = 120_000L  // 2 min between upgrade attempts
        private const val MAX_HISTORY = 20

        // EMA smoothing: alpha = 1/4  (num=1, den=4)
        private const val EMA_ALPHA_NUM = 1L
        private const val EMA_ALPHA_DEN = 4L
    }
}

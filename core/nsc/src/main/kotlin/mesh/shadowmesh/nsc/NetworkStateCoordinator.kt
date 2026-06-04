// TODO: [BLE Redesign] setActiveMeshMode() + onActiveMeshModeChanged added.
// ASSUMPTION: NSC does not import BleScanMode (core:mesh) to avoid a build-graph cycle.
// AppModule wires onActiveMeshModeChanged to call bleGattTransport?.setMeshScanMode().
// ASSUMPTION: No NSC saga log checkpoint is needed for mesh-mode changes — it is a
// best-effort preference toggle, not a data-integrity transition.

package mesh.shadowmesh.nsc

import android.content.Context
import android.util.Log
import androidx.room.*
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.PriorityBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.Executors
import mesh.shadowmesh.diagnostics.Diag

// ── File-level constants ───────────────────────────────────────────────────────

private const val SYNC_CYCLE_MS = 15_000L

// ── Enumerations ──────────────────────────────────────────────────────────────

enum class LockType(val ordinal_: Int) {
    NODE_TIER(0), DHT_SLICE(1), FRAGMENT_DELIVERY(2),
    NETWORK_MODE(3), BEACON_MODE(4), PEER_SELECTION(5)
}

enum class Priority(val level: Int, val maxHoldMs: Long) {
    P1_DATA_INTEGRITY(1, 60_000),
    P2_DELIVERY(2, 30_000),
    P3_TOPOLOGY(3, 4 * SYNC_CYCLE_MS),
    P4_CONFIGURATION(4, 0)
}

enum class TransitionScope { LOCAL, GLOBAL }

enum class TransitionStatus {
    QUEUED, IN_PROGRESS, COMMITTED, ROLLED_BACK, TIMED_OUT, DEAD_LETTERED,
    // UNRECOVERABLE: rollback lambda threw during a Failure path. The NSC cannot
    // guarantee consistent state. The drain loop halts and all queued transitions
    // are dead-lettered. Callers must detect this via queryTransitionStatus and
    // re-issue through a fresh NSC instance after recovery.
    UNRECOVERABLE
}

// ── FIX (Issue 3) — Typed Rollback Opcodes ────────────────────────────────────
// Replaces the "LAMBDA" string placeholder. Each opcode carries the data
// needed to replay a rollback after process death without lambda closures.

sealed class RollbackOpcode {
    data class ReclaimDhtSlice(val fromNodeId: String, val toNodeId: String) : RollbackOpcode()
    data class RevertTierPromotion(val nodeId: String, val previousTier: Int) : RollbackOpcode()
    data class CancelFragmentDelivery(val fragmentId: String) : RollbackOpcode()
    data class RestoreNetworkMode(val previousMode: String) : RollbackOpcode()
    data class RestoreBeaconMode(val wasEnabled: Boolean) : RollbackOpcode()
    data class RestorePeerSelection(val previousMode: String) : RollbackOpcode()
    object NoOp : RollbackOpcode()

    fun encode(): Pair<String, String> = when (this) {
        is ReclaimDhtSlice        -> "RECLAIM_DHT_SLICE"      to "$fromNodeId|$toNodeId"
        is RevertTierPromotion    -> "REVERT_TIER_PROMOTION"  to "$nodeId|$previousTier"
        is CancelFragmentDelivery -> "CANCEL_FRAGMENT"        to fragmentId
        is RestoreNetworkMode     -> "RESTORE_NETWORK_MODE"   to previousMode
        is RestoreBeaconMode      -> "RESTORE_BEACON_MODE"    to wasEnabled.toString()
        is RestorePeerSelection   -> "RESTORE_PEER_SELECTION" to previousMode
        NoOp                      -> "NOOP"                   to ""
    }

    companion object {
        /** Attempts per rollback lambda before escalating to UNRECOVERABLE. */
        const val ROLLBACK_MAX_ATTEMPTS    = 3
        /** Exponential backoff base (ms): attempt 1=50ms, 2=100ms, 3=200ms. */
        const val ROLLBACK_BACKOFF_BASE_MS = 50L
        fun decode(opcode: String, args: String): RollbackOpcode = when (opcode) {
            "RECLAIM_DHT_SLICE"     -> args.split("|").let { ReclaimDhtSlice(it[0], it[1]) }
            "REVERT_TIER_PROMOTION" -> args.split("|").let { RevertTierPromotion(it[0], it[1].toInt()) }
            "CANCEL_FRAGMENT"       -> CancelFragmentDelivery(args)
            "RESTORE_NETWORK_MODE"  -> RestoreNetworkMode(args)
            "RESTORE_BEACON_MODE"   -> RestoreBeaconMode(args.toBoolean())
            "RESTORE_PEER_SELECTION"-> RestorePeerSelection(args)
            else                    -> NoOp
        }
    }
}

// ── Transition model ──────────────────────────────────────────────────────────

data class LockKey(val type: LockType, val entityId: String)

data class Checkpoint(
    val description: String,
    val opcode:      RollbackOpcode,           // persisted for process-death replay
    val rollback:    suspend () -> Unit         // in-process fast path
)

data class StateTransition(
    val id:           String,
    val description:  String,
    val priority:     Priority,
    val scope:        TransitionScope,
    val requiredLocks:List<LockKey>,
    val deadlineMs:   Long,
    val execute:      suspend (log: (Checkpoint) -> Unit) -> TransitionResult
) : Comparable<StateTransition> {
    override fun compareTo(other: StateTransition) =
        compareValuesBy(this, other, { it.priority.level }, { it.deadlineMs })
}

sealed class TransitionResult {
    object Success : TransitionResult()
    data class Failure(val reason: String, val shouldRetry: Boolean = false) : TransitionResult()
    data class Deferred(val waitForConsensusToken: String) : TransitionResult()
}

// ── Room persistence ──────────────────────────────────────────────────────────

@Entity(tableName = "nsc_transitions")
data class PersistedTransition(
    @PrimaryKey val id: String,
    val description: String, val priorityLevel: Int, val scopeName: String,
    val requiredLockJson: String, val deadlineMs: Long, val status: String,
    val createdAtMs: Long, val startedAtMs: Long?,
    val completedAtMs: Long?, val failureReason: String?
)

@Entity(tableName = "nsc_checkpoints")
data class PersistedCheckpoint(
    @PrimaryKey(autoGenerate = true) val rowId: Long = 0,
    val transitionId: String, val sequence: Int, val description: String,
    val rollbackOpcode: String, val rollbackArgs: String
)

@Dao
interface NscDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsertTransition(t: PersistedTransition)

    @Query("UPDATE nsc_transitions SET status=:status,completedAtMs=:now,failureReason=:reason WHERE id=:id")
    suspend fun finaliseTransition(id: String, status: String, now: Long, reason: String?)

    @Query("SELECT * FROM nsc_transitions WHERE status IN ('QUEUED','IN_PROGRESS') ORDER BY priorityLevel ASC, deadlineMs ASC")
    suspend fun loadIncompleteTransitions(): List<PersistedTransition>

    @Query("SELECT * FROM nsc_transitions WHERE id=:id")
    suspend fun loadTransition(id: String): PersistedTransition?

    @Query("SELECT * FROM nsc_checkpoints WHERE transitionId=:tid ORDER BY sequence ASC")
    suspend fun loadCheckpoints(tid: String): List<PersistedCheckpoint>

    @Insert
    suspend fun insertCheckpoint(c: PersistedCheckpoint)

    @Query("DELETE FROM nsc_checkpoints WHERE transitionId=:tid")
    suspend fun deleteCheckpoints(tid: String)

    @Query("DELETE FROM nsc_transitions WHERE status IN ('COMMITTED','ROLLED_BACK','DEAD_LETTERED','UNRECOVERABLE') AND completedAtMs<:cutoffMs")
    suspend fun pruneOldTransitions(cutoffMs: Long)
}

// ── Room migrations ───────────────────────────────────────────────────────────
//
// v1 → v2: adds UNRECOVERABLE as a valid status string (no schema change needed —
// status is stored as TEXT and Room does not enforce enum membership at the DB
// layer). The migration exists to satisfy the "no destructive fallback" requirement
// and to document the intent. If you later add a column (e.g. unrecoverableReason),
// add it in MIGRATION_2_3.

val MIGRATION_1_2 = object : Migration(1, 2) {
    override fun migrate(db: SupportSQLiteDatabase) {
        // No structural change — UNRECOVERABLE is a new TEXT value for the
        // existing `status` column. The migration is a no-op at the SQL level
        // but must exist so Room does not fall back to destructive migration.
    }
}

@Database(entities = [PersistedTransition::class, PersistedCheckpoint::class], version = 2)
abstract class NscDatabase : RoomDatabase() {
    abstract fun dao(): NscDao
    companion object {
        @Volatile private var INSTANCE: NscDatabase? = null
        fun get(ctx: Context): NscDatabase = INSTANCE ?: synchronized(this) {
            INSTANCE ?: Room.databaseBuilder(ctx, NscDatabase::class.java, "shadowmesh_nsc.db")
                .addMigrations(MIGRATION_1_2)
                .build().also { INSTANCE = it }
        }
    }
}

// ── Rollback registry ─────────────────────────────────────────────────────────

object RollbackRegistry {
    private val handlers = ConcurrentHashMap<String, suspend (String) -> Unit>()

    fun register(opcode: String, handler: suspend (String) -> Unit) { handlers[opcode] = handler }

    /**
     * Execute the persisted rollback for [opcode] with [args].
     *
     * NOOP opcodes are silently skipped.  All other opcodes MUST have a handler
     * registered via [register] before [NetworkStateCoordinator.initialise] is called —
     * if no handler is found, this throws [IllegalStateException] so the caller
     * (replayRollback → initialise) treats the replay as failed and the NSC remains
     * halted rather than silently skipping the rollback and leaving the DHT/tier state
     * inconsistent.
     *
     * @throws IllegalStateException if [opcode] is not NOOP and has no registered handler.
     */
    suspend fun execute(opcode: String, args: String) {
        if (opcode == "NOOP") return
        val handler = handlers[opcode]
            ?: throw IllegalStateException(
                "RollbackRegistry: no handler registered for opcode '$opcode'. " +
                "All RollbackOpcode variants must be registered in " +
                "ShadowMeshApplication.registerNscRollbackHandlers() before " +
                "NetworkStateCoordinator.initialise() is called. " +
                "NSC will remain halted until this is resolved."
            )
        handler(args)
    }
}

// ── Consensus gate ────────────────────────────────────────────────────────────

class ConsensusGate {
    private val pending = ConcurrentHashMap<String, CompletableDeferred<Boolean>>()

    suspend fun awaitConsensus(token: String, timeoutMs: Long): Boolean {
        val d = CompletableDeferred<Boolean>()
        pending[token] = d
        return try { withTimeout(timeoutMs) { d.await() } }
        catch (e: TimeoutCancellationException) { false }
        finally { pending.remove(token) }
    }

    fun resolve(token: String, agreed: Boolean) { pending[token]?.complete(agreed) }
}

// ── Active lock ───────────────────────────────────────────────────────────────

data class ActiveLock(
    val key: LockKey, val transitionId: String,
    val acquiredAtMs: Long, val maxHoldMs: Long, val watchdogJob: Job
)

// ── Network State Coordinator ─────────────────────────────────────────────────
// FIX (Issue 2): drainMutex removed. The single-threaded dispatcher already
// guarantees sequential transition execution — the mutex was redundant.
//
// Phase 2 addition: UNRECOVERABLE escalation. When a rollback lambda itself
// throws, the NSC cannot guarantee consistent state. It escalates the
// transition to UNRECOVERABLE, stops the drain loop, and dead-letters all
// remaining queued transitions. The halt flag is exposed so callers can detect
// it via isHalted and take recovery action (restart the process, alert the user,
// etc.). This matches the roadmap requirement: "UNRECOVERABLE flag fires on
// rollback failure. Queue drains after UNRECOVERABLE."

/** Minimal interface so callers (and tests) can avoid the full Android-context constructor. */
interface NscLike {
    fun requestTransition(transition: StateTransition): kotlinx.coroutines.Deferred<TransitionResult>
}

class NetworkStateCoordinator(
    private val context: Context,
    private val scope:   CoroutineScope,
    val consensusGate:   ConsensusGate = ConsensusGate()
) : NscLike {
    private val TAG = "NSC"
    private val db  = NscDatabase.get(context)
    private val dao = db.dao()
    private val queue       = PriorityBlockingQueue<StateTransition>()
    private val activeLocks = ConcurrentHashMap<LockKey, ActiveLock>()

    // Pending caller deferreds keyed by transition ID.
    //
    // Bug this fixes: requestTransition() wraps the original `execute` lambda to call
    // `result.complete(r)` when the transition is executed. But startDeadLetterReaper()
    // and drainQueueAfterUnrecoverable() remove transitions from the queue WITHOUT calling
    // `execute`, so `result` is never completed and the caller's `.await()` hangs forever.
    //
    // Fix: store every pending deferred in this map. Dead-letter paths look up and
    // complete the deferred with Failure before removing the transition.
    private val pendingDeferreds = ConcurrentHashMap<String, CompletableDeferred<TransitionResult>>()

    // Single-threaded: guarantees sequential execution without additional locking.
    // The executor is stored so [close] can shut it down and release the thread.
    private val dispatcherExecutor = Executors.newSingleThreadExecutor()
    private val dispatcher = dispatcherExecutor.asCoroutineDispatcher()

    // StateFlow-backed halt state — callers subscribe reactively rather than polling.
    private val _haltedFlow = MutableStateFlow(false)

    /**
     * Emits true when the NSC enters UNRECOVERABLE state.
     * Collect in a ViewModel or notification handler to surface the halt to the user
     * and trigger process restart.
     */
    val haltedFlow: StateFlow<Boolean> = _haltedFlow.asStateFlow()

    /** Synchronous read of the halt state — mirrors haltedFlow.value. */
    val isHalted: Boolean get() = _haltedFlow.value

    /**
     * Initialise the NSC after process start or restart.
     *
     * Replays IN_PROGRESS rollbacks from the saga log BEFORE clearing isHalted.
     * Previous behaviour unconditionally set isHalted=false first, meaning a restart
     * after an UNRECOVERABLE event would clear the halt flag even if the half-rolled-back
     * state was never repaired. Now: replay first, clear halt only on success.
     */
    suspend fun initialise() {
        var replayFailed = false
        dao.loadIncompleteTransitions().forEach { p ->
            when (TransitionStatus.valueOf(p.status)) {
                TransitionStatus.IN_PROGRESS -> {
                    runCatching { replayRollback(p.id) }
                        .onSuccess {
                            dao.finaliseTransition(p.id, TransitionStatus.ROLLED_BACK.name,
                                System.currentTimeMillis(), "Process death during execution")
                        }
                        .onFailure { ex ->
                            Log.e(TAG, "INIT: replay rollback failed for ${p.id}: ${ex.message}")
                            replayFailed = true
                            // Mark the broken transition UNRECOVERABLE so it is never retried
                            // on the next restart.  Without this, a broken rollback handler
                            // (e.g., a missing opcode registration or a permanently unavailable
                            // engine API) would cause every subsequent initialise() to attempt
                            // the same rollback, fail, and leave NSC halted forever.
                            runCatching {
                                dao.finaliseTransition(
                                    p.id, TransitionStatus.UNRECOVERABLE.name,
                                    System.currentTimeMillis(),
                                    "Rollback replay failed at startup: ${ex.message}"
                                )
                            }
                        }
                }
                TransitionStatus.QUEUED ->
                    dao.finaliseTransition(p.id, TransitionStatus.DEAD_LETTERED.name,
                        System.currentTimeMillis(), "Process death while queued — re-issue required")
                else -> {}
            }
        }
        // Only clear halt if all replays succeeded — stay halted if any failed.
        if (!replayFailed) {
            _haltedFlow.value = false
        } else {
            Log.e(TAG, "INIT: one or more rollback replays failed — NSC remains halted")
        }
        dao.pruneOldTransitions(System.currentTimeMillis() - TimeUnit.DAYS.toMillis(7))
        startDrainLoop()
        startDeadLetterReaper()
    }

    /**
     * Shut down the NSC cleanly.
     *
     * Closes the coroutine dispatcher and shuts down the backing executor, releasing
     * the single background thread. Call from [Application.onTerminate] or the
     * foreground service [onDestroy]. The NSC is not usable after this call.
     *
     * Without this, the thread created by [Executors.newSingleThreadExecutor] persists
     * for the process lifetime but is never formally shut down, which is a minor thread
     * leak visible in profilers.
     */
    fun close() {
        dispatcher.close()
        dispatcherExecutor.shutdown()
    }

    override fun requestTransition(transition: StateTransition): Deferred<TransitionResult> {
        val result = CompletableDeferred<TransitionResult>()
        scope.launch {
            if (isHalted) {
                result.complete(TransitionResult.Failure("NSC is halted (UNRECOVERABLE state)"))
                return@launch
            }
            if (System.currentTimeMillis() >= transition.deadlineMs) {
                result.complete(TransitionResult.Failure("Deadline already passed"))
                return@launch
            }
            persistTransition(transition, TransitionStatus.QUEUED)
            // Register the deferred so dead-letter paths (reaper, drainQueueAfterUnrecoverable)
            // can complete it with Failure instead of letting the caller hang forever.
            pendingDeferreds[transition.id] = result
            queue.add(transition.copy(execute = { log ->
                val r = transition.execute(log)
                pendingDeferreds.remove(transition.id)
                result.complete(r)
                r
            }))
        }
        return result
    }

    /** Query the persisted status of any transition by ID. */
    suspend fun queryTransitionStatus(id: String): TransitionStatus? =
        dao.loadTransition(id)?.let { TransitionStatus.valueOf(it.status) }

    private fun completePendingDeferred(transitionId: String, reason: String) {
        pendingDeferreds.remove(transitionId)?.complete(
            TransitionResult.Failure("Dead-lettered: $reason")
        )
    }

    private fun startDrainLoop() {
        scope.launch(dispatcher) {
            while (isActive && !isHalted) {
                val t = queue.peek() ?: run { delay(100); return@run null } ?: continue
                if (System.currentTimeMillis() >= t.deadlineMs) {
                    queue.remove(t)
                    completePendingDeferred(t.id, "deadline expired while queued")
                    dao.finaliseTransition(t.id, TransitionStatus.DEAD_LETTERED.name,
                        System.currentTimeMillis(), "Deadline expired while queued")
                    continue
                }
                if (!tryAcquireAllLocks(t)) { delay(50); continue }
                queue.remove(t)
                executeTransition(t)
                // Check halt flag after each transition — set inside executeTransition
                // if a rollback threw.
            }
        }
    }

    private fun tryAcquireAllLocks(t: StateTransition): Boolean {
        val ordered  = t.requiredLocks.sortedWith(compareBy({ it.type.ordinal_ }, { it.entityId }))
        val acquired = mutableListOf<LockKey>()
        for (key in ordered) {
            val lock = ActiveLock(key, t.id, System.currentTimeMillis(),
                t.priority.maxHoldMs, scheduleWatchdog(t, key))
            if (activeLocks.putIfAbsent(key, lock) != null) {
                lock.watchdogJob.cancel()
                acquired.forEach { releaseLock(it) }
                return false
            }
            acquired.add(key)
        }
        return true
    }

    private fun scheduleWatchdog(t: StateTransition, key: LockKey): Job =
        // B16 fix: launch on dispatcher, not scope.
        // scope.launch runs on the shared coroutine scope — if a watchdog fires
        // concurrently with the drain loop executing a transition, both can access
        // activeLocks and call dao.finaliseTransition concurrently, bypassing the
        // single-threaded dispatcher guarantee. Launching on dispatcher ensures the
        // watchdog is serialised with the drain loop.
        scope.launch(dispatcher) {
            if (t.priority.maxHoldMs <= 0L) return@launch
            delay(t.priority.maxHoldMs)
            val lock = activeLocks[key] ?: return@launch
            if (lock.transitionId != t.id) return@launch
            Log.e(TAG, "WATCHDOG fired on ${t.id} — rolling back")
            // A persisted rollback handler may throw (e.g. an opcode whose engine API does
            // not exist yet). Mirror the executeTransition Failure→UNRECOVERABLE path: on a
            // thrown replay we cannot guarantee consistent state, so escalate and halt rather
            // than leaking the lock and finalising a false ROLLED_BACK over un-reverted state.
            runCatching { replayRollback(t.id) }
                .onSuccess {
                    releaseLock(key)
                    dao.finaliseTransition(t.id, TransitionStatus.ROLLED_BACK.name,
                        System.currentTimeMillis(), "Watchdog timeout ${t.priority.maxHoldMs}ms")
                }
                .onFailure { ex ->
                    Log.e(TAG, "WATCHDOG: replay rollback failed for ${t.id}: ${ex.message} " +
                        "— escalating to UNRECOVERABLE")
                    releaseLock(key)
                    dao.finaliseTransition(t.id, TransitionStatus.UNRECOVERABLE.name,
                        System.currentTimeMillis(),
                        "Watchdog rollback failed (${t.priority.maxHoldMs}ms timeout): ${ex.message}")
                    _haltedFlow.value = true
                    drainQueueAfterUnrecoverable()
                }
        }

    private fun releaseLock(key: LockKey) { activeLocks.remove(key)?.watchdogJob?.cancel() }
    private fun releaseAllLocks(t: StateTransition) { t.requiredLocks.forEach { releaseLock(it) } }

    private suspend fun executeTransition(t: StateTransition) {
        if (t.scope == TransitionScope.GLOBAL) {
            val agreed = consensusGate.awaitConsensus("consensus_${t.id}",
                minOf(t.deadlineMs - System.currentTimeMillis(), t.priority.maxHoldMs))
            if (!agreed) {
                releaseAllLocks(t)
                dao.finaliseTransition(t.id, TransitionStatus.ROLLED_BACK.name,
                    System.currentTimeMillis(), "Global consensus not reached")
                return
            }
        }
        dao.upsertTransition(toPersistedTransition(t, TransitionStatus.IN_PROGRESS))

        val checkpoints = mutableListOf<Checkpoint>()
        // AtomicInteger: seq++ is called from the logger lambda which scope.launch dispatches
        // concurrently — a plain Int would produce data races and duplicate sequence numbers,
        // corrupting the rollback replay order on crash recovery.
        val seq = java.util.concurrent.atomic.AtomicInteger(0)
        val logger: (Checkpoint) -> Unit = { cp ->
            checkpoints.add(cp)
            val (opcode, args) = cp.opcode.encode()
            val seqNo = seq.getAndIncrement()
            // Dispatch on dispatcher (not the default scope) so checkpoint inserts are
            // serialized with the drain loop. Without this, a process crash between
            // execute() returning and the fire-and-forget inserts completing would leave
            // incomplete checkpoint rows — replayRollback on restart would miss rollback
            // steps and leave the saga log in an inconsistent state.
            scope.launch(dispatcher) { dao.insertCheckpoint(PersistedCheckpoint(
                transitionId = t.id, sequence = seqNo,
                description = cp.description, rollbackOpcode = opcode, rollbackArgs = args)) }
        }

        val result = try { t.execute(logger) }
        catch (e: Exception) {
            if (e is kotlinx.coroutines.CancellationException) throw e
            Diag.swallowed("nsc", "transition-execute", e, "id" to t.id, "desc" to t.description)
            TransitionResult.Failure("Exception: ${e.message}")
        }

        when (result) {
            is TransitionResult.Success -> {
                dao.deleteCheckpoints(t.id)
                dao.finaliseTransition(t.id, TransitionStatus.COMMITTED.name,
                    System.currentTimeMillis(), null)
            }
            is TransitionResult.Failure -> {
                // Execute rollback lambdas in reverse checkpoint order.
                // If any rollback lambda itself throws, the NSC has lost the ability
                // to guarantee consistent state — escalate to UNRECOVERABLE.
                // Bounded-retry rollback: retry each compensation up to ROLLBACK_MAX_ATTEMPTS
                // times with exponential backoff before escalating to UNRECOVERABLE.
                // Rollback lambdas must be idempotent — retrying a completed compensation
                // is a safe no-op. Only persistent failures exhaust all retries.
                var rollbackFailed = false
                checkpoints.reversed().forEach { cp ->
                    var succeeded = false
                    var lastEx: Throwable? = null
                    for (attempt in 0 until RollbackOpcode.ROLLBACK_MAX_ATTEMPTS) {
                        if (succeeded) break
                        runCatching { cp.rollback() }
                            .onSuccess { succeeded = true }
                            .onFailure { ex ->
                                lastEx = ex
                                Log.w(TAG, "ROLLBACK attempt ${attempt + 1}/${RollbackOpcode.ROLLBACK_MAX_ATTEMPTS} " +
                                    "threw on '${cp.description}': ${ex.message}")
                                if (attempt < RollbackOpcode.ROLLBACK_MAX_ATTEMPTS - 1) {
                                    val backoffMs = RollbackOpcode.ROLLBACK_BACKOFF_BASE_MS shl attempt
                                    // B15 fix: delay() directly — this is already a suspend fun
                                    // running on the single-threaded dispatcher. runBlocking{}
                                    // would block the dispatcher thread, freezing the watchdog,
                                    // drain loop, and all other dispatcher work for backoffMs.
                                    delay(backoffMs)
                                }
                            }
                    }
                    if (!succeeded) {
                        Log.e(TAG, "ROLLBACK EXHAUSTED (${RollbackOpcode.ROLLBACK_MAX_ATTEMPTS} attempts) " +
                            "on '${cp.description}': ${lastEx?.message}")
                        rollbackFailed = true
                    }
                }
                dao.deleteCheckpoints(t.id)

                if (rollbackFailed) {
                    val reason = "Rollback exhausted ${RollbackOpcode.ROLLBACK_MAX_ATTEMPTS} attempts. " +
                        "Reason: ${result.reason}"
                    Log.e(TAG, "UNRECOVERABLE: $reason (transition ${t.id})")
                    dao.finaliseTransition(t.id, TransitionStatus.UNRECOVERABLE.name,
                        System.currentTimeMillis(), reason)
                    _haltedFlow.value = true
                    drainQueueAfterUnrecoverable()
                } else {
                    dao.finaliseTransition(t.id, TransitionStatus.ROLLED_BACK.name,
                        System.currentTimeMillis(), result.reason)
                }
            }
            is TransitionResult.Deferred -> { /* watchdog enforces timeout */ }
        }
        if (result !is TransitionResult.Deferred) releaseAllLocks(t)
    }

    // Dead-letters all queued transitions after an UNRECOVERABLE event.
    // Called on the single-threaded dispatcher (inside executeTransition),
    // so no concurrent drain can race against this drain.
    private suspend fun drainQueueAfterUnrecoverable() {
        val now = System.currentTimeMillis()
        val drained = mutableListOf<StateTransition>()
        queue.drainTo(drained)
        Log.e(TAG, "UNRECOVERABLE drain: dead-lettering ${drained.size} queued transition(s)")
        drained.forEach { t ->
            // Complete the caller's deferred so it doesn't hang indefinitely.
            completePendingDeferred(t.id, "NSC entered UNRECOVERABLE state")
            dao.finaliseTransition(t.id, TransitionStatus.DEAD_LETTERED.name,
                now, "Dead-lettered after UNRECOVERABLE transition")
        }
    }

    private suspend fun replayRollback(transitionId: String) {
        dao.loadCheckpoints(transitionId).sortedByDescending { it.sequence }.forEach { cp ->
            RollbackRegistry.execute(cp.rollbackOpcode, cp.rollbackArgs)
        }
        dao.deleteCheckpoints(transitionId)
    }

    private fun startDeadLetterReaper() {
        scope.launch {
            while (isActive && !isHalted) {
                delay(REAPER_INTERVAL_MS)
                val now = System.currentTimeMillis()
                queue.filter { it.deadlineMs <= now }.forEach { t ->
                    queue.remove(t)
                    // Complete the caller's deferred before finalising the DB row.
                    completePendingDeferred(t.id, "deadline expired while queued (reaped)")
                    dao.finaliseTransition(t.id, TransitionStatus.DEAD_LETTERED.name,
                        now, "Reaped by periodic deadline scan")
                }
            }
        }
    }

    private suspend fun persistTransition(t: StateTransition, s: TransitionStatus) =
        dao.upsertTransition(toPersistedTransition(t, s))

    private fun toPersistedTransition(t: StateTransition, s: TransitionStatus) = PersistedTransition(
        id = t.id, description = t.description, priorityLevel = t.priority.level,
        scopeName = t.scope.name,
        requiredLockJson = t.requiredLocks.joinToString(",") { "${it.type.name}:${it.entityId}" },
        deadlineMs = t.deadlineMs, status = s.name,
        createdAtMs = System.currentTimeMillis(),
        startedAtMs = if (s == TransitionStatus.IN_PROGRESS) System.currentTimeMillis() else null,
        completedAtMs = null, failureReason = null
    )

    // ── Active Mesh Mode (scan aggressiveness) ────────────────────────────

    /**
     * Invoked by [setActiveMeshMode] whenever the user's "Active Mesh Mode" preference
     * changes. Wire this in AppModule to call `bleGattTransport?.setMeshScanMode(...)`.
     * The callback receives `true` when ACTIVE mode is requested, `false` for BALANCED.
     *
     * Kept as a nullable lambda (not a direct BleScanMode reference) so `core:nsc` does
     * not take a dependency on `core:mesh`.
     */
    var onActiveMeshModeChanged: ((Boolean) -> Unit)? = null

    /**
     * Propagates the user's "Active Mesh Mode" preference to the mesh BLE transport.
     * Called from AppModule / UI layer when the settings toggle changes.
     * The charging-state override in [ShadowMeshForegroundService] also calls this.
     */
    fun setActiveMeshMode(active: Boolean) {
        onActiveMeshModeChanged?.invoke(active)
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    companion object {
        private const val REAPER_INTERVAL_MS = 5_000L
    }
}

// ── Anchor handoff example ────────────────────────────────────────────────────

fun buildAnchorHandoffTransition(
    sourceNodeId: String, targetNodeId: String,
    dhtSliceTransferFn: suspend () -> Boolean,
    merkleVerifyFn: suspend () -> Boolean,
    dhtUpdateFn: suspend () -> Unit,
    revertDhtFn: suspend () -> Unit
): StateTransition = StateTransition(
    id = "anchor_handoff_${sourceNodeId}_to_${targetNodeId}_${System.currentTimeMillis()}",
    description = "Anchor DHT handoff: $sourceNodeId → $targetNodeId",
    priority = Priority.P1_DATA_INTEGRITY, scope = TransitionScope.GLOBAL,
    requiredLocks = listOf(
        LockKey(LockType.NODE_TIER, sourceNodeId),
        LockKey(LockType.NODE_TIER, targetNodeId),
        LockKey(LockType.DHT_SLICE, sourceNodeId)),
    deadlineMs = System.currentTimeMillis() + 55_000L,
    execute = { log ->
        if (!dhtSliceTransferFn())
            return@StateTransition TransitionResult.Failure("DHT slice transfer failed")
        log(Checkpoint("DHT slice transferred",
            RollbackOpcode.ReclaimDhtSlice(targetNodeId, sourceNodeId)) { revertDhtFn() })

        if (!merkleVerifyFn())
            return@StateTransition TransitionResult.Failure("Merkle verification failed", shouldRetry = true)
        log(Checkpoint("Merkle verified", RollbackOpcode.NoOp) {})

        dhtUpdateFn()
        log(Checkpoint("DHT updated",
            RollbackOpcode.ReclaimDhtSlice(targetNodeId, sourceNodeId)) { revertDhtFn() })
        TransitionResult.Success
    }
)

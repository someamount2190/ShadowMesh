package mesh.shadowmesh.diagnostics

/**
 * Central reporting seam for things that would otherwise fail silently: swallowed
 * exceptions, failure-masking fallbacks, silent degradations, and violated invariants.
 *
 * Production code calls [Diag.swallowed] / [Diag.fallback] / [Diag.degraded] /
 * [Diag.invariant] at the exact points it currently hides a problem. By default these are
 * no-ops gated by [enabled] (false in release), so the cost is a boolean check. The
 * debug-diagnostics module installs a recording [DiagnosticSink] and sets [enabled] = true,
 * surfacing every report in the on-device event log.
 */
object Diag {

    @Volatile var enabled: Boolean = false
        private set

    @Volatile private var sink: DiagnosticSink = NoOpSink

    /** Called once by the debug build to start recording. Never called in release. */
    fun install(newSink: DiagnosticSink) {
        sink = newSink
        enabled = true
    }

    /** Restore the no-op sink (e.g. for tests). */
    fun uninstall() {
        sink = NoOpSink
        enabled = false
    }

    private fun emit(
        severity:  Severity,
        subsystem: String,
        code:      String,
        message:   String,
        throwable: Throwable?,
        fields:    Array<out Pair<String, String>>
    ) {
        if (!enabled) return
        sink.onEvent(
            DiagEvent(
                severity     = severity,
                subsystem    = subsystem,
                code         = code,
                message      = message,
                throwableMsg = throwable?.let { "${it::class.simpleName}: ${it.message}" },
                fields       = if (fields.isEmpty()) emptyMap() else fields.toMap(),
                timestampMs  = System.currentTimeMillis()
            )
        )
    }

    /** An exception was caught and not rethrown. [code] is a short stable tag. */
    fun swallowed(subsystem: String, code: String, t: Throwable, vararg fields: Pair<String, String>) =
        emit(Severity.SWALLOWED, subsystem, code, t.message ?: "(no message)", t, fields)

    /** A nullable/Result failure was masked by a default value. [why] explains the default. */
    fun fallback(subsystem: String, code: String, why: String, vararg fields: Pair<String, String>) =
        emit(Severity.FALLBACK, subsystem, code, why, null, fields)

    /** The system continued at reduced assurance/capability rather than failing. */
    fun degraded(subsystem: String, code: String, why: String, vararg fields: Pair<String, String>) =
        emit(Severity.DEGRADED, subsystem, code, why, null, fields)

    /** Record an informational checkpoint (reached-here / completed-X). */
    fun info(subsystem: String, code: String, message: String, vararg fields: Pair<String, String>) =
        emit(Severity.INFO, subsystem, code, message, null, fields)

    /**
     * Assert an invariant. If [condition] is false, an INVARIANT_VIOLATED event is recorded.
     * Returns [condition] so callers can branch: `if (!Diag.invariant(x == y, ...)) return`.
     */
    fun invariant(
        condition: Boolean,
        subsystem: String,
        code:      String,
        message:   String,
        vararg fields: Pair<String, String>
    ): Boolean {
        if (!condition) emit(Severity.INVARIANT_VIOLATED, subsystem, code, message, null, fields)
        return condition
    }
}

enum class Severity { SWALLOWED, FALLBACK, DEGRADED, INVARIANT_VIOLATED, INFO }

data class DiagEvent(
    val severity:     Severity,
    val subsystem:    String,
    val code:         String,
    val message:      String,
    val throwableMsg: String?,
    val fields:       Map<String, String>,
    val timestampMs:  Long
)

fun interface DiagnosticSink {
    fun onEvent(event: DiagEvent)
}

internal object NoOpSink : DiagnosticSink {
    override fun onEvent(event: DiagEvent) { /* no-op */ }
}

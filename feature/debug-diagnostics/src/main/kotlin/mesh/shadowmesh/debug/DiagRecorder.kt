package mesh.shadowmesh.debug

import mesh.shadowmesh.diagnostics.DiagEvent
import mesh.shadowmesh.diagnostics.DiagnosticSink
import mesh.shadowmesh.diagnostics.Severity
import java.util.concurrent.atomic.AtomicLong

/**
 * Records [DiagEvent]s reported by production code through the [mesh.shadowmesh.diagnostics.Diag]
 * seam into a bounded in-memory ring buffer the diagnostics screen can display.
 *
 * The whole point: the things production code used to swallow now show up here. A non-empty
 * recorder after exercising the app means something failed quietly — which is exactly what
 * "nothing fails silently" is meant to expose.
 */
object DiagRecorder : DiagnosticSink {

    private const val CAPACITY = 1000
    private val ring = ArrayDeque<DiagEvent>(CAPACITY)
    private val counts = HashMap<Severity, Long>()
    private val total = AtomicLong(0)

    @Synchronized
    override fun onEvent(event: DiagEvent) {
        if (ring.size >= CAPACITY) ring.removeFirst()
        ring.addLast(event)
        counts[event.severity] = (counts[event.severity] ?: 0L) + 1
        total.incrementAndGet()
    }

    @Synchronized fun snapshot(): List<DiagEvent> = ring.toList().asReversed()  // newest first

    @Synchronized fun countsBySeverity(): Map<Severity, Long> = counts.toMap()

    fun totalRecorded(): Long = total.get()

    @Synchronized fun clear() {
        ring.clear(); counts.clear(); total.set(0)
    }
}

package mesh.shadowmesh.crypto

import mesh.shadowmesh.diagnostics.Diag

/**
 * Typed result for all cryptographic operations.
 *
 * Crypto failures must never propagate as unchecked exceptions into
 * business logic. Every operation returns CryptoResult. Callers pattern-
 * match; they never catch Exception.
 */
sealed class CryptoResult<out T> {
    data class Success<T>(val value: T) : CryptoResult<T>()
    data class Failure(val reason: String, val cause: Throwable? = null) : CryptoResult<Nothing>()

    val isSuccess get() = this is Success
    val isFailure get() = this is Failure

    fun getOrNull(): T? = (this as? Success)?.value

    fun getOrThrow(): T = when (this) {
        is Success -> value
        is Failure -> throw IllegalStateException("CryptoResult.Failure: $reason", cause)
    }

    inline fun onSuccess(block: (T) -> Unit): CryptoResult<T> {
        if (this is Success) block(value)
        return this
    }

    inline fun onFailure(block: (Failure) -> Unit): CryptoResult<T> {
        if (this is Failure) block(this)
        return this
    }

    inline fun <R> map(transform: (T) -> R): CryptoResult<R> = when (this) {
        is Success -> Success(transform(value))
        is Failure -> this
    }
}

/** Convenience: wrap a block that may throw into a CryptoResult. */
inline fun <T> cryptoRunCatching(block: () -> T): CryptoResult<T> = try {
    CryptoResult.Success(block())
} catch (e: kotlinx.coroutines.CancellationException) {
    // Never swallow CancellationException — it is the coroutine cancellation signal.
    // Wrapping it in a CryptoResult.Failure and returning normally would prevent the
    // calling coroutine from being cancelled, breaking structured concurrency.
    throw e
} catch (e: Exception) {
    mesh.shadowmesh.diagnostics.Diag.swallowed("crypto", "crypto-run-catching", e)
    CryptoResult.Failure(e.message ?: "Unknown crypto error", e)
}

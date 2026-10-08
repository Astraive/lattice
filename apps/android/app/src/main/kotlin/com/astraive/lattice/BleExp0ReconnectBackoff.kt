package com.astraive.lattice

/** Bounded delay schedule for transient central-link failures within one selected sighting. */
internal object BleExp0ReconnectBackoff {
    const val MAX_ATTEMPTS = 5
    private const val INITIAL_DELAY_MILLIS = 1_000L

    fun delayMillis(attempt: Int): Long? {
        if (attempt !in 1..MAX_ATTEMPTS) return null
        return INITIAL_DELAY_MILLIS shl (attempt - 1)
    }
}

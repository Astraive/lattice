package com.astraive.lattice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BleExp0ReconnectBackoffTest {
    @Test
    fun transientRetriesUseBoundedExponentialDelays() {
        assertEquals(
            listOf(1_000L, 2_000L, 4_000L, 8_000L, 16_000L),
            (1..BleExp0ReconnectBackoff.MAX_ATTEMPTS).map {
                BleExp0ReconnectBackoff.delayMillis(it)
            },
        )
        assertNull(BleExp0ReconnectBackoff.delayMillis(0))
        assertNull(BleExp0ReconnectBackoff.delayMillis(BleExp0ReconnectBackoff.MAX_ATTEMPTS + 1))
    }
}

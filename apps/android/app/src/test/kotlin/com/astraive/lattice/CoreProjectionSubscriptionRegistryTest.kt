package com.astraive.lattice

import org.junit.Assert.assertEquals
import org.junit.Test

class CoreProjectionSubscriptionRegistryTest {
    @Test
    fun profileCloseCancelsTrackedAndLateSubscriptionsExactlyOnce() {
        val registry = CoreProjectionSubscriptionRegistry()
        var firstClosed = 0
        var secondClosed = 0
        val first = registry.track(AutoCloseable { firstClosed++ })
        registry.track(AutoCloseable { secondClosed++ })

        registry.close()
        assertEquals(1, firstClosed)
        assertEquals(1, secondClosed)

        first.close()
        registry.close()
        assertEquals(1, firstClosed)
        assertEquals(1, secondClosed)

        var lateClosed = 0
        val late = registry.track(AutoCloseable { lateClosed++ })
        assertEquals(1, lateClosed)
        late.close()
        assertEquals(1, lateClosed)
    }
}

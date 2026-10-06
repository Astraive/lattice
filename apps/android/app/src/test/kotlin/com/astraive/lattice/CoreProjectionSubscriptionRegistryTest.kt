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

    @Test
    fun dispatcherCoalescesQueuedProjectionChangesIntoOneMainThreadCallback() {
        val posted = mutableListOf<() -> Unit>()
        val delivered = mutableListOf<CoreProjectionChange>()
        val dispatcher = CoreProjectionChangeDispatcher(
            post = { action -> posted += action },
            observer = delivered::add,
        )

        dispatcher.offer(CoreProjectionChange.SPACES)
        dispatcher.offer(CoreProjectionChange.MESSAGES)

        assertEquals(1, posted.size)
        posted.removeAt(0).invoke()
        assertEquals(listOf(CoreProjectionChange.ALL), delivered)
        assertEquals(0, posted.size)
    }

    @Test
    fun acceptedEventRefreshRemainsNotificationEligibleWhenCoalescedWithMessageChanges() {
        val posted = mutableListOf<() -> Unit>()
        val delivered = mutableListOf<CoreProjectionChange>()
        val dispatcher = CoreProjectionChangeDispatcher(
            post = { action -> posted += action },
            observer = delivered::add,
        )

        dispatcher.offer(CoreProjectionChange.MESSAGES)
        dispatcher.offer(CoreProjectionChange.SYNCED_EVENTS)

        assertEquals(1, posted.size)
        posted.removeAt(0).invoke()
        assertEquals(listOf(CoreProjectionChange.SYNCED_EVENTS), delivered)
    }

    @Test
    fun dispatcherDropsQueuedAndFutureChangesAfterClose() {
        val posted = mutableListOf<() -> Unit>()
        val delivered = mutableListOf<CoreProjectionChange>()
        val dispatcher = CoreProjectionChangeDispatcher(
            post = { action -> posted += action },
            observer = delivered::add,
        )

        dispatcher.offer(CoreProjectionChange.SYNCED_EVENTS)
        dispatcher.close()
        posted.removeAt(0).invoke()
        dispatcher.offer(CoreProjectionChange.MESSAGES)

        assertEquals(emptyList<CoreProjectionChange>(), delivered)
        assertEquals(0, posted.size)
    }
}

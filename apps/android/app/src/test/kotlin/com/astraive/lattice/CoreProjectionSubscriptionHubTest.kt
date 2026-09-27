package com.astraive.lattice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CoreProjectionSubscriptionHubTest {
    @Test
    fun closedSubscriptionAndProfileReceiveNoFutureProjectionNotifications() {
        val hub = CoreProjectionSubscriptionHub()
        var activeNotifications = 0
        var profileNotifications = 0
        val deliveredChanges = mutableListOf<CoreProjectionChange>()
        val activeSubscription = hub.subscribe { _ -> activeNotifications++ }
        hub.subscribe { change ->
            profileNotifications++
            deliveredChanges += change
        }

        hub.publishChanged(CoreProjectionChange.MESSAGES)
        assertEquals(1, activeNotifications)
        assertEquals(1, profileNotifications)

        activeSubscription.close()
        hub.publishChanged(CoreProjectionChange.ALL)
        assertEquals(1, activeNotifications)
        assertEquals(2, profileNotifications)
        assertEquals(
            listOf(CoreProjectionChange.MESSAGES, CoreProjectionChange.ALL),
            deliveredChanges,
        )

        hub.close()
        hub.publishChanged(CoreProjectionChange.SPACES)
        assertEquals(1, activeNotifications)
        assertEquals(2, profileNotifications)
        assertThrows(IllegalStateException::class.java) {
            hub.subscribe { _ -> profileNotifications++ }
        }
    }
}

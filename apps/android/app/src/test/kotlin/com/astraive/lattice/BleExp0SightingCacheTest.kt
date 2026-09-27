package com.astraive.lattice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class BleExp0SightingCacheTest {
    @Test
    fun tokenIsDeduplicatedUntilTheExactRetentionBoundary() {
        val cache = BleExp0SightingCache(maxEntries = 2, ttlMillis = 900)

        assertTrue(cache.remember("token", 100))
        assertFalse(cache.remember("token", 999))
        assertEquals(1, cache.expire(999))
        assertEquals(0, cache.expire(1_000))
        assertTrue(cache.remember("token", 1_000))
    }

    @Test
    fun aFullCacheAcceptsNewTokensAfterExpiredEntriesAreRemoved() {
        val cache = BleExp0SightingCache(maxEntries = 1, ttlMillis = 10)

        assertTrue(cache.remember("first", 0))
        assertFalse(cache.remember("second", 9))
        assertTrue(cache.remember("second", 10))
        assertEquals(1, cache.size)
        assertEquals(1L, cache.nextExpiryDelayMillis(19))
    }
}

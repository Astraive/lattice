package com.astraive.lattice

/** Memory-only token deduplication with the exp0 900-second retention bound. */
internal class BleExp0SightingCache(
    private val maxEntries: Int = MAX_ENTRIES,
    private val ttlMillis: Long = BleExp0Advertisement.TOKEN_ROTATION_MILLIS,
) {
    private val expiriesByToken = LinkedHashMap<String, Long>()

    init {
        require(maxEntries > 0)
        require(ttlMillis > 0)
    }

    val size: Int
        get() = expiriesByToken.size

    fun remember(token: String, nowMillis: Long): Boolean {
        expireEntries(nowMillis)
        if (expiriesByToken.containsKey(token) || expiriesByToken.size >= maxEntries) return false
        expiriesByToken[token] = nowMillis
        return true
    }

    fun expire(nowMillis: Long): Int = expireEntries(nowMillis)

    fun nextExpiryDelayMillis(nowMillis: Long): Long? {
        val earliest = expiriesByToken.values.minOrNull() ?: return null
        return (earliest + ttlMillis - nowMillis).coerceAtLeast(1)
    }

    fun clear() = expiriesByToken.clear()

    private fun expireEntries(nowMillis: Long): Int {
        val iterator = expiriesByToken.entries.iterator()
        while (iterator.hasNext()) {
            if (nowMillis - iterator.next().value >= ttlMillis) iterator.remove()
        }
        return expiriesByToken.size
    }

    private companion object {
        const val MAX_ENTRIES = 1024
    }
}

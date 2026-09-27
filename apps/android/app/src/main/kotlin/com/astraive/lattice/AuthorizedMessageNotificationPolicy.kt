package com.astraive.lattice

import uniffi.lattice_uniffi.MobileLocalTextMessage

internal fun newlyProjectedIncomingMessages(
    previous: List<MobileLocalTextMessage>,
    current: List<MobileLocalTextMessage>,
    localFingerprintHex: String?,
): List<MobileLocalTextMessage> {
    if (localFingerprintHex == null) return emptyList()
    val previousEventIds = previous.mapTo(HashSet()) { it.eventId.toLowerHex() }
    return current.filter { message ->
        message.authorId.toLowerHex() != localFingerprintHex &&
            message.eventId.toLowerHex() !in previousEventIds
    }
}

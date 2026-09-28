package com.astraive.lattice

import uniffi.lattice_uniffi.MobileOutboxEntry
import uniffi.lattice_uniffi.MobileOutboxState

/** Selects due durable rows and advances one authenticated BLE transfer at a time. */
internal class BleExp0OutboxPump(
    private val profile: AndroidMobileProfile,
    private val transport: BleExp0EnvelopeTransport,
    /** Router authorization for this peer; event envelope bytes remain opaque here. */
    private val isRoutedToPeer: (eventId: ByteArray) -> Boolean,
) {
    /** Starts the first due nonterminal entry in event-ID order, if one exists. */
    fun startNextDue(
        nowUnixMillis: Long,
        nowElapsedMillis: Long,
        retryAt: (attemptCount: UInt, nowUnixMillis: Long) -> Long,
    ): Boolean {
        val pageSize = OUTBOX_PAGE_SIZE
        var cursor: ByteArray? = null
        while (true) {
            val page = profile.outboxPage(cursor, pageSize)
            val due = page.firstOrNull { it.isDueAt(nowUnixMillis) && isRoutedToPeer(it.eventId.copyOf()) }
            if (due != null) {
                transport.sendEnvelope(
                    due,
                    retryAt(due.attemptCount, nowUnixMillis),
                    nowUnixMillis,
                    nowElapsedMillis,
                )
                return true
            }
            if (page.size < pageSize) return false
            cursor = page.last().eventId
        }
    }

    /** Continues the durable queue after an authenticated LBFA ingress acknowledgement. */
    fun receiveControl(
        ciphertext: ByteArray,
        nowUnixMillis: Long,
        nowElapsedMillis: Long,
        retryAt: (attemptCount: UInt, nowUnixMillis: Long) -> Long,
    ): ByteArray? {
        val ingressEventId = transport.receiveControl(ciphertext, nowElapsedMillis) ?: return null
        startNextDue(nowUnixMillis, nowElapsedMillis, retryAt)
        return ingressEventId
    }

    private fun MobileOutboxEntry.isDueAt(nowUnixMillis: Long): Boolean =
        (state == MobileOutboxState.QUEUED ||
            state == MobileOutboxState.FORWARDING ||
            state == MobileOutboxState.FORWARDED ||
            state == MobileOutboxState.PEER_INGRESS_ACCEPTED) &&
            nextAttemptMs <= nowUnixMillis

    private companion object {
        const val OUTBOX_PAGE_SIZE = 64
    }
}

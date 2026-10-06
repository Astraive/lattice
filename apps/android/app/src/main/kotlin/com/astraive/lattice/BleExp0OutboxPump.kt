package com.astraive.lattice

import uniffi.lattice_uniffi.MobileDirectMessageOutboxEntry
import uniffi.lattice_uniffi.MobileForwardableEventEntry
import uniffi.lattice_uniffi.MobileOutboxEntry
import uniffi.lattice_uniffi.MobileOutboxState

internal interface BleExp0OutboxProfile : BleExp0IngressProfile {
    fun outboxPage(afterEventId: ByteArray? = null, limit: Int = 64): List<MobileOutboxEntry>
    fun directMessageOutboxPage(
        afterPacketId: ByteArray? = null,
        limit: UInt = 64u,
    ): List<MobileDirectMessageOutboxEntry>
}

/** Selects due durable rows and advances one authenticated BLE transfer at a time. */
internal class BleExp0OutboxPump(
    private val profile: BleExp0OutboxProfile,
    private val transport: BleExp0EnvelopeTransport,
    /** Router authorization for signed-event envelopes. */
    private val isRoutedToPeer: (eventId: ByteArray) -> Boolean,
) {
    /** Starts one due event or DM packet addressed to this authenticated peer. */
    fun startNextDue(
        nowUnixMillis: Long,
        nowElapsedMillis: Long,
        retryAt: (attemptCount: UInt, nowUnixMillis: Long) -> Long,
    ): Boolean {
        val peerIdentity = transport.authenticatedPeerIdentityFingerprint()
        var eventCursor: ByteArray? = null
        var forwardedCursor: ByteArray? = null
        var directMessageCursor: ByteArray? = null
        var eventsExhausted = false
        var forwardedEventsExhausted = false
        var directMessagesExhausted = false
        while (!eventsExhausted || !forwardedEventsExhausted || !directMessagesExhausted) {
            val eventPage = if (eventsExhausted) {
                emptyList()
            } else {
                profile.outboxPage(eventCursor, OUTBOX_PAGE_SIZE)
            }
            val forwardedPage = if (forwardedEventsExhausted) {
                emptyList()
            } else {
                profile.forwardableEventPage(
                    peerIdentity,
                    forwardedCursor,
                    nowUnixMillis,
                    OUTBOX_PAGE_SIZE,
                )
            }
            val directMessagePage = if (directMessagesExhausted) {
                emptyList()
            } else {
                profile.directMessageOutboxPage(directMessageCursor, OUTBOX_PAGE_SIZE.toUInt())
            }
            val event = eventPage.firstOrNull {
                it.isDueAt(nowUnixMillis) && isRoutedToPeer(it.eventId.copyOf())
            }
            val forwardedEvent = forwardedPage.firstOrNull {
                isRoutedToPeer(it.eventId.copyOf())
            }
            val directMessage = directMessagePage.firstOrNull {
                it.isDueAt(nowUnixMillis) &&
                    profile.isDirectMessageRoutedToPeer(it.groupReference, peerIdentity)
            }
            val candidates = listOfNotNull(
                event?.let { it to null },
                forwardedEvent?.let { it.asTransportEntry() to peerIdentity },
                directMessage?.asTransportEntry()?.let { it to null },
            )
            val due = candidates.minWithOrNull { left, right ->
                comparePacketIds(left.first.eventId, right.first.eventId)
            }
            if (due != null) {
                transport.sendEnvelope(
                    due.first,
                    retryAt(due.first.attemptCount, nowUnixMillis),
                    nowUnixMillis,
                    nowElapsedMillis,
                    relayPeerIdentity = due.second,
                )
                return true
            }
            if (!eventsExhausted) {
                eventsExhausted = eventPage.size < OUTBOX_PAGE_SIZE
                if (!eventsExhausted) eventCursor = eventPage.last().eventId
            }
            if (!forwardedEventsExhausted) {
                forwardedEventsExhausted = forwardedPage.size < OUTBOX_PAGE_SIZE
                if (!forwardedEventsExhausted) {
                    forwardedCursor = forwardedPage.last().eventId
                }
            }
            if (!directMessagesExhausted) {
                directMessagesExhausted = directMessagePage.size < OUTBOX_PAGE_SIZE
                if (!directMessagesExhausted) {
                    directMessageCursor = directMessagePage.last().packetId
                }
            }
        }
        return false
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

    private fun uniffi.lattice_uniffi.MobileDirectMessageOutboxEntry.isDueAt(
        nowUnixMillis: Long,
    ): Boolean = (state == MobileOutboxState.QUEUED ||
        state == MobileOutboxState.FORWARDING ||
        state == MobileOutboxState.FORWARDED ||
        state == MobileOutboxState.PEER_INGRESS_ACCEPTED) &&
        nextAttemptMs <= nowUnixMillis

    private fun uniffi.lattice_uniffi.MobileDirectMessageOutboxEntry.asTransportEntry() =
        MobileOutboxEntry(
            eventId = packetId,
            envelopeBytes = envelopeBytes,
            nextAttemptMs = nextAttemptMs,
            attemptCount = attemptCount,
            state = state,
        )
    private fun MobileForwardableEventEntry.asTransportEntry() =
        MobileOutboxEntry(
            eventId = eventId,
            envelopeBytes = canonicalBytes,
            nextAttemptMs = nextAttemptMs,
            attemptCount = attemptCount,
            state = MobileOutboxState.QUEUED,
        )


    private fun comparePacketIds(left: ByteArray, right: ByteArray): Int {
        for (index in 0 until minOf(left.size, right.size)) {
            val comparison = (left[index].toInt() and 0xff).compareTo(right[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return left.size.compareTo(right.size)
    }

    private companion object {
        const val OUTBOX_PAGE_SIZE = 64
    }
}

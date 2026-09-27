package com.astraive.lattice

import org.junit.Assert.assertEquals
import org.junit.Test
import uniffi.lattice_uniffi.MobileLocalTextMessage

class AuthorizedMessageNotificationPolicyTest {
    @Test
    fun notificationsIncludeOnlyNewMessagesFromOtherAuthors() {
        val localAuthor = ByteArray(32) { 1 }
        val remoteAuthor = ByteArray(32) { 2 }
        val oldMessage = message(event = 10, author = remoteAuthor)
        val localMessage = message(event = 11, author = localAuthor)
        val incoming = message(event = 12, author = remoteAuthor)

        assertEquals(
            listOf(incoming),
            newlyProjectedIncomingMessages(
                previous = listOf(oldMessage),
                current = listOf(oldMessage, localMessage, incoming),
                localFingerprintHex = localAuthor.toLowerHex(),
            ),
        )
        assertEquals(
            emptyList<MobileLocalTextMessage>(),
            newlyProjectedIncomingMessages(emptyList(), listOf(incoming), null),
        )
    }

    private fun message(event: Int, author: ByteArray) = MobileLocalTextMessage(
        eventId = ByteArray(32) { event.toByte() },
        authorId = author,
        authorSequence = 1uL,
        lamport = 1uL,
        content = "decrypted test content",
        outboxState = null,
    )
}

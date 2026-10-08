package com.astraive.lattice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import uniffi.lattice_uniffi.MobileForwardableEventEntry
import uniffi.lattice_uniffi.MobileOutboxEntry
import uniffi.lattice_uniffi.MobileOutboxState
import uniffi.lattice_uniffi.MobileSyncEventResult
import uniffi.lattice_uniffi.MobileSyncEventState

class BleExp0EnvelopeTransportTest {
    @Test
    fun outboxPumpSelectsAcceptedRelayEventForAuthenticatedPeer() {
        val eventId = ByteArray(32) { (it + 1).toByte() }
        val canonicalBytes = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val peerIdentity = ByteArray(32) { 0x11 }
        val profile = RecordingProfile(eventId, MobileSyncEventState.ACCEPTED, false)
        profile.forwardableEvents = listOf(
            MobileForwardableEventEntry(eventId, canonicalBytes, 0, 0u),
        )
        val io = RecordingIo()
        val transport = BleExp0EnvelopeTransport(
            profile,
            IdentitySessionCipher(),
            BleExp0TransferProtocol(1, 247, 41),
            io,
        )
        val pump = BleExp0OutboxPump(profile, transport) { it.contentEquals(eventId) }

        assertTrue(pump.startNextDue(0, 0) { _, now -> now + 100 })
        assertEquals(peerIdentity.toList(), profile.relayAttemptPeer?.toList())
        assertEquals(eventId.toList(), profile.relayAttemptEventId?.toList())
        assertEquals(1, io.controls.size)
    }
    @Test
    fun relayAttemptAndAuthenticatedAcceptanceAreTrackedPerPeer() {
        val peerIdentity = ByteArray(32) { 0x11 }
        val fixture = transfer(MobileSyncEventState.ACCEPTED, false, peerIdentity)

        assertEquals(peerIdentity.toList(), fixture.senderProfile.relayAttemptPeer?.toList())
        assertEquals(peerIdentity.toList(), fixture.senderProfile.relayAcceptedPeer?.toList())
        assertEquals(fixture.eventId.toList(), fixture.senderProfile.relayAcceptedEventId?.toList())
        assertEquals(
            byteArrayOf(0x01, 0x02, 0x03, 0x04).toList(),
            fixture.receiverProfile.ingressCanonicalBytes?.toList(),
        )
        assertEquals(peerIdentity.toList(), fixture.receiverProfile.authenticatedPeer?.toList())
    }
    @Test
    fun pendingIngressAcknowledgementNeverBecomesDestinationDelivery() {
        val fixture = transferWithIngressResult(MobileSyncEventState.PENDING)

        assertEquals(MobileOutboxState.PEER_INGRESS_ACCEPTED, fixture.senderProfile.state)
        assertEquals(fixture.eventId.toList(), fixture.senderProfile.ingressEventId?.toList())
        assertTrue(fixture.receiverIo.controls.any(::isCompletion))
        assertEquals(MobileSyncEventState.PENDING, fixture.ingressResults.single().state)
    }

    @Test
    fun unauthorizedCoreIngressDisconnectsWithoutCompletionAcknowledgement() {
        val fixture = transferWithIngressFailure()

        assertEquals(MobileOutboxState.FORWARDING, fixture.senderProfile.state)
        assertFalse(fixture.receiverIo.controls.any(::isCompletion))
        assertTrue(fixture.receiverIo.disconnected)
        assertTrue(fixture.senderIo.disconnected)
        assertTrue(fixture.ingressResults.isEmpty())
    }

    @Test
    fun gattWriteFailureAfterDurableAttemptRemainsRetryableWithoutPeerReceipt() {
        val eventId = ByteArray(32) { (it + 1).toByte() }
        val profile = RecordingProfile(eventId, MobileSyncEventState.ACCEPTED, false)
        val io = RecordingIo(rejectControls = true)
        val transport = BleExp0EnvelopeTransport(
            profile,
            IdentitySessionCipher(),
            BleExp0TransferProtocol(1, 247, 41),
            io,
        )

        var rejected = false
        try {
            transport.sendEnvelope(
                MobileOutboxEntry(
                    eventId = eventId,
                    envelopeBytes = byteArrayOf(0x01, 0x02, 0x03),
                    nextAttemptMs = 0,
                    attemptCount = 0u,
                    state = MobileOutboxState.QUEUED,
                ),
                retryAtUnixMillis = 100,
                nowUnixMillis = 0,
                nowElapsedMillis = 0,
            )
        } catch (_: IllegalStateException) {
            rejected = true
        }

        assertTrue(rejected)
        assertEquals(MobileOutboxState.FORWARDING, profile.state)
        assertEquals(eventId.toList(), profile.attemptEventId?.toList())
        assertTrue(profile.ingressEventId == null)
        assertTrue(io.disconnected)
    }

    @Test
    fun duplicateIngressIsAcknowledgedAsPeerIngressNotDelivery() {
        val fixture = transferWithIngressResult(MobileSyncEventState.DUPLICATE)

        assertEquals(MobileOutboxState.PEER_INGRESS_ACCEPTED, fixture.senderProfile.state)
        assertEquals(1, fixture.receiverProfile.ingressCalls)
        assertTrue(fixture.receiverIo.controls.any(::isCompletion))
        assertEquals(MobileSyncEventState.DUPLICATE, fixture.ingressResults.single().state)
    }

    @Test
    fun acceptedIngressOutcomeIsAvailableForPhysicalDiagnostics() {
        val fixture = transferWithIngressResult(MobileSyncEventState.ACCEPTED)

        assertEquals(MobileSyncEventState.ACCEPTED, fixture.ingressResults.single().state)
        assertTrue(fixture.eventId.contentEquals(fixture.ingressResults.single().eventId))
    }

    @Test
    fun opaqueDirectMessagePacketsUseAuthenticatedPeerIngressPath() {
        val packetId = ByteArray(32) { (it + 9).toByte() }
        val envelope = byteArrayOf(0x4c, 0x44, 0x4d, 0x50, 0x01, 0x01) +
            ByteArray(32) { 0x22 } + byteArrayOf(0x01)
        val senderProfile = RecordingProfile(packetId, MobileSyncEventState.ACCEPTED, false)
        val receiverProfile = RecordingProfile(packetId, MobileSyncEventState.ACCEPTED, false)
        val senderIo = RecordingIo()
        val receiverIo = RecordingIo()
        val sender = BleExp0EnvelopeTransport(
            senderProfile,
            IdentitySessionCipher(),
            BleExp0TransferProtocol(1, 247, 41),
            senderIo,
        )
        val receiver = BleExp0EnvelopeTransport(
            receiverProfile,
            IdentitySessionCipher(),
            BleExp0TransferProtocol(2, 247, 91),
            receiverIo,
        )

        sender.sendEnvelope(
            MobileOutboxEntry(
                eventId = packetId,
                envelopeBytes = envelope,
                nextAttemptMs = 0,
                attemptCount = 0u,
                state = MobileOutboxState.QUEUED,
            ),
            retryAtUnixMillis = 100,
            nowUnixMillis = 0,
            nowElapsedMillis = 0,
        )
        receiver.receiveControl(senderIo.controls.single(), nowMillis = 1)
        sender.receiveControl(receiverIo.controls.last(), nowMillis = 2)
        receiver.receiveFrame(senderIo.frames.single(), nowMillis = 3)
        sender.receiveControl(receiverIo.controls.last(), nowMillis = 4)

        assertEquals(packetId.toList(), senderProfile.directMessageAttemptId?.toList())
        assertEquals(packetId.toList(), senderProfile.directMessageIngressId?.toList())
        assertEquals(0, receiverProfile.ingressCalls)
        assertEquals(1, receiverProfile.directMessageIngressCalls)
        assertEquals(ByteArray(32) { 0x11 }.toList(), receiverProfile.authenticatedPeer?.toList())
    }

    private fun transferWithIngressResult(state: MobileSyncEventState): Fixture = transfer(state, false)

    private fun transferWithIngressFailure(): Fixture = transfer(MobileSyncEventState.ACCEPTED, true)

    private fun transfer(
        state: MobileSyncEventState,
        failIngress: Boolean,
        relayPeerIdentity: ByteArray? = null,
    ): Fixture {
        val eventId = ByteArray(32) { (it + 1).toByte() }
        val envelope = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        val senderProfile = RecordingProfile(eventId, state, false)
        val receiverProfile = RecordingProfile(eventId, state, failIngress)
        val senderIo = RecordingIo()
        val ingressResults = mutableListOf<MobileSyncEventResult>()
        val receiverIo = RecordingIo()
        val sender = BleExp0EnvelopeTransport(
            senderProfile,
            IdentitySessionCipher(),
            BleExp0TransferProtocol(1, 247, 41),
            senderIo,
        )
        val receiver = BleExp0EnvelopeTransport(
            receiverProfile,
            IdentitySessionCipher(),
            BleExp0TransferProtocol(2, 247, 91),
            receiverIo,
            onCoreIngressResult = { ingressResults += it },
        )
        sender.sendEnvelope(
            MobileOutboxEntry(
                eventId = eventId,
                envelopeBytes = envelope,
                nextAttemptMs = 0,
                attemptCount = 0u,
                state = MobileOutboxState.QUEUED,
            ),
            retryAtUnixMillis = 100,
            nowUnixMillis = 0,
            nowElapsedMillis = 0,
            relayPeerIdentity = relayPeerIdentity,
        )
        receiver.receiveControl(senderIo.controls.single(), nowMillis = 1)
        sender.receiveControl(receiverIo.controls.last(), nowMillis = 2)
        val inboundFrame = senderIo.frames.single()
        if (failIngress) {
            var rejected = false
            try {
                receiver.receiveFrame(inboundFrame, nowMillis = 3)
            } catch (_: IllegalStateException) {
                rejected = true
            }
            assertTrue(rejected)
            sender.close()
        } else {
            receiver.receiveFrame(inboundFrame, nowMillis = 3)
            sender.receiveControl(receiverIo.controls.last(), nowMillis = 4)
        }
        return Fixture(eventId, senderProfile, receiverProfile, senderIo, receiverIo, ingressResults)
    }

    private fun isCompletion(record: ByteArray): Boolean =
        record.size >= 4 && record[0] == 0x4c.toByte() && record[1] == 0x42.toByte() &&
            record[2] == 0x46.toByte() && record[3] == 0x41.toByte()

    private data class Fixture(
        val eventId: ByteArray,
        val senderProfile: RecordingProfile,
        val receiverProfile: RecordingProfile,
        val senderIo: RecordingIo,
        val receiverIo: RecordingIo,
        val ingressResults: List<MobileSyncEventResult>,
    )

    private class IdentitySessionCipher : BleExp0SessionCipher {
        override fun isAuthenticated(): Boolean = true
        override fun peerIdentityFingerprint(): ByteArray = ByteArray(32) { 0x11 }
        override fun encryptRecord(plaintext: ByteArray): ByteArray = plaintext.copyOf()
        override fun decryptRecord(ciphertext: ByteArray): ByteArray = ciphertext.copyOf()
    }

    private class RecordingIo(private val rejectControls: Boolean = false) : BleExp0EnvelopeIo {
        val controls = mutableListOf<ByteArray>()
        val frames = mutableListOf<ByteArray>()
        var disconnected = false

        override fun enqueueControl(ciphertext: ByteArray): Boolean {
            if (rejectControls) return false
            controls += ciphertext.copyOf()
            return true
        }

        override fun enqueueFrame(frame: ByteArray): Boolean {
            frames += frame.copyOf()
            return true
        }

        override fun disconnect() {
            disconnected = true
        }
    }

    private class RecordingProfile(
        private val eventId: ByteArray,
        private val resultState: MobileSyncEventState,
        private val failIngress: Boolean,
    ) : BleExp0OutboxProfile {
        var forwardableEvents = emptyList<MobileForwardableEventEntry>()
        var state = MobileOutboxState.QUEUED
        var ingressEventId: ByteArray? = null
        var attemptEventId: ByteArray? = null
        var ingressCalls = 0
        var directMessageAttemptId: ByteArray? = null
        var directMessageIngressId: ByteArray? = null
        var directMessageIngressCalls = 0
        var relayAttemptPeer: ByteArray? = null
        var relayAttemptEventId: ByteArray? = null
        var relayAcceptedPeer: ByteArray? = null
        var relayAcceptedEventId: ByteArray? = null
        var authenticatedPeer: ByteArray? = null
        var ingressCanonicalBytes: ByteArray? = null
        override fun markOutboxAttempt(eventId: ByteArray, nextAttemptMs: Long) {
            require(eventId.contentEquals(this.eventId))
            require(nextAttemptMs == 100L)
            attemptEventId = eventId.copyOf()
            state = MobileOutboxState.FORWARDING
        }

        override fun recordPeerIngressAccepted(eventId: ByteArray) {
            require(eventId.contentEquals(this.eventId))
            ingressEventId = eventId.copyOf()
            state = MobileOutboxState.PEER_INGRESS_ACCEPTED
        }
        override fun outboxPage(afterEventId: ByteArray?, limit: Int): List<MobileOutboxEntry> =
            emptyList()

        override fun directMessageOutboxPage(
            afterPacketId: ByteArray?,
            limit: UInt,
        ): List<uniffi.lattice_uniffi.MobileDirectMessageOutboxEntry> = emptyList()

        override fun forwardableEventPage(
            peerIdentity: ByteArray,
            afterEventId: ByteArray?,
            nowUnixMillis: Long,
            limit: Int,
        ): List<MobileForwardableEventEntry> = forwardableEvents

        override fun markRelayEventAttempt(
            peerIdentity: ByteArray,
            eventId: ByteArray,
            nextAttemptMs: Long,
        ) {
            require(eventId.contentEquals(this.eventId))
            require(nextAttemptMs == 100L)
            relayAttemptPeer = peerIdentity.copyOf()
            relayAttemptEventId = eventId.copyOf()
        }

        override fun recordRelayEventPeerAcceptance(peerIdentity: ByteArray, eventId: ByteArray) {
            require(eventId.contentEquals(this.eventId))
            relayAcceptedPeer = peerIdentity.copyOf()
            relayAcceptedEventId = eventId.copyOf()
        }

        override fun ingestSyncedApplicationEvent(
            canonicalBytes: ByteArray,
            authenticatedPeerIdentity: ByteArray,
        ): MobileSyncEventResult {
            ingressCalls++
            authenticatedPeer = authenticatedPeerIdentity.copyOf()
            ingressCanonicalBytes = canonicalBytes.copyOf()
            if (failIngress) throw IllegalStateException("Core rejected unauthorized ingress")
            return MobileSyncEventResult(
                eventId = eventId.copyOf(),
                state = resultState,
                missingDependencies = emptyList(),
            )
        }

        override fun markDirectMessageAttempt(packetId: ByteArray, nextAttemptMs: Long) {
            require(packetId.contentEquals(eventId))
            require(nextAttemptMs == 100L)
            directMessageAttemptId = packetId.copyOf()
            state = MobileOutboxState.FORWARDING
        }

        override fun recordDirectMessagePeerIngressAccepted(packetId: ByteArray) {
            require(packetId.contentEquals(eventId))
            directMessageIngressId = packetId.copyOf()
            state = MobileOutboxState.PEER_INGRESS_ACCEPTED
        }

        override fun ingestDirectMessagePacket(
            authenticatedPeerIdentity: ByteArray,
            envelopeBytes: ByteArray,
        ): uniffi.lattice_uniffi.MobileDirectMessageIngressResult {
            directMessageIngressCalls++
            authenticatedPeer = authenticatedPeerIdentity.copyOf()
            return uniffi.lattice_uniffi.MobileDirectMessageIngressResult(
                packetId = eventId.copyOf(),
                duplicate = false,
                invitationPending = true,
                groupReference = ByteArray(32) { 0x22 },
                peerIdentity = authenticatedPeerIdentity.copyOf(),
                content = null,
            )
        }

        override fun isDirectMessageRoutedToPeer(
            groupReference: ByteArray,
            peerIdentity: ByteArray,
        ): Boolean = groupReference.contentEquals(ByteArray(32) { 0x22 }) &&
            peerIdentity.contentEquals(ByteArray(32) { 0x11 })
    }
}

package com.astraive.lattice

import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Test

class BleExp0TransferProtocolTest {
    @Test
    fun pacesFourFramesUntilCreditAndCompletesOnlyAfterIngressAcknowledgement() {
        val sender = BleExp0TransferProtocol(localRole = 1, negotiatedMtu = 247, initialOutboundTransferId = 41)
        val receiver = BleExp0TransferProtocol(localRole = 2, negotiatedMtu = 247, initialOutboundTransferId = 91)
        val envelope = ByteArray(1_000) { (it * 17).toByte() }

        val start = sender.beginOutbound(envelope, nowMillis = 0)
        val initialCredit = receiver.acceptStart(start, nowMillis = 0)
        check(initialCredit.copyOfRange(0, 4).contentEquals(byteArrayOf(0x4c, 0x42, 0x57, 0x43)))
        check(readUnsignedShort(initialCredit, 14) == 4)

        val firstWindow = sender.acceptCredit(initialCredit, nowMillis = 1)
        check(firstWindow.size == 4)
        check(firstWindow.all { it.size <= 244 })
        var nextCredit = initialCredit
        firstWindow.forEachIndexed { index, frame ->
            val update = receiver.acceptFrame(frame, nowMillis = 2L + index)
            nextCredit = checkNotNull(update.creditRecord)
        }
        check(readUnsignedShort(nextCredit, 14) == 5)

        val secondWindow = sender.acceptCredit(nextCredit, nowMillis = 6)
        check(secondWindow.size == 1)
        val finalUpdate = receiver.acceptFrame(secondWindow.single(), nowMillis = 7)
        check(finalUpdate.completedEnvelope?.contentEquals(envelope) == true)
        check(finalUpdate.creditRecord != null)

        val completion = receiver.acknowledgeIngress(41, nowMillis = 8)
        sender.acceptCompletion(completion, nowMillis = 9)
        check(!sender.isClosed)
        val nextStart = sender.beginOutbound(byteArrayOf(8), nowMillis = 10)
        check(readUnsignedShort(receiver.acceptStart(nextStart, nowMillis = 10), 14) == 1)
    }

    @Test
    fun exactDuplicateIsIdempotentAfterAssemblyAndIngressIsExplicit() {
        val sender = BleExp0TransferProtocol(localRole = 1, negotiatedMtu = 154, initialOutboundTransferId = 7)
        val receiver = BleExp0TransferProtocol(localRole = 2, negotiatedMtu = 154, initialOutboundTransferId = 99)
        val envelope = ByteArray(200) { it.toByte() }
        val start = sender.beginOutbound(envelope, nowMillis = 10)
        val credit = receiver.acceptStart(start, nowMillis = 10)
        val frames = sender.acceptCredit(credit, nowMillis = 11)
        check(frames.size == 2)
        check(frames.all { it.size <= 151 })
        val first = receiver.acceptFrame(frames[0], nowMillis = 12)
        val final = receiver.acceptFrame(frames[1], nowMillis = 13)
        check(final.completedEnvelope?.contentEquals(envelope) == true)
        check(receiver.acceptFrame(frames[1].copyOf(), nowMillis = 14) ==
            BleExp0TransferProtocol.InboundUpdate(null, null))

        val completion = receiver.acknowledgeIngress(7, nowMillis = 16)
        sender.acceptCompletion(completion, nowMillis = 17)
        check(first.creditRecord != null)
    }

    @Test
    fun malformedCreditConflictingDuplicateAndExpiredTransferCloseTheSession() {
        val sender = BleExp0TransferProtocol(localRole = 1, negotiatedMtu = 247, initialOutboundTransferId = 12)
        val receiver = BleExp0TransferProtocol(localRole = 2, negotiatedMtu = 247, initialOutboundTransferId = 13)
        val start = sender.beginOutbound(ByteArray(1_000), nowMillis = 0)
        val credit = receiver.acceptStart(start, nowMillis = 0).copyOf()
        ByteBuffer.wrap(credit).order(ByteOrder.BIG_ENDIAN).putShort(14, 3)
        expectIllegalArgument { sender.acceptCredit(credit, nowMillis = 1) }
        check(sender.isClosed)

        val duplicateSender = BleExp0TransferProtocol(1, 247, 14)
        val duplicateReceiver = BleExp0TransferProtocol(2, 247, 15)
        val transferStart = duplicateSender.beginOutbound(ByteArray(100), nowMillis = 0)
        val transferCredit = duplicateReceiver.acceptStart(transferStart, nowMillis = 0)
        val frame = duplicateSender.acceptCredit(transferCredit, nowMillis = 1).single()
        duplicateReceiver.acceptFrame(frame, nowMillis = 2)
        val conflicting = frame.copyOf().also { it[it.lastIndex] = (it.last() + 1).toByte() }
        expectIllegalArgument { duplicateReceiver.acceptFrame(conflicting, nowMillis = 3) }
        check(duplicateReceiver.isClosed)

        val expiring = BleExp0TransferProtocol(1, 247, 16)
        expiring.beginOutbound(ByteArray(8), nowMillis = 100)
        check(!expiring.expire(30_099))
        check(expiring.expire(30_100))
        check(expiring.isClosed)
        val incomingSender = BleExp0TransferProtocol(1, 247, 17)
        val incomingReceiver = BleExp0TransferProtocol(2, 247, 18)
        val incomingStart = incomingSender.beginOutbound(ByteArray(8), nowMillis = 100)
        incomingReceiver.acceptStart(incomingStart, nowMillis = 100)
        check(!incomingReceiver.expire(30_099))
        check(incomingReceiver.expire(30_100))
        check(incomingReceiver.isClosed)
    }

    private fun readUnsignedShort(bytes: ByteArray, offset: Int): Int =
        ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN).getShort(offset).toInt() and 0xffff

    private inline fun expectIllegalArgument(block: () -> Unit) {
        try {
            block()
            error("Expected IllegalArgumentException")
        } catch (_: IllegalArgumentException) {
            // Expected malformed or out-of-order protocol input.
        }
    }
}

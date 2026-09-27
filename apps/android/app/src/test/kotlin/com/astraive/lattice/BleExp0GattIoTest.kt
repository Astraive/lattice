package com.astraive.lattice

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

class BleExp0GattIoTest {
    @Test
    fun serializesControlAndFramesAndCopiesQueuedValues() {
        val started = mutableListOf<Pair<UUID, ByteArray>>()
        val failures = mutableListOf<Int>()
        val queue = BleGattSerializedValueQueue(
            start = { characteristic, payload ->
                started += characteristic to payload
                BleGattStatus.STARTED
            },
            onFailure = failures::add,
        )
        val original = byteArrayOf(1, 2, 3)

        assertTrue(queue.enqueue(BleExp0GattProfile.controlUuid, original))
        original[0] = 9
        assertTrue(queue.enqueue(BleExp0GattProfile.rxUuid, byteArrayOf(4, 5)))
        assertEquals(1, started.size)
        assertEquals(listOf(1, 2, 3), started[0].second.map { it.toInt() })

        queue.onOperationComplete(BleExp0GattProfile.controlUuid, 0)
        assertEquals(2, started.size)
        assertEquals(BleExp0GattProfile.rxUuid, started[1].first)
        queue.onOperationComplete(BleExp0GattProfile.rxUuid, 0)
        assertTrue(failures.isEmpty())
    }

    @Test
    fun rejectsCapacityAndClosesOnFailedGattCallback() {
        val failures = mutableListOf<Int>()
        val queue = BleGattSerializedValueQueue(
            start = { _, _ -> BleGattStatus.STARTED },
            onFailure = failures::add,
            maxOperations = 1,
            maxBytes = 2,
        )

        assertTrue(queue.enqueue(BleExp0GattProfile.controlUuid, byteArrayOf(1, 2)))
        assertFalse(queue.enqueue(BleExp0GattProfile.rxUuid, byteArrayOf(3)))
        queue.onOperationComplete(BleExp0GattProfile.controlUuid, 133)
        assertEquals(listOf(133), failures)
        assertFalse(queue.enqueue(BleExp0GattProfile.rxUuid, byteArrayOf(4)))
    }

    @Test
    fun failsClosedWhenCallbackTargetsAnotherCharacteristic() {
        val failures = mutableListOf<Int>()
        val queue = BleGattSerializedValueQueue(
            start = { _, _ -> BleGattStatus.STARTED },
            onFailure = failures::add,
        )
        val unknownCharacteristic = UUID.fromString("2c9a0002-7d31-4f6a-9b43-4c4154544943")
        assertTrue(queue.enqueue(BleExp0GattProfile.controlUuid, byteArrayOf(1)))

        queue.onOperationComplete(unknownCharacteristic, 0)

        assertEquals(1, failures.size)
        assertFalse(queue.enqueue(BleExp0GattProfile.rxUuid, byteArrayOf(2)))
    }
}

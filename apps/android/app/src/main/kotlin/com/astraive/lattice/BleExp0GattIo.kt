package com.astraive.lattice

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import java.util.ArrayDeque
import java.util.UUID

/** One-in-flight bounded FIFO for ATT writes and server notifications. */
internal class BleGattSerializedValueQueue(
    private val start: (UUID, ByteArray) -> BleGattStatus,
    private val onFailure: (Int) -> Unit,
    private val maxOperations: Int = MAX_PENDING_OPERATIONS,
    private val maxBytes: Int = MAX_PENDING_BYTES,
) {
    private data class Operation(val characteristic: UUID, val payload: ByteArray)

    private val lock = Any()
    private val waiting = ArrayDeque<Operation>()
    private var active: Operation? = null
    private var queuedBytes = 0
    private var closed = false

    init {
        require(maxOperations > 0)
        require(maxBytes > 0)
    }

    fun enqueue(characteristic: UUID, payload: ByteArray): Boolean {
        return synchronized(lock) {
            if (closed || payload.isEmpty() || payload.size > MAX_GATT_ATTRIBUTE_BYTES) return@synchronized false
            if (waiting.size + (if (active == null) 0 else 1) >= maxOperations) return@synchronized false
            if (queuedBytes > maxBytes - payload.size) return@synchronized false
            val operation = Operation(characteristic, payload.copyOf())
            waiting.addLast(operation)
            queuedBytes += operation.payload.size
            pumpLocked()
            !closed
        }
    }

    fun onOperationComplete(characteristic: UUID, status: Int) {
        synchronized(lock) {
            val current = active ?: return@synchronized
            if (current.characteristic != characteristic) {
                failLocked(BluetoothGatt.GATT_FAILURE)
                return@synchronized
            }
            completeLocked(current, status)
        }
    }

    fun onOperationComplete(status: Int) {
        synchronized(lock) {
            val current = active ?: return@synchronized
            completeLocked(current, status)
        }
    }

    fun activeCharacteristic(): UUID? = synchronized(lock) { active?.characteristic }

    private fun completeLocked(current: Operation, status: Int) {
        if (status != BluetoothGatt.GATT_SUCCESS) {
            failLocked(status)
            return
        }
        queuedBytes -= current.payload.size
        active = null
        pumpLocked()
    }

    fun close() {
        synchronized(lock) {
            if (closed) return@synchronized
            closed = true
            active = null
            waiting.clear()
            queuedBytes = 0
        }
    }

    private fun pumpLocked() {
        if (closed || active != null) return
        val next = waiting.pollFirst() ?: return
        active = next
        if (start(next.characteristic, next.payload) != BleGattStatus.STARTED) {
            failLocked(BluetoothGatt.GATT_FAILURE)
        }
    }

    private fun failLocked(status: Int) {
        if (closed) return
        closed = true
        active = null
        waiting.clear()
        queuedBytes = 0
        onFailure(status)
    }

    private companion object {
        const val MAX_GATT_ATTRIBUTE_BYTES = 512
        const val MAX_PENDING_OPERATIONS = 8
        const val MAX_PENDING_BYTES = 4096
    }
}

/** Central-side Noise controls and exp0 frames share one ordered ATT-write queue. */
internal class BleExp0CentralEnvelopeIo(
    private val adapter: BleGattCentralAdapter,
    private val characteristics: BleExp0GattCharacteristics,
    onFailure: (Int) -> Unit,
    private val onControlSent: (Int) -> Unit = {},
) : BleExp0EnvelopeIo {
    private val queue = BleGattSerializedValueQueue(
        start = { uuid, payload ->
            val characteristic = when (uuid) {
                BleExp0GattProfile.controlUuid -> characteristics.control
                BleExp0GattProfile.rxUuid -> characteristics.rx
                else -> null
            }
            characteristic?.let { adapter.write(it, payload) } ?: BleGattStatus.FAILED
        },
        onFailure = onFailure,
    )

    override fun enqueueControl(ciphertext: ByteArray): Boolean =
        queue.enqueue(BleExp0GattProfile.controlUuid, ciphertext)

    override fun enqueueFrame(frame: ByteArray): Boolean =
        queue.enqueue(BleExp0GattProfile.rxUuid, frame)

    fun onCharacteristicWrite(characteristic: UUID, status: Int) {
        queue.onOperationComplete(characteristic, status)
        if (characteristic == BleExp0GattProfile.controlUuid) onControlSent(status)
    }

    override fun disconnect() {
        queue.close()
        adapter.close()
    }
}

/** Peripheral-side Noise controls and exp0 frames share one notification queue. */
internal class BleExp0PeripheralEnvelopeIo(
    private val adapter: BleGattPeripheralAdapter,
    private val device: BluetoothDevice,
    private val characteristics: BleExp0GattCharacteristics,
    onFailure: (Int) -> Unit,
    private val onControlSent: (Int) -> Unit = {},
) : BleExp0EnvelopeIo {
    private val queue = BleGattSerializedValueQueue(
        start = { uuid, payload ->
            val characteristic = when (uuid) {
                BleExp0GattProfile.controlUuid -> characteristics.control
                BleExp0GattProfile.txUuid -> characteristics.tx
                else -> null
            }
            characteristic?.let { adapter.notify(device, it, payload) } ?: BleGattStatus.FAILED
        },
        onFailure = onFailure,
    )

    override fun enqueueControl(ciphertext: ByteArray): Boolean =
        queue.enqueue(BleExp0GattProfile.controlUuid, ciphertext)

    override fun enqueueFrame(frame: ByteArray): Boolean =
        queue.enqueue(BleExp0GattProfile.txUuid, frame)

    fun onNotificationSent(peer: BluetoothDevice, status: Int) {
        if (peer != device) return
        val sentControl = queue.activeCharacteristic() == BleExp0GattProfile.controlUuid
        queue.onOperationComplete(status)
        if (sentControl) onControlSent(status)
    }
    override fun disconnect() {
        queue.close()
        adapter.disconnect(device)
    }
}

package com.astraive.lattice

import android.annotation.SuppressLint
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCallback
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothStatusCodes
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.util.UUID

internal enum class BleGattStatus {
    /** Accepted by the local Android stack; not evidence of peer delivery. */
    STARTED,
    PERMISSION_MISSING,
    ADAPTER_UNAVAILABLE,
    BLUETOOTH_OFF,
    NOT_CONNECTED,
    INVALID_PAYLOAD,
    FAILED,
}

/** Android 12+ protects GATT operations with CONNECT; earlier releases grant it at install time. */
internal object BleGattPermissionPolicy {
    @SuppressLint("InlinedApi")
    fun requiredRuntimePermissions(apiLevel: Int): Set<String> =
        if (apiLevel >= Build.VERSION_CODES.S) {
            setOf(android.Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            emptySet()
        }

    fun hasConnectPermission(context: Context): Boolean =
        requiredRuntimePermissions(Build.VERSION.SDK_INT).all {
            context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        }
}

internal interface BleGattCentralListener {
    fun onConnectionChanged(connected: Boolean)
    fun onServicesDiscovered(status: Int, services: List<BluetoothGattService>)
    fun onCharacteristicChanged(characteristic: UUID, value: ByteArray)
    fun onCharacteristicWrite(characteristic: UUID, status: Int)
    fun onDescriptorWrite(descriptor: UUID, status: Int)
    fun onFailure(status: Int)
}

/** A bounded central/client adapter. Authentication and frame policy stay above GATT. */
internal class BleGattCentralAdapter(
    context: Context,
    private val listener: BleGattCentralListener,
    private val maxAttributeBytes: Int = MAX_GATT_ATTRIBUTE_BYTES,
) {
    private val appContext = context.applicationContext
    private val lock = Any()
    private var gatt: BluetoothGatt? = null

    init {
        require(maxAttributeBytes in 1..MAX_GATT_ATTRIBUTE_BYTES)
    }

    @SuppressLint("MissingPermission")
    fun connect(device: BluetoothDevice): BleGattStatus = synchronized(lock) {
        if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
            return BleGattStatus.PERMISSION_MISSING
        }
        if (gatt != null) return BleGattStatus.FAILED
        val adapter = try {
            appContext.getSystemService(BluetoothManager::class.java)?.adapter
        } catch (_: SecurityException) {
            return BleGattStatus.PERMISSION_MISSING
        } ?: return BleGattStatus.ADAPTER_UNAVAILABLE
        val enabled = try {
            adapter.isEnabled
        } catch (_: SecurityException) {
            return BleGattStatus.PERMISSION_MISSING
        }
        if (!enabled) return BleGattStatus.BLUETOOTH_OFF
        try {
            gatt = device.connectGatt(appContext, false, callback, BluetoothDevice.TRANSPORT_LE)
                ?: return BleGattStatus.FAILED
            BleGattStatus.STARTED
        } catch (_: SecurityException) {
            BleGattStatus.PERMISSION_MISSING
        } catch (_: RuntimeException) {
            BleGattStatus.FAILED
        }
    }

    @SuppressLint("MissingPermission")
    fun discoverServices(): BleGattStatus = synchronized(lock) {
        if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
            return BleGattStatus.PERMISSION_MISSING
        }
        val current = gatt ?: return BleGattStatus.NOT_CONNECTED
        try {
            if (current.discoverServices()) BleGattStatus.STARTED else BleGattStatus.FAILED
        } catch (_: SecurityException) {
            BleGattStatus.PERMISSION_MISSING
        } catch (_: RuntimeException) {
            BleGattStatus.FAILED
        }
    }

    @SuppressLint("MissingPermission")
    fun write(characteristic: BluetoothGattCharacteristic, payload: ByteArray): BleGattStatus =
        synchronized(lock) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                return BleGattStatus.PERMISSION_MISSING
            }
            val current = gatt ?: return BleGattStatus.NOT_CONNECTED
            if (payload.isEmpty() || payload.size > maxAttributeBytes) {
                return BleGattStatus.INVALID_PAYLOAD
            }
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    if (
                        current.writeCharacteristic(
                            characteristic,
                            payload,
                            BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT,
                        ) == BluetoothStatusCodes.SUCCESS
                    ) {
                        BleGattStatus.STARTED
                    } else {
                        BleGattStatus.FAILED
                    }
                } else {
                    @Suppress("DEPRECATION")
                    run {
                        characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT
                        characteristic.value = payload.copyOf()
                        if (current.writeCharacteristic(characteristic)) {
                            BleGattStatus.STARTED
                        } else {
                            BleGattStatus.FAILED
                        }
                    }
                }
            } catch (_: SecurityException) {
                BleGattStatus.PERMISSION_MISSING
            } catch (_: RuntimeException) {
                BleGattStatus.FAILED
            }
        }

    @SuppressLint("MissingPermission")
    fun setNotifications(
        characteristic: BluetoothGattCharacteristic,
        descriptor: BluetoothGattDescriptor,
        enabled: Boolean,
    ): BleGattStatus = synchronized(lock) {
        if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
            return BleGattStatus.PERMISSION_MISSING
        }
        val current = gatt ?: return BleGattStatus.NOT_CONNECTED
        try {
            if (!current.setCharacteristicNotification(characteristic, enabled)) {
                return BleGattStatus.FAILED
            }
            val descriptorValue = if (enabled) {
                BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            } else {
                BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (current.writeDescriptor(descriptor, descriptorValue) == BluetoothStatusCodes.SUCCESS) {
                    BleGattStatus.STARTED
                } else {
                    BleGattStatus.FAILED
                }
            } else {
                @Suppress("DEPRECATION")
                run {
                    descriptor.value = descriptorValue
                    if (current.writeDescriptor(descriptor)) BleGattStatus.STARTED else BleGattStatus.FAILED
                }
            }
        } catch (_: SecurityException) {
            BleGattStatus.PERMISSION_MISSING
        } catch (_: RuntimeException) {
            BleGattStatus.FAILED
        }
    }

    @SuppressLint("MissingPermission")
    fun close() {
        val current = synchronized(lock) {
            val closing = gatt
            gatt = null
            closing
        } ?: return
        try {
            current.disconnect()
        } catch (_: SecurityException) {
            // Permission revocation must not keep the local GATT handle alive.
        } catch (_: RuntimeException) {
            // The peer or radio may already have closed the connection.
        } finally {
            try {
                current.close()
            } catch (_: SecurityException) {
                // Release is best-effort after permission revocation.
            } catch (_: RuntimeException) {
                // The platform may have already released the handle.
            }
        }
    }

    private val callback = object : BluetoothGattCallback() {
        @SuppressLint("MissingPermission")
        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val connected = status == BluetoothGatt.GATT_SUCCESS &&
                newState == BluetoothGatt.STATE_CONNECTED
            if (!connected && newState == BluetoothGatt.STATE_DISCONNECTED) {
                synchronized(lock) {
                    if (this@BleGattCentralAdapter.gatt === gatt) {
                        this@BleGattCentralAdapter.gatt = null
                    }
                }
                try {
                    gatt.close()
                } catch (_: SecurityException) {
                    // The handle is no longer usable after permission revocation.
                } catch (_: RuntimeException) {
                    // The platform may already have closed this handle.
                }
            }
            listener.onConnectionChanged(connected)
            if (status != BluetoothGatt.GATT_SUCCESS) listener.onFailure(status)
        }

        @SuppressLint("MissingPermission")
        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            try {
                listener.onServicesDiscovered(
                    status,
                    if (status == BluetoothGatt.GATT_SUCCESS) gatt.services.toList() else emptyList(),
                )
            } catch (_: SecurityException) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
            } catch (_: RuntimeException) {
                listener.onFailure(BluetoothGatt.GATT_FAILURE)
            }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
        ) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            @Suppress("DEPRECATION")
            val value = characteristic.value?.copyOf() ?: return
            if (value.size <= maxAttributeBytes) {
                listener.onCharacteristicChanged(characteristic.uuid, value)
            } else {
                listener.onFailure(BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH)
            }
        }

        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
        ) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            if (value.size <= maxAttributeBytes) {
                listener.onCharacteristicChanged(characteristic.uuid, value.copyOf())
            } else {
                listener.onFailure(BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH)
            }
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            listener.onCharacteristicWrite(characteristic.uuid, status)
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int,
        ) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            listener.onDescriptorWrite(descriptor.uuid, status)
        }
    }

    private companion object {
        const val MAX_GATT_ATTRIBUTE_BYTES = 512
    }
}

internal interface BleGattPeripheralListener {
    fun onPeerConnected(device: BluetoothDevice)
    fun onPeerDisconnected(device: BluetoothDevice)
    fun onCharacteristicWrite(device: BluetoothDevice, characteristic: UUID, value: ByteArray)
    fun onServiceAdded(status: Int)
    fun onFailure(status: Int)
}

/** A bounded peripheral/server adapter. It does not advertise or authenticate peers. */
internal class BleGattPeripheralAdapter(
    context: Context,
    private val listener: BleGattPeripheralListener,
    private val maxAttributeBytes: Int = MAX_GATT_ATTRIBUTE_BYTES,
) {
    private val appContext = context.applicationContext
    private val lock = Any()
    private var server: BluetoothGattServer? = null

    init {
        require(maxAttributeBytes in 1..MAX_GATT_ATTRIBUTE_BYTES)
    }

    @SuppressLint("MissingPermission")
    fun open(): BleGattStatus = synchronized(lock) {
        if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
            return BleGattStatus.PERMISSION_MISSING
        }
        if (server != null) return BleGattStatus.FAILED
        val manager = try {
            appContext.getSystemService(BluetoothManager::class.java)
        } catch (_: SecurityException) {
            return BleGattStatus.PERMISSION_MISSING
        } ?: return BleGattStatus.ADAPTER_UNAVAILABLE
        val adapter = try {
            manager.adapter
        } catch (_: SecurityException) {
            return BleGattStatus.PERMISSION_MISSING
        } ?: return BleGattStatus.ADAPTER_UNAVAILABLE
        val enabled = try {
            adapter.isEnabled
        } catch (_: SecurityException) {
            return BleGattStatus.PERMISSION_MISSING
        }
        if (!enabled) return BleGattStatus.BLUETOOTH_OFF
        try {
            server = manager.openGattServer(appContext, callback)
                ?: return BleGattStatus.ADAPTER_UNAVAILABLE
            BleGattStatus.STARTED
        } catch (_: SecurityException) {
            BleGattStatus.PERMISSION_MISSING
        } catch (_: RuntimeException) {
            BleGattStatus.FAILED
        }
    }

    @SuppressLint("MissingPermission")
    fun addService(service: BluetoothGattService): BleGattStatus = synchronized(lock) {
        if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
            return BleGattStatus.PERMISSION_MISSING
        }
        val current = server ?: return BleGattStatus.NOT_CONNECTED
        try {
            if (current.addService(service)) BleGattStatus.STARTED else BleGattStatus.FAILED
        } catch (_: SecurityException) {
            BleGattStatus.PERMISSION_MISSING
        } catch (_: RuntimeException) {
            BleGattStatus.FAILED
        }
    }

    @SuppressLint("MissingPermission")
    fun notify(
        device: BluetoothDevice,
        characteristic: BluetoothGattCharacteristic,
        payload: ByteArray,
    ): BleGattStatus = synchronized(lock) {
        if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
            return BleGattStatus.PERMISSION_MISSING
        }
        val current = server ?: return BleGattStatus.NOT_CONNECTED
        if (payload.isEmpty() || payload.size > maxAttributeBytes) {
            return BleGattStatus.INVALID_PAYLOAD
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (
                    current.notifyCharacteristicChanged(
                        device,
                        characteristic,
                        false,
                        payload,
                    ) == BluetoothStatusCodes.SUCCESS
                ) {
                    BleGattStatus.STARTED
                } else {
                    BleGattStatus.FAILED
                }
            } else {
                @Suppress("DEPRECATION")
                run {
                    characteristic.value = payload.copyOf()
                    if (current.notifyCharacteristicChanged(device, characteristic, false)) {
                        BleGattStatus.STARTED
                    } else {
                        BleGattStatus.FAILED
                    }
                }
            }
        } catch (_: SecurityException) {
            BleGattStatus.PERMISSION_MISSING
        } catch (_: RuntimeException) {
            BleGattStatus.FAILED
        }
    }

    @SuppressLint("MissingPermission")
    fun close() {
        val current = synchronized(lock) {
            val closing = server
            server = null
            closing
        } ?: return
        try {
            current.close()
        } catch (_: SecurityException) {
            // Permission revocation must not keep the local GATT handle alive.
        } catch (_: RuntimeException) {
            // The adapter or process lifecycle may already have closed the server.
        }
    }

    private val callback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            when {
                status != BluetoothGatt.GATT_SUCCESS -> listener.onFailure(status)
                newState == BluetoothGatt.STATE_CONNECTED -> listener.onPeerConnected(device)
                newState == BluetoothGatt.STATE_DISCONNECTED -> listener.onPeerDisconnected(device)
            }
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            listener.onServiceAdded(status)
        }

        @SuppressLint("MissingPermission")
        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            val status = when {
                preparedWrite || offset != 0 -> BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
                value.isEmpty() || value.size > maxAttributeBytes ->
                    BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH
                else -> BluetoothGatt.GATT_SUCCESS
            }
            if (status == BluetoothGatt.GATT_SUCCESS) {
                listener.onCharacteristicWrite(device, characteristic.uuid, value.copyOf())
            }
            if (responseNeeded) {
                try {
                    synchronized(lock) {
                        if (BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                            server?.sendResponse(device, requestId, status, 0, null)
                        } else {
                            listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                        }
                    }
                } catch (_: SecurityException) {
                    listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                } catch (_: RuntimeException) {
                    listener.onFailure(BluetoothGatt.GATT_FAILURE)
                }
            }
        }

        @SuppressLint("MissingPermission")
        override fun onDescriptorWriteRequest(
            device: BluetoothDevice,
            requestId: Int,
            descriptor: BluetoothGattDescriptor,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray,
        ) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            val supported = descriptor.uuid == CLIENT_CONFIGURATION_DESCRIPTOR_UUID &&
                !preparedWrite && offset == 0 &&
                (value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) ||
                    value.contentEquals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE) ||
                    value.contentEquals(BluetoothGattDescriptor.ENABLE_INDICATION_VALUE))
            val status = if (supported) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
            if (supported) descriptor.value = value.copyOf()
            if (responseNeeded) {
                try {
                    synchronized(lock) {
                        if (BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                            server?.sendResponse(device, requestId, status, 0, null)
                        } else {
                            listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                        }
                    }
                } catch (_: SecurityException) {
                    listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                } catch (_: RuntimeException) {
                    listener.onFailure(BluetoothGatt.GATT_FAILURE)
                }
            }
        }
    }

    private companion object {
        const val MAX_GATT_ATTRIBUTE_BYTES = 512
        val CLIENT_CONFIGURATION_DESCRIPTOR_UUID: UUID =
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")
    }
}

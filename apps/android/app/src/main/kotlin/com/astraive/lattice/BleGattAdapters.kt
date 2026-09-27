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
    NOT_SUBSCRIBED,
    INVALID_PAYLOAD,
    INVALID_MTU,
    FAILED,
}

internal data class BleExp0GattCharacteristics(
    val control: BluetoothGattCharacteristic,
    val rx: BluetoothGattCharacteristic,
    val tx: BluetoothGattCharacteristic,
    val capabilities: BluetoothGattCharacteristic,
    val upgrade: BluetoothGattCharacteristic,
)

/** EXPERIMENTAL exp0 service layout; profile semantics remain above Android GATT. */
internal object BleExp0GattProfile {
    val serviceUuid: UUID = UUID.fromString("1c9a0000-7d31-4f6a-9b43-4c4154544943")
    val controlUuid: UUID = UUID.fromString("1c9a0002-7d31-4f6a-9b43-4c4154544943")
    val rxUuid: UUID = UUID.fromString("1c9a0003-7d31-4f6a-9b43-4c4154544943")
    val txUuid: UUID = UUID.fromString("1c9a0004-7d31-4f6a-9b43-4c4154544943")
    val capabilitiesUuid: UUID = UUID.fromString("1c9a0005-7d31-4f6a-9b43-4c4154544943")
    val upgradeUuid: UUID = UUID.fromString("1c9a0006-7d31-4f6a-9b43-4c4154544943")
    val capabilitiesValue: ByteArray get() = byteArrayOf(0, 0, 0)
    val clientConfigurationUuid: UUID =
        UUID.fromString("00002902-0000-1000-8000-00805f9b34fb")

    fun newService(): Pair<BluetoothGattService, BleExp0GattCharacteristics> {
        val service = BluetoothGattService(
            serviceUuid,
            BluetoothGattService.SERVICE_TYPE_PRIMARY,
        )
        val control = characteristic(
            controlUuid,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
            notifications = true,
        )
        val rx = characteristic(
            rxUuid,
            BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
        )
        val tx = characteristic(
            txUuid,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            0,
            notifications = true,
        )
        val capabilities = characteristic(
            capabilitiesUuid,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ,
        ).apply { value = capabilitiesValue }
        val upgrade = characteristic(
            upgradeUuid,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_WRITE,
            notifications = true,
        )
        listOf(control, rx, tx, capabilities, upgrade).forEach { service.addCharacteristic(it) }
        return service to BleExp0GattCharacteristics(control, rx, tx, capabilities, upgrade)
    }

    private fun characteristic(
        uuid: UUID,
        properties: Int,
        permissions: Int,
        notifications: Boolean = false,
    ): BluetoothGattCharacteristic =
        BluetoothGattCharacteristic(uuid, properties, permissions).apply {
            if (notifications) {
                addDescriptor(
                    BluetoothGattDescriptor(
                        clientConfigurationUuid,
                        BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE,
                    ),
                )
            }
        }
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
    fun onMtuChanged(mtu: Int, status: Int)
    fun onServicesDiscovered(status: Int, services: List<BluetoothGattService>)
    fun onCharacteristicChanged(characteristic: UUID, value: ByteArray)
    fun onCharacteristicRead(characteristic: UUID, value: ByteArray, status: Int)
    fun onCharacteristicWrite(characteristic: UUID, status: Int)
    fun onDescriptorWrite(characteristic: UUID, descriptor: UUID, status: Int)
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
    fun requestMtu(mtu: Int): BleGattStatus = synchronized(lock) {
        if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
            return BleGattStatus.PERMISSION_MISSING
        }
        val current = gatt ?: return BleGattStatus.NOT_CONNECTED
        if (mtu !in MIN_ATT_MTU..MAX_ATT_MTU) return BleGattStatus.INVALID_MTU
        try {
            if (current.requestMtu(mtu)) BleGattStatus.STARTED else BleGattStatus.FAILED
        } catch (_: SecurityException) {
            BleGattStatus.PERMISSION_MISSING
        } catch (_: RuntimeException) {
            BleGattStatus.FAILED
        }
    }

    @SuppressLint("MissingPermission")
    fun read(characteristic: BluetoothGattCharacteristic): BleGattStatus = synchronized(lock) {
        if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
            return BleGattStatus.PERMISSION_MISSING
        }
        val current = gatt ?: return BleGattStatus.NOT_CONNECTED
        try {
            if (current.readCharacteristic(characteristic)) BleGattStatus.STARTED else BleGattStatus.FAILED
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

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            listener.onMtuChanged(mtu, status)
        }
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

        @Suppress("DEPRECATION")
        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int,
        ) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            val value = characteristic.value?.copyOf() ?: ByteArray(0)
            if (value.size <= maxAttributeBytes) {
                listener.onCharacteristicRead(characteristic.uuid, value, status)
            } else {
                listener.onFailure(BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH)
            }
        }

        override fun onCharacteristicRead(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray,
            status: Int,
        ) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            if (value.size <= maxAttributeBytes) {
                listener.onCharacteristicRead(characteristic.uuid, value.copyOf(), status)
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
            val characteristicUuid = descriptor.characteristic?.uuid
            if (characteristicUuid == null) {
                listener.onFailure(BluetoothGatt.GATT_FAILURE)
                return
            }
            listener.onDescriptorWrite(characteristicUuid, descriptor.uuid, status)
        }
    }

    private companion object {
        const val MAX_GATT_ATTRIBUTE_BYTES = 512
        const val MIN_ATT_MTU = 23
        const val MAX_ATT_MTU = 517
    }
}

internal interface BleGattPeripheralListener {
    fun onPeerConnected(device: BluetoothDevice)
    fun onPeerDisconnected(device: BluetoothDevice)
    fun onCharacteristicWrite(device: BluetoothDevice, characteristic: UUID, value: ByteArray)
    fun onNotificationSubscriptionChanged(device: BluetoothDevice, characteristic: UUID, enabled: Boolean)
    fun onServiceAdded(status: Int)
    fun onFailure(status: Int)
    fun onMtuChanged(device: BluetoothDevice, mtu: Int)
    fun onNotificationSent(device: BluetoothDevice, status: Int)
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
    private val notificationSubscriptions = mutableMapOf<BluetoothDevice, MutableSet<UUID>>()

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
        if (characteristic.uuid !in notificationSubscriptions[device].orEmpty()) {
            return BleGattStatus.NOT_SUBSCRIBED
        }
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
    fun disconnect(device: BluetoothDevice): BleGattStatus = synchronized(lock) {
        if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
            return BleGattStatus.PERMISSION_MISSING
        }
        val current = server ?: return BleGattStatus.NOT_CONNECTED
        try {
            current.cancelConnection(device)
            BleGattStatus.STARTED
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
            notificationSubscriptions.clear()
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
        @SuppressLint("MissingPermission")
        override fun onCharacteristicReadRequest(
            device: BluetoothDevice,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic,
        ) {
            if (!BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                listener.onFailure(BluetoothGatt.GATT_INSUFFICIENT_AUTHENTICATION)
                return
            }
            val response = if (
                characteristic.uuid == BleExp0GattProfile.capabilitiesUuid &&
                offset == 0
            ) {
                BleExp0GattProfile.capabilitiesValue
            } else {
                null
            }
            val status = when {
                response != null -> BluetoothGatt.GATT_SUCCESS
                characteristic.uuid == BleExp0GattProfile.capabilitiesUuid ->
                    BluetoothGatt.GATT_INVALID_OFFSET
                else -> BluetoothGatt.GATT_READ_NOT_PERMITTED
            }
            try {
                synchronized(lock) {
                    if (BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                        server?.sendResponse(device, requestId, status, 0, response)
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
        override fun onConnectionStateChange(device: BluetoothDevice, status: Int, newState: Int) {
            when {
                newState == BluetoothGatt.STATE_DISCONNECTED -> {
                    synchronized(lock) { notificationSubscriptions.remove(device) }
                    listener.onPeerDisconnected(device)
                    if (status != BluetoothGatt.GATT_SUCCESS) listener.onFailure(status)
                }
                status != BluetoothGatt.GATT_SUCCESS -> listener.onFailure(status)
                newState == BluetoothGatt.STATE_CONNECTED -> listener.onPeerConnected(device)
            }
        }
        override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
            listener.onMtuChanged(device, mtu)
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService) {
            listener.onServiceAdded(status)
        }
        override fun onNotificationSent(device: BluetoothDevice, status: Int) {
            listener.onNotificationSent(device, status)
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
            val supportedCharacteristic = characteristic.uuid == BleExp0GattProfile.controlUuid ||
                characteristic.uuid == BleExp0GattProfile.rxUuid ||
                characteristic.uuid == BleExp0GattProfile.upgradeUuid
            val status = when {
                preparedWrite || offset != 0 -> BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
                !supportedCharacteristic -> BluetoothGatt.GATT_WRITE_NOT_PERMITTED
                value.isEmpty() || value.size > maxAttributeBytes ->
                    BluetoothGatt.GATT_INVALID_ATTRIBUTE_LENGTH
                else -> BluetoothGatt.GATT_SUCCESS
            }
            var responseAccepted = !responseNeeded
            if (responseNeeded) {
                try {
                    synchronized(lock) {
                        if (BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                            responseAccepted = server?.sendResponse(device, requestId, status, 0, null) == true
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
            if (status == BluetoothGatt.GATT_SUCCESS && responseAccepted) {
                listener.onCharacteristicWrite(device, characteristic.uuid, value.copyOf())
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
            val characteristicUuid = descriptor.characteristic?.uuid
            val notificationCharacteristic = characteristicUuid == BleExp0GattProfile.controlUuid ||
                characteristicUuid == BleExp0GattProfile.txUuid ||
                characteristicUuid == BleExp0GattProfile.upgradeUuid
            val enabled = value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) ||
                value.contentEquals(BluetoothGattDescriptor.ENABLE_INDICATION_VALUE)
            val supported = descriptor.uuid == BleExp0GattProfile.clientConfigurationUuid &&
                notificationCharacteristic && !preparedWrite && offset == 0 &&
                (enabled || value.contentEquals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE))
            val status = if (supported) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_REQUEST_NOT_SUPPORTED
            var responseAccepted = !responseNeeded
            if (responseNeeded) {
                try {
                    synchronized(lock) {
                        if (BleGattPermissionPolicy.hasConnectPermission(appContext)) {
                            responseAccepted = server?.sendResponse(device, requestId, status, 0, null) == true
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
            if (supported && responseAccepted) {
                descriptor.value = value.copyOf()
                val characteristic = checkNotNull(characteristicUuid)
                synchronized(lock) {
                    if (enabled) {
                        notificationSubscriptions.getOrPut(device) { mutableSetOf() }.add(characteristic)
                    } else {
                        notificationSubscriptions[device]?.let { subscriptions ->
                            subscriptions.remove(characteristic)
                            if (subscriptions.isEmpty()) notificationSubscriptions.remove(device)
                        }
                    }
                }
                listener.onNotificationSubscriptionChanged(device, characteristic, enabled)
            }
        }
    }

    private companion object {
        const val MAX_GATT_ATTRIBUTE_BYTES = 512
    }
}

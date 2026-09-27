package com.astraive.lattice

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattService
import android.content.Context
import android.os.Handler
import android.os.SystemClock
import android.os.Looper
import uniffi.lattice_uniffi.MobileBlePeerInfo
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import uniffi.lattice_uniffi.MobileBleRole
import java.util.UUID

/** Owns one user-selected central connection from service discovery through authenticated transport. */
internal class BleExp0CentralSession(
    context: Context,
    private val profile: AndroidMobileProfile,
    private val device: BluetoothDevice,
    observedResponderToken: ByteArray,
    private val isRoutedToPeer: (ByteArray) -> Boolean,
    private val retryAt: (attemptCount: UInt, nowUnixMillis: Long) -> Long,
    private val onPeerVerificationRequired: (MobileBlePeerInfo, (Boolean) -> Unit) -> Unit,
    private val onAuthenticated: (BleExp0OutboxPump, (Boolean) -> Unit) -> Unit,
    private val onFailure: (String) -> Unit,
) : BleGattCentralListener, AutoCloseable {
    private val decisionExecutor: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "lattice-ble-central").apply { isDaemon = true }
    }
    private enum class State { CONNECTING, MTU, DISCOVERY, CONTROL_CCCD, TX_CCCD, READY, CLOSED }

    private val token = observedResponderToken.copyOf()
    private val adapter = BleGattCentralAdapter(context, this)
    private val timeoutHandler = Handler(Looper.getMainLooper())
    private val setupStartedAt = SystemClock.elapsedRealtime()
    private val timeoutTask = object : Runnable {
        override fun run() {
            val (coordinator, setupTimedOut, active) = synchronized(lock) {
                Triple(
                    session,
                    session == null && SystemClock.elapsedRealtime() - setupStartedAt >= SETUP_TIMEOUT_MS,
                    state != State.CLOSED,
                )
            }
            if (coordinator?.expire() == true) close()
            else if (setupTimedOut) fail("GATT connection setup timed out")
            else if (active) timeoutHandler.postDelayed(this, TIMER_INTERVAL_MS)
        }
    }
    private val lock = Any()
    private var state = State.CONNECTING
    private var mtu = 0
    private var characteristics: BleExp0GattCharacteristics? = null
    private var envelopeIo: BleExp0CentralEnvelopeIo? = null
    private var session: BleExp0SessionCoordinator? = null

    init {
        require(token.size == BleExp0Advertisement.TOKEN_BYTES)
    }

    fun connect(): BleGattStatus {
        val result = adapter.connect(device)
        if (result != BleGattStatus.STARTED) fail("GATT connection could not start ($result)")
        else timeoutHandler.postDelayed(timeoutTask, TIMER_INTERVAL_MS)
        return result
    }

    override fun onConnectionChanged(connected: Boolean) {
        if (!connected) {
            fail("GATT peer disconnected")
            return
        }
        synchronized(lock) {
            if (state != State.CONNECTING) return
            state = State.MTU
        }
        when (val status = adapter.requestMtu(MAX_REQUESTED_MTU)) {
            BleGattStatus.STARTED -> Unit
            else -> fail("GATT MTU negotiation could not start ($status)")
        }
    }

    override fun onMtuChanged(mtu: Int, status: Int) {
        if (status != BluetoothGatt.GATT_SUCCESS || mtu < BleExp0TransferProtocol.MIN_ATT_MTU) {
            fail("GATT negotiated an unsupported MTU ($mtu, status $status)")
            return
        }
        synchronized(lock) {
            if (state != State.MTU) return
            this.mtu = mtu
            state = State.DISCOVERY
        }
        when (val result = adapter.discoverServices()) {
            BleGattStatus.STARTED -> Unit
            else -> fail("GATT service discovery could not start ($result)")
        }
    }

    override fun onServicesDiscovered(status: Int, services: List<BluetoothGattService>) {
        if (status != BluetoothGatt.GATT_SUCCESS) {
            fail("GATT service discovery failed ($status)")
            return
        }
        val service = services.firstOrNull { it.uuid == BleExp0GattProfile.serviceUuid }
            ?: return fail("The peer does not expose the exp0 GATT service")
        val discovered = characteristicSet(service) ?: return fail("The exp0 GATT service is incomplete")
        synchronized(lock) {
            if (state != State.DISCOVERY) return
            characteristics = discovered
            state = State.CONTROL_CCCD
        }
        when (val result = adapter.setNotifications(
            discovered.control,
            requireNotNull(discovered.control.getDescriptor(BleExp0GattProfile.clientConfigurationUuid)),
            true,
        )) {
            BleGattStatus.STARTED -> Unit
            else -> fail("GATT control notifications could not start ($result)")
        }
    }

    override fun onDescriptorWrite(characteristic: UUID, descriptor: UUID, status: Int) {
        if (descriptor != BleExp0GattProfile.clientConfigurationUuid || status != BluetoothGatt.GATT_SUCCESS) {
            fail("GATT notification subscription failed ($status)")
            return
        }
        
        val discovered = synchronized(lock) { characteristics } ?: return fail("GATT characteristics disappeared")
        when (synchronized(lock) { state }) {
            State.CONTROL_CCCD -> {
                if (characteristic != BleExp0GattProfile.controlUuid) return fail("Unexpected control subscription response")
                synchronized(lock) { state = State.TX_CCCD }
                when (val result = adapter.setNotifications(
                    discovered.tx,
                    requireNotNull(discovered.tx.getDescriptor(BleExp0GattProfile.clientConfigurationUuid)),
                    true,
                )) {
                    BleGattStatus.STARTED -> Unit
                    else -> fail("GATT frame notifications could not start ($result)")
                }
            }
            State.TX_CCCD -> {
                if (characteristic != BleExp0GattProfile.txUuid) return fail("Unexpected frame subscription response")
                startAuthenticatedSession(discovered)
            }
            else -> fail("Unexpected GATT descriptor completion")
        }
    }

    override fun onCharacteristicChanged(characteristic: UUID, value: ByteArray) {
        val coordinator = synchronized(lock) { session } ?: return fail("GATT data arrived before session setup")
        when (characteristic) {
            BleExp0GattProfile.controlUuid -> coordinator.receiveControl(value)
            BleExp0GattProfile.txUuid -> coordinator.receiveFrame(value)
            else -> fail("Unexpected exp0 characteristic notification")
        }
    }

    override fun onCharacteristicRead(characteristic: UUID, value: ByteArray, status: Int) {
        fail("Unexpected GATT characteristic read callback ($status)")
    }

    override fun onCharacteristicWrite(characteristic: UUID, status: Int) {
        if (characteristic != BleExp0GattProfile.controlUuid && characteristic != BleExp0GattProfile.rxUuid) {
            fail("Unexpected GATT write completion")
            return
        }
        envelopeIo?.onCharacteristicWrite(characteristic, status)
    }

    override fun onFailure(status: Int) = fail("Android GATT failed ($status)")

    override fun close() {
        val current = synchronized(lock) {
            if (state == State.CLOSED) return
            state = State.CLOSED
            session.also { session = null }
        }
        timeoutHandler.removeCallbacks(timeoutTask)
        decisionExecutor.shutdownNow()
        current?.close() ?: adapter.close()
        token.fill(0)
        synchronized(lock) {
            characteristics = null
            envelopeIo = null
        }
    }

    private fun startAuthenticatedSession(discovered: BleExp0GattCharacteristics) {
        synchronized(lock) {
            if (state != State.TX_CCCD) return
            state = State.READY
        }
        val io = BleExp0CentralEnvelopeIo(
            adapter = adapter,
            characteristics = discovered,
            onFailure = { status -> fail("GATT write queue failed ($status)") },
            onControlSent = { status -> session?.onControlWriteCompleted(status) },
        )
        val coordinator = try {
            BleExp0SessionCoordinator(
                profile = profile,
                role = MobileBleRole.INITIATOR,
                responderToken = { token.takeIf { it.isNotEmpty() }?.copyOf() },
                negotiatedMtu = mtu,
                io = io,
                isRoutedToPeer = isRoutedToPeer,
                retryAt = retryAt,
                onPeerVerificationRequired = onPeerVerificationRequired,
                decisionExecutor = decisionExecutor,
                onAuthenticated = onAuthenticated,
                onFailure = onFailure,
            )
        } catch (error: Exception) {
            io.disconnect()
            fail(error.message ?: "Authenticated GATT session could not be created")
            return
        }
        synchronized(lock) {
            envelopeIo = io
            session = coordinator
        }
        coordinator.start()
    }

    private fun characteristicSet(service: BluetoothGattService): BleExp0GattCharacteristics? {
        val control = service.getCharacteristic(BleExp0GattProfile.controlUuid) ?: return null
        val rx = service.getCharacteristic(BleExp0GattProfile.rxUuid) ?: return null
        val tx = service.getCharacteristic(BleExp0GattProfile.txUuid) ?: return null
        val capabilities = service.getCharacteristic(BleExp0GattProfile.capabilitiesUuid) ?: return null
        val upgrade = service.getCharacteristic(BleExp0GattProfile.upgradeUuid) ?: return null
        if (control.getDescriptor(BleExp0GattProfile.clientConfigurationUuid) == null ||
            tx.getDescriptor(BleExp0GattProfile.clientConfigurationUuid) == null
        ) return null
        return BleExp0GattCharacteristics(control, rx, tx, capabilities, upgrade)
    }

    private fun fail(message: String) {
        val shouldNotify = synchronized(lock) { state != State.CLOSED }
        if (!shouldNotify) return
        onFailure(message)
        close()
    }

    private companion object {
        const val MAX_REQUESTED_MTU = 517
        const val TIMER_INTERVAL_MS = 1_000L
        const val SETUP_TIMEOUT_MS = 30_000L
    }
}

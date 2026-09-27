package com.astraive.lattice

import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattService
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import uniffi.lattice_uniffi.MobileBlePeerInfo
import uniffi.lattice_uniffi.MobileBleRole
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.UUID

/** Owns one experimental GATT server peer and its responder authentication/session lifecycle. */
internal class BleExp0PeripheralSession(
    context: Context,
    private val profile: AndroidMobileProfile,
    private val activeResponderToken: () -> ByteArray?,
    private val isRoutedToPeer: (ByteArray) -> Boolean,
    private val retryAt: (attemptCount: UInt, nowUnixMillis: Long) -> Long,
    private val onAuthenticated: (BleExp0OutboxPump, (Boolean) -> Unit) -> Unit,
    private val onPeerVerificationRequired: (MobileBlePeerInfo, (Boolean) -> Unit) -> Unit,
    private val onFailure: (String) -> Unit,
) : BleGattPeripheralListener, AutoCloseable {
    private val lock = Any()
    private val adapter = BleGattPeripheralAdapter(context, this)
    private val decisionExecutor: ExecutorService = Executors.newSingleThreadExecutor { task ->
        Thread(task, "lattice-ble-peripheral").apply { isDaemon = true }
    }
    private val timeoutHandler = Handler(Looper.getMainLooper())
    private val timeoutTask = object : Runnable {
        override fun run() {
            val (current, setupTimedOut, active) = synchronized(lock) {
                Triple(
                    session,
                    session == null && peerConnectedAt?.let {
                        SystemClock.elapsedRealtime() - it >= SETUP_TIMEOUT_MS
                    } == true,
                    !closed,
                )
            }
            if (current?.expire() == true) clearPeer(disconnectPeer = true)
            else if (setupTimedOut) {
                fail("GATT peer setup timed out")
            }
            if (active) timeoutHandler.postDelayed(this, TIMER_INTERVAL_MS)
        }
    }
    private val service: BluetoothGattService
    private val characteristics: BleExp0GattCharacteristics
    private var peer: BluetoothDevice? = null
    private var mtu = 23
    private var serviceAdded = false
    private var controlSubscribed = false
    private var txSubscribed = false
    private var io: BleExp0PeripheralEnvelopeIo? = null
    private var peerConnectedAt: Long? = null
    private var session: BleExp0SessionCoordinator? = null
    private var closed = false

    init {
        val (newService, newCharacteristics) = BleExp0GattProfile.newService()
        service = newService
        characteristics = newCharacteristics
    }

    fun start(): BleGattStatus {
        val opened = adapter.open()
        if (opened != BleGattStatus.STARTED) {
            fail("GATT server could not open ($opened)")
            adapter.close()
            return opened
        }
        val added = adapter.addService(service)
        if (added != BleGattStatus.STARTED) {
            fail("exp0 GATT service could not be added ($added)")
            adapter.close()
        } else {
            timeoutHandler.postDelayed(timeoutTask, TIMER_INTERVAL_MS)
        }
        return added
    }

    override fun onServiceAdded(status: Int) {
        if (status != BluetoothGatt.GATT_SUCCESS) {
            fail("Android could not register the exp0 GATT service ($status)")
            return
        }
        synchronized(lock) { serviceAdded = true }
        maybeStartResponder()
    }

    override fun onPeerConnected(device: BluetoothDevice) {
        val accepted = synchronized(lock) {
            if (closed) return
            val current = peer
            if (current == null) {
                peer = device
                mtu = 23
                peerConnectedAt = SystemClock.elapsedRealtime()
                true
            } else {
                current == device
            }
        }
        if (!accepted) {
            adapter.disconnect(device)
            return
        }
    }

    override fun onPeerDisconnected(device: BluetoothDevice) {
        if (synchronized(lock) { peer == device }) clearPeer(disconnectPeer = false)
    }

    override fun onMtuChanged(device: BluetoothDevice, mtu: Int) {
        if (mtu !in BleExp0TransferProtocol.MIN_ATT_MTU..MAX_ATT_MTU) {
            if (synchronized(lock) { peer == device }) fail("Peer negotiated an unsupported GATT MTU ($mtu)")
            return
        }
        synchronized(lock) {
            if (peer != device) return
            this.mtu = mtu
        }
        maybeStartResponder()
    }

    override fun onNotificationSubscriptionChanged(device: BluetoothDevice, characteristic: UUID, enabled: Boolean) {
        synchronized(lock) {
            if (peer != device) return
            when (characteristic) {
                BleExp0GattProfile.controlUuid -> controlSubscribed = enabled
                BleExp0GattProfile.txUuid -> txSubscribed = enabled
                else -> return
            }
        }
        maybeStartResponder()
    }

    override fun onCharacteristicWrite(device: BluetoothDevice, characteristic: UUID, value: ByteArray) {
        val coordinator = synchronized(lock) {
            if (peer != device) return
            session
        } ?: return
        when (characteristic) {
            BleExp0GattProfile.controlUuid -> coordinator.receiveControl(value)
            BleExp0GattProfile.rxUuid -> coordinator.receiveFrame(value)
            else -> fail("Unsupported GATT write characteristic")
        }
    }

    override fun onNotificationSent(device: BluetoothDevice, status: Int) {
        io?.onNotificationSent(device, status)
    }

    override fun onFailure(status: Int) = fail("Android GATT server failed ($status)")

    override fun close() {
        val shouldClose = synchronized(lock) {
            if (closed) return
            closed = true
            true
        }
        if (!shouldClose) return
        decisionExecutor.shutdownNow()
        timeoutHandler.removeCallbacks(timeoutTask)
        clearPeer(disconnectPeer = true)
        adapter.close()
    }

    private fun maybeStartResponder() {
        val current = synchronized(lock) {
            if (closed || !serviceAdded || peer == null ||
                mtu < BleExp0TransferProtocol.MIN_ATT_MTU || !controlSubscribed || !txSubscribed || session != null
            ) return
            val currentPeer = peer ?: return
            currentPeer to mtu
        }
        val (device, negotiatedMtu) = current
        val newIo = BleExp0PeripheralEnvelopeIo(
            adapter = adapter,
            device = device,
            characteristics = characteristics,
            onFailure = { status -> fail("GATT notification queue failed ($status)") },
            onControlSent = { status -> session?.onControlWriteCompleted(status) },
        )
        val coordinator = try {
            BleExp0SessionCoordinator(
                profile = profile,
                role = MobileBleRole.RESPONDER,
                responderToken = activeResponderToken,
                negotiatedMtu = negotiatedMtu,
                io = newIo,
                isRoutedToPeer = isRoutedToPeer,
                decisionExecutor = decisionExecutor,
                retryAt = retryAt,
                onPeerVerificationRequired = onPeerVerificationRequired,
                onAuthenticated = onAuthenticated,
                onFailure = onFailure,
            )
        } catch (error: Exception) {
            newIo.disconnect()
            fail(error.message ?: "Responder session could not be created")
            return
        }
        synchronized(lock) {
            if (closed || peer != device || session != null) {
                coordinator.close()
                return
            }
            io = newIo
            session = coordinator
        }
        coordinator.start()
    }

    private fun clearPeer(disconnectPeer: Boolean) {
        val (currentSession, currentIo, currentPeer) = synchronized(lock) {
            val result = Triple(session, io, peer)
            session = null
            io = null
            peer = null
            mtu = 23
            controlSubscribed = false
            peerConnectedAt = null
            txSubscribed = false
            result
        }
        currentSession?.close()
        if (currentSession == null && currentIo != null) currentIo.disconnect()
        if (disconnectPeer && currentPeer != null && currentSession == null && currentIo == null) {
            adapter.disconnect(currentPeer)
        }
    }

    private fun fail(message: String) {
        if (synchronized(lock) { closed }) return
        onFailure(message)
        clearPeer(disconnectPeer = true)
    }

    private companion object {
        const val MAX_ATT_MTU = 517
        const val TIMER_INTERVAL_MS = 1_000L
        const val SETUP_TIMEOUT_MS = 30_000L
    }
}

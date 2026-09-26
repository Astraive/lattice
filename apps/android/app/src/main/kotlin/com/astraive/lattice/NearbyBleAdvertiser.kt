package com.astraive.lattice

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import java.security.SecureRandom

/** Advertises one exp0 discovery token at a time; it does not accept or authenticate GATT peers. */
internal class NearbyBleAdvertiser(
    context: Context,
    private val onFailure: (String) -> Unit,
) {
    enum class StartResult {
        STARTED,
        PERMISSION_MISSING,
        ADAPTER_UNAVAILABLE,
        BLUETOOTH_OFF,
        ADVERTISER_UNAVAILABLE,
        FAILED,
    }

    private val appContext = context.applicationContext
    private val lock = Any()
    private val handler = Handler(Looper.getMainLooper())
    private val secureRandom = SecureRandom()
    private val rotationTask = Runnable { rotateToken() }
    private var advertiser: BluetoothLeAdvertiser? = null
    private var activeCallback: AdvertiseCallback? = null
    private var activeToken: ByteArray? = null
    private var running = false

    fun start(): StartResult = synchronized(lock) {
        if (running) return@synchronized StartResult.STARTED
        if (!BleDiscoveryPermissionPolicy.hasRequiredPermissions(appContext)) {
            return@synchronized StartResult.PERMISSION_MISSING
        }
        val adapter = try {
            appContext.getSystemService(BluetoothManager::class.java)?.adapter
        } catch (_: SecurityException) {
            return@synchronized StartResult.PERMISSION_MISSING
        } ?: return@synchronized StartResult.ADAPTER_UNAVAILABLE
        val enabled = try {
            adapter.isEnabled
        } catch (_: SecurityException) {
            return@synchronized StartResult.PERMISSION_MISSING
        }
        if (!enabled) return@synchronized StartResult.BLUETOOTH_OFF
        val leAdvertiser = try {
            adapter.bluetoothLeAdvertiser
        } catch (_: SecurityException) {
            return@synchronized StartResult.PERMISSION_MISSING
        } ?: return@synchronized StartResult.ADVERTISER_UNAVAILABLE

        advertiser = leAdvertiser
        activeToken = freshToken()
        running = true
        startAdvertisingLocked(leAdvertiser, checkNotNull(activeToken)).also { result ->
            if (result != StartResult.STARTED) stopLocked()
        }
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        synchronized(lock) { stopLocked() }
    }

    @SuppressLint("MissingPermission")
    private fun startAdvertisingLocked(
        leAdvertiser: BluetoothLeAdvertiser,
        token: ByteArray,
    ): StartResult {
        val callback = object : AdvertiseCallback() {
            override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
                synchronized(lock) {
                    if (running && activeCallback === this) scheduleRotationLocked()
                }
            }

            override fun onStartFailure(errorCode: Int) {
                fail(this, "Android rejected exp0 BLE advertising (error $errorCode).")
            }
        }
        activeCallback = callback
        return try {
            leAdvertiser.startAdvertising(settings, advertisement(token), callback)
            StartResult.STARTED
        } catch (_: SecurityException) {
            activeCallback = null
            StartResult.PERMISSION_MISSING
        } catch (_: RuntimeException) {
            activeCallback = null
            StartResult.FAILED
        }
    }

    private fun scheduleRotationLocked() {
        handler.removeCallbacks(rotationTask)
        handler.postDelayed(rotationTask, BleExp0Advertisement.TOKEN_ROTATION_MILLIS)
    }

    @SuppressLint("MissingPermission")
    private fun rotateToken() {
        var failure: String? = null
        synchronized(lock) {
            if (!running) return
            val leAdvertiser = advertiser ?: return
            val previousCallback = activeCallback ?: return
            try {
                leAdvertiser.stopAdvertising(previousCallback)
                activeCallback = null
                activeToken?.fill(0)
                val nextToken = freshToken()
                activeToken = nextToken
                if (startAdvertisingLocked(leAdvertiser, nextToken) != StartResult.STARTED) {
                    stopLocked()
                    failure = "Android could not rotate the exp0 BLE discovery token."
                }
            } catch (_: SecurityException) {
                stopLocked()
                failure = "Bluetooth advertising permission was revoked."
            } catch (_: RuntimeException) {
                stopLocked()
                failure = "Android could not rotate the exp0 BLE discovery token."
            }
        }
        failure?.let(onFailure)
    }

    @SuppressLint("MissingPermission")
    private fun fail(callback: AdvertiseCallback, message: String) {
        val shouldNotify = synchronized(lock) {
            if (!running || activeCallback !== callback) {
                false
            } else {
                stopLocked()
                true
            }
        }
        if (shouldNotify) onFailure(message)
    }

    @SuppressLint("MissingPermission")
    private fun stopLocked() {
        running = false
        handler.removeCallbacks(rotationTask)
        val leAdvertiser = advertiser
        val callback = activeCallback
        advertiser = null
        activeCallback = null
        activeToken?.fill(0)
        activeToken = null
        if (leAdvertiser != null && callback != null) {
            try {
                leAdvertiser.stopAdvertising(callback)
            } catch (_: SecurityException) {
                // Permission revocation still clears the local token and callback state.
            } catch (_: RuntimeException) {
                // The platform may already have stopped the advertiser.
            }
        }
    }

    private fun freshToken(): ByteArray = ByteArray(BleExp0Advertisement.TOKEN_BYTES).also {
        secureRandom.nextBytes(it)
    }

    private fun advertisement(token: ByteArray): AdvertiseData = AdvertiseData.Builder()
        .setIncludeDeviceName(false)
        .setIncludeTxPowerLevel(false)
        .addServiceData(
            ParcelUuid(BleExp0Advertisement.SERVICE_UUID),
            BleExp0Advertisement.serviceData(token),
        )
        .build()

    private companion object {
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_POWER)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_LOW)
            .setConnectable(true)
            .setTimeout(0)
            .build()
    }
}

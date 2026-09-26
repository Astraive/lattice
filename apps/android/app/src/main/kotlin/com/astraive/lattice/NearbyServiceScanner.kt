package com.astraive.lattice

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.os.SystemClock
import android.util.Base64

/** Scans only valid exp0 service-data tokens and never reads or retains device addresses. */
internal class NearbyServiceScanner(
    context: Context,
    private val onSightingsChanged: (Int) -> Unit,
    private val onFailure: (String) -> Unit,
) {
    enum class StartResult {
        STARTED,
        PERMISSION_MISSING,
        ADAPTER_UNAVAILABLE,
        BLUETOOTH_OFF,
        SCANNER_UNAVAILABLE,
        FAILED,
    }

    private val appContext = context.applicationContext
    private val lock = Any()
    private var scanner: BluetoothLeScanner? = null
    private var callback: ScanCallback? = null
    private var running = false
    private val sightings = BleExp0SightingCache()
    private val expiryHandler = Handler(Looper.getMainLooper())
    private val expiryTask = Runnable { expireSightings() }

    fun start(): StartResult {
        synchronized(lock) {
            if (!hasScanPermissions()) return StartResult.PERMISSION_MISSING
            val adapter = try {
                bluetoothAdapter() ?: return StartResult.ADAPTER_UNAVAILABLE
            } catch (_: SecurityException) {
                return StartResult.PERMISSION_MISSING
            }
            val enabled = try {
                adapter.isEnabled
            } catch (_: SecurityException) {
                return StartResult.PERMISSION_MISSING
            }
            if (!enabled) return StartResult.BLUETOOTH_OFF
            val leScanner = try {
                adapter.bluetoothLeScanner ?: return StartResult.SCANNER_UNAVAILABLE
            } catch (_: SecurityException) {
                return StartResult.PERMISSION_MISSING
            }

            clearSession()
            val scanCallback = object : ScanCallback() {
                override fun onScanResult(callbackType: Int, result: ScanResult) {
                    record(result)
                }

                override fun onBatchScanResults(results: MutableList<ScanResult>) {
                    results.forEach(::record)
                }

                override fun onScanFailed(errorCode: Int) {
                    synchronized(lock) {
                        if (!running) return
                        running = false
                        scanner = null
                        callback = null
                        clearSession()
                    }
                    onFailure("Bluetooth scanning stopped with platform error $errorCode.")
                }
            }
            return try {
                leScanner.startScan(
                    listOf(
                        ScanFilter.Builder()
                            .setServiceData(
                                SERVICE_DATA_UUID,
                                byteArrayOf(BleExp0Advertisement.PROFILE_DISCRIMINATOR),
                                byteArrayOf(0xff.toByte()),
                            )
                            .build(),
                    ),
                    ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_POWER).build(),
                    scanCallback,
                )
                scanner = leScanner
                callback = scanCallback
                running = true
                StartResult.STARTED
            } catch (_: SecurityException) {
                clearSession()
                StartResult.PERMISSION_MISSING
            } catch (_: RuntimeException) {
                clearSession()
                StartResult.FAILED
            }
        }
    }

    fun stop() {
        synchronized(lock) {
            val currentScanner = scanner
            val currentCallback = callback
            running = false
            scanner = null
            callback = null
            clearSession()
            if (currentScanner != null && currentCallback != null) {
                try {
                    currentScanner.stopScan(currentCallback)
                } catch (_: SecurityException) {
                    // Permission revocation must still clear all ephemeral scan state.
                } catch (_: RuntimeException) {
                    // The OS may already have stopped the scan.
                }
            }
        }
    }

    private fun record(result: ScanResult) {
        val token = BleExp0Advertisement.tokenFromServiceData(
            result.scanRecord?.getServiceData(SERVICE_DATA_UUID),
        ) ?: return
        val key = Base64.encodeToString(token, Base64.NO_WRAP)
        token.fill(0)
        val now = SystemClock.elapsedRealtime()
        val newCount = synchronized(lock) {
            if (!running || !sightings.remember(key, now)) return
            scheduleExpiryLocked(now)
            sightings.size
        }
        onSightingsChanged(newCount)
    }

    private fun clearSession() {
        expiryHandler.removeCallbacks(expiryTask)
        sightings.clear()
    }

    private fun expireSightings() {
        val count = synchronized(lock) {
            if (!running) return
            val now = SystemClock.elapsedRealtime()
            val currentCount = sightings.expire(now)
            scheduleExpiryLocked(now)
            currentCount
        }
        onSightingsChanged(count)
    }

    private fun scheduleExpiryLocked(nowMillis: Long) {
        expiryHandler.removeCallbacks(expiryTask)
        val delay = sightings.nextExpiryDelayMillis(nowMillis) ?: return
        expiryHandler.postDelayed(expiryTask, delay)
    }

    private fun hasScanPermissions(): Boolean =
        BleDiscoveryPermissionPolicy.hasRequiredPermissions(appContext)

    private fun bluetoothAdapter(): BluetoothAdapter? =
        appContext.getSystemService(BluetoothManager::class.java)?.adapter

    private companion object {
        val SERVICE_DATA_UUID = ParcelUuid(BleExp0Advertisement.SERVICE_UUID)
    }
}

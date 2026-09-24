package com.astraive.lattice

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.ParcelUuid
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID

/** Scans for the single generic candidate service. It never connects or retains device data. */
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
    private var sessionSalt: ByteArray? = null
    private var digest: MessageDigest? = null
    private val observedDigests = HashSet<String>()

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
            sessionSalt = ByteArray(32).also { SecureRandom().nextBytes(it) }
            digest = MessageDigest.getInstance("SHA-256")
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
                            .setServiceUuid(ParcelUuid(LATTICE_SERVICE_UUID_V1))
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
        val newCount = synchronized(lock) {
            if (!running || observedDigests.size >= MAX_EPHEMERAL_SIGHTINGS) return
            val address = try {
                result.device.address
            } catch (_: SecurityException) {
                return
            }
            val localDigest = digest ?: return
            val salt = sessionSalt ?: return
            localDigest.reset()
            localDigest.update(salt)
            val key = Base64.encodeToString(
                localDigest.digest(address.toByteArray(StandardCharsets.UTF_8)),
                Base64.NO_WRAP,
            )
            if (!observedDigests.add(key)) return
            observedDigests.size
        }
        onSightingsChanged(newCount)
    }

    private fun clearSession() {
        observedDigests.clear()
        sessionSalt?.fill(0)
        sessionSalt = null
        digest = null
    }

    private fun hasScanPermissions(): Boolean {
        val required = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }
        return required.all {
            appContext.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun bluetoothAdapter(): BluetoothAdapter? =
        appContext.getSystemService(BluetoothManager::class.java)?.adapter

    private companion object {
        const val MAX_EPHEMERAL_SIGHTINGS = 1024
        val LATTICE_SERVICE_UUID_V1: UUID = UUID.fromString("1c9a0001-7d31-4f6a-9b43-4c4154544943")
    }
}

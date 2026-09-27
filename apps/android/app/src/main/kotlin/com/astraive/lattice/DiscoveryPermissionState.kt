package com.astraive.lattice

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build

/** Permission states shown to the user before any nearby scan is started. */
enum class DiscoveryPermissionState {
    NOT_REQUESTED,
    GRANTED,
    DENIED,
    PERMANENTLY_DENIED,
    REVOKED,
}

data class RuntimePermissionObservation(
    val granted: Boolean,
    val requestedBefore: Boolean,
    val shouldShowRationale: Boolean,
)

/** Pure classification so permission transitions can be tested without an Android device. */
object DiscoveryPermissionClassifier {
    fun classify(
        observations: List<RuntimePermissionObservation>,
        wasPreviouslyGranted: Boolean,
    ): DiscoveryPermissionState {
        if (observations.isEmpty()) {
            return DiscoveryPermissionState.NOT_REQUESTED
        }
        if (observations.all { it.granted }) {
            return DiscoveryPermissionState.GRANTED
        }
        if (wasPreviouslyGranted) {
            return DiscoveryPermissionState.REVOKED
        }
        if (observations.any { !it.granted && it.shouldShowRationale }) {
            return DiscoveryPermissionState.DENIED
        }
        if (observations.any { !it.granted && it.requestedBefore }) {
            return DiscoveryPermissionState.PERMANENTLY_DENIED
        }
        return DiscoveryPermissionState.NOT_REQUESTED
    }
}

/** Runtime permissions required for exp0 scanning, advertising, and later GATT setup. */
internal object BleDiscoveryPermissionPolicy {
    @SuppressLint("InlinedApi")
    fun requiredRuntimePermissions(apiLevel: Int): Set<String> =
        if (apiLevel >= Build.VERSION_CODES.S) {
            setOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
            )
        } else {
            setOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

    fun hasRequiredPermissions(context: Context): Boolean =
        requiredRuntimePermissions(Build.VERSION.SDK_INT).all {
            context.checkSelfPermission(it) == PackageManager.PERMISSION_GRANTED
        }
}

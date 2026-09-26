package com.astraive.lattice

import android.Manifest
import android.os.Build
import org.junit.Assert.assertEquals
import org.junit.Test

class AndroidWifiCapabilityProbeTest {
    @Test
    fun runtimePermissionMatchesWifiApiGeneration() {
        assertEquals(
            Manifest.permission.ACCESS_FINE_LOCATION,
            WifiCapabilityPolicy.requiredRuntimePermission(Build.VERSION_CODES.S_V2),
        )
        assertEquals(
            Manifest.permission.NEARBY_WIFI_DEVICES,
            WifiCapabilityPolicy.requiredRuntimePermission(Build.VERSION_CODES.TIRAMISU),
        )
    }

    @Test
    fun unsupportedHardwareNeverAppearsAvailable() {
        assertEquals(
            WifiCapabilityState.UNSUPPORTED,
            WifiCapabilityPolicy.classify(
                featurePresent = false,
                availableNow = true,
                permissionGranted = true,
            ),
        )
    }

    @Test
    fun missingPermissionDoesNotBecomeAUsableUpgrade() {
        assertEquals(
            WifiCapabilityState.PERMISSION_REQUIRED,
            WifiCapabilityPolicy.classify(
                featurePresent = true,
                availableNow = true,
                permissionGranted = false,
            ),
        )
    }

    @Test
    fun supportedHardwareAvailabilityIsDistinguished() {
        assertEquals(
            WifiCapabilityState.TEMPORARILY_UNAVAILABLE,
            WifiCapabilityPolicy.classify(
                featurePresent = true,
                availableNow = false,
                permissionGranted = true,
            ),
        )
        assertEquals(
            WifiCapabilityState.AVAILABLE,
            WifiCapabilityPolicy.classify(
                featurePresent = true,
                availableNow = true,
                permissionGranted = true,
            ),
        )
    }
}

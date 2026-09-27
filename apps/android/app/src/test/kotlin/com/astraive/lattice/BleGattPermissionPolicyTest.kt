package com.astraive.lattice

import android.Manifest
import android.os.Build
import org.junit.Assert.assertEquals
import org.junit.Test

class BleGattPermissionPolicyTest {
    @Test
    fun gattConnectPermissionIsRuntimeRequiredOnlyFromAndroidS() {
        assertEquals(
            emptySet<String>(),
            BleGattPermissionPolicy.requiredRuntimePermissions(Build.VERSION_CODES.R),
        )
        assertEquals(
            setOf(Manifest.permission.BLUETOOTH_CONNECT),
            BleGattPermissionPolicy.requiredRuntimePermissions(Build.VERSION_CODES.S),
        )
    }

    @Test
    fun exp0RequiresScanConnectAndAdvertisePermissionsOnAndroidS() {
        assertEquals(
            setOf(
                Manifest.permission.BLUETOOTH_SCAN,
                Manifest.permission.BLUETOOTH_CONNECT,
                Manifest.permission.BLUETOOTH_ADVERTISE,
            ),
            BleDiscoveryPermissionPolicy.requiredRuntimePermissions(Build.VERSION_CODES.S),
        )
    }

    @Test
    fun preSDiscoveryRequiresLocationPermissionForBleScanning() {
        assertEquals(
            setOf(Manifest.permission.ACCESS_FINE_LOCATION),
            BleDiscoveryPermissionPolicy.requiredRuntimePermissions(Build.VERSION_CODES.R),
        )
    }

}

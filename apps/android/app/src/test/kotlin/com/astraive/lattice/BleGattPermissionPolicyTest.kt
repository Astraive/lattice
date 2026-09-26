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
}

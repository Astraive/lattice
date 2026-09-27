package com.astraive.lattice

import android.os.Build
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PersistentNearbyPermissionPolicyTest {
    @Test
    fun foregroundStatusNotificationRequiresRuntimeGrantFromAndroidTiramisu() {
        assertFalse(
            PersistentNearbyPermissionPolicy.requiresNotificationPermission(Build.VERSION_CODES.S_V2),
        )
        assertTrue(
            PersistentNearbyPermissionPolicy.requiresNotificationPermission(Build.VERSION_CODES.TIRAMISU),
        )
    }
}

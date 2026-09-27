package com.astraive.lattice

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class BleExp0AdvertisementTest {
    @Test
    fun serviceDataUsesProfileDiscriminatorAndCopiesTheNineByteToken() {
        val token = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9)
        val serviceData = BleExp0Advertisement.serviceData(token)
        token.fill(0)

        assertArrayEquals(byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9), serviceData)
        val parsed = BleExp0Advertisement.tokenFromServiceData(serviceData) ?: error("valid token rejected")
        serviceData.fill(0)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8, 9), parsed)
    }

    @Test
    fun serviceDataRejectsUnknownDiscriminatorAndWrongLengths() {
        assertNull(BleExp0Advertisement.tokenFromServiceData(null))
        assertNull(BleExp0Advertisement.tokenFromServiceData(ByteArray(9)))
        assertNull(BleExp0Advertisement.tokenFromServiceData(ByteArray(11)))
        assertNull(BleExp0Advertisement.tokenFromServiceData(byteArrayOf(1) + ByteArray(9)))
    }

    @Test
    fun serviceDataBuilderRejectsNonNineByteTokens() {
        try {
            BleExp0Advertisement.serviceData(ByteArray(8))
        } catch (_: IllegalArgumentException) {
            return
        }
        error("invalid exp0 token length was accepted")
    }

    @Test
    fun gattProfileUuidAssignmentsMatchTheExperimentalProfile() {
        assertEquals("1c9a0000-7d31-4f6a-9b43-4c4154544943", BleExp0GattProfile.serviceUuid.toString())
        assertEquals("1c9a0002-7d31-4f6a-9b43-4c4154544943", BleExp0GattProfile.controlUuid.toString())
        assertEquals("1c9a0003-7d31-4f6a-9b43-4c4154544943", BleExp0GattProfile.rxUuid.toString())
        assertEquals("1c9a0004-7d31-4f6a-9b43-4c4154544943", BleExp0GattProfile.txUuid.toString())
        assertEquals(
            "1c9a0005-7d31-4f6a-9b43-4c4154544943",
            BleExp0GattProfile.capabilitiesUuid.toString(),
        )
        assertEquals("1c9a0006-7d31-4f6a-9b43-4c4154544943", BleExp0GattProfile.upgradeUuid.toString())
    }
}

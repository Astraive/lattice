package com.astraive.lattice

import org.junit.Assert.assertArrayEquals
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
}

package com.astraive.lattice

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class BleExp0AdvertisementTest {

    @Test
    fun canonicalFixtureMatchesAdvertisementAndCapabilityWireValues() {
        val fixture = JSONObject(File(javaClass.classLoader!!.getResource("ble-exp0.json")!!.toURI()).readText())
        val constants = fixture.getJSONObject("constants")
        val advertisement = fixture.getJSONObject("advertisement")
        assertEquals(constants.getString("service_uuid"), BleExp0Advertisement.SERVICE_UUID.toString())
        assertEquals(constants.getString("service_uuid"), BleExp0GattProfile.serviceUuid.toString())
        val token = advertisement.getString("token_hex").hexBytes()
        val serviceData = byteArrayOf(0) + token
        assertArrayEquals(serviceData, BleExp0Advertisement.serviceData(token))
        assertArrayEquals(token, BleExp0Advertisement.tokenFromServiceData(serviceData))
        assertEquals(constants.getString("service_uuid_advertising_little_endian_hex"),
            BleExp0Advertisement.SERVICE_UUID.advertisingLittleEndian().toHex())
        val capabilities = constants.getJSONObject("gatt_characteristics").getString("capabilities_value_hex").hexBytes()
        assertArrayEquals(capabilities, BleExp0GattProfile.capabilitiesValue)
        assertTrue(BleExp0GattProfile.acceptsCapabilities(capabilities))
        val payload = advertisement.getString("payload_hex").hexBytes()
        assertEquals(31, payload.size)
        assertArrayEquals(byteArrayOf(2, 1, 6, 27, 0x21), payload.copyOfRange(0, 5))
        assertArrayEquals(BleExp0Advertisement.SERVICE_UUID.advertisingLittleEndian(), payload.copyOfRange(5, 21))
        assertArrayEquals(serviceData, payload.copyOfRange(21, payload.size))
        assertArrayEquals(token, BleExp0Advertisement.tokenFromServiceData(payload.copyOfRange(21, payload.size)))

        val negatives = fixture.getJSONArray("negative_cases")
        for (index in 0 until negatives.length()) {
            val testCase = negatives.getJSONObject(index)
            val bytes = testCase.getString("input_hex").hexBytes()
            val target = testCase.getString("target")
            when (target) {
                "advertisement" -> assertNull(testCase.getString("case_id"),
                    BleExp0Advertisement.tokenFromServiceData(bytes))
                "capabilities" -> assertFalse(testCase.getString("case_id"),
                    BleExp0GattProfile.acceptsCapabilities(bytes))
                "control" -> {
                    val protocol = BleExp0TransferProtocol(BleExp0TransferProtocol.ROLE_RESPONDER, 154, 9L)
                    assertRejectedAndClosed(testCase.getString("case_id"), protocol) {
                        protocol.acceptStart(bytes, 0)
                    }
                }
                "frame" -> {
                    val protocol = BleExp0TransferProtocol(BleExp0TransferProtocol.ROLE_RESPONDER, 154, 9L)
                    val start = fixture.getJSONObject("transport_records")
                        .getString("transfer_start_plaintext_hex").hexBytes()
                    protocol.acceptStart(start, 0)
                    assertRejectedAndClosed(testCase.getString("case_id"), protocol) {
                        protocol.acceptFrame(bytes, 1)
                    }
                }
                "proof", "noise" -> Unit
                else -> error("Unsupported BLE negative vector target: $target")
            }
        }
    }

    private fun assertRejectedAndClosed(
        caseId: String,
        protocol: BleExp0TransferProtocol,
        action: () -> Unit,
    ) {
        try {
            action()
        } catch (_: IllegalArgumentException) {
            assertTrue("$caseId must close the protocol", protocol.isClosed)
            return
        }
        error("$caseId was accepted")
    }


    @Test
    fun exactCapabilityDescriptorRejectsWrongLengthAndUnknownBits() {
        for (bad in listOf(byteArrayOf(), byteArrayOf(0, 0), byteArrayOf(0, 0, 0, 0),
            byteArrayOf(1, 0, 0), byteArrayOf(0, 1, 0), byteArrayOf(0, 0, 1))) {
            assertFalse(BleExp0GattProfile.acceptsCapabilities(bad))
        }
    }

    private fun String.hexBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun java.util.UUID.advertisingLittleEndian(): ByteArray =
        java.nio.ByteBuffer.allocate(16).putLong(mostSignificantBits).putLong(leastSignificantBits).array().reversedArray()
    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

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
        val constants = JSONObject(File(javaClass.classLoader!!.getResource("ble-exp0.json")!!.toURI()).readText())
            .getJSONObject("constants")
        val characteristics = constants.getJSONObject("gatt_characteristics")
        assertEquals(constants.getString("service_uuid"), BleExp0GattProfile.serviceUuid.toString())
        assertEquals(characteristics.getString("control_uuid"), BleExp0GattProfile.controlUuid.toString())
        assertEquals(characteristics.getString("rx_uuid"), BleExp0GattProfile.rxUuid.toString())
        assertEquals(characteristics.getString("tx_uuid"), BleExp0GattProfile.txUuid.toString())
        assertEquals(characteristics.getString("capabilities_uuid"), BleExp0GattProfile.capabilitiesUuid.toString())
        assertEquals(characteristics.getString("upgrade_uuid"), BleExp0GattProfile.upgradeUuid.toString())
}

}

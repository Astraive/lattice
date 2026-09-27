package com.astraive.lattice

import java.util.UUID

/** Exact application Service Data bytes for the experimental BLE discovery token. */
internal object BleExp0Advertisement {
    val SERVICE_UUID: UUID = UUID.fromString("1c9a0000-7d31-4f6a-9b43-4c4154544943")

    const val PROFILE_DISCRIMINATOR: Byte = 0
    const val TOKEN_BYTES = 9
    const val SERVICE_DATA_BYTES = 1 + TOKEN_BYTES
    const val TOKEN_ROTATION_MILLIS = 900_000L

    fun serviceData(token: ByteArray): ByteArray {
        require(token.size == TOKEN_BYTES) { "exp0 discovery token must be exactly 9 bytes" }
        return ByteArray(SERVICE_DATA_BYTES).also {
            it[0] = PROFILE_DISCRIMINATOR
            token.copyInto(it, destinationOffset = 1)
        }
    }

    fun tokenFromServiceData(serviceData: ByteArray?): ByteArray? {
        if (serviceData == null || serviceData.size != SERVICE_DATA_BYTES) return null
        if (serviceData[0] != PROFILE_DISCRIMINATOR) return null
        return serviceData.copyOfRange(1, SERVICE_DATA_BYTES)
    }
}

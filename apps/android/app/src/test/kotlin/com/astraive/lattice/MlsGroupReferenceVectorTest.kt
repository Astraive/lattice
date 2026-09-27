package com.astraive.lattice

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import org.junit.Assert.assertEquals
import org.junit.Test

class MlsGroupReferenceVectorTest {
    @Test
    fun matchesTheSharedRustAndProtocolGroupReferenceVector() {
        val vector = checkNotNull(javaClass.getResourceAsStream("/mls-group-reference.txt"))
            .bufferedReader(StandardCharsets.UTF_8)
            .useLines { lines ->
                lines.associate { line ->
                    val fields = line.split(" = ", limit = 2)
                    check(fields.size == 2)
                    fields[0] to fields[1]
                }
            }
        val domain = vector.getValue("domain").toByteArray(StandardCharsets.UTF_8)
        val groupId = vector.getValue("group_id_hex").decodeHex()
        val actual = MessageDigest.getInstance("SHA-256")
            .apply {
                update(domain)
                update(0.toByte())
                update(groupId)
            }
            .digest()
            .encodeHex()

        assertEquals(vector.getValue("group_reference_hex"), actual)
    }

    private fun String.decodeHex(): ByteArray {
        require(length % 2 == 0)
        return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    private fun ByteArray.encodeHex(): String = joinToString("") {
        "%02x".format(it.toInt() and 0xff)
    }
}

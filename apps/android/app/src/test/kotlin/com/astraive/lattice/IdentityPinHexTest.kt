package com.astraive.lattice

import com.astraive.lattice.identity.decodeIdentityHex
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Test

class IdentityPinHexTest {
    @Test
    fun decodesExactWidthAsciiHexCaseInsensitively() {
        assertArrayEquals(
            byteArrayOf(0x00, 0xaf.toByte(), 0xff.toByte()),
            decodeIdentityHex("00aFfF", 3),
        )
    }

    @Test
    fun rejectsWrongWidthsInvalidDigitsAndNonAsciiCharacters() {
        assertNull(decodeIdentityHex("0", 1))
        assertNull(decodeIdentityHex("0g", 1))
        assertNull(decodeIdentityHex("ＦＦ", 1))
        assertNull(decodeIdentityHex("", -1))
    }
}

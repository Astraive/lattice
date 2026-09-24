package com.astraive.lattice

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SpaceCreationInputTest {
    @Test
    fun acceptsOnlyNonemptyEvenLengthHexWithinTheCredentialLimit() {
        assertFalse(isCredentialVectorHex(""))
        assertFalse(isCredentialVectorHex("f"))
        assertFalse(isCredentialVectorHex("0g"))
        assertTrue(isCredentialVectorHex("aB"))
    }

    @Test
    fun enforcesTheExactSixteenKibibyteDecodedCredentialLimit() {
        assertTrue(isCredentialVectorHex("ab".repeat(MAX_CREDENTIAL_HEX_LENGTH / 2)))
        assertFalse(isCredentialVectorHex("ab".repeat(MAX_CREDENTIAL_HEX_LENGTH / 2 + 1)))
    }

    @Test
    fun validatesChannelNamesByUtf8BytesAndRejectsNul() {
        assertTrue(isValidInitialChannelName("g".repeat(128)))
        assertFalse(isValidInitialChannelName("g".repeat(129)))
        assertTrue(isValidInitialChannelName("界".repeat(42)))
        assertFalse(isValidInitialChannelName("界".repeat(43)))
        assertFalse(isValidInitialChannelName(" \t"))
        assertFalse(isValidInitialChannelName("general\u0000hidden"))
    }

}

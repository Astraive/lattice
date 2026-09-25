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
    fun boundsWelcomeBootstrapBase64ToOneMebibyteAndStandardAlphabet() {
        assertFalse(isSpaceWelcomeBootstrapBase64Input(""))
        assertTrue(isSpaceWelcomeBootstrapBase64Input("AQID"))
        assertFalse(isSpaceWelcomeBootstrapBase64Input("AQ=I"))
        assertFalse(isSpaceWelcomeBootstrapBase64Input("AQID\n"))

        val exactMaximum =
            "A".repeat(MAX_SPACE_WELCOME_BOOTSTRAP_BASE64_CHARS - 2) + "=="
        val overMaximum = "A".repeat(MAX_SPACE_WELCOME_BOOTSTRAP_BASE64_CHARS - 1) + "="
        assertTrue(isSpaceWelcomeBootstrapBase64Input(exactMaximum))
        assertFalse(isSpaceWelcomeBootstrapBase64Input(overMaximum))
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

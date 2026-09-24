package com.astraive.lattice

import java.security.SecureRandom
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.Test

class AndroidPrivateKeyProtectorTest {
    @Test
    fun wrapsAndUnwrapsVersionedProfileBoundEnvelope() {
        val protector = testProtector()
        val clear = byteArrayOf(0, 1, 2, 3, 0xfe.toByte())

        val protected = protector.wrap("profile-alpha", clear)

        check(protected.size == 1 + NONCE_BYTES + clear.size + TAG_BYTES)
        check(protected[0].toInt() and 0xff == 1)
        check(protector.unwrap("profile-alpha", protected).contentEquals(clear))
    }

    @Test
    fun wrongProfileAndCiphertextTamperingFailAuthentication() {
        val protector = testProtector()
        val protected = protector.wrap("profile-alpha", byteArrayOf(5, 4, 3, 2, 1))

        expectFailure { protector.unwrap("profile-beta", protected) }
        val tampered = protected.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        expectFailure { protector.unwrap("profile-alpha", tampered) }
    }

    @Test
    fun rejectsUnknownVersionAndTruncatedEnvelopesBeforeDecryption() {
        val protector = testProtector()
        val valid = protector.wrap("profile-alpha", byteArrayOf(7))
        val unknownVersion = valid.copyOf().also { it[0] = 2 }

        expectFailure { protector.unwrap("profile-alpha", unknownVersion) }
        expectFailure { protector.unwrap("profile-alpha", ByteArray(1 + NONCE_BYTES + TAG_BYTES)) }
        expectFailure { protector.unwrap("profile-alpha", valid.copyOf(valid.size - 1)) }
    }

    @Test
    fun enforcesMaterialAndProfileBounds() {
        val protector = testProtector()
        expectFailure { protector.wrap("profile", byteArrayOf()) }
        expectFailure { protector.wrap("profile", ByteArray(MAX_CLEAR_BYTES + 1)) }
        expectFailure { protector.unwrap("profile", ByteArray(MAX_PROTECTED_BYTES + 1)) }

        expectFailure { protector.wrap("", byteArrayOf(1)) }
        expectFailure { protector.wrap("x".repeat(MAX_PROFILE_ID_BYTES + 1), byteArrayOf(1)) }
        expectFailure { protector.wrap("x\u0000y", byteArrayOf(1)) }
        expectFailure { protector.wrap("\u0085", byteArrayOf(1)) }
        expectFailure { protector.wrap("\uD800", byteArrayOf(1)) }

        val maximumProfile = "x".repeat(MAX_PROFILE_ID_BYTES)
        val maximumFittingClear = ByteArray(MAX_PROTECTED_BYTES - ENVELOPE_OVERHEAD_BYTES)
        val envelope = protector.wrap(maximumProfile, maximumFittingClear)
        check(envelope.size == MAX_PROTECTED_BYTES)
        check(protector.unwrap(maximumProfile, envelope).contentEquals(maximumFittingClear))
        expectFailure {
            protector.wrap(
                maximumProfile,
                ByteArray(MAX_PROTECTED_BYTES - ENVELOPE_OVERHEAD_BYTES + 1),
            )
        }
    }

    private fun testProtector(): AndroidPrivateKeyProtector = AndroidPrivateKeyProtector(
        object : AndroidPrivateKeyProtector.KeyProvider {
            private val key: SecretKey = KeyGenerator.getInstance("AES").apply { init(256, SecureRandom()) }.generateKey()

            override fun keyFor(profileIdUtf8: ByteArray): SecretKey = key
        },
    )

    private inline fun expectFailure(block: () -> Unit) {
        try {
            block()
        } catch (_: IllegalArgumentException) {
            return
        } catch (_: Exception) {
            return
        }
        error("Expected protection operation to fail")
    }

    private companion object {
        const val NONCE_BYTES = 12
        const val TAG_BYTES = 16
        const val ENVELOPE_OVERHEAD_BYTES = 1 + NONCE_BYTES + TAG_BYTES
        const val MAX_CLEAR_BYTES = 4096
        const val MAX_PROTECTED_BYTES = 4096
        const val MAX_PROFILE_ID_BYTES = 128
    }
}

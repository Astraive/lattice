package com.astraive.lattice

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Wraps private material in an authenticated, profile-bound envelope.
 * AndroidKeyStore keys remain non-exportable; this class does not provide a plaintext fallback.
 */
class AndroidPrivateKeyProtector {
    private val keyProvider: KeyProvider

    constructor() {
        keyProvider = AndroidKeyStoreKeyProvider()
    }

    internal constructor(keyProvider: KeyProvider) {
        this.keyProvider = keyProvider
    }

    /** Returns version || 12-byte nonce || AES-GCM ciphertext and 16-byte tag. */
    fun wrap(profileId: String, clearMaterial: ByteArray): ByteArray {
        val profileBytes = encodeProfileId(profileId)
        require(
            clearMaterial.isNotEmpty() &&
                clearMaterial.size <= MAX_CLEAR_BYTES &&
                clearMaterial.size <= MAX_PROTECTED_BYTES - ENVELOPE_OVERHEAD_BYTES,
        ) {
            "Private material size is outside the allowed range"
        }

        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, keyProvider.keyFor(profileBytes))
        cipher.updateAAD(associatedData(profileBytes))
        val encrypted = cipher.doFinal(clearMaterial)
        val nonce = cipher.iv
        check(nonce.size == NONCE_BYTES) { "AES-GCM provider returned an invalid nonce" }
        val protected = ByteArray(ENVELOPE_HEADER_BYTES + encrypted.size)
        protected[0] = ENVELOPE_VERSION.toByte()
        nonce.copyInto(protected, VERSION_BYTES)
        encrypted.copyInto(protected, ENVELOPE_HEADER_BYTES)
        check(protected.size <= MAX_PROTECTED_BYTES) {
            "AES-GCM output exceeds the protected material size limit"
        }
        return protected
    }

    /** Authenticates and unwraps a versioned envelope for the specified profile. */
    fun unwrap(profileId: String, protectedMaterial: ByteArray): ByteArray {
        val profileBytes = encodeProfileId(profileId)
        require(protectedMaterial.size <= MAX_PROTECTED_BYTES) {
            "Protected material exceeds the allowed size"
        }
        require(protectedMaterial.size >= MIN_PROTECTED_BYTES) {
            "Protected material is truncated"
        }
        require(protectedMaterial[0].toInt() and 0xff == ENVELOPE_VERSION) {
            "Unsupported protected material version"
        }

        val nonce = protectedMaterial.copyOfRange(VERSION_BYTES, ENVELOPE_HEADER_BYTES)
        val encrypted = protectedMaterial.copyOfRange(ENVELOPE_HEADER_BYTES, protectedMaterial.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, keyProvider.keyFor(profileBytes), GCMParameterSpec(TAG_BITS, nonce))
        cipher.updateAAD(associatedData(profileBytes))
        val clear = cipher.doFinal(encrypted)
        require(clear.isNotEmpty() && clear.size <= MAX_CLEAR_BYTES) {
            "Unwrapped private material size is outside the allowed range"
        }
        return clear
    }

    internal interface KeyProvider {
        fun keyFor(profileIdUtf8: ByteArray): SecretKey
    }

    private class AndroidKeyStoreKeyProvider : KeyProvider {
        override fun keyFor(profileIdUtf8: ByteArray): SecretKey = synchronized(KEY_STORE_LOCK) {
            val alias = KEY_ALIAS_PREFIX + aliasDigest(profileIdUtf8)
            val keyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }
            val existing = keyStore.getKey(alias, null)
            if (existing != null) {
                return@synchronized existing as? SecretKey
                    ?: throw IllegalStateException("AndroidKeyStore entry is not a secret key")
            }

            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
            generator.init(
                KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setKeySize(KEY_BITS)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generator.generateKey()
        }
    }

    private companion object {
        val KEY_STORE_LOCK = Any()
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val ENVELOPE_VERSION = 1
        const val VERSION_BYTES = 1
        const val NONCE_BYTES = 12
        const val TAG_BITS = 128
        const val TAG_BYTES = TAG_BITS / 8
        const val ENVELOPE_HEADER_BYTES = VERSION_BYTES + NONCE_BYTES
        const val ENVELOPE_OVERHEAD_BYTES = ENVELOPE_HEADER_BYTES + TAG_BYTES
        const val MIN_PROTECTED_BYTES = ENVELOPE_OVERHEAD_BYTES + 1
        const val MAX_CLEAR_BYTES = 4096
        const val MAX_PROTECTED_BYTES = 4096
        const val KEY_BITS = 256
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val KEY_ALIAS_PREFIX = "lattice.private-key-wrap."
        const val KEY_ALIAS_DOMAIN = "lattice.android-keystore.private-key-wrap\u0000"
        val AAD_PREFIX = "lattice.private-key-wrap\u0000".toByteArray(StandardCharsets.UTF_8)

        fun encodeProfileId(profileId: String): ByteArray {
            val bytes = try {
                val encoded = StandardCharsets.UTF_8.newEncoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .encode(CharBuffer.wrap(profileId))
                ByteArray(encoded.remaining()).also { encoded.get(it) }
            } catch (_: CharacterCodingException) {
                throw IllegalArgumentException("Profile ID is not valid UTF-8 text")
            }
            require(bytes.isNotEmpty() && bytes.size <= MAX_PROFILE_ID_BYTES) {
                "Profile ID UTF-8 size is outside the allowed range"
            }
            require(!profileId.any { Character.isISOControl(it) }) {
                "Profile ID must not contain control characters"
            }
            return bytes
        }

        fun associatedData(profileIdUtf8: ByteArray): ByteArray = ByteArray(AAD_PREFIX.size + VERSION_BYTES + profileIdUtf8.size).also { aad ->
            AAD_PREFIX.copyInto(aad)
            aad[AAD_PREFIX.size] = ENVELOPE_VERSION.toByte()
            profileIdUtf8.copyInto(aad, AAD_PREFIX.size + VERSION_BYTES)
        }

        fun aliasDigest(profileIdUtf8: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(KEY_ALIAS_DOMAIN.toByteArray(StandardCharsets.UTF_8))
            val hash = digest.digest(profileIdUtf8)
            val hex = "0123456789abcdef"
            return buildString(hash.size * 2) {
                for (byte in hash) {
                    val value = byte.toInt() and 0xff
                    append(hex[value ushr 4])
                    append(hex[value and 0x0f])
                }
            }
        }

        const val MAX_PROFILE_ID_BYTES = 128
    }
}

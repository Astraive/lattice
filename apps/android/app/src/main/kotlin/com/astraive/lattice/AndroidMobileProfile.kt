package com.astraive.lattice

import android.content.Context
import java.io.File
import uniffi.lattice_uniffi.MobileClient
import uniffi.lattice_uniffi.MobileIdentityInfo
import uniffi.lattice_uniffi.MobileSpaceCursor
import uniffi.lattice_uniffi.MobileSpacePage
import uniffi.lattice_uniffi.PlatformKeyProtector
import uniffi.lattice_uniffi.ProtectorException

/** AndroidKeyStore-backed callback required by the shared Rust profile. */
internal class AndroidPlatformKeyProtector : PlatformKeyProtector {
    private val delegate = AndroidPrivateKeyProtector()

    override fun wrap(profileId: String, clearMaterial: ByteArray): ByteArray = try {
        delegate.wrap(profileId, clearMaterial)
    } catch (_: Exception) {
        throw ProtectorException.Failure()
    } finally {
        clearMaterial.fill(0)
    }

    override fun unwrap(profileId: String, ciphertext: ByteArray): ByteArray = try {
        delegate.unwrap(profileId, ciphertext)
    } catch (_: Exception) {
        throw ProtectorException.Failure()
    }
}

/** Owns a Rust profile and the callback that bridges to AndroidKeyStore. */
internal class AndroidMobileProfile private constructor(
    private val client: MobileClient,
    @Suppress("unused") private val keyProtector: AndroidPlatformKeyProtector,
) : AutoCloseable {
    fun identityInfo(): MobileIdentityInfo = client.identityInfo()

    fun localSpaces(after: MobileSpaceCursor? = null): MobileSpacePage =
        client.listLocalSpaces(after)

    override fun close() {
        client.close()
    }

    companion object {
        private const val DATABASE_NAME = "lattice.sqlite"

        fun open(context: Context): AndroidMobileProfile {
            val database = context.getDatabasePath(DATABASE_NAME)
            val directory: File = database.parentFile
                ?: throw IllegalStateException("Android database directory is unavailable")
            if (!directory.isDirectory && !directory.mkdirs()) {
                throw IllegalStateException("Android database directory could not be created")
            }

            val keyProtector = AndroidPlatformKeyProtector()
            val client = MobileClient.openOrCreate(
                database.absolutePath,
                context.packageName,
                keyProtector,
            )
            return AndroidMobileProfile(client, keyProtector)
        }
    }
}

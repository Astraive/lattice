package com.astraive.lattice

import android.content.Context
import java.io.File
import uniffi.lattice_uniffi.MobileQueuedMessage
import uniffi.lattice_uniffi.MobileClient
import uniffi.lattice_uniffi.MobileIdentityInfo
import uniffi.lattice_uniffi.MobileCreatedSpace
import uniffi.lattice_uniffi.MobileInitialChannel
import uniffi.lattice_uniffi.MobilePinnedIdentity
import uniffi.lattice_uniffi.MobileSpaceCursor
import uniffi.lattice_uniffi.MobileSpacePage
import uniffi.lattice_uniffi.PlatformKeyProtector
import uniffi.lattice_uniffi.ProtectorException
import uniffi.lattice_uniffi.MobileLocalTextMessage

/** AndroidKeyStore-backed callback required by the shared Rust profile. */
internal class AndroidPlatformKeyProtector : PlatformKeyProtector {
    private val delegate = AndroidPrivateKeyProtector()

    fun protectionLevel(profileId: String): AndroidKeyProtectionLevel = delegate.protectionLevel(profileId)

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
    private val keyProtector: AndroidPlatformKeyProtector,
    private val profileId: String,
) : AutoCloseable {
    fun keyProtectionLevel(): AndroidKeyProtectionLevel = keyProtector.protectionLevel(profileId)
    fun identityInfo(): MobileIdentityInfo = client.identityInfo()

    fun certificateSigningRequest(): ByteArray = client.certificateSigningRequest()

    fun createLocalSpace(
        credentialVector: ByteArray,
        channels: List<MobileInitialChannel>,
    ): MobileCreatedSpace = client.createLocalSpace(credentialVector, channels)

    fun joinSpaceFromWelcomeBootstrap(
        bootstrapPackage: ByteArray,
        expectedInviterFingerprint: ByteArray,
        credentialVector: ByteArray,
    ): MobileCreatedSpace = client.joinSpaceFromWelcomeBootstrap(
        bootstrapPackage,
        expectedInviterFingerprint,
        credentialVector,
    )

    fun recoverLocalSpaceGeneration(
        spaceId: ByteArray,
        groupReference: ByteArray,
        credentialVector: ByteArray,
    ): MobileCreatedSpace = client.recoverLocalSpaceGeneration(
        spaceId,
        groupReference,
        credentialVector,
    )

    fun pinIdentity(publicBundle: ByteArray, expectedFingerprint: ByteArray): MobilePinnedIdentity =
        client.pinIdentity(publicBundle, expectedFingerprint)

    fun pinnedIdentity(fingerprint: ByteArray): MobilePinnedIdentity? =
        client.pinnedIdentity(fingerprint)

    fun unpinIdentity(fingerprint: ByteArray): Boolean = client.unpinIdentity(fingerprint)

    fun localSpaces(after: MobileSpaceCursor? = null): MobileSpacePage =
        client.listLocalSpaces(after)

    fun localTextMessages(
        spaceId: ByteArray,
        groupReference: ByteArray,
        channelId: ByteArray,
    ): List<MobileLocalTextMessage> = client.listLocalTextMessages(spaceId, groupReference, channelId)
    fun queueLocalTextMessage(
        spaceId: ByteArray,
        groupReference: ByteArray,
        credentialVector: ByteArray,
        channelId: ByteArray,
        content: String,
    ): MobileQueuedMessage = client.queueLocalTextMessage(
        spaceId,
        groupReference,
        credentialVector,
        channelId,
        content,
    )


    fun queueLocalTextMessageEdit(
        spaceId: ByteArray,
        groupReference: ByteArray,
        credentialVector: ByteArray,
        channelId: ByteArray,
        targetMessageId: ByteArray,
        content: String,
    ): MobileQueuedMessage = client.queueLocalTextMessageEdit(
        spaceId,
        groupReference,
        credentialVector,
        channelId,
        targetMessageId,
        content,
    )
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
            return AndroidMobileProfile(client, keyProtector, context.packageName)
        }
    }
}

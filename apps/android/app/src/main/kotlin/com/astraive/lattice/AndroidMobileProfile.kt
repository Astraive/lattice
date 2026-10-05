package com.astraive.lattice

import android.content.Context
import android.database.Cursor
import android.net.Uri
import android.provider.OpenableColumns
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.util.UUID
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
import uniffi.lattice_uniffi.MobileBleRole
import uniffi.lattice_uniffi.MobileBleSession
import uniffi.lattice_uniffi.MobileOutboxEntry
import uniffi.lattice_uniffi.MobileSyncEventResult

import uniffi.lattice_uniffi.MobileSpaceInvitation
import uniffi.lattice_uniffi.MobileCreatedDirectMessage
import uniffi.lattice_uniffi.MobileDirectMessageConversation
import uniffi.lattice_uniffi.MobileDirectMessageHistoryEntry
import uniffi.lattice_uniffi.MobileDirectMessageIngressResult
import uniffi.lattice_uniffi.MobileDirectMessageOutboxEntry
import uniffi.lattice_uniffi.MobileDirectMessagePendingInvitation
import uniffi.lattice_uniffi.MobileDirectMessagePacket
import uniffi.lattice_uniffi.MobileDirectMessageExchange
import uniffi.lattice_uniffi.MobileAttachmentExport
import uniffi.lattice_uniffi.MobileAttachmentManifest
import uniffi.lattice_uniffi.MobileAttachmentQueueReceipt
import uniffi.lattice_uniffi.MobileAttachmentTransferReceipt
import uniffi.lattice_uniffi.MobileAuthorizedAttachmentManifest
import uniffi.lattice_uniffi.MobileAttachmentStagingStatus

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.Executors

internal enum class CoreProjectionChange { SPACES, MESSAGES, ALL, SYNCED_EVENTS }

private fun uniffi.lattice_uniffi.MobileProjectionChange.toCoreProjectionChange(): CoreProjectionChange =
    when (this) {
        uniffi.lattice_uniffi.MobileProjectionChange.SPACES -> CoreProjectionChange.SPACES
        uniffi.lattice_uniffi.MobileProjectionChange.MESSAGES -> CoreProjectionChange.MESSAGES
        uniffi.lattice_uniffi.MobileProjectionChange.ALL -> CoreProjectionChange.ALL
        uniffi.lattice_uniffi.MobileProjectionChange.SYNCED_EVENTS -> CoreProjectionChange.SYNCED_EVENTS
    }

internal class CoreProjectionChangeDispatcher(
    private val post: ((() -> Unit) -> Unit),
    private val observer: (CoreProjectionChange) -> Unit,
) : AutoCloseable {
    private val lock = Any()
    private var pending = 0
    private var scheduled = false
    private var closed = false

    fun offer(change: CoreProjectionChange) {
        val shouldPost = synchronized(lock) {
            if (closed) return
            pending = pending or change.mask()
            if (scheduled) {
                false
            } else {
                scheduled = true
                true
            }
        }
        if (shouldPost) post(::drain)
    }

    private fun drain() {
        val change = synchronized(lock) {
            if (closed) {
                pending = 0
                scheduled = false
                return
            }
            coalescedChange(pending).also { pending = 0 }
        }
        try {
            change?.let(observer)
        } finally {
            val shouldPost = synchronized(lock) {
                if (closed || pending == 0) {
                    pending = 0
                    scheduled = false
                    false
                } else {
                    true
                }
            }
            if (shouldPost) post(::drain)
        }
    }

    override fun close() {
        synchronized(lock) {
            closed = true
            pending = 0
        }
    }

    private fun CoreProjectionChange.mask(): Int = when (this) {
        CoreProjectionChange.SPACES -> SPACE_CHANGE
        CoreProjectionChange.MESSAGES -> MESSAGE_CHANGE
        CoreProjectionChange.ALL -> ALL_CHANGE
        CoreProjectionChange.SYNCED_EVENTS -> SYNCED_EVENT_CHANGE
    }

    private fun coalescedChange(changes: Int): CoreProjectionChange? {
        val spacesAndMessages =
            (changes and (SPACE_CHANGE or MESSAGE_CHANGE)) == (SPACE_CHANGE or MESSAGE_CHANGE)
        return when {
            (changes and SYNCED_EVENT_CHANGE) != 0 -> CoreProjectionChange.SYNCED_EVENTS
            (changes and ALL_CHANGE) != 0 || spacesAndMessages -> CoreProjectionChange.ALL
            (changes and MESSAGE_CHANGE) != 0 -> CoreProjectionChange.MESSAGES
            (changes and SPACE_CHANGE) != 0 -> CoreProjectionChange.SPACES
            else -> null
        }
    }

    private companion object {
        const val SPACE_CHANGE = 1
        const val MESSAGE_CHANGE = 2
        const val ALL_CHANGE = 4
        const val SYNCED_EVENT_CHANGE = 8
    }
}


internal class CoreProjectionSubscriptionRegistry : AutoCloseable {
    private val lock = Any()
    private val subscriptions = LinkedHashSet<AutoCloseable>()
    private var closed = false

    fun track(subscription: AutoCloseable): AutoCloseable {
        lateinit var handle: AutoCloseable
        val active = AtomicBoolean(true)
        handle = AutoCloseable {
            if (active.compareAndSet(true, false)) {
                synchronized(lock) { subscriptions.remove(handle) }
                subscription.close()
            }
        }
        synchronized(lock) {
            if (!closed) {
                subscriptions.add(handle)
                return handle
            }
        }
        handle.close()
        return handle
    }

    override fun close() {
        val current = synchronized(lock) {
            if (closed) return
            closed = true
            subscriptions.toList().also { subscriptions.clear() }
        }
        current.forEach(AutoCloseable::close)
    }
}
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

/** Source imported through Android's document provider into app-private storage. */
internal data class MobileImportedAttachment(val sourceId: String, val filename: String)

/** Owns a Rust profile and the callback that bridges to AndroidKeyStore. */
internal class AndroidMobileProfile private constructor(
    private val client: MobileClient,
    private val keyProtector: AndroidPlatformKeyProtector,
    private val profileId: String,
    private val applicationContext: Context,
    private val attachmentRoot: File,
): AutoCloseable, BleExp0IngressProfile {
    private val projectionSubscriptions = CoreProjectionSubscriptionRegistry()
    private val closed = AtomicBoolean(false)

    fun subscribeProjectionChanges(observer: (CoreProjectionChange) -> Unit): AutoCloseable {
        check(!closed.get()) { "Android mobile profile is closed" }
        val subscription = client.subscribeProjectionChanges()
        val executor = Executors.newSingleThreadExecutor { task ->
            Thread(task, "lattice-core-projection").apply { isDaemon = true }
        }
        val worker = executor.submit {
            while (!Thread.currentThread().isInterrupted) {
                val change = try {
                    subscription.waitForChange(30_000uL)
                } catch (_: Exception) {
                    break
                }
                if (change == null) {
                    if (subscription.isClosed()) break
                    continue
                }
                try {
                    observer(change.toCoreProjectionChange())
                } catch (_: RuntimeException) {
                    // A UI projection observer cannot fail a Core mutation.
                }
            }
        }
        lateinit var handle: AutoCloseable
        handle = AutoCloseable {
            subscription.cancel()
            subscription.close()
            worker.cancel(true)
            executor.shutdownNow()
        }
        return projectionSubscriptions.track(handle)
    }
    fun keyProtectionLevel(): AndroidKeyProtectionLevel = keyProtector.protectionLevel(profileId)
    fun identityInfo(): MobileIdentityInfo = client.identityInfo()
    fun certificateSigningRequest(): ByteArray = client.certificateSigningRequest()
    fun createLocalSpace(
        credentialVector: ByteArray,
        channels: List<MobileInitialChannel>,
    ): MobileCreatedSpace = client.createLocalSpace(credentialVector, channels)
    fun publishSpaceKeyPackage(credentialVector: ByteArray): ByteArray =
        client.publishSpaceKeyPackage(credentialVector)

    fun createSpaceInvitation(
        spaceId: ByteArray,
        groupReference: ByteArray,
        credentialVector: ByteArray,
        keyPackageWire: ByteArray,
        expiresAtUnixSeconds: ULong,
        maxUses: UInt?,
    ): MobileSpaceInvitation = client.createSpaceInvitation(
        spaceId,
        groupReference,
        credentialVector,
        keyPackageWire,
        expiresAtUnixSeconds,
        maxUses,
    )

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
    fun newBleSession(role: MobileBleRole, responderToken: ByteArray): MobileBleSession =
        MobileBleSession(client, role, responderToken)

    fun localSpaces(after: MobileSpaceCursor? = null): MobileSpacePage =
        client.listLocalSpaces(after)


    fun importSelectedAttachment(uri: Uri): MobileImportedAttachment {
        val directory = attachmentSubdirectory("imports")
        cleanupAttachmentImports(directory)
        val existing = directory.listFiles()
            ?.filter { it.isFile && (it.name.endsWith(".import") || it.name.endsWith(".tmp")) }
            ?: throw IOException("Attachment import directory cannot be listed")
        val usedBytes = existing.sumOf(File::length)
        if (existing.size >= MAX_ATTACHMENT_IMPORTS || usedBytes >= MAX_ATTACHMENT_IMPORT_BYTES) {
            throw IOException("Private attachment import storage is full")
        }

        val displayName = applicationContext.contentResolver.query(
            uri,
            arrayOf(OpenableColumns.DISPLAY_NAME),
            null,
            null,
            null,
        )?.use { cursor: Cursor ->
            val column = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (column >= 0 && cursor.moveToFirst()) cursor.getString(column) else null
        }?.takeIf { it.isNotBlank() } ?: "attachment"

        val sourceId = UUID.randomUUID().toString().replace("-", "").lowercase()
        val temporary = File(directory, "$sourceId.tmp")
        val imported = File(directory, "$sourceId.import")
        try {
            val input = applicationContext.contentResolver.openInputStream(uri)
                ?: throw IOException("The selected document could not be opened")
            input.use { source ->
                FileOutputStream(temporary).use { destination ->
                    val buffer = ByteArray(64 * 1024)
                    var copied = 0L
                    while (true) {
                        val count = source.read(buffer)
                        if (count < 0) break
                        if (count == 0) continue
                        copied += count
                        if (copied > MAX_ATTACHMENT_BYTES ||
                            copied > MAX_ATTACHMENT_IMPORT_BYTES - usedBytes
                        ) {
                            throw IOException("The selected document exceeds private attachment storage limits")
                        }
                        destination.write(buffer, 0, count)
                    }
                    destination.fd.sync()
                }
            }
            if (!temporary.renameTo(imported)) {
                throw IOException("The selected document could not be saved privately")
            }
            return MobileImportedAttachment(sourceId, displayName)
        } catch (error: Exception) {
            temporary.delete()
            imported.delete()
            throw error
        }
    }

    fun createAttachmentManifest(
        sourceId: String,
        filename: String,
    ): MobileAttachmentManifest = client.createAttachmentManifest(sourceId, filename)

    fun queueAttachmentManifest(
        spaceId: ByteArray,
        groupReference: ByteArray,
        credentialVector: ByteArray,
        channelId: ByteArray,
        sourceId: String,
        preview: MobileAttachmentManifest,
    ): MobileAttachmentQueueReceipt = client.queueAttachmentManifest(
        spaceId,
        groupReference,
        credentialVector,
        channelId,
        sourceId,
        preview,
    )

    fun authorizedAttachmentManifest(
        spaceId: ByteArray,
        groupReference: ByteArray,
        eventId: ByteArray,
    ): MobileAuthorizedAttachmentManifest =
        client.authorizedAttachmentManifest(spaceId, groupReference, eventId)


    fun attachmentStagingStatus(
        spaceId: ByteArray,
        groupReference: ByteArray,
        eventId: ByteArray,
    ): MobileAttachmentStagingStatus =
        client.attachmentStagingStatus(spaceId, groupReference, eventId)
    fun sendAttachmentOnce(
        spaceId: ByteArray,
        groupReference: ByteArray,
        eventId: ByteArray,
        peerFingerprint: ByteArray,
        connectAddress: String,
    ): MobileAttachmentTransferReceipt = client.sendAttachmentOnce(
        spaceId,
        groupReference,
        eventId,
        peerFingerprint,
        connectAddress,
    )

    fun receiveAttachmentOnce(
        spaceId: ByteArray,
        groupReference: ByteArray,
        eventId: ByteArray,
        peerFingerprint: ByteArray,
        listenAddress: String,
        userConsented: Boolean,
    ): MobileAttachmentTransferReceipt = client.receiveAttachmentOnce(
        spaceId,
        groupReference,
        eventId,
        peerFingerprint,
        listenAddress,
        userConsented,
    )

    fun prepareAttachmentExport(
        spaceId: ByteArray,
        groupReference: ByteArray,
        eventId: ByteArray,
    ): MobileAttachmentExport =
        client.prepareAttachmentExport(spaceId, groupReference, eventId)

    fun copyAttachmentExportToDocument(export: MobileAttachmentExport, destination: Uri) {
        require(export.exportId.matches(Regex("[0-9a-f]{64}"))) {
            "Invalid private attachment export identifier"
        }
        val directory = attachmentSubdirectory("exports").canonicalFile
        val source = File(directory, "${export.exportId}.export")
        require(source.canonicalFile.parentFile == directory && source.isFile) {
            "Verified attachment export is unavailable"
        }
        val expectedSize = export.fileSize.toLong()
        require(expectedSize in 0..MAX_ATTACHMENT_BYTES && source.length() == expectedSize) {
            "Verified attachment export has an unexpected size"
        }
        val expectedHash = export.fileHash
        require(expectedHash.size == 32) { "Verified attachment export has invalid metadata" }
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        FileInputStream(source).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                if (count > 0) digest.update(buffer, 0, count)
            }
        }
        require(digest.digest().contentEquals(expectedHash)) {
            "Verified attachment export changed before delivery"
        }

        val output = applicationContext.contentResolver.openOutputStream(destination, "wt")
            ?: throw IOException("The selected export destination could not be opened")
        val copyDigest = java.security.MessageDigest.getInstance("SHA-256")
        var copiedBytes = 0L
        FileInputStream(source).use { input ->
            output.use { destinationStream ->
                val buffer = ByteArray(64 * 1024)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count > 0) {
                        copiedBytes += count
                        copyDigest.update(buffer, 0, count)
                        destinationStream.write(buffer, 0, count)
                    }
                }
                destinationStream.flush()
            }
        }
        require(copiedBytes == expectedSize && copyDigest.digest().contentEquals(expectedHash)) {
            "Exported attachment changed while being copied"
        }
        client.finishAttachmentExport(export.exportId)
    }

    fun finishAttachmentExport(exportId: String): Boolean =
        client.finishAttachmentExport(exportId)

    private fun attachmentSubdirectory(name: String): File {
        require(name in setOf("imports", "exports"))
        if (!attachmentRoot.exists() && !attachmentRoot.mkdirs()) {
            throw IOException("Private attachment storage is unavailable")
        }
        val root = attachmentRoot.canonicalFile
        val directory = File(root, name)
        if (!directory.exists() && !directory.mkdirs()) {
            throw IOException("Private attachment storage is unavailable")
        }
        val canonical = directory.canonicalFile
        if (!canonical.isDirectory || canonical.parentFile != root) {
            throw IOException("Private attachment storage is unsafe")
        }
        return canonical
    }

    private fun cleanupAttachmentImports(directory: File) {
        val cutoff = System.currentTimeMillis() - ATTACHMENT_IMPORT_RETENTION_MS
        for (file in directory.listFiles()
            ?: throw IOException("Attachment import directory cannot be listed")
        ) {
            if (!file.name.endsWith(".import") && !file.name.endsWith(".tmp")) {
                throw IOException("Private attachment import storage contains an unexpected entry")
            }
            if (file.lastModified() < cutoff && !file.delete()) {
                throw IOException("Expired private attachment import could not be removed")
            }
        }
    }

    fun outboxPage(afterEventId: ByteArray? = null, limit: Int = 64): List<MobileOutboxEntry> =
        client.outboxPage(afterEventId, limit)

    override fun markOutboxAttempt(eventId: ByteArray, nextAttemptMs: Long) =
        client.markOutboxAttempt(eventId, nextAttemptMs)

    override fun recordPeerIngressAccepted(eventId: ByteArray) =
        client.recordPeerIngressAccepted(eventId)

    fun localTextMessages(
        spaceId: ByteArray,
        groupReference: ByteArray,
        channelId: ByteArray,
    ): List<MobileLocalTextMessage> = client.listLocalTextMessages(spaceId, groupReference, channelId)

    override fun ingestSyncedApplicationEvent(canonicalBytes: ByteArray): MobileSyncEventResult =
        client.ingestSyncedApplicationEvent(canonicalBytes)

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

    fun queueLocalTextMessageReply(
        spaceId: ByteArray,
        groupReference: ByteArray,
        credentialVector: ByteArray,
        channelId: ByteArray,
        threadRoot: ByteArray,
        content: String,
    ): MobileQueuedMessage = client.queueLocalTextMessageReply(
        spaceId,
        groupReference,
        credentialVector,
        channelId,
        threadRoot,
        content,
    )

    fun queueLocalTextMessageTombstone(
        spaceId: ByteArray,
        groupReference: ByteArray,
        credentialVector: ByteArray,
        channelId: ByteArray,
        targetMessageId: ByteArray,
    ): MobileQueuedMessage = client.queueLocalTextMessageTombstone(
        spaceId,
        groupReference,
        credentialVector,
        channelId,
        targetMessageId,
    )

    fun queueLocalTextMessageReaction(
        spaceId: ByteArray,
        groupReference: ByteArray,
        credentialVector: ByteArray,
        channelId: ByteArray,
        targetMessageId: ByteArray,
        token: String,
        add: Boolean,
        tag: ByteArray?,
    ): MobileQueuedMessage = client.queueLocalTextMessageReaction(
        spaceId,
        groupReference,
        credentialVector,
        channelId,
        targetMessageId,
        token,
        add,
        tag,
    )

    fun queueLocalTextMessagePin(
        spaceId: ByteArray,
        groupReference: ByteArray,
        credentialVector: ByteArray,
        channelId: ByteArray,
        targetMessageId: ByteArray,
        add: Boolean,
        tag: ByteArray?,
    ): MobileQueuedMessage = client.queueLocalTextMessagePin(
        spaceId,
        groupReference,
        credentialVector,
        channelId,
        targetMessageId,
        add,
        tag,
    )
    fun publishDirectMessageKeyPackage(credentialVector: ByteArray): ByteArray =
        client.publishDirectMessageKeyPackage(
            credentialVector,
            (System.currentTimeMillis() / 1000).toULong(),
        )

    fun createDirectMessage(
        credentialVector: ByteArray,
        peerIdentity: ByteArray,
        peerKeyPackage: ByteArray,
        nextAttemptMs: Long,
    ): MobileCreatedDirectMessage = client.createDirectMessage(
        credentialVector,
        peerIdentity,
        peerKeyPackage,
        nextAttemptMs,
    )

    fun acceptDirectMessageInvitation(
        credentialVector: ByteArray,
        authenticatedPeerIdentity: ByteArray,
        invitationPacket: ByteArray,
        userAccepted: Boolean,
    ): ByteArray = client.acceptDirectMessageInvitation(
        credentialVector,
        authenticatedPeerIdentity,
        invitationPacket,
        userAccepted,
    )

    fun queueDirectMessageText(
        credentialVector: ByteArray,
        groupReference: ByteArray,
        content: String,
        nextAttemptMs: Long,
    ): MobileDirectMessagePacket = client.queueDirectMessageText(
        credentialVector,
        groupReference,
        content,
        nextAttemptMs,
    )

    override fun ingestDirectMessagePacket(
        authenticatedPeerIdentity: ByteArray,
        envelopeBytes: ByteArray,
    ): MobileDirectMessageIngressResult =
        client.ingestDirectMessagePacket(authenticatedPeerIdentity, envelopeBytes)

    fun directMessageConversations(
        limit: UInt = 64u,
    ): List<MobileDirectMessageConversation> = client.directMessageConversations(limit)

    fun directMessageHistory(
        groupReference: ByteArray,
        limit: UInt = 100u,
    ): List<MobileDirectMessageHistoryEntry> =
        client.directMessageHistory(groupReference, limit)

    fun directMessageOutboxPage(
        afterPacketId: ByteArray? = null,
        limit: UInt = 64u,
    ): List<MobileDirectMessageOutboxEntry> =
        client.directMessageOutboxPage(afterPacketId, limit)

    fun exchangeDirectMessagesOnce(
        connectAddress: String,
        listenAddress: String,
        peerFingerprint: ByteArray,
    ): MobileDirectMessageExchange =
        client.exchangeDirectMessagesOnce(connectAddress, listenAddress, peerFingerprint)

    override fun markDirectMessageAttempt(packetId: ByteArray, nextAttemptMs: Long) =
        client.markDirectMessageAttempt(packetId, nextAttemptMs)

    override fun recordDirectMessagePeerIngressAccepted(packetId: ByteArray) =
        client.recordDirectMessagePeerIngressAccepted(packetId)

    override fun isDirectMessageRoutedToPeer(
        groupReference: ByteArray,
        peerIdentity: ByteArray,
    ): Boolean = client.directMessageIsForPeer(groupReference, peerIdentity)

    fun pendingDirectMessageInvitations(
        limit: UInt = 64u,
    ): List<MobileDirectMessagePendingInvitation> = client.pendingDirectMessageInvitations(limit)

    fun acceptPendingDirectMessageInvitation(
        credentialVector: ByteArray,
        authenticatedPeerIdentity: ByteArray,
        packetId: ByteArray,
        userAccepted: Boolean,
    ): ByteArray = client.acceptPendingDirectMessageInvitation(
        credentialVector,
        authenticatedPeerIdentity,
        packetId,
        userAccepted,
    )

    fun declinePendingDirectMessageInvitation(packetId: ByteArray): Boolean =
        client.declinePendingDirectMessageInvitation(packetId)

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        projectionSubscriptions.close()
        client.close()
    }

    companion object {
        private const val DATABASE_NAME = "lattice.sqlite"
        private const val MAX_ATTACHMENT_BYTES = 128 * 1024 * 1024L
        private const val MAX_ATTACHMENT_IMPORT_BYTES = 512 * 1024 * 1024L
        private const val MAX_ATTACHMENT_IMPORTS = 4
        private const val ATTACHMENT_IMPORT_RETENTION_MS = 24 * 60 * 60 * 1000L

        fun open(context: Context): AndroidMobileProfile {
            val database = context.getDatabasePath(DATABASE_NAME)
            val directory: File = database.parentFile
                ?: throw IllegalStateException("Android database directory is unavailable")
            if (!directory.isDirectory && !directory.mkdirs()) {
                throw IllegalStateException("Android database directory could not be created")
            }
            val attachmentRoot = File(directory, "attachments")
            if (!attachmentRoot.isDirectory && !attachmentRoot.mkdirs()) {
                throw IllegalStateException("Private attachment storage could not be created")
            }

            val keyProtector = AndroidPlatformKeyProtector()
            val client = MobileClient.openOrCreate(
                database.absolutePath,
                context.packageName,
                keyProtector,
            )
            return AndroidMobileProfile(
                client,
                keyProtector,
                context.packageName,
                context.applicationContext,
                attachmentRoot,
            )
        }
    }
}

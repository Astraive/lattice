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
import uniffi.lattice_uniffi.MobileBleRole
import uniffi.lattice_uniffi.MobileBleSession
import uniffi.lattice_uniffi.MobileOutboxEntry
import uniffi.lattice_uniffi.MobileSyncEventResult


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

/** Owns a Rust profile and the callback that bridges to AndroidKeyStore. */
internal class AndroidMobileProfile private constructor(
    private val client: MobileClient,
    private val keyProtector: AndroidPlatformKeyProtector,
    private val profileId: String,
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
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        projectionSubscriptions.close()
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

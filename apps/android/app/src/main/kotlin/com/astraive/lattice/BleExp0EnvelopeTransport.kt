package com.astraive.lattice

import uniffi.lattice_uniffi.MobileBleSession
import uniffi.lattice_uniffi.MobileOutboxEntry
import uniffi.lattice_uniffi.MobileOutboxState

/** FIFO GATT write queue; implementations must serialize control and frame writes. */
internal interface BleExp0EnvelopeIo {
    fun enqueueControl(ciphertext: ByteArray): Boolean
    fun enqueueFrame(frame: ByteArray): Boolean
    fun disconnect()
}

/**
 * Bridges authenticated Noise records, bounded exp0 transfers, FIFO GATT value
 * queues, Rust Core event ingress, and durable destination receipts. Invoke
 * from a serialized worker, never directly from the main thread.
 */
internal class BleExp0EnvelopeTransport(
    private val profile: AndroidMobileProfile,
    private val session: MobileBleSession,
    private val transfer: BleExp0TransferProtocol,
    private val io: BleExp0EnvelopeIo,
) {
    private var closed = false
    private var activeOutboundEventId: ByteArray? = null

    /** Starts a due durable envelope and records the attempt before GATT transmission. */
    @Synchronized
    fun sendEnvelope(
        entry: MobileOutboxEntry,
        retryAtUnixMillis: Long,
        nowUnixMillis: Long,
        nowElapsedMillis: Long,
    ) {
        requireAuthenticated()
        require(entry.state == MobileOutboxState.QUEUED || entry.state == MobileOutboxState.FORWARDED) {
            "Only queued or forwarded outbox entries can be sent"
        }
        require(entry.nextAttemptMs <= nowUnixMillis) { "Outbox entry is not due yet" }
        require(retryAtUnixMillis >= 0) { "Retry time must be nonnegative" }
        require(entry.eventId.size == 32) { "Outbox event ID must contain 32 bytes" }
        val start = try {
            transfer.beginOutbound(entry.envelopeBytes, nowElapsedMillis)
        } catch (error: Exception) {
            if (transfer.isClosed) failClosed()
            throw error
        }
        try {
            profile.markOutboxForwarded(entry.eventId, retryAtUnixMillis)
            activeOutboundEventId = entry.eventId.copyOf()
            sendProtectedControl(start)
        } catch (error: Exception) {
            failClosed()
            throw error
        }
    }

    /** Receives one Noise-protected LBTS, LBWC, or LBFA on the GATT control characteristic. */
    @Synchronized
    fun receiveControl(ciphertext: ByteArray, nowMillis: Long): ByteArray? {
        requireAuthenticated()
        try {
            val plaintext = session.decryptRecord(ciphertext)
            return when {
                hasMagic(plaintext, START_MAGIC) -> {
                    sendProtectedControl(transfer.acceptStart(plaintext, nowMillis))
                    null
                }
                hasMagic(plaintext, CREDIT_MAGIC) -> {
                    transfer.acceptCredit(plaintext, nowMillis).forEach(::sendFrame)
                    null
                }
                hasMagic(plaintext, COMPLETION_MAGIC) -> {
                    transfer.acceptCompletion(plaintext, nowMillis)
                    val eventId = activeOutboundEventId
                        ?: throw IllegalStateException("Completion has no active outbox event")
                    profile.recordDestinationReceipt(eventId)
                    activeOutboundEventId = null
                    eventId.copyOf()
                }
                else -> throw IllegalArgumentException("Unsupported exp0 transfer control")
            }
        } catch (error: Exception) {
            failClosed()
            throw error
        }
    }

    /** Receives one opaque envelope fragment on the GATT data characteristic. */
    @Synchronized
    fun receiveFrame(frame: ByteArray, nowMillis: Long) {
        requireAuthenticated()
        try {
            val update = transfer.acceptFrame(frame, nowMillis)
            update.creditRecord?.let(::sendProtectedControl)
            val completedEnvelope = update.completedEnvelope ?: return
            profile.ingestSyncedApplicationEvent(completedEnvelope)
            sendProtectedControl(
                transfer.acknowledgeIngress(
                    readTransferId(frame),
                    android.os.SystemClock.elapsedRealtime(),
                ),
            )
        } catch (error: Exception) {
            failClosed()
            throw error
        }
    }

    /** Expires active transfers using monotonic elapsed-realtime milliseconds. */
    @Synchronized
    fun expire(nowMillis: Long): Boolean {
        if (closed) return true
        return try {
            if (transfer.expire(nowMillis)) {
                failClosed()
                true
            } else {
                false
            }
        } catch (error: Exception) {
            failClosed()
            throw error
        }
    }
    /** Closes transient state when lifecycle, radio, permission, or GATT ownership ends. */
    @Synchronized
    fun close() = failClosed()

    private fun requireAuthenticated() {
        check(!closed) { "BLE envelope transport is closed" }
        try {
            check(session.isAuthenticated()) {
                "BLE application transport requires peer confirmation"
            }
        } catch (error: Exception) {
            failClosed()
            throw error
        }
    }

    private fun sendProtectedControl(plaintext: ByteArray) {
        val ciphertext = session.encryptRecord(plaintext)
        check(io.enqueueControl(ciphertext)) { "GATT control write queue rejected a record" }
    }

    private fun sendFrame(frame: ByteArray) {
        check(io.enqueueFrame(frame)) { "GATT frame write queue rejected a frame" }
    }

    private fun failClosed() {
        if (closed) return
        closed = true
        activeOutboundEventId = null
        transfer.close()
        io.disconnect()
    }

    private fun hasMagic(record: ByteArray, magic: ByteArray): Boolean {
        if (record.size < magic.size) return false
        return magic.indices.all { record[it] == magic[it] }
    }

    private fun readTransferId(frame: ByteArray): Long =
        java.nio.ByteBuffer.wrap(frame).order(java.nio.ByteOrder.BIG_ENDIAN).getLong(4)

    private companion object {
        val START_MAGIC = byteArrayOf(0x4c, 0x42, 0x54, 0x53)
        val CREDIT_MAGIC = byteArrayOf(0x4c, 0x42, 0x57, 0x43)
        val COMPLETION_MAGIC = byteArrayOf(0x4c, 0x42, 0x46, 0x41)
    }
}

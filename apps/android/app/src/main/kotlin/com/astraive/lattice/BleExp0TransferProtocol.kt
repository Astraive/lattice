package com.astraive.lattice

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * Per-authenticated-session exp0 transfer control and bounded frame pacing.
 * Inputs and outputs are plaintext records; callers must protect every record
 * with MobileBleSession before it reaches GATT.
 */
internal class BleExp0TransferProtocol(
    private val localRole: Byte,
    private val negotiatedMtu: Int,
    initialOutboundTransferId: Long,
) {
    data class InboundUpdate(
        val creditRecord: ByteArray?,
        val completedEnvelope: ByteArray?,
    )

    private data class Outbound(
        val id: Long,
        val frames: List<ByteArray>,
        val startedAt: Long,
        var grantLimit: Int = 0,
        var nextFrame: Int = 0,
    )

    private data class Inbound(
        val id: Long,
        val envelopeLength: Int,
        val frameCount: Int,
        val startedAt: Long,
        val acceptedFrames: MutableMap<Int, ByteArray> = mutableMapOf(),
        var grantLimit: Int = minOf(INITIAL_WINDOW, frameCount),
        var completedEnvelope: ByteArray? = null,
    )

    private val remoteRole = if (localRole == ROLE_INITIATOR) ROLE_RESPONDER else ROLE_INITIATOR
    private val valueLimit = minOf(MAX_GATT_VALUE_BYTES, negotiatedMtu - ATT_OVERHEAD_BYTES)
    private val payloadCapacity = valueLimit - BleFrameCodec.HEADER_BYTES
    private val frameCodec: BleFrameCodec
    private var outbound: Outbound? = null
    private var inbound: Inbound? = null
    private var nextOutboundId = initialOutboundTransferId
    private var lastInboundId: Long? = null
    private var lastNow = -1L
    private var closed = false

    init {
        require(localRole == ROLE_INITIATOR || localRole == ROLE_RESPONDER)
        require(negotiatedMtu >= MIN_ATT_MTU)
        require(valueLimit <= MAX_GATT_VALUE_BYTES && valueLimit > BleFrameCodec.HEADER_BYTES)
        require(initialOutboundTransferId != 0L)
        frameCodec = BleFrameCodec(
            BleFrameCodec.Limits(
                maxFrameBytes = valueLimit,
                maxAggregateBufferedBytes = MAX_ENVELOPE_BYTES,
                assemblyTtlMillis = TRANSFER_TIMEOUT_MS,
            ),
        )
    }

    /** Starts one durable outbox envelope and returns its encrypted-by-caller LBTS plaintext. */
    fun beginOutbound(envelope: ByteArray, nowMillis: Long): ByteArray {
        ensureOpen()
        observeTime(nowMillis)
        checkNotExpired(nowMillis)
        require(outbound == null) { "An outbound transfer is already active" }
        require(envelope.isNotEmpty() && envelope.size <= MAX_ENVELOPE_BYTES) {
            "Envelope size is outside exp0 limits"
        }
        require(nextOutboundId != 0L) { "Transfer ID wrapped" }
        val frames = frameCodec.fragment(envelope, nextOutboundId)
        val transfer = Outbound(nextOutboundId, frames, nowMillis)
        outbound = transfer
        return encodeStart(localRole, transfer.id, envelope.size, frames.size)
    }

    /** Validates a receiver's monotonic sliding-window grant and releases at most four frames. */
    fun acceptCredit(record: ByteArray, nowMillis: Long): List<ByteArray> {
        ensureOpen()
        observeTime(nowMillis)
        checkNotExpired(nowMillis)
        val transfer = outbound ?: return fail("No outbound transfer is active")
        val (id, limit) = decodeCredit(record, localRole)
        if (id != transfer.id || limit > transfer.frames.size || limit < transfer.grantLimit) {
            return fail("Credit does not match the active transfer")
        }
        val expectedInitial = minOf(INITIAL_WINDOW, transfer.frames.size)
        if (transfer.grantLimit == 0 && limit != expectedInitial) {
            return fail("Initial credit is not canonical")
        }
        if (limit > transfer.grantLimit + INITIAL_WINDOW) {
            return fail("Credit exceeds the sliding window")
        }
        transfer.grantLimit = limit
        val acceptedLowerBound = maxOf(0, limit - INITIAL_WINDOW)
        val frames = ArrayList<ByteArray>(minOf(INITIAL_WINDOW, limit - transfer.nextFrame))
        while (transfer.nextFrame < limit && transfer.nextFrame - acceptedLowerBound < INITIAL_WINDOW) {
            frames.add(transfer.frames[transfer.nextFrame])
            transfer.nextFrame++
        }
        return frames
    }


    /** Completes an outbound transfer only after a matching authenticated LBFA. */
    fun acceptCompletion(record: ByteArray, nowMillis: Long) {
        ensureOpen()
        observeTime(nowMillis)
        checkNotExpired(nowMillis)
        val transfer = outbound ?: fail("No outbound transfer is active")
        val id = decodeCompletion(record, localRole)
        if (id != transfer.id || transfer.nextFrame != transfer.frames.size) {
            fail("Completion does not match the sent transfer")
        }
        outbound = null
        nextOutboundId = if (id == -1L) 0L else id + 1
        if (nextOutboundId == 0L) close()
    }

    /** Validates one authenticated peer LBTS and returns the first four-frame grant. */
    fun acceptStart(record: ByteArray, nowMillis: Long): ByteArray {
        ensureOpen()
        observeTime(nowMillis)
        checkNotExpired(nowMillis)
        if (inbound != null) return fail("An inbound transfer is already active")
        val (id, length, count) = decodeStart(record, remoteRole)
        if (id == 0L || (lastInboundId != null &&
                (lastInboundId == -1L || id != lastInboundId!! + 1))) {
            return fail("Inbound transfer ID is not sequential")
        }
        val expectedCount = frameCountFor(length)
        if (count != expectedCount) return fail("Inbound frame count is inconsistent")
        val state = Inbound(id, length, count, nowMillis)
        inbound = state
        return encodeCredit(remoteRole, id, state.grantLimit)
    }

    /** Accepts one canonical fragment and returns new credit plus any completed envelope. */
    fun acceptFrame(frame: ByteArray, nowMillis: Long): InboundUpdate {
        ensureOpen()
        observeTime(nowMillis)
        checkNotExpired(nowMillis)
        val state = inbound ?: return fail("No inbound transfer is active")
        if (frame.size > valueLimit || frame.size < BleFrameCodec.HEADER_BYTES + 1) {
            return fail("Frame size exceeds negotiated value bound")
        }
        val metadata = parseFrameMetadata(frame)
        if (metadata.id != state.id || metadata.count != state.frameCount ||
            metadata.totalLength != state.envelopeLength || metadata.index >= state.grantLimit
        ) {
            return fail("Frame does not match current transfer credit")
        }
        val prior = state.acceptedFrames[metadata.index]
        if (prior != null) {
            if (!prior.contentEquals(frame)) return fail("Conflicting duplicate fragment")
            return InboundUpdate(null, null)
        }
        if (metadata.index != state.acceptedFrames.size) {
            return fail("Fragments must arrive in increasing order")
        }
        val completed = try {
            frameCodec.accept(frame, nowMillis)
        } catch (_: IllegalArgumentException) {
            return fail("Malformed fragment")
        }
        state.acceptedFrames[metadata.index] = frame.copyOf()
        state.grantLimit = minOf(state.acceptedFrames.size + INITIAL_WINDOW, state.frameCount)
        if (completed != null) {
            if (completed.size != state.envelopeLength || state.acceptedFrames.size != state.frameCount) {
                return fail("Completed envelope length is inconsistent")
            }
            state.completedEnvelope = completed
        }
        return InboundUpdate(encodeCredit(remoteRole, state.id, state.grantLimit), completed)
    }

    /** Returns LBFA only after Core accepted the complete envelope into bounded ingress. */
    fun acknowledgeIngress(transferId: Long, nowMillis: Long): ByteArray {
        ensureOpen()
        observeTime(nowMillis)
        checkNotExpired(nowMillis)
        val state = inbound ?: return fail("No inbound transfer is active")
        if (state.id != transferId || state.completedEnvelope == null) {
            return fail("Ingress acknowledgement precedes a complete envelope")
        }
        inbound = null
        lastInboundId = transferId
        return encodeCompletion(remoteRole, transferId)
    }

    /** Closes the session when either direction reaches the 30-second deadline. */
    fun expire(nowMillis: Long): Boolean {
        ensureOpen()
        observeTime(nowMillis)
        return expireActive(nowMillis)
    }

    val isClosed: Boolean get() = closed

    /** Closes the protocol state when GATT, Core-ingress, or lifecycle work fails. */
    fun close() {
        closed = true
        inbound = null
        outbound = null
    }


    private fun frameCountFor(length: Int): Int {
        if (length !in 1..MAX_ENVELOPE_BYTES) return fail("Invalid envelope length")
        val count = (length.toLong() + payloadCapacity - 1) / payloadCapacity
        if (count !in 1..MAX_FRAME_COUNT.toLong()) return fail("Envelope requires too many frames")
        return count.toInt()
    }
    private fun expireActive(nowMillis: Long): Boolean {
        val timedOut = inbound?.let { nowMillis - it.startedAt >= TRANSFER_TIMEOUT_MS } == true ||
            outbound?.let { nowMillis - it.startedAt >= TRANSFER_TIMEOUT_MS } == true
        if (timedOut) close()
        return timedOut
    }

    private fun checkNotExpired(nowMillis: Long) {
        if (expireActive(nowMillis)) throw IllegalStateException("Transfer timed out")
    }

    private fun observeTime(nowMillis: Long) {
        if (nowMillis < 0 || (lastNow >= 0 && nowMillis < lastNow)) {
            close()
            throw IllegalArgumentException("Monotonic time moved backwards")
        }
        lastNow = nowMillis
    }

    private fun ensureOpen() {
        check(!closed) { "Transfer protocol is closed" }
    }

    private fun fail(message: String): Nothing {
        close()
        throw IllegalArgumentException(message)
    }

    private data class FrameMetadata(
        val id: Long,
        val index: Int,
        val count: Int,
        val totalLength: Int,
    )

    private fun parseFrameMetadata(frame: ByteArray): FrameMetadata {
        val buffer = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN)
        if (buffer.get() != FRAME_MAGIC_0 || buffer.get() != FRAME_MAGIC_1 ||
            buffer.get() != FRAME_VERSION || buffer.get().toInt() != 0
        ) return fail("Invalid frame header")
        val id = buffer.long
        val sequence = buffer.short.toInt() and 0xffff
        val index = buffer.short.toInt() and 0xffff
        val count = buffer.short.toInt() and 0xffff
        val totalLength = buffer.int
        val payloadLength = buffer.short.toInt() and 0xffff
        if (id == 0L || sequence != index || payloadLength != buffer.remaining() || payloadLength == 0) {
            return fail("Invalid frame metadata")
        }
        return FrameMetadata(id, index, count, totalLength)
    }

    private fun encodeStart(role: Byte, id: Long, length: Int, count: Int): ByteArray =
        ByteBuffer.allocate(START_RECORD_BYTES).order(ByteOrder.BIG_ENDIAN)
            .put(START_MAGIC).put(CONTROL_VERSION).put(role).putLong(id).putInt(length).putShort(count.toShort()).array()

    private fun decodeStart(record: ByteArray, expectedRole: Byte): Triple<Long, Int, Int> {
        if (record.size != START_RECORD_BYTES) return fail("Invalid transfer-start length")
        val buffer = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN)
        if (!readHeader(buffer, START_MAGIC, expectedRole)) return fail("Invalid transfer-start header")
        val id = buffer.long
        val length = buffer.int
        val count = buffer.short.toInt() and 0xffff
        if (id == 0L) return fail("Zero transfer ID")
        return Triple(id, length, count)
    }

    private fun encodeCredit(role: Byte, id: Long, limit: Int): ByteArray =
        ByteBuffer.allocate(CREDIT_RECORD_BYTES).order(ByteOrder.BIG_ENDIAN)
            .put(CREDIT_MAGIC).put(CONTROL_VERSION).put(role).putLong(id).putShort(limit.toShort()).array()

    private fun decodeCredit(record: ByteArray, expectedRole: Byte): Pair<Long, Int> {
        if (record.size != CREDIT_RECORD_BYTES) return fail("Invalid credit length")
        val buffer = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN)
        if (!readHeader(buffer, CREDIT_MAGIC, expectedRole)) return fail("Invalid credit header")
        return buffer.long to (buffer.short.toInt() and 0xffff)
    }

    private fun encodeCompletion(role: Byte, id: Long): ByteArray =
        ByteBuffer.allocate(COMPLETION_RECORD_BYTES).order(ByteOrder.BIG_ENDIAN)
            .put(COMPLETION_MAGIC).put(CONTROL_VERSION).put(role).putLong(id).array()

    private fun decodeCompletion(record: ByteArray, expectedRole: Byte): Long {
        if (record.size != COMPLETION_RECORD_BYTES) return fail("Invalid completion length")
        val buffer = ByteBuffer.wrap(record).order(ByteOrder.BIG_ENDIAN)
        if (!readHeader(buffer, COMPLETION_MAGIC, expectedRole)) return fail("Invalid completion header")
        val id = buffer.long
        if (id == 0L) return fail("Zero completion transfer ID")
        return id
    }

    private fun readHeader(buffer: ByteBuffer, magic: ByteArray, role: Byte): Boolean {
        for (expected in magic) {
            if (buffer.get() != expected) return false
        }
        return buffer.get() == CONTROL_VERSION && buffer.get() == role
    }

    internal companion object {
        fun forAuthenticatedSession(localRole: Byte, negotiatedMtu: Int): BleExp0TransferProtocol {
            val random = SecureRandom()
            var initialTransferId: Long
            do {
                initialTransferId = random.nextLong()
            } while (initialTransferId == 0L)
            return BleExp0TransferProtocol(localRole, negotiatedMtu, initialTransferId)
        }
        const val ROLE_INITIATOR: Byte = 1
        const val ROLE_RESPONDER: Byte = 2
        const val CONTROL_VERSION: Byte = 0
        const val ATT_OVERHEAD_BYTES = 3
        const val MIN_ATT_MTU = 154
        const val MAX_GATT_VALUE_BYTES = 512
        const val MAX_ENVELOPE_BYTES = 110 * 1024
        const val MAX_FRAME_COUNT = 1024
        const val INITIAL_WINDOW = 4
        const val TRANSFER_TIMEOUT_MS = 30_000L
        const val START_RECORD_BYTES = 20
        const val CREDIT_RECORD_BYTES = 16
        const val COMPLETION_RECORD_BYTES = 14
        const val FRAME_MAGIC_0: Byte = 0x4c
        const val FRAME_MAGIC_1: Byte = 0x46
        const val FRAME_VERSION: Byte = 1
        val START_MAGIC = byteArrayOf(0x4c, 0x42, 0x54, 0x53)
        val CREDIT_MAGIC = byteArrayOf(0x4c, 0x42, 0x57, 0x43)
        val COMPLETION_MAGIC = byteArrayOf(0x4c, 0x42, 0x46, 0x41)
    }
}

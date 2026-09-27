package com.astraive.lattice

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Bounded framing for opaque exp0 envelope bytes. This codec performs no
 * encryption, authentication, peer validation, or replay protection; its caller
 * must use an authenticated session and validate the completed envelope.
 */
class BleFrameCodec(
    private val limits: Limits = Limits(),
) {
    data class Limits(
        val maxEnvelopeBytes: Int = MAX_EXP0_ENVELOPE_BYTES,
        val maxFrameBytes: Int = MAX_FRAME_BYTES,
        val maxFrameCount: Int = MAX_EXP0_FRAME_COUNT,
        val maxAggregateBufferedBytes: Int = MAX_EXP0_ENVELOPE_BYTES,
        val assemblyTtlMillis: Long = 30_000,
    ) {
        init {
            require(maxEnvelopeBytes in 1..MAX_EXP0_ENVELOPE_BYTES)
            require(maxFrameBytes in (HEADER_BYTES + 1)..MAX_FRAME_BYTES)
            require(maxFrameCount in 1..MAX_EXP0_FRAME_COUNT)
            require(maxAggregateBufferedBytes in 1..MAX_EXP0_ENVELOPE_BYTES)
            require(assemblyTtlMillis > 0)
        }
    }

    private data class Assembly(
        val totalLength: Int,
        val frameCount: Int,
        val createdAtMillis: Long,
        val chunks: Array<ByteArray?>,
        var receivedCount: Int = 0,
        var bufferedBytes: Int = 0,
    )

    private data class ParsedFrame(
        val transferId: Long,
        val index: Int,
        val frameCount: Int,
        val totalLength: Int,
        val payload: ByteArray,
    )

    private val assemblies = LinkedHashMap<Long, Assembly>()
    private var aggregateBufferedBytes = 0
    private var lastNowMillis = Long.MIN_VALUE
    private val payloadCapacity = limits.maxFrameBytes - HEADER_BYTES

    /** Splits one envelope into canonical frames no larger than the negotiated value bound. */
    fun fragment(ciphertext: ByteArray, transferId: Long): List<ByteArray> {
        require(transferId != 0L) { "Transfer ID must be non-zero" }
        require(ciphertext.isNotEmpty()) { "Envelope must not be empty" }
        require(ciphertext.size <= limits.maxEnvelopeBytes) { "Envelope exceeds configured limit" }
        val count = (ciphertext.size.toLong() + payloadCapacity - 1) / payloadCapacity
        require(count <= limits.maxFrameCount) { "Envelope requires too many frames" }

        return List(count.toInt()) { index ->
            val start = index * payloadCapacity
            val payloadLength = minOf(payloadCapacity, ciphertext.size - start)
            val buffer = ByteBuffer.allocate(HEADER_BYTES + payloadLength).order(ByteOrder.BIG_ENDIAN)
            buffer.put(MAGIC_0)
            buffer.put(MAGIC_1)
            buffer.put(VERSION)
            buffer.put(0) // reserved; must remain zero
            buffer.putLong(transferId)
            buffer.putShort(index.toShort()) // sequence
            buffer.putShort(index.toShort()) // fragment index
            buffer.putShort(count.toShort())
            buffer.putInt(ciphertext.size)
            buffer.putShort(payloadLength.toShort())
            buffer.put(ciphertext, start, payloadLength)
            buffer.array()
        }
    }

    /** Returns the completed envelope exactly once, or null while fragments remain. */
    fun accept(frame: ByteArray, nowMillis: Long): ByteArray? {
        expire(nowMillis)
        val parsed = parse(frame)
        val existing = assemblies[parsed.transferId]
        if (existing != null &&
            (existing.totalLength != parsed.totalLength || existing.frameCount != parsed.frameCount)
        ) {
            discard(parsed.transferId)
            throw IllegalArgumentException("Inconsistent metadata for transfer")
        }

        val assembly = existing ?: run {
            require(assemblies.size < MAX_ASSEMBLIES) { "Too many concurrent transfers" }
            Assembly(
                totalLength = parsed.totalLength,
                frameCount = parsed.frameCount,
                createdAtMillis = nowMillis,
                chunks = arrayOfNulls(parsed.frameCount),
            ).also { assemblies[parsed.transferId] = it }
        }

        val prior = assembly.chunks[parsed.index]
        if (prior != null) {
            if (prior.contentEquals(parsed.payload)) return null
            discard(parsed.transferId)
            throw IllegalArgumentException("Conflicting duplicate fragment")
        }
        if (parsed.payload.size > limits.maxAggregateBufferedBytes - aggregateBufferedBytes) {
            discard(parsed.transferId)
            throw IllegalArgumentException("Aggregate buffered fragment limit exceeded")
        }

        assembly.chunks[parsed.index] = parsed.payload
        assembly.receivedCount++
        assembly.bufferedBytes += parsed.payload.size
        aggregateBufferedBytes += parsed.payload.size
        if (assembly.receivedCount != assembly.frameCount) return null

        check(assembly.bufferedBytes == assembly.totalLength) { "Completed transfer length mismatch" }
        val completed = ByteArray(assembly.totalLength)
        var offset = 0
        for (chunk in assembly.chunks) {
            val bytes = checkNotNull(chunk)
            bytes.copyInto(completed, offset)
            offset += bytes.size
        }
        discard(parsed.transferId)
        return completed
    }

    /** Expires the single in-progress assembly at the configured monotonic-time boundary. */
    fun expire(nowMillis: Long): Int {
        require(nowMillis >= 0) { "Monotonic time must be non-negative" }
        require(lastNowMillis == Long.MIN_VALUE || nowMillis >= lastNowMillis) {
            "Monotonic time moved backwards"
        }
        lastNowMillis = nowMillis
        val entry = assemblies.entries.firstOrNull() ?: return 0
        if (nowMillis - entry.value.createdAtMillis < limits.assemblyTtlMillis) return 0
        discard(entry.key)
        return 1
    }

    private fun parse(frame: ByteArray): ParsedFrame {
        require(frame.size in (HEADER_BYTES + 1)..limits.maxFrameBytes) { "Invalid frame size" }
        val buffer = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN)
        require(buffer.get() == MAGIC_0 && buffer.get() == MAGIC_1) { "Invalid frame magic" }
        require(buffer.get() == VERSION) { "Unsupported frame version" }
        require(buffer.get().toInt() == 0) { "Reserved header bits must be zero" }
        val transferId = buffer.long
        require(transferId != 0L) { "Transfer ID must be non-zero" }
        val sequence = buffer.short.toInt() and 0xffff
        val index = buffer.short.toInt() and 0xffff
        val frameCount = buffer.short.toInt() and 0xffff
        val totalLength = buffer.int
        val payloadLength = buffer.short.toInt() and 0xffff
        require(sequence == index) { "Invalid frame sequence/index" }
        require(payloadLength == buffer.remaining() && payloadLength > 0) { "Invalid payload length" }
        require(frameCount in 1..limits.maxFrameCount && frameCount == frameCountFor(totalLength)) {
            "Invalid frame count or envelope length"
        }
        require(index < frameCount) { "Invalid fragment index" }
        val expectedPayloadLength = if (index == frameCount - 1) {
            totalLength - payloadCapacity * (frameCount - 1)
        } else {
            payloadCapacity
        }
        require(payloadLength == expectedPayloadLength) { "Non-canonical fragment length" }
        val payload = ByteArray(payloadLength)
        buffer.get(payload)
        return ParsedFrame(transferId, index, frameCount, totalLength, payload)
    }

    private fun frameCountFor(totalLength: Int): Int {
        require(totalLength in 1..limits.maxEnvelopeBytes) { "Invalid envelope length" }
        val count = (totalLength.toLong() + payloadCapacity - 1) / payloadCapacity
        require(count <= limits.maxFrameCount) { "Envelope requires too many frames" }
        return count.toInt()
    }

    private fun discard(transferId: Long) {
        val removed = assemblies.remove(transferId) ?: return
        aggregateBufferedBytes -= removed.bufferedBytes
    }

    internal companion object {
        const val MAGIC_0: Byte = 0x4c
        const val MAGIC_1: Byte = 0x46
        const val VERSION: Byte = 1
        internal const val HEADER_BYTES = 24
        const val MAX_FRAME_BYTES = 512
        const val MAX_EXP0_FRAME_COUNT = 1024
        const val MAX_EXP0_ENVELOPE_BYTES = 110 * 1024
        const val MAX_ASSEMBLIES = 1
    }
}

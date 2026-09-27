package com.astraive.lattice

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Bounded framing for an already-encrypted opaque envelope. This codec performs no
 * encryption, authentication, peer validation, or replay protection; callers must
 * provide ciphertext and validate the completed envelope at the protocol layer.
 */
class BleFrameCodec(
    private val limits: Limits = Limits(),
) {
    data class Limits(
        val maxEnvelopeBytes: Int = 256 * 1024,
        val maxFrameBytes: Int = 512,
        val maxFrameCount: Int = 1024,
        val maxAssemblies: Int = 16,
        val maxAggregateBufferedBytes: Int = 1024 * 1024,
        val assemblyTtlMillis: Long = 30_000,
    ) {
        init {
            require(maxEnvelopeBytes > 0)
            require(maxFrameBytes > HEADER_BYTES && maxFrameBytes <= MAX_FRAME_BYTES)
            require(maxFrameCount in 1..MAX_WIRE_FRAME_COUNT)
            require(maxAssemblies > 0)
            require(maxAggregateBufferedBytes > 0)
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

    private val assemblies = LinkedHashMap<Long, Assembly>()
    private var aggregateBufferedBytes = 0
    private var lastNowMillis = Long.MIN_VALUE
    private val payloadCapacity = limits.maxFrameBytes - HEADER_BYTES

    /** Split ciphertext into canonical frames, each no larger than [Limits.maxFrameBytes]. */
    fun fragment(ciphertext: ByteArray, transferId: Long): List<ByteArray> {
        require(ciphertext.isNotEmpty()) { "Envelope must not be empty" }
        require(ciphertext.size <= limits.maxEnvelopeBytes) { "Envelope exceeds configured limit" }
        val count = (ciphertext.size.toLong() + payloadCapacity - 1) / payloadCapacity
        require(count <= limits.maxFrameCount && count <= MAX_WIRE_FRAME_COUNT) {
            "Envelope requires too many frames"
        }

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

    /**
     * Accept one frame at caller-supplied monotonic time. Returns the completed
     * ciphertext exactly once, or null while more fragments are needed.
     * Identical duplicate frames are idempotent. A conflicting duplicate or
     * inconsistent frame set discards that transfer and throws.
     */
    fun accept(frame: ByteArray, nowMillis: Long): ByteArray? {
        require(nowMillis >= 0) { "Monotonic time must be non-negative" }
        require(lastNowMillis == Long.MIN_VALUE || nowMillis >= lastNowMillis) {
            "Monotonic time moved backwards"
        }
        lastNowMillis = nowMillis
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
            require(assemblies.size < limits.maxAssemblies) { "Too many concurrent transfers" }
            // parse() has already checked this arithmetic and canonical count/length relationship.
            val created = Assembly(
                totalLength = parsed.totalLength,
                frameCount = parsed.frameCount,
                createdAtMillis = nowMillis,
                chunks = arrayOfNulls(parsed.frameCount),
            )
            assemblies[parsed.transferId] = created
            created
        }

        val prior = assembly.chunks[parsed.index]
        if (prior != null) {
            if (prior.contentEquals(parsed.payload)) return null
            discard(parsed.transferId)
            throw IllegalArgumentException("Conflicting duplicate fragment")
        }
        require(parsed.payload.size <= limits.maxAggregateBufferedBytes - aggregateBufferedBytes) {
            discard(parsed.transferId)
            "Aggregate buffered fragment limit exceeded"
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

    /** Expire assemblies whose age has reached the configured lifetime. */
    fun expire(nowMillis: Long): Int {
        require(nowMillis >= 0) { "Monotonic time must be non-negative" }
        require(lastNowMillis == Long.MIN_VALUE || nowMillis >= lastNowMillis) {
            "Monotonic time moved backwards"
        }
        lastNowMillis = nowMillis
        val expired = assemblies.entries
            .filter { nowMillis - it.value.createdAtMillis >= limits.assemblyTtlMillis }
            .map { it.key }
        expired.forEach(::discard)
        return expired.size
    }

    private data class ParsedFrame(
        val transferId: Long,
        val index: Int,
        val frameCount: Int,
        val totalLength: Int,
        val payload: ByteArray,
    )

    private fun parse(frame: ByteArray): ParsedFrame {
        require(frame.size in (HEADER_BYTES + 1)..limits.maxFrameBytes) { "Invalid frame size" }
        val buffer = ByteBuffer.wrap(frame).order(ByteOrder.BIG_ENDIAN)
        require(buffer.get() == MAGIC_0 && buffer.get() == MAGIC_1) { "Invalid frame magic" }
        require(buffer.get() == VERSION.toByte()) { "Unsupported frame version" }
        require(buffer.get().toInt() == 0) { "Reserved header bits must be zero" }
        val transferId = buffer.long
        val sequence = buffer.short.toInt() and 0xffff
        val index = buffer.short.toInt() and 0xffff
        val count = buffer.short.toInt() and 0xffff
        val totalLength = buffer.int
        val payloadLength = buffer.short.toInt() and 0xffff
        require(payloadLength == buffer.remaining() && payloadLength > 0) { "Invalid payload length" }
        require(count in 1..limits.maxFrameCount && count == frameCountFor(totalLength)) {
            "Invalid frame count or envelope length"
        }
        require(index < count && sequence == index) { "Invalid frame sequence/index" }
        val expectedPayloadLength = if (index == count - 1) {
            totalLength - payloadCapacity * (count - 1)
        } else {
            payloadCapacity
        }
        require(payloadLength == expectedPayloadLength) { "Non-canonical fragment length" }
        val payload = ByteArray(payloadLength)
        buffer.get(payload)
        return ParsedFrame(transferId, index, count, totalLength, payload)
    }

    private fun frameCountFor(totalLength: Int): Int {
        require(totalLength in 1..limits.maxEnvelopeBytes) { "Invalid envelope length" }
        val count = (totalLength.toLong() + payloadCapacity - 1) / payloadCapacity
        require(count <= limits.maxFrameCount && count <= MAX_WIRE_FRAME_COUNT) {
            "Envelope requires too many frames"
        }
        return count.toInt()
    }

    private fun discard(transferId: Long) {
        val removed = assemblies.remove(transferId) ?: return
        aggregateBufferedBytes -= removed.bufferedBytes
    }

    companion object {
        private const val MAGIC_0: Byte = 0x4c
        private const val MAGIC_1: Byte = 0x46
        private const val VERSION: Byte = 1
        private const val HEADER_BYTES = 24
        private const val MAX_FRAME_BYTES = 0xffff
        private const val MAX_WIRE_FRAME_COUNT = 0xffff
    }
}

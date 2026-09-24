package com.astraive.lattice

import org.junit.Test

class BleFrameCodecTest {

    @Test
    fun reconstructsReorderedFramesAndAcceptsIdenticalDuplicates() {
        val codec = BleFrameCodec(BleFrameCodec.Limits(maxFrameBytes = 28))
        val input = ByteArray(10) { it.toByte() }
        val frames = codec.fragment(input, transferId = 42)
        check(frames.size == 3)
        check(frames.all { it.size <= 28 })
        check(codec.accept(frames[2], 0) == null)
        check(codec.accept(frames[2].copyOf(), 0) == null)
        check(codec.accept(frames[0], 0) == null)
        check(codec.accept(frames[1], 0)?.contentEquals(input) == true)
        check(codec.accept(frames[0], 0) == null) // completed transfers are not retained
    }

    @Test
    fun rejectsCorruptIndexAndOversizedEnvelopes() {
        val codec = BleFrameCodec(BleFrameCodec.Limits(maxFrameBytes = 28, maxEnvelopeBytes = 8))
        val frame = codec.fragment(byteArrayOf(1, 2, 3, 4, 5), 7).first().copyOf()
        frame[14] = 0 // sequence remains zero
        frame[15] = 1 // index no longer agrees with sequence
        expectIllegalArgument { codec.accept(frame, 0) }
        expectIllegalArgument { codec.fragment(ByteArray(9), 1) }

        val oversizedWireFrame = codec.fragment(byteArrayOf(1), 8).single() + byteArrayOf(0)
        expectIllegalArgument { codec.accept(oversizedWireFrame, 1) }
    }

    @Test
    fun rejectsConflictingDuplicates() {
        val codec = BleFrameCodec(BleFrameCodec.Limits(maxFrameBytes = 28))
        val frames = codec.fragment(byteArrayOf(1, 2, 3, 4, 5), 12)
        codec.accept(frames.first(), 0)
        val conflicting = frames.first().copyOf()
        conflicting[conflicting.lastIndex] = (conflicting.last() + 1).toByte()
        expectIllegalArgument { codec.accept(conflicting, 1) }
        check(codec.accept(frames.last(), 1) == null)
    }

    @Test
    fun enforcesAggregateBufferLimit() {
        val codec = BleFrameCodec(
            BleFrameCodec.Limits(
                maxFrameBytes = 28,
                maxEnvelopeBytes = 8,
                maxAggregateBufferedBytes = 3,
            ),
        )
        val frames = codec.fragment(byteArrayOf(1, 2, 3, 4, 5), 9)
        expectIllegalArgument { codec.accept(frames.first(), 0) }
        // The rejected transfer was discarded, so a smaller transfer can be assembled.
        val small = codec.fragment(byteArrayOf(6, 7, 8), 10).single()
        check(codec.accept(small, 1)?.contentEquals(byteArrayOf(6, 7, 8)) == true)
    }

    @Test
    fun enforcesConcurrentAssemblyLimit() {
        val codec = BleFrameCodec(
            BleFrameCodec.Limits(maxFrameBytes = 28, maxAssemblies = 1),
        )
        val first = codec.fragment(byteArrayOf(1, 2, 3, 4, 5), 13)
        val second = codec.fragment(byteArrayOf(6, 7, 8, 9, 10), 14)
        check(codec.accept(first.first(), 0) == null)
        expectIllegalArgument { codec.accept(second.first(), 1) }
        check(codec.expire(30_000) == 1)
        check(codec.accept(second.first(), 30_000) == null)
    }

    @Test
    fun expiresAssembliesAtTheConfiguredBoundary() {
        val codec = BleFrameCodec(
            BleFrameCodec.Limits(maxFrameBytes = 28, assemblyTtlMillis = 10),
        )
        val frames = codec.fragment(byteArrayOf(1, 2, 3, 4, 5), 11)
        check(codec.accept(frames.first(), 100) == null)
        check(codec.expire(109) == 0)
        check(codec.expire(110) == 1)
        check(codec.accept(frames.last(), 110) == null)
    }

    private inline fun expectIllegalArgument(block: () -> Unit) {
        try {
            block()
        } catch (_: IllegalArgumentException) {
            return
        }
        error("Expected IllegalArgumentException")
    }
}

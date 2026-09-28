package com.astraive.lattice

import android.os.SystemClock
import uniffi.lattice_uniffi.MobileBlePeerInfo
import uniffi.lattice_uniffi.MobileBleSession
import uniffi.lattice_uniffi.MobileBleRole
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicBoolean

/** Owns Noise, first-contact consent, identity confirmation, and the authenticated data path. */
internal class BleExp0SessionCoordinator(
    private val profile: AndroidMobileProfile,
    private val role: MobileBleRole,
    private val responderToken: () -> ByteArray?,
    private val negotiatedMtu: Int,
    private val io: BleExp0EnvelopeIo,
    private val isRoutedToPeer: (ByteArray) -> Boolean,
    private val retryAt: (attemptCount: UInt, nowUnixMillis: Long) -> Long,
    private val onPeerVerificationRequired: (MobileBlePeerInfo, (Boolean) -> Unit) -> Unit,
    private val onAuthenticated: (BleExp0OutboxPump, (Boolean) -> Unit) -> Unit,
    private val decisionExecutor: Executor,
    private val onFailure: (String) -> Unit,
) : AutoCloseable {
    private enum class Stage {
        NEW,
        INITIATOR_WAIT_MESSAGE_1_WRITE,
        INITIATOR_WAIT_MESSAGE_2,
        INITIATOR_WAIT_MESSAGE_3_WRITE,
        INITIATOR_WAIT_IDENTITY_PROOF_WRITE,
        INITIATOR_WAIT_PEER_PROOF,
        INITIATOR_WAIT_USER_APPROVAL,
        INITIATOR_WAIT_CONFIRMATION_WRITE,
        INITIATOR_WAIT_PEER_CONFIRMATION,
        RESPONDER_WAIT_MESSAGE_1,
        RESPONDER_WAIT_MESSAGE_2_WRITE,
        RESPONDER_WAIT_MESSAGE_3,
        RESPONDER_WAIT_INITIATOR_PROOF,
        RESPONDER_WAIT_USER_APPROVAL,
        RESPONDER_WAIT_PROOF_WRITE,
        RESPONDER_WAIT_INITIATOR_CONFIRMATION,
        RESPONDER_WAIT_CONFIRMATION_WRITE,
        AUTHENTICATED,
        CLOSED,
    }

    private val session: MobileBleSession
    private var stage = Stage.NEW
    private var transport: BleExp0EnvelopeTransport? = null
    private var pump: BleExp0OutboxPump? = null
    private var lastActivityMillis = SystemClock.elapsedRealtime()
    private val routeAllowed = AtomicBoolean(false)
    private var pendingPeerInfo: MobileBlePeerInfo? = null

    init {
        val boundToken = requireNotNull(responderToken()) { "The observed responder token is unavailable" }
        try {
            session = profile.newBleSession(role, boundToken)
        } finally {
            boundToken.fill(0)
        }
    }

    /** Starts the initiator flight or arms the responder for the first Noise message. */
    @Synchronized
    fun start() {
        check(stage == Stage.NEW) { "BLE handshake has already started" }
        try {
            when (role) {
                MobileBleRole.INITIATOR -> {
                    stage = Stage.INITIATOR_WAIT_MESSAGE_1_WRITE
                    sendPlainHandshake(session.writeHandshakeMessage())
                }
                MobileBleRole.RESPONDER -> stage = Stage.RESPONDER_WAIT_MESSAGE_1
            }
            touch(SystemClock.elapsedRealtime())
        } catch (error: Exception) {
            failClosed(error)
        }
    }

    /** Feeds a raw Noise handshake/proof record or an authenticated transfer control. */
    @Synchronized
    fun receiveControl(value: ByteArray, elapsedMillis: Long = SystemClock.elapsedRealtime()) {
        if (stage == Stage.CLOSED) return
        try {
            require(value.isNotEmpty()) { "Empty GATT control value" }
            checkFresh(elapsedMillis)
            if (stage == Stage.AUTHENTICATED) {
                val ingressEventId = requireNotNull(pump).receiveControl(
                    value,
                    System.currentTimeMillis(),
                    elapsedMillis,
                    retryAt,
                )
                if (ingressEventId != null) startNextDue(elapsedMillis)
                touch(elapsedMillis)
                return
            }
            when (stage) {
                Stage.INITIATOR_WAIT_MESSAGE_2 -> {
                    session.readHandshakeMessage(value)
                    stage = Stage.INITIATOR_WAIT_MESSAGE_3_WRITE
                    sendPlainHandshake(session.writeHandshakeMessage())
                }
                Stage.INITIATOR_WAIT_PEER_PROOF -> {
                    val peer = session.readIdentityProof(value)
                    stage = Stage.INITIATOR_WAIT_USER_APPROVAL
                    requestPin(peer)
                }
                Stage.INITIATOR_WAIT_PEER_CONFIRMATION -> {
                    session.readConfirmation(value)
                    check(session.isAuthenticated()) { "Peer confirmation did not authenticate" }
                    establishAuthenticatedTransport()
                }
                Stage.RESPONDER_WAIT_MESSAGE_1 -> {
                    session.readHandshakeMessage(value)
                    stage = Stage.RESPONDER_WAIT_MESSAGE_2_WRITE
                    sendPlainHandshake(session.writeHandshakeMessage())
                }
                Stage.RESPONDER_WAIT_MESSAGE_3 -> {
                    session.readHandshakeMessage(value)
                    check(session.handshakeComplete()) { "Noise handshake is incomplete" }
                    stage = Stage.RESPONDER_WAIT_INITIATOR_PROOF
                }
                Stage.RESPONDER_WAIT_INITIATOR_PROOF -> {
                    val activeToken = requireNotNull(responderToken()) {
                        "The active responder token is unavailable"
                    }
                    try {
                        session.validateActiveResponderToken(activeToken)
                    } finally {
                        activeToken.fill(0)
                    }
                    val peer = session.readIdentityProof(value)
                    stage = Stage.RESPONDER_WAIT_USER_APPROVAL
                    requestPin(peer)
                }
                Stage.RESPONDER_WAIT_INITIATOR_CONFIRMATION -> {
                    session.readConfirmation(value)
                    stage = Stage.RESPONDER_WAIT_CONFIRMATION_WRITE
                    enqueueSessionRecord(session.writeConfirmation())
                }
                else -> error("Control record is invalid in handshake state $stage")
            }
            touch(elapsedMillis)
        } catch (error: Exception) {
            failClosed(error)
        }
    }

    /** Advances handshake state only after the local GATT control write/notify succeeded. */
    @Synchronized
    fun onControlWriteCompleted(status: Int) {
        if (stage == Stage.CLOSED || stage == Stage.AUTHENTICATED) return
        if (status != GATT_SUCCESS) {
            failClosed(IllegalStateException("GATT control transmission failed ($status)"))
            return
        }
        try {
            when (stage) {
                Stage.INITIATOR_WAIT_MESSAGE_1_WRITE -> stage = Stage.INITIATOR_WAIT_MESSAGE_2
                Stage.INITIATOR_WAIT_MESSAGE_3_WRITE -> {
                    stage = Stage.INITIATOR_WAIT_IDENTITY_PROOF_WRITE
                    enqueueSessionRecord(session.writeIdentityProof())
                }
                Stage.INITIATOR_WAIT_IDENTITY_PROOF_WRITE -> stage = Stage.INITIATOR_WAIT_PEER_PROOF
                Stage.INITIATOR_WAIT_CONFIRMATION_WRITE -> stage = Stage.INITIATOR_WAIT_PEER_CONFIRMATION
                Stage.RESPONDER_WAIT_MESSAGE_2_WRITE -> stage = Stage.RESPONDER_WAIT_MESSAGE_3
                Stage.RESPONDER_WAIT_PROOF_WRITE -> stage = Stage.RESPONDER_WAIT_INITIATOR_CONFIRMATION
                Stage.RESPONDER_WAIT_CONFIRMATION_WRITE -> {
                    session.confirmationWriteSucceeded()
                    check(session.isAuthenticated()) { "Local confirmation did not authenticate" }
                    establishAuthenticatedTransport()
                }
                else -> error("Unexpected successful GATT control completion in state $stage")
            }
            touch(SystemClock.elapsedRealtime())
        } catch (error: Exception) {
            failClosed(error)
        }
    }

    /** Accepts a completed GATT frame only after the identity-confirmed session is live. */
    @Synchronized
    fun receiveFrame(frame: ByteArray, elapsedMillis: Long = SystemClock.elapsedRealtime()) {
        if (stage == Stage.CLOSED) return
        try {
            checkFresh(elapsedMillis)
            check(stage == Stage.AUTHENTICATED) { "Application frames require peer confirmation" }
            requireNotNull(transport).receiveFrame(frame, elapsedMillis)
            touch(elapsedMillis)
        } catch (error: Exception) {
            failClosed(error)
        }
    }

    /** Runs handshake and transfer deadlines from the session owner's timer. */
    @Synchronized
    fun expire(elapsedMillis: Long = SystemClock.elapsedRealtime()): Boolean {
        if (stage == Stage.CLOSED) return true
        return try {
            checkFresh(elapsedMillis)
            val timeout = if (stage == Stage.INITIATOR_WAIT_USER_APPROVAL ||
                stage == Stage.RESPONDER_WAIT_USER_APPROVAL
            ) USER_APPROVAL_TIMEOUT_MS else HANDSHAKE_TIMEOUT_MS
            if (elapsedMillis - lastActivityMillis >= timeout) {
                failClosed(IllegalStateException("BLE session timed out"))
                true
            } else {
                transport?.expire(elapsedMillis) ?: false
            }
        } catch (error: Exception) {
            failClosed(error)
            true
        }
    }

    /** Closes authentication state and the owned GATT transport. */
    @Synchronized
    override fun close() {
        if (stage == Stage.CLOSED) return
        stage = Stage.CLOSED
        pendingPeerInfo?.identityBundle?.fill(0)
        pendingPeerInfo?.fingerprint?.fill(0)
        pendingPeerInfo = null
        pump = null
        val activeTransport = transport
        transport = null
        activeTransport?.close()
        try {
            session.terminate()
        } catch (_: Exception) {
            // Closure is fail-closed even if Rust state was already unavailable.
        }
        if (activeTransport == null) io.disconnect()
    }

    @Synchronized
    private fun startNextDue(elapsedMillis: Long) {
        requireNotNull(pump).startNextDue(
            System.currentTimeMillis(),
            elapsedMillis,
            retryAt,
        )
    }

    private fun requestPin(peer: MobileBlePeerInfo) {
        if (peer.alreadyPinned) {
            try {
                pinAndContinue(peer)
            } finally {
                peer.identityBundle.fill(0)
                peer.fingerprint.fill(0)
            }
            return
        }
        val decisionCompleted = AtomicBoolean(false)
        pendingPeerInfo = peer
        try {
            onPeerVerificationRequired(peer) { approved ->
                if (!decisionCompleted.compareAndSet(false, true)) return@onPeerVerificationRequired
                try {
                    decisionExecutor.execute {
                        synchronized(this) {
                            if (stage == Stage.CLOSED) {
                                releasePeerInfo(peer)
                                return@synchronized
                            }
                            if (!approved) {
                                releasePeerInfo(peer)
                                failClosed(IllegalStateException("First-contact peer was not approved"))
                                return@synchronized
                            }
                            try {
                                pinAndContinue(peer)
                            } catch (error: Exception) {
                                failClosed(error)
                            } finally {
                                releasePeerInfo(peer)
                            }
                        }
                    }
                } catch (_: java.util.concurrent.RejectedExecutionException) {
                    synchronized(this) { releasePeerInfo(peer) }
                }
            }
        } catch (error: Exception) {
            synchronized(this) { releasePeerInfo(peer) }
            throw error
        }
    }

    private fun releasePeerInfo(peer: MobileBlePeerInfo) {
        if (pendingPeerInfo === peer) pendingPeerInfo = null
        peer.identityBundle.fill(0)
        peer.fingerprint.fill(0)
    }
    private fun pinAndContinue(peer: MobileBlePeerInfo) {
        val publicBundle = peer.identityBundle.copyOf()
        val fingerprint = peer.fingerprint.copyOf()
        try {
            profile.pinIdentity(publicBundle, fingerprint)
        } finally {
            publicBundle.fill(0)
            fingerprint.fill(0)
        }
        when (role) {
            MobileBleRole.INITIATOR -> {
                stage = Stage.INITIATOR_WAIT_CONFIRMATION_WRITE
                enqueueSessionRecord(session.writeConfirmation())
            }
            MobileBleRole.RESPONDER -> {
                stage = Stage.RESPONDER_WAIT_PROOF_WRITE
                enqueueSessionRecord(session.writeIdentityProof())
            }
        }
    }

    private fun sendPlainHandshake(plaintext: ByteArray) = enqueueSessionRecord(plaintext)

    /** Session methods already produce Noise ciphertext for proofs and confirmations. */
    private fun enqueueSessionRecord(record: ByteArray) {
        check(io.enqueueControl(record)) { "GATT control queue rejected a session record" }

    }

    private fun establishAuthenticatedTransport() {
        check(stage != Stage.AUTHENTICATED && stage != Stage.CLOSED)
        check(session.isAuthenticated()) { "Peer identity has not been confirmed" }
        stage = Stage.AUTHENTICATED
        val localRole = when (role) {
            MobileBleRole.INITIATOR -> BleExp0TransferProtocol.ROLE_INITIATOR
            MobileBleRole.RESPONDER -> BleExp0TransferProtocol.ROLE_RESPONDER
        }
        val transfer = BleExp0TransferProtocol.forAuthenticatedSession(localRole, negotiatedMtu)
        val authenticatedTransport = BleExp0EnvelopeTransport(
            profile,
            MobileBleSessionCipher(session),
            transfer,
            io,
        )
        val outboxPump = BleExp0OutboxPump(profile, authenticatedTransport) { eventId ->
            routeAllowed.get() && isRoutedToPeer(eventId)
        }
        transport = authenticatedTransport
        pump = outboxPump
        onAuthenticated(outboxPump) { allowed ->
            try {
                decisionExecutor.execute {
                    synchronized(this) {
                        if (stage != Stage.AUTHENTICATED) return@synchronized
                        routeAllowed.set(allowed)
                        if (allowed) {
                            try {
                                startNextDue(SystemClock.elapsedRealtime())
                            } catch (error: Exception) {
                                failClosed(error)
                            }
                        }
                    }
                }
            } catch (_: java.util.concurrent.RejectedExecutionException) {
                // Session teardown already prevents forwarding.
            }
    }
    }


    private fun checkFresh(nowMillis: Long) {
        check(nowMillis >= lastActivityMillis) { "Monotonic clock moved backwards" }
        if (stage != Stage.AUTHENTICATED) {
            val timeout = if (stage == Stage.INITIATOR_WAIT_USER_APPROVAL ||
                stage == Stage.RESPONDER_WAIT_USER_APPROVAL
            ) USER_APPROVAL_TIMEOUT_MS else HANDSHAKE_TIMEOUT_MS
            check(nowMillis - lastActivityMillis < timeout) { "BLE session timed out" }
        }
    }

    private fun touch(nowMillis: Long) {
        check(nowMillis >= lastActivityMillis) { "Monotonic clock moved backwards" }
        lastActivityMillis = nowMillis
    }

    private fun failClosed(error: Exception) {
        if (stage == Stage.CLOSED) return
        close()
        onFailure(error.message ?: "BLE session failed")
    }

    private companion object {
        const val GATT_SUCCESS = 0
        const val HANDSHAKE_TIMEOUT_MS = 30_000L
        const val USER_APPROVAL_TIMEOUT_MS = 120_000L
    }
}

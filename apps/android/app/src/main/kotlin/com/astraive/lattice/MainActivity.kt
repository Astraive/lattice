package com.astraive.lattice

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.content.ClipData
import android.content.ClipboardManager
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.util.Base64
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.lattice_uniffi.MobileException
import uniffi.lattice_uniffi.MobileCreatedSpace
import uniffi.lattice_uniffi.MobileSpaceCursor
import uniffi.lattice_uniffi.MobileSpaceSummary
import uniffi.lattice_uniffi.MobileChannelType
import uniffi.lattice_uniffi.MobileInitialChannel
import uniffi.lattice_uniffi.MobileLocalTextMessage
import com.astraive.lattice.identity.IdentityPinCard
import com.astraive.lattice.identity.IdentityPinUiState
import com.astraive.lattice.identity.decodeIdentityHex

internal enum class BluetoothReadiness {
    PERMISSION_REQUIRED,
    READY,
    BLUETOOTH_OFF,
    ADAPTER_UNAVAILABLE,
    SCANNER_UNAVAILABLE,
    ACCESS_UNAVAILABLE,
}

internal data class NearbyScreenState(
    val permission: DiscoveryPermissionState = DiscoveryPermissionState.NOT_REQUESTED,
    val bluetooth: BluetoothReadiness = BluetoothReadiness.PERMISSION_REQUIRED,
    val scanning: Boolean = false,
    val sightings: Int = 0,
    val persistentNearbyEnabled: Boolean = false,
    val persistentNearbyStatus: String = "Persistent nearby mode is off.",
    val wifiCapabilities: AndroidWifiCapabilities = AndroidWifiCapabilities(),
    val message: String = "Bluetooth permission has not been requested. Nearby discovery has not started.",
    val showPermissionRationale: Boolean = false,
    val profileStatus: String = "Preparing protected device profile.",
    val identityFingerprint: String? = null,
    val identityBundleHex: String? = null,
    val identityPin: IdentityPinUiState = IdentityPinUiState(),
    val certificateRequestPem: String? = null,
    val certificateRequestStatus: String? = null,
    val generatingCertificateRequest: Boolean = false,
    val localSpaces: List<MobileSpaceSummary> = emptyList(),
    val localSpacesStatus: String = "Local Space snapshots are loading.",
    val nextSpaceCursor: MobileSpaceCursor? = null,
    val loadingSpacePage: Boolean = false,
    val spaceCreation: SpaceCreationUiState = SpaceCreationUiState(),
    val spaceWelcomeJoin: SpaceWelcomeJoinUiState = SpaceWelcomeJoinUiState(),
    val spaceRecovery: LocalSpaceRecoveryUiState = LocalSpaceRecoveryUiState(),
    val identityClipboardStatus: String? = null,
    val messageComposers: Map<String, LocalMessageComposerState> = emptyMap(),
)

private fun localSpaceKey(space: MobileSpaceSummary): String =
    "${space.spaceId.toLowerHex()}:${space.groupReference.toLowerHex()}"

class MainActivity : ComponentActivity() {
    private val preferences by lazy { getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE) }
    private var screenState by mutableStateOf(NearbyScreenState())
    private var mobileProfile: AndroidMobileProfile? = null
    private lateinit var nearbyScanner: NearbyServiceScanner
    private var receiverRegistered = false
    private var persistentReceiverRegistered = false
    private var permissionHistoryBeforePrompt = false
    private var wifiNetworkCallback: ConnectivityManager.NetworkCallback? = null

    private val permissionRequest = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        handlePermissionResult(result)
    }

    private val notificationPermissionRequest = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            startPersistentNearbyService()
        } else {
            screenState = screenState.copy(
                persistentNearbyEnabled = false,
                persistentNearbyStatus = "Not started. Android notification permission is required for a visible persistent-mode notification.",
            )
        }
    }

    private val persistentStatusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != PersistentNearbyService.ACTION_STATUS) return
            screenState = screenState.copy(
                persistentNearbyEnabled = intent.getBooleanExtra(PersistentNearbyService.EXTRA_ENABLED, false),
                persistentNearbyStatus = intent.getStringExtra(PersistentNearbyService.EXTRA_STATUS)
                    ?: "Persistent nearby mode status is unavailable.",
            )
        }
    }
    private fun handlePermissionResult(result: Map<String, Boolean>) {
        if (result.isEmpty()) {
            preferences.edit().putBoolean(KEY_REQUESTED_BEFORE, permissionHistoryBeforePrompt).apply()
            val permission = refreshReadiness()
            screenState = screenState.copy(
                message = if (permission == DiscoveryPermissionState.GRANTED) {
                    bluetoothMessage(screenState.bluetooth)
                } else {
                    "The Android permission request was not completed. Nearby discovery remains off; tap Find nearby service to try again."
                },
            )
            return
        }

        if (runtimePermissions().any {
                result[it] != true && checkSelfPermission(it) != PackageManager.PERMISSION_GRANTED
            }
        ) {
            preferences.edit().putBoolean(KEY_PREVIOUSLY_GRANTED, false).apply()
        }
        val permission = refreshReadiness()
        screenState = screenState.copy(
            message = when (permission) {
                DiscoveryPermissionState.GRANTED -> if (screenState.bluetooth == BluetoothReadiness.READY) {
                    "Bluetooth access is granted. Tap Find nearby service to start a scan."
                } else {
                    bluetoothMessage(screenState.bluetooth)
                }
                DiscoveryPermissionState.DENIED -> "Bluetooth access was denied. Nearby discovery is off; you can review the reason and try again."
                DiscoveryPermissionState.PERMANENTLY_DENIED -> "Bluetooth access is blocked. Open app settings to allow nearby discovery."
                DiscoveryPermissionState.REVOKED -> "Bluetooth access is no longer granted. Nearby discovery is off until access is restored."
                DiscoveryPermissionState.NOT_REQUESTED -> "Bluetooth permission was not granted. Nearby discovery has not started."
            },
        )
    }

    private val bluetoothReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                BluetoothAdapter.STATE_TURNING_OFF,
                BluetoothAdapter.STATE_OFF -> {
                    stopScanning("Bluetooth is turning off or is off. Nearby discovery stopped.")
                    screenState = screenState.copy(bluetooth = BluetoothReadiness.BLUETOOTH_OFF)
                }
                else -> refreshReadiness()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        nearbyScanner = NearbyServiceScanner(
            context = this,
            onSightingsChanged = { count ->
                runOnUiThread {
                    if (!isFinishing && !isDestroyed && screenState.scanning) {
                        screenState = screenState.copy(
                            sightings = count,
                            message = "Scanning for the generic Lattice service. $count unverified service sighting${if (count == 1) "" else "s"} found.",
                        )
                    }
                }
            },
            onFailure = { failure ->
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) {
                        screenState = screenState.copy(scanning = false, sightings = 0, message = failure)
                    }
                }
            },
        )
        refreshReadiness()
        setContent {
            MaterialTheme {
                NearbyReadinessScreen(
                    state = screenState,
                    permissionRationale = permissionRationaleText(),
                    onPrimaryAction = ::onPrimaryAction,
                    onPersistentNearbyAction = ::onPersistentNearbyAction,
                    onDismissRationale = { screenState = screenState.copy(showPermissionRationale = false) },
                    onContinuePermission = ::continuePermissionFlow,
                    onMessageCredentialHexChanged = ::onMessageCredentialHexChanged,
                    onMessageContentChanged = ::onMessageContentChanged,
                    onMessageChannelSelected = ::onMessageChannelSelected,
                    onQueueLocalMessage = ::queueLocalMessage,
                    onLoadMessageHistory = ::loadLocalMessageHistory,
                    onEditLocalMessage = ::editLocalMessage,
                    onCancelMessageEdit = ::cancelLocalMessageEdit,
                    onRefreshLocalSpaces = ::refreshLocalSpaces,
                    onLoadMoreSpaces = ::loadMoreLocalSpaces,
                    onCredentialVectorHexChanged = ::onCredentialVectorHexChanged,
                    onSpaceChannelNameChanged = ::onSpaceChannelNameChanged,
                    onRecoverySpaceSelected = ::onRecoverySpaceSelected,
                    onRecoveryCredentialChanged = ::onRecoveryCredentialChanged,
                    onRecoverLocalSpace = ::recoverLocalSpace,
                    onCreateLocalSpace = ::createLocalSpace,
                    onWelcomeBootstrapBase64Changed = ::onWelcomeBootstrapBase64Changed,
                    onWelcomeInviterFingerprintChanged = ::onWelcomeInviterFingerprintChanged,
                    onWelcomeCredentialVectorChanged = ::onWelcomeCredentialVectorChanged,
                    onJoinSpaceFromWelcome = ::joinSpaceFromWelcome,
                    onGenerateCertificateRequest = ::generateCertificateRequest,
                    onCopyCertificateRequest = ::copyCertificateRequest,
                    onLookupPinnedIdentity = ::lookupPinnedIdentity,
                    onUnpinPeerIdentity = ::unpinPeerIdentity,
                    onCopyPinnedBundle = { bundle -> copyPublicValue("peer identity bundle", bundle) },
                    onCopyIdentityBundle = {
                        screenState.identityBundleHex?.let { copyPublicValue("device public bundle", it) }
                    },
                    onCopyIdentityFingerprint = {
                        screenState.identityFingerprint?.let { copyPublicValue("device fingerprint", it) }
                    },
                    onPeerBundleHexChanged = ::onPeerBundleHexChanged,
                    onPeerFingerprintHexChanged = ::onPeerFingerprintHexChanged,
                    onPinPeerIdentity = ::pinPeerIdentity,
                )
            }
        }
        initializeMobileProfile()
    }

    private fun initializeMobileProfile() {
        lifecycleScope.launch {
            try {
                val profile = withContext(Dispatchers.IO) {
                    AndroidMobileProfile.open(applicationContext)
                }
                if (isFinishing || isDestroyed) {
                    profile.close()
                    return@launch
                }
                val (identity, firstSpacePage) = try {
                    withContext(Dispatchers.IO) {
                        profile.identityInfo() to profile.localSpaces()
                    }
                } catch (error: Exception) {
                    profile.close()
                    throw error
                }
                if (isFinishing || isDestroyed) {
                    profile.close()
                    return@launch
                }
                mobileProfile = profile
                screenState = screenState.copy(
                    profileStatus = "Protected local identity is available on this device.",
                    identityFingerprint = identity.fingerprint.toLowerHex(),
                    identityBundleHex = identity.publicBundle.toLowerHex(),
                    localSpaces = firstSpacePage.spaces,
                    localSpacesStatus = localSpacesStatus(firstSpacePage.spaces.size, firstSpacePage.nextCursor != null),
                    nextSpaceCursor = firstSpacePage.nextCursor,
                )
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        profileStatus = when (error) {
                            is MobileException.InvalidIdentityBundle -> "The local identity bundle is invalid."
                            is MobileException.InvalidFingerprint -> "The local identity fingerprint is invalid."
                            is MobileException.FingerprintMismatch -> "The local identity fingerprint does not match its bundle."
                            is MobileException.PinnedIdentityConflict -> "The local profile conflicts with an existing identity pin."
                            is MobileException.InvalidProfileId -> "The local profile identifier is invalid."
                            is MobileException.KeyProtectionFailed -> "Android Keystore access failed; no software-key fallback was used."
                            is MobileException.ProfileOpenFailed -> "The protected local profile could not be opened."
                            is MobileException.ProfileUnavailable -> "The protected local profile is unavailable."
                            is MobileException.CertificateSigningRequestFailed -> "The device certificate request could not be generated."
                            is MobileException.InvalidSpaceCredential -> "The X.509 credential is not trusted or does not match this device."
                            is MobileException.InvalidSpaceInput -> "The initial Space channel is invalid."
                            is MobileException.SpaceCreationFailed -> "The local Space transaction failed."
                            is MobileException.InvalidSpaceCursor -> "The local Space cursor is invalid."
                            else -> "The protected local profile could not be opened."
                        },
                    )
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        profileStatus = "The protected local profile could not be opened.",
                    )
                }
            }
        }
    }

    private fun refreshLocalSpaces() {
        val profile = mobileProfile ?: return
        if (screenState.loadingSpacePage) return
        screenState = screenState.copy(loadingSpacePage = true)
        lifecycleScope.launch {
            try {
                val page = withContext(Dispatchers.IO) {
                    profile.localSpaces()
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        localSpaces = page.spaces,
                        localSpacesStatus = localSpacesStatus(page.spaces.size, page.nextCursor != null),
                        nextSpaceCursor = page.nextCursor,
                        loadingSpacePage = false,
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        localSpacesStatus = "Local Space snapshots could not be restored.",
                        loadingSpacePage = false,
                    )
                }
            }
        }
    }

    private fun loadMoreLocalSpaces(after: MobileSpaceCursor) {
        val profile = mobileProfile ?: return
        if (screenState.loadingSpacePage) return
        screenState = screenState.copy(loadingSpacePage = true)
        lifecycleScope.launch {
            try {
                val page = withContext(Dispatchers.IO) {
                    profile.localSpaces(after)
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        localSpaces = screenState.localSpaces + page.spaces,
                        localSpacesStatus = localSpacesStatus(
                            screenState.localSpaces.size + page.spaces.size,
                            page.nextCursor != null,
                        ),
                        nextSpaceCursor = page.nextCursor,
                        loadingSpacePage = false,
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        localSpacesStatus = "The next local Space page could not be restored.",
                        loadingSpacePage = false,
                    )
                }
            }
        }
    }

    private fun updateMessageComposer(spaceKey: String, update: (LocalMessageComposerState) -> LocalMessageComposerState) {
        val composers = screenState.messageComposers
        screenState = screenState.copy(
            messageComposers = composers + (spaceKey to update(composers[spaceKey] ?: LocalMessageComposerState())),
        )
    }

    private fun onMessageCredentialHexChanged(spaceKey: String, value: String) {
        if (value.length > MAX_LOCAL_MESSAGE_CREDENTIAL_HEX_LENGTH) {
            updateMessageComposer(spaceKey) {
                it.copy(status = "Credential vector exceeds the 16 KiB decoded input limit.")
            }
            return
        }
        updateMessageComposer(spaceKey) {
            it.copy(credentialVectorHex = value, eventIdHex = null, status = "Credential input changed; not yet validated.")
        }
    }

    private fun onMessageContentChanged(spaceKey: String, value: String) {
        if (value.length > MAX_LOCAL_MESSAGE_BYTES) {
            updateMessageComposer(spaceKey) {
                it.copy(status = "Message exceeds the 16 KiB UTF-8 input limit.")
            }
            return
        }
        updateMessageComposer(spaceKey) {
            it.copy(content = value, eventIdHex = null, status = "Message input changed; not yet queued.")
        }
    }

    private fun onMessageChannelSelected(spaceKey: String, channelIdHex: String) {
        updateMessageComposer(spaceKey) {
            it.copy(
                selectedChannelIdHex = channelIdHex,
                eventIdHex = null,
                historyChannelIdHex = null,
                historyStatus = null,
                status = "Channel selected; message not yet queued.",
            )
        }
    }

    private fun editLocalMessage(spaceKey: String, message: MobileLocalTextMessage) {
        val composer = screenState.messageComposers[spaceKey] ?: LocalMessageComposerState()
        if (composer.submitting || message.authorId.toLowerHex() != screenState.identityFingerprint) return
        updateMessageComposer(spaceKey) {
            it.copy(
                content = message.content,
                editTargetMessageIdHex = message.eventId.toLowerHex(),
                eventIdHex = null,
                status = "Editing your local message. The original event remains immutable.",
            )
        }
    }

    private fun cancelLocalMessageEdit(spaceKey: String) {
        updateMessageComposer(spaceKey) {
            it.copy(
                content = "",
                editTargetMessageIdHex = null,
                eventIdHex = null,
                status = "Edit cancelled; original message remains unchanged.",
            )
        }
    }
    private fun loadLocalMessageHistory(spaceKey: String) {
        val profile = mobileProfile ?: run {
            updateMessageComposer(spaceKey) {
                it.copy(historyStatus = "The protected profile is not ready.")
            }
            return
        }
        val space = screenState.localSpaces.firstOrNull { localSpaceKey(it) == spaceKey } ?: run {
            updateMessageComposer(spaceKey) {
                it.copy(historyStatus = "This local Space is no longer available.")
            }
            return
        }
        val composer = screenState.messageComposers[spaceKey] ?: LocalMessageComposerState()
        if (composer.loadingHistory) return
        val channels = space.channels.filter {
            !it.archived &&
                (it.channelType == MobileChannelType.TEXT ||
                    it.channelType == MobileChannelType.ANNOUNCEMENT)
        }
        val channel = channels.firstOrNull {
            it.id.toLowerHex() == composer.selectedChannelIdHex
        } ?: if (composer.selectedChannelIdHex == null) channels.firstOrNull() else null
        if (channel == null) {
            updateMessageComposer(spaceKey) {
                it.copy(historyStatus = "Select an active text or announcement channel.")
            }
            return
        }
        val channelIdHex = channel.id.toLowerHex()
        updateMessageComposer(spaceKey) {
            it.copy(loadingHistory = true, historyStatus = "Authenticating local message history…")
        }
        lifecycleScope.launch {
            try {
                val history = withContext(Dispatchers.IO) {
                    profile.localTextMessages(space.spaceId, space.groupReference, channel.id)
                }
                if (!isFinishing && !isDestroyed) {
                    updateMessageComposer(spaceKey) {
                        it.copy(
                            loadingHistory = false,
                            history = history,
                            historyChannelIdHex = channelIdHex,
                            historyStatus = if (history.isEmpty()) {
                                "No locally retained outgoing messages for this channel."
                            } else {
                                "Showing ${history.size} recent locally retained outgoing message(s)."
                            },
                        )
                    }
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    updateMessageComposer(spaceKey) {
                        it.copy(
                            loadingHistory = false,
                            historyStatus = mobileErrorStatus(error),
                        )
                    }
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    updateMessageComposer(spaceKey) {
                        it.copy(
                            loadingHistory = false,
                            historyStatus = "Local message history could not be authenticated.",
                        )
                    }
                }
            }
        }
    }

    private fun queueLocalMessage(spaceKey: String) {
        val profile = mobileProfile ?: run {
            updateMessageComposer(spaceKey) { it.copy(status = "The protected profile is not ready.") }
            return
        }
        val composer = screenState.messageComposers[spaceKey] ?: LocalMessageComposerState()
        if (composer.submitting) return
        val space = screenState.localSpaces.firstOrNull { localSpaceKey(it) == spaceKey } ?: run {
            updateMessageComposer(spaceKey) { it.copy(status = "This local Space is no longer available.") }
            return
        }
        val eligibleChannels = space.channels.filter {
            !it.archived && (it.channelType == MobileChannelType.TEXT || it.channelType == MobileChannelType.ANNOUNCEMENT)
        }
        val channel = eligibleChannels.firstOrNull { it.id.toLowerHex() == composer.selectedChannelIdHex }
            ?: if (composer.selectedChannelIdHex == null) eligibleChannels.firstOrNull() else null
        if (channel == null) {
            updateMessageComposer(spaceKey) { it.copy(status = "Select an active text or announcement channel.") }
            return
        }
        val hex = composer.credentialVectorHex
        if (hex.isEmpty() || hex.length > MAX_LOCAL_MESSAGE_CREDENTIAL_HEX_LENGTH || hex.length % 2 != 0) {
            updateMessageComposer(spaceKey) { it.copy(status = "Enter non-empty, even-length credential hex (at most 16 KiB decoded).") }
            return
        }
        val credentialVector = decodeStrictBoundedHex(hex) ?: run {
            updateMessageComposer(spaceKey) { it.copy(status = "Credential vector must contain hexadecimal characters only.") }
            return
        }
        if (composer.content.isEmpty()) {
            credentialVector.fill(0)
            updateMessageComposer(spaceKey) { it.copy(status = "Enter a message before queueing.") }
            return
        }
        if (composer.content.length > MAX_LOCAL_MESSAGE_BYTES) {
            credentialVector.fill(0)
            updateMessageComposer(spaceKey) { it.copy(status = "Message exceeds the 16 KiB input limit.") }
            return
        }
        val contentBytes = composer.content.toByteArray(Charsets.UTF_8)
        if (contentBytes.size > MAX_LOCAL_MESSAGE_BYTES) {
            credentialVector.fill(0)
            contentBytes.fill(0)
            updateMessageComposer(spaceKey) { it.copy(status = "Message exceeds the 16 KiB UTF-8 input limit.") }
            return
        }
        updateMessageComposer(spaceKey) {
            it.copy(submitting = true, eventIdHex = null, status = "Validating certificate and committing a local outbox event…")
        }
        lifecycleScope.launch {
            try {
                val queued = withContext(Dispatchers.IO) {
                    val target = composer.editTargetMessageIdHex?.let { decodeIdentityHex(it, 32) }
                    if (composer.editTargetMessageIdHex != null && target == null) {
                        throw IllegalArgumentException("The selected message ID is malformed.")
                    }
                    if (target == null) {
                        profile.queueLocalTextMessage(
                            space.spaceId,
                            space.groupReference,
                            credentialVector,
                            channel.id,
                            composer.content,
                        )
                    } else {
                        profile.queueLocalTextMessageEdit(
                            space.spaceId,
                            space.groupReference,
                            credentialVector,
                            channel.id,
                            target,
                            composer.content,
                        )
                    }
                }
                if (!isFinishing && !isDestroyed) {
                    updateMessageComposer(spaceKey) {
                        it.copy(
                            submitting = false,
                            content = "",
                            editTargetMessageIdHex = null,
                            eventIdHex = queued.eventId.toLowerHex(),
                            status = if (composer.editTargetMessageIdHex == null) {
                                "Queued locally in the durable outbox. Network forwarding and recipient delivery are unknown."
                            } else {
                                "Edit committed locally as a new immutable event. Network forwarding and recipient delivery are unknown."
                            },
                        )
                    }
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    updateMessageComposer(spaceKey) {
                        it.copy(submitting = false, status = mobileQueueErrorStatus(error))
                    }
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    updateMessageComposer(spaceKey) {
                        it.copy(submitting = false, status = "The message could not be confirmed as queued locally.")
                    }
                }
            } finally {
                credentialVector.fill(0)
                contentBytes.fill(0)
                if (!isFinishing && !isDestroyed) loadLocalMessageHistory(spaceKey)
            }
        }
    }

    private fun decodeStrictBoundedHex(value: String): ByteArray? {
        if (value.isEmpty() || value.length > MAX_LOCAL_MESSAGE_CREDENTIAL_HEX_LENGTH || value.length % 2 != 0) return null
        val bytes = ByteArray(value.length / 2)
        fun hexValue(char: Char): Int = when (char) {
            in '0'..'9' -> char - '0'
            in 'a'..'f' -> char - 'a' + 10
            in 'A'..'F' -> char - 'A' + 10
            else -> -1
        }
        for (index in bytes.indices) {
            val high = hexValue(value[index * 2])
            val low = hexValue(value[index * 2 + 1])
            if (high < 0 || low < 0) {
                bytes.fill(0)
                return null
            }
            bytes[index] = ((high shl 4) or low).toByte()
        }
        return bytes
    }

    private fun mobileQueueErrorStatus(error: MobileException): String = when (error) {
        is MobileException.InvalidSpaceMessageId -> "The restored Space identifiers are invalid; no message was queued."
        is MobileException.InvalidSpaceCredential -> "The certificate is invalid, untrusted, or does not match this device; no message was queued."
        is MobileException.InvalidMessageInput -> "The channel or message input is invalid; no message was queued."
        is MobileException.MessageRejected -> "The local Space rejected this message; no event was queued."
        is MobileException.MessageQueueFailed -> "The local durable outbox operation failed; no queued event was confirmed."
        else -> mobileErrorStatus(error)
    }

    private fun onCredentialVectorHexChanged(value: String) {
        if (value.length > MAX_CREDENTIAL_HEX_LENGTH) {
            screenState = screenState.copy(
                spaceCreation = screenState.spaceCreation.copy(
                    status = "The credential vector exceeds the 16 KiB input limit.",
                ),
            )
            return
        }
        screenState = screenState.copy(
            spaceCreation = screenState.spaceCreation.copy(
                credentialVectorHex = value,
                status = "Credential input changed; it has not been validated.",
                created = null,
            ),
        )
    }

    private fun onSpaceChannelNameChanged(value: String) {
        if (value.length > MAX_INITIAL_CHANNEL_NAME_BYTES) {
            screenState = screenState.copy(
                spaceCreation = screenState.spaceCreation.copy(
                    status = "The channel name exceeds the 128-character input bound.",
                ),
            )
            return
        }
        screenState = screenState.copy(
            spaceCreation = screenState.spaceCreation.copy(
                channelName = value,
                status = "Channel input changed; it has not been validated.",
                created = null,
            ),
        )
    }

    private fun createLocalSpace() {
        val current = screenState.spaceCreation
        if (current.creating) return
        val profile = mobileProfile ?: run {
            screenState = screenState.copy(
                spaceCreation = current.copy(status = "The protected local profile is not ready."),
            )
            return
        }
        val credentialHex = current.credentialVectorHex
        if (credentialHex.isEmpty() ||
            credentialHex.length > MAX_CREDENTIAL_HEX_LENGTH ||
            credentialHex.length % 2 != 0
        ) {
            screenState = screenState.copy(
                spaceCreation = current.copy(status = "Enter a bounded, even-length hexadecimal X.509 credential vector."),
            )
            return
        }
        val credentialVector = decodeIdentityHex(credentialHex, credentialHex.length / 2)
        if (credentialVector == null || !isValidInitialChannelName(current.channelName)) {
            screenState = screenState.copy(
                spaceCreation = current.copy(status = "Check the credential hex and channel name (1–128 UTF-8 bytes, no NUL)."),
            )
            return
        }

        screenState = screenState.copy(
            spaceCreation = current.copy(creating = true, status = "Checking OS trust and creating local MLS state.", created = null),
        )
        lifecycleScope.launch {
            try {
                val created = withContext(Dispatchers.IO) {
                    profile.createLocalSpace(
                        credentialVector,
                        listOf(
                            MobileInitialChannel(
                                MobileChannelType.TEXT,
                                current.channelName,
                                0uL,
                                0uL,
                            ),
                        ),
                    )
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceCreation = current.copy(
                            credentialVectorHex = "",
                            creating = true,
                            status = "Local Genesis committed; no network was contacted and no remote member joined.",
                            created = created,
                        ),
                    )
                }
                val page = withContext(Dispatchers.IO) {
                    profile.localSpaces()
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        localSpaces = page.spaces,
                        localSpacesStatus = localSpacesStatus(page.spaces.size, page.nextCursor != null),
                        nextSpaceCursor = page.nextCursor,
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    val created = screenState.spaceCreation.created
                    screenState = screenState.copy(
                        spaceCreation = screenState.spaceCreation.copy(
                            status = if (created == null) {
                                mobileErrorStatus(error)
                            } else {
                                "Local Genesis committed, but the snapshot list could not be refreshed."
                            },
                            created = created,
                        ),
                    )
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    val created = screenState.spaceCreation.created
                    screenState = screenState.copy(
                        spaceCreation = screenState.spaceCreation.copy(
                            status = if (created == null) {
                                "The local Space could not be created."
                            } else {
                                "Local Genesis committed, but the snapshot list could not be refreshed."
                            },
                            created = created,
                        ),
                    )
                }
            } finally {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceCreation = screenState.spaceCreation.copy(creating = false),
                    )
                }
            }
        }
    }

    private fun onWelcomeBootstrapBase64Changed(value: String) {
        if (value.length > MAX_SPACE_WELCOME_BOOTSTRAP_BASE64_CHARS) {
            screenState = screenState.copy(
                spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(
                    status = "The bootstrap package exceeds the 1 MiB decoded package bound.",
                ),
            )
            return
        }
        screenState = screenState.copy(
            spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(
                bootstrapPackageBase64 = value,
                joined = null,
                status = "Package input changed; the signature and Welcome have not been validated.",
            ),
        )
    }

    private fun onWelcomeInviterFingerprintChanged(value: String) {
        if (value.length > 64) {
            screenState = screenState.copy(
                spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(
                    status = "The inviter fingerprint must be exactly 32 bytes.",
                ),
            )
            return
        }
        screenState = screenState.copy(
            spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(
                inviterFingerprintHex = value,
                joined = null,
                status = "Inviter fingerprint changed; no pin or join was performed.",
            ),
        )
    }

    private fun onWelcomeCredentialVectorChanged(value: String) {
        if (value.length > MAX_CREDENTIAL_HEX_LENGTH) {
            screenState = screenState.copy(
                spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(
                    status = "The credential vector exceeds the 16 KiB input limit.",
                ),
            )
            return
        }
        screenState = screenState.copy(
            spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(
                credentialVectorHex = value,
                joined = null,
                status = "Credential changed; it has not been validated.",
            ),
        )
    }

    private fun joinSpaceFromWelcome() {
        val current = screenState.spaceWelcomeJoin
        if (current.joining) return
        val profile = mobileProfile ?: run {
            screenState = screenState.copy(
                spaceWelcomeJoin = current.copy(status = "The protected local profile is not ready."),
            )
            return
        }
        val packageBytes = try {
            if (!isSpaceWelcomeBootstrapBase64Input(current.bootstrapPackageBase64)) {
                null
            } else {
                Base64.decode(current.bootstrapPackageBase64, Base64.NO_WRAP)
            }
        } catch (_: IllegalArgumentException) {
            null
        }
        val inviterFingerprint = decodeIdentityHex(current.inviterFingerprintHex, 32)
        val credentialVector = decodeIdentityHex(
            current.credentialVectorHex,
            current.credentialVectorHex.length / 2,
        )
        if (packageBytes == null || packageBytes.isEmpty() ||
            packageBytes.size > MAX_SPACE_WELCOME_BOOTSTRAP_BYTES ||
            inviterFingerprint == null || credentialVector == null ||
            current.credentialVectorHex.length % 2 != 0
        ) {
            screenState = screenState.copy(
                spaceWelcomeJoin = current.copy(
                    status = "Enter a bounded Base64 package, a 32-byte inviter fingerprint, and an even-length credential vector.",
                ),
            )
            credentialVector?.fill(0)
            return
        }
        screenState = screenState.copy(
            spaceWelcomeJoin = current.copy(
                joining = true,
                joined = null,
                status = "Validating the pinned inviter, X.509 identity, Welcome, and signed checkpoint.",
            ),
        )
        lifecycleScope.launch {
            var joined: MobileCreatedSpace? = null
            try {
                joined = withContext(Dispatchers.IO) {
                    try {
                        profile.joinSpaceFromWelcomeBootstrap(
                            packageBytes,
                            inviterFingerprint,
                            credentialVector,
                        )
                    } finally {
                        credentialVector.fill(0)
                    }
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(
                            status = "Signed Welcome and policy checkpoint imported locally; no relay was contacted.",
                            joined = joined,
                        ),
                    )
                }
                val page = withContext(Dispatchers.IO) { profile.localSpaces() }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        localSpaces = page.spaces,
                        localSpacesStatus = localSpacesStatus(page.spaces.size, page.nextCursor != null),
                        nextSpaceCursor = page.nextCursor,
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(
                            status = if (joined == null) mobileErrorStatus(error) else {
                                "Welcome was committed locally, but the snapshot list could not be refreshed."
                            },
                            joined = joined,
                        ),
                    )
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(
                            status = if (joined == null) "The Welcome package could not be imported." else {
                                "Welcome was committed locally, but the snapshot list could not be refreshed."
                            },
                            joined = joined,
                        ),
                    )
                }
            } finally {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceWelcomeJoin = screenState.spaceWelcomeJoin.copy(joining = false),
                    )
                }
            }
        }
    }

    private fun onRecoverySpaceSelected(spaceKey: String) {
        val space = screenState.localSpaces.firstOrNull { localSpaceKey(it) == spaceKey } ?: return
        screenState = screenState.copy(
            spaceRecovery = screenState.spaceRecovery.copy(
                selectedSpaceKey = spaceKey,
                recovered = null,
                status = "Selected local generation ${space.spaceId.toLowerHex()} for recovery.",
            ),
        )
    }

    private fun onRecoveryCredentialChanged(value: String) {
        val recovery = screenState.spaceRecovery
        if (value.length > MAX_CREDENTIAL_HEX_LENGTH) {
            screenState = screenState.copy(
                spaceRecovery = recovery.copy(
                    status = "The recovery credential vector exceeds the 16 KiB input limit.",
                ),
            )
            return
        }
        screenState = screenState.copy(
            spaceRecovery = recovery.copy(
                credentialVectorHex = value,
                recovered = null,
                status = "Recovery credential input changed; it has not been validated.",
            ),
        )
    }

    private fun recoverLocalSpace() {
        val profile = mobileProfile ?: run {
            screenState = screenState.copy(
                spaceRecovery = screenState.spaceRecovery.copy(status = "The protected local profile is not ready."),
            )
            return
        }
        val recovery = screenState.spaceRecovery
        if (recovery.recovering) return
        val space = screenState.localSpaces.firstOrNull {
            localSpaceKey(it) == recovery.selectedSpaceKey
        } ?: run {
            screenState = screenState.copy(
                spaceRecovery = recovery.copy(status = "Select a locally stored generation to recover."),
            )
            return
        }
        if (!isCredentialVectorHex(recovery.credentialVectorHex)) {
            screenState = screenState.copy(
                spaceRecovery = recovery.copy(status = "Enter a bounded, even-length hexadecimal X.509 credential vector."),
            )
            return
        }
        val credentialVector = decodeStrictBoundedHex(recovery.credentialVectorHex) ?: run {
            screenState = screenState.copy(
                spaceRecovery = recovery.copy(status = "Credential vector must contain hexadecimal characters only."),
            )
            return
        }
        if (space.spaceId.size != 16 || space.groupReference.size != 32) {
            credentialVector.fill(0)
            screenState = screenState.copy(
                spaceRecovery = recovery.copy(status = "The selected local generation identifiers have invalid lengths."),
            )
            return
        }
        screenState = screenState.copy(
            spaceRecovery = recovery.copy(
                recovering = true,
                recovered = null,
                status = "Validating the credential and creating a local recovery generation…",
            ),
        )
        lifecycleScope.launch {
            try {
                val recovered = withContext(Dispatchers.IO) {
                    profile.recoverLocalSpaceGeneration(
                        space.spaceId,
                        space.groupReference,
                        credentialVector,
                    )
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceRecovery = screenState.spaceRecovery.copy(
                            recovering = false,
                            credentialVectorHex = "",
                            recovered = recovered,
                            status = "Recovery root committed locally. No network was contacted and no remote membership was restored.",
                        ),
                    )
                    refreshLocalSpaces()
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceRecovery = screenState.spaceRecovery.copy(
                            recovering = false,
                            status = mobileRecoveryErrorStatus(error),
                        ),
                    )
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceRecovery = screenState.spaceRecovery.copy(
                            recovering = false,
                            status = "The local Space generation could not be recovered.",
                        ),
                    )
                }
            } finally {
                credentialVector.fill(0)
            }
        }
    }

    private fun mobileRecoveryErrorStatus(error: MobileException): String = when (error) {
        is MobileException.InvalidSpaceMessageId -> "The selected Space ID or generation reference is invalid."
        is MobileException.InvalidSpaceCredential -> "The recovery credential is invalid, untrusted, or does not match this device."
        is MobileException.SpaceRecoveryFailed -> "The prior local generation could not be restored or authorized for recovery."
        else -> mobileErrorStatus(error)
    }

    private fun generateCertificateRequest() {
        val profile = mobileProfile ?: return
        if (screenState.generatingCertificateRequest) return
        screenState = screenState.copy(
            generatingCertificateRequest = true,
            certificateRequestStatus = null,
        )
        lifecycleScope.launch {
            try {
                val der = withContext(Dispatchers.IO) {
                    profile.certificateSigningRequest()
                }
                val encoded = Base64.encodeToString(der, Base64.NO_WRAP)
                val pem = buildString {
                    append("-----BEGIN CERTIFICATE REQUEST-----\n")
                    encoded.chunked(64).forEach { append(it).append('\n') }
                    append("-----END CERTIFICATE REQUEST-----\n")
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        certificateRequestPem = pem,
                        certificateRequestStatus = "Certificate request ready. It contains the public key and identity fingerprint, not the private key.",
                        generatingCertificateRequest = false,
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        certificateRequestStatus = when (error) {
                            is MobileException.CertificateSigningRequestFailed ->
                                "The protected device key could not create a certificate request."
                            is MobileException.ProfileUnavailable ->
                                "The protected local profile is unavailable."
                            else -> "The certificate request could not be generated."
                        },
                        generatingCertificateRequest = false,
                    )
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        certificateRequestStatus = "The certificate request could not be generated.",
                        generatingCertificateRequest = false,
                    )
                }
            }
        }
    }

    private fun copyCertificateRequest() {
        val pem = screenState.certificateRequestPem ?: return
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        if (clipboard == null) {
            screenState = screenState.copy(certificateRequestStatus = "The Android clipboard is unavailable.")
            return
        }
        clipboard.setPrimaryClip(ClipData.newPlainText("Lattice certificate request", pem))
        screenState = screenState.copy(certificateRequestStatus = "Certificate request copied to the clipboard.")
    }
    private fun onPeerBundleHexChanged(value: String) {
        val pin = screenState.identityPin
        screenState = if (value.length <= 130) {
            screenState.copy(
                identityPin = pin.copy(
                    peerBundleHexInput = value,
                    pinnedPeerFingerprint = null,
                    pinnedPeerBundleHex = null,
                    identityPinStatus = "Compare the full fingerprint out of band before pinning.",
                ),
            )
        } else {
            screenState.copy(
                identityPin = pin.copy(
                    identityPinStatus = "The public bundle must be exactly 130 hexadecimal characters.",
                ),
            )
        }
    }

    private fun onPeerFingerprintHexChanged(value: String) {
        val pin = screenState.identityPin
        screenState = if (value.length <= 64) {
            screenState.copy(
                identityPin = pin.copy(
                    peerFingerprintHexInput = value,
                    pinnedPeerFingerprint = null,
                    pinnedPeerBundleHex = null,
                    identityPinStatus = "Compare the full fingerprint out of band before pinning.",
                ),
            )
        } else {
            screenState.copy(
                identityPin = pin.copy(
                    identityPinStatus = "The fingerprint must be exactly 64 hexadecimal characters.",
                ),
            )
        }
    }

    private fun lookupPinnedIdentity() {
        val currentPinState = screenState.identityPin
        if (currentPinState.lookingUpPinnedIdentity || currentPinState.pinningIdentity ||
            currentPinState.unpinningIdentity
        ) return
        val profile = mobileProfile ?: run {
            screenState = screenState.copy(
                identityPin = screenState.identityPin.copy(
                    identityPinStatus = "The protected profile is not ready.",
                ),
            )
            return
        }
        val pin = screenState.identityPin
        val fingerprint = decodeIdentityHex(pin.peerFingerprintHexInput, 32)
        if (fingerprint == null) {
            screenState = screenState.copy(
                identityPin = pin.copy(
                    identityPinStatus = "Enter the saved peer's full 32-byte fingerprint as hexadecimal.",
                ),
            )
            return
        }

        screenState = screenState.copy(
            identityPin = pin.copy(
                lookingUpPinnedIdentity = true,
                identityPinStatus = "Checking this fingerprint against locally saved pins…",
            ),
        )
        lifecycleScope.launch {
            try {
                val saved = withContext(Dispatchers.IO) {
                    profile.pinnedIdentity(fingerprint)
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        identityPin = screenState.identityPin.copy(
                            lookingUpPinnedIdentity = false,
                            pinnedPeerFingerprint = saved?.fingerprint?.toLowerHex(),
                            pinnedPeerBundleHex = saved?.publicBundle?.toLowerHex(),
                            identityPinStatus = if (saved == null) {
                                "No local pin exists for this fingerprint. No connection or membership was checked."
                            } else {
                                "Exact locally pinned bytes were revalidated. This does not authenticate a session or grant Space membership."
                            },
                        ),
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        identityPin = screenState.identityPin.copy(
                            lookingUpPinnedIdentity = false,
                            identityPinStatus = mobileErrorStatus(error),
                        ),
                    )
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        identityPin = screenState.identityPin.copy(
                            lookingUpPinnedIdentity = false,
                            identityPinStatus = "The local identity pin could not be read.",
                        ),
                    )
                }
            }
        }
    }

    private fun unpinPeerIdentity() {
        val pin = screenState.identityPin
        if (pin.lookingUpPinnedIdentity || pin.pinningIdentity || pin.unpinningIdentity) return
        val savedFingerprint = pin.pinnedPeerFingerprint
        val fingerprint = savedFingerprint?.let { decodeIdentityHex(it, 32) }
        if (fingerprint == null) {
            screenState = screenState.copy(
                identityPin = pin.copy(
                    identityPinStatus = "Look up the exact saved fingerprint before removing its local pin.",
                ),
            )
            return
        }
        val profile = mobileProfile ?: run {
            screenState = screenState.copy(
                identityPin = pin.copy(identityPinStatus = "The protected profile is not ready."),
            )
            return
        }

        screenState = screenState.copy(
            identityPin = pin.copy(
                unpinningIdentity = true,
                identityPinStatus = "Removing the local peer pin…",
            ),
        )
        lifecycleScope.launch {
            try {
                val removed = withContext(Dispatchers.IO) { profile.unpinIdentity(fingerprint) }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        identityPin = screenState.identityPin.copy(
                            unpinningIdentity = false,
                            pinnedPeerFingerprint = null,
                            pinnedPeerBundleHex = null,
                            identityPinStatus = if (removed) {
                                "Local peer pin removed. Remote identity and Space membership are unchanged."
                            } else {
                                "No local pin exists for this fingerprint."
                            },
                        ),
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        identityPin = screenState.identityPin.copy(
                            unpinningIdentity = false,
                            identityPinStatus = mobileErrorStatus(error),
                        ),
                    )
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        identityPin = screenState.identityPin.copy(
                            unpinningIdentity = false,
                            identityPinStatus = "The local identity pin could not be removed.",
                        ),
                    )
                }
            }
        }
    }

    private fun copyPublicValue(label: String, value: String) {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        if (clipboard == null) {
            screenState = screenState.copy(identityClipboardStatus = "The Android clipboard is unavailable.")
            return
        }
        try {
            clipboard.setPrimaryClip(ClipData.newPlainText("Lattice $label", value))
            screenState = screenState.copy(identityClipboardStatus = "$label copied to the clipboard.")
        } catch (_: Exception) {
            screenState = screenState.copy(identityClipboardStatus = "The $label could not be copied.")
        }
    }

    private fun mobileErrorStatus(error: MobileException): String = when (error) {
        is MobileException.InvalidIdentityBundle -> "The public bundle is malformed or has an unusable X25519 key."
        is MobileException.InvalidFingerprint -> "The full fingerprint must be exactly 32 bytes."
        is MobileException.FingerprintMismatch -> "Fingerprint mismatch. No pin was saved."
        is MobileException.PinnedIdentityConflict -> "This fingerprint is already pinned to different bundle bytes. The existing pin was not changed."
        is MobileException.InvalidProfileId -> "The local profile identifier is invalid."
        is MobileException.KeyProtectionFailed -> "Android Keystore access failed; no software-key fallback was used."
        is MobileException.ProfileOpenFailed -> "The protected local profile could not be opened."
        is MobileException.ProfileUnavailable -> "The protected local profile is unavailable."
        is MobileException.CertificateSigningRequestFailed -> "The device certificate request could not be generated."
        is MobileException.InvalidSpaceCredential -> "The X.509 credential is untrusted or does not match this device identity."
        is MobileException.InvalidSpaceInput -> "The initial Space channel inputs are invalid."
        is MobileException.SpaceCreationFailed -> "The local Space transaction failed."
        is MobileException.InvalidSpaceCursor -> "The local Space cursor is invalid."
        is MobileException.InvalidSpaceMessageId -> "The local Space message identifiers are invalid."
        is MobileException.InvalidMessageInput -> "The local message or channel input is invalid."
        is MobileException.MessageRejected -> "Local MLS rejected the message."
        is MobileException.MessageQueueFailed -> "The local message could not be durably queued."
        is MobileException.MessageHistoryUnavailable -> "The locally retained message history is unavailable or failed authentication."
        is MobileException.InvalidMessageSearch -> "Enter a non-empty search phrase of at most 256 UTF-8 bytes."
        is MobileException.SpaceRecoveryFailed -> "The prior local generation could not be restored or authorized for recovery."
        is MobileException.InvalidSpaceBootstrap -> "The Welcome bootstrap package is invalid or exceeds its size bound."
        is MobileException.UntrustedSpaceInviter -> "The inviter identity is not pinned to the exact expected bundle."
        is MobileException.SpaceJoinFailed -> "The signed Welcome or policy checkpoint could not be imported."
    }

    private fun pinPeerIdentity() {
        val currentPinState = screenState.identityPin
        if (currentPinState.pinningIdentity || currentPinState.lookingUpPinnedIdentity ||
            currentPinState.unpinningIdentity
        ) return
        val profile = mobileProfile ?: run {
            screenState = screenState.copy(
                identityPin = screenState.identityPin.copy(
                    identityPinStatus = "The protected profile is not ready.",
                ),
            )
            return
        }
        val pin = screenState.identityPin
        val bundle = decodeIdentityHex(pin.peerBundleHexInput, 65)
        val fingerprint = decodeIdentityHex(pin.peerFingerprintHexInput, 32)
        if (bundle == null || fingerprint == null) {
            screenState = screenState.copy(
                identityPin = pin.copy(
                    identityPinStatus = "Enter a 65-byte public bundle and its full 32-byte fingerprint as hexadecimal.",
                ),
            )
            return
        }

        screenState = screenState.copy(
            identityPin = pin.copy(
                pinningIdentity = true,
                identityPinStatus = "Checking the full fingerprint and saving the local pin…",
            ),
        )
        lifecycleScope.launch {
            try {
                val pinned = withContext(Dispatchers.IO) {
                    profile.pinIdentity(bundle, fingerprint)
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        identityPin = screenState.identityPin.copy(
                            pinningIdentity = false,
                            pinnedPeerFingerprint = pinned.fingerprint.toLowerHex(),
                            pinnedPeerBundleHex = pinned.publicBundle.toLowerHex(),
                            identityPinStatus = "Exact bundle/fingerprint match stored locally. This does not authenticate a session or grant Space membership.",
                        ),
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        identityPin = screenState.identityPin.copy(
                            pinningIdentity = false,
                            identityPinStatus = mobileErrorStatus(error),
                        ),
                    )
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        identityPin = screenState.identityPin.copy(
                            pinningIdentity = false,
                            identityPinStatus = "The local identity pin could not be stored.",
                        ),
                    )
                }
            }
        }
    }

    private fun localSpacesStatus(loadedCount: Int, hasNextPage: Boolean): String = when {
        hasNextPage -> "More locally recoverable Genesis snapshots are available."
        loadedCount == 0 -> "No local Space Genesis snapshots were found."
        else -> "All locally recoverable Genesis snapshots are shown."
    }


    private fun onPersistentNearbyAction() {
        if (screenState.persistentNearbyEnabled || PersistentNearbyService.isOptedIn(this)) {
            stopPersistentNearbyService()
            return
        }
        if (refreshReadiness() != DiscoveryPermissionState.GRANTED) {
            screenState = screenState.copy(showPermissionRationale = true)
            return
        }
        if (
            PersistentNearbyPermissionPolicy.requiresNotificationPermission(Build.VERSION.SDK_INT) &&
            checkSelfPermission(
                PersistentNearbyPermissionPolicy.notificationPermission(),
            ) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermissionRequest.launch(
                PersistentNearbyPermissionPolicy.notificationPermission(),
            )
            return
        }
        if (!PersistentNearbyPermissionPolicy.hasNotificationPermission(this)) {
            screenState = screenState.copy(
                persistentNearbyEnabled = false,
                persistentNearbyStatus = "Android notifications are disabled. Allow them in app settings before starting persistent mode.",
            )
            openAppSettings()
            return
        }
        startPersistentNearbyService()
    }

    private fun startPersistentNearbyService() {
        if (refreshReadiness() != DiscoveryPermissionState.GRANTED) {
            screenState = screenState.copy(showPermissionRationale = true)
            return
        }
        if (!PersistentNearbyPermissionPolicy.hasNotificationPermission(this)) {
            screenState = screenState.copy(
                persistentNearbyEnabled = false,
                persistentNearbyStatus = "Persistent mode needs an enabled Android status notification.",
            )
            return
        }
        stopScanning("Temporary nearby scan stopped; persistent discovery is starting.")
        try {
            startForegroundService(
                Intent(this, PersistentNearbyService::class.java)
                    .setAction(PersistentNearbyService.ACTION_START),
            )
            screenState = screenState.copy(
                persistentNearbyEnabled = true,
                persistentNearbyStatus = "Starting the visible persistent nearby service…",
            )
        } catch (_: SecurityException) {
            screenState = screenState.copy(
                persistentNearbyEnabled = false,
                persistentNearbyStatus = "Android denied the persistent service. Check Bluetooth and notification permissions.",
            )
        } catch (_: RuntimeException) {
            screenState = screenState.copy(
                persistentNearbyEnabled = false,
                persistentNearbyStatus = "Android could not start the persistent nearby service from the current app state.",
            )
        }
    }

    private fun stopPersistentNearbyService() {
        try {
            startService(
                Intent(this, PersistentNearbyService::class.java)
                    .setAction(PersistentNearbyService.ACTION_STOP),
            )
        } catch (_: RuntimeException) {
            stopService(Intent(this, PersistentNearbyService::class.java))
        }
        screenState = screenState.copy(
            persistentNearbyEnabled = false,
            persistentNearbyStatus = "Persistent nearby mode stopped.",
        )
    }

    private fun restorePersistentNearbyMode() {
        if (!PersistentNearbyService.isOptedIn(this)) {
            screenState = screenState.copy(
                persistentNearbyEnabled = false,
                persistentNearbyStatus = "Persistent nearby mode is off.",
            )
            return
        }
        if (
            refreshReadiness() != DiscoveryPermissionState.GRANTED ||
            !PersistentNearbyPermissionPolicy.hasNotificationPermission(this)
        ) {
            stopPersistentNearbyService()
            screenState = screenState.copy(
                persistentNearbyEnabled = false,
                persistentNearbyStatus = "Persistent mode was not resumed because a required permission is unavailable.",
            )
            return
        }
        if (PersistentNearbyService.isRunning()) {
            screenState = screenState.copy(
                persistentNearbyEnabled = true,
                persistentNearbyStatus = "Persistent foreground service is running. See its notification for radio status.",
            )
        } else {
            startPersistentNearbyService()
        }
    }

    private fun refreshWifiCapabilities() {
        screenState = screenState.copy(
            wifiCapabilities = AndroidWifiCapabilityProbe.probe(applicationContext),
        )
    }

    private fun startWifiCapabilityMonitoring() {
        if (wifiNetworkCallback != null) return
        val connectivityManager = getSystemService(ConnectivityManager::class.java) ?: return
        fun scheduleRefresh() {
            runOnUiThread {
                if (!isFinishing && !isDestroyed) refreshWifiCapabilities()
            }
        }
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) = scheduleRefresh()
            override fun onLost(network: Network) = scheduleRefresh()
            override fun onCapabilitiesChanged(
                network: Network,
                networkCapabilities: android.net.NetworkCapabilities,
            ) = scheduleRefresh()
        }
        try {
            connectivityManager.registerDefaultNetworkCallback(callback)
            wifiNetworkCallback = callback
        } catch (_: RuntimeException) {
            refreshWifiCapabilities()
        }
    }

    private fun stopWifiCapabilityMonitoring() {
        val callback = wifiNetworkCallback ?: return
        wifiNetworkCallback = null
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
        } catch (_: RuntimeException) {
            // The system may already have removed the callback during process teardown.
        }
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(bluetoothReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(bluetoothReceiver, filter)
        }
        receiverRegistered = true
        val persistentFilter = IntentFilter(PersistentNearbyService.ACTION_STATUS)
        ContextCompat.registerReceiver(
            this,
            persistentStatusReceiver,
            persistentFilter,
            ContextCompat.RECEIVER_NOT_EXPORTED,
        )
        persistentReceiverRegistered = true
        refreshReadiness()
        refreshWifiCapabilities()
        startWifiCapabilityMonitoring()
        restorePersistentNearbyMode()
    }

    override fun onResume() {
        super.onResume()
        refreshWifiCapabilities()
        val permission = refreshReadiness()
        if (
            permission != DiscoveryPermissionState.GRANTED ||
            !PersistentNearbyPermissionPolicy.hasNotificationPermission(this)
        ) {
            if (PersistentNearbyService.isOptedIn(this)) stopPersistentNearbyService()
        }
    }

    override fun onStop() {
        stopScanning("Nearby scan stopped because the app left the foreground. No sightings are retained.")
        if (receiverRegistered) {
            unregisterReceiver(bluetoothReceiver)
            receiverRegistered = false
        }
        if (persistentReceiverRegistered) {
            unregisterReceiver(persistentStatusReceiver)
            persistentReceiverRegistered = false
        }
        stopWifiCapabilityMonitoring()
        super.onStop()
    }

    override fun onDestroy() {
        if (::nearbyScanner.isInitialized) nearbyScanner.stop()
        mobileProfile?.close()
        mobileProfile = null
        super.onDestroy()
    }

    private fun onPrimaryAction() {
        if (screenState.scanning) {
            stopScanning("Nearby scan stopped. Temporary sightings were cleared.")
            return
        }

        val permission = refreshReadiness()
        if (permission != DiscoveryPermissionState.GRANTED) {
            screenState = screenState.copy(showPermissionRationale = true)
            return
        }
        when (screenState.bluetooth) {
            BluetoothReadiness.READY -> startScanning()
            BluetoothReadiness.BLUETOOTH_OFF -> openBluetoothSettings()
            BluetoothReadiness.PERMISSION_REQUIRED -> screenState = screenState.copy(showPermissionRationale = true)
            BluetoothReadiness.ADAPTER_UNAVAILABLE,
            BluetoothReadiness.SCANNER_UNAVAILABLE,
            BluetoothReadiness.ACCESS_UNAVAILABLE -> refreshReadiness()
        }
    }

    private fun continuePermissionFlow() {
        screenState = screenState.copy(showPermissionRationale = false)
        val current = DiscoveryPermissionClassifier.classify(
            permissionObservations(),
            preferences.getBoolean(KEY_PREVIOUSLY_GRANTED, false),
        )
        when (current) {
            DiscoveryPermissionState.PERMANENTLY_DENIED -> openAppSettings()
            DiscoveryPermissionState.GRANTED -> refreshReadiness()
            else -> {
                permissionHistoryBeforePrompt = preferences.getBoolean(KEY_REQUESTED_BEFORE, false)
                preferences.edit().putBoolean(KEY_REQUESTED_BEFORE, true).apply()
                permissionRequest.launch(runtimePermissions())
            }
        }
    }

    private fun startScanning() {
        when (nearbyScanner.start()) {
            NearbyServiceScanner.StartResult.STARTED -> {
                screenState = screenState.copy(
                    scanning = true,
                    sightings = 0,
                    message = "Scanning for the generic Lattice service. A found service is not an authenticated Lattice peer.",
                )
            }
            NearbyServiceScanner.StartResult.PERMISSION_MISSING -> {
                if (refreshReadiness() == DiscoveryPermissionState.GRANTED) {
                    setBluetoothFailure(
                        BluetoothReadiness.ACCESS_UNAVAILABLE,
                        "Android refused to start the Bluetooth scan. Check app permissions and Bluetooth settings.",
                    )
                } else {
                    screenState = screenState.copy(showPermissionRationale = true)
                }
            }
            NearbyServiceScanner.StartResult.ADAPTER_UNAVAILABLE -> setBluetoothFailure(
                BluetoothReadiness.ADAPTER_UNAVAILABLE,
                "No Bluetooth adapter is available on this device.",
            )
            NearbyServiceScanner.StartResult.BLUETOOTH_OFF -> setBluetoothFailure(
                BluetoothReadiness.BLUETOOTH_OFF,
                "Bluetooth is off. Turn it on to discover the generic Lattice service.",
            )
            NearbyServiceScanner.StartResult.SCANNER_UNAVAILABLE -> setBluetoothFailure(
                BluetoothReadiness.SCANNER_UNAVAILABLE,
                "This device does not currently provide a Bluetooth LE scanner.",
            )
            NearbyServiceScanner.StartResult.FAILED -> setBluetoothFailure(
                BluetoothReadiness.ACCESS_UNAVAILABLE,
                "Android could not start Bluetooth scanning. Check Bluetooth availability and try again.",
            )
        }
    }

    private fun setBluetoothFailure(readiness: BluetoothReadiness, message: String) {
        nearbyScanner.stop()
        screenState = screenState.copy(
            bluetooth = readiness,
            scanning = false,
            sightings = 0,
            message = message,
        )
    }

    private fun stopScanning(message: String) {
        if (::nearbyScanner.isInitialized) nearbyScanner.stop()
        screenState = screenState.copy(scanning = false, sightings = 0, message = message)
    }

    /** Updates permission and radio state without starting or resuming a scan. */
    private fun refreshReadiness(): DiscoveryPermissionState {
        val wasPreviouslyGranted = preferences.getBoolean(KEY_PREVIOUSLY_GRANTED, false)
        val permission = DiscoveryPermissionClassifier.classify(permissionObservations(), wasPreviouslyGranted)
        if (permission == DiscoveryPermissionState.GRANTED) {
            preferences.edit().putBoolean(KEY_PREVIOUSLY_GRANTED, true).apply()
        }

        if (permission != DiscoveryPermissionState.GRANTED) {
            if (screenState.scanning) nearbyScanner.stop()
            screenState = screenState.copy(
                permission = permission,
                bluetooth = BluetoothReadiness.PERMISSION_REQUIRED,
                scanning = false,
                sightings = 0,
                message = permissionMessage(permission),
            )
            return permission
        }

        val bluetooth = try {
            val adapter = getSystemService(BluetoothManager::class.java)?.adapter
            when {
                adapter == null -> BluetoothReadiness.ADAPTER_UNAVAILABLE
                !adapter.isEnabled -> BluetoothReadiness.BLUETOOTH_OFF
                adapter.bluetoothLeScanner == null -> BluetoothReadiness.SCANNER_UNAVAILABLE
                else -> BluetoothReadiness.READY
            }
        } catch (_: SecurityException) {
            BluetoothReadiness.ACCESS_UNAVAILABLE
        }
        if (screenState.scanning && bluetooth != BluetoothReadiness.READY) nearbyScanner.stop()
        val stillScanning = screenState.scanning && bluetooth == BluetoothReadiness.READY
        screenState = screenState.copy(
            permission = permission,
            bluetooth = bluetooth,
            scanning = stillScanning,
            sightings = if (stillScanning) screenState.sightings else 0,
            message = if (stillScanning) screenState.message else bluetoothMessage(bluetooth),
        )
        return permission
    }

    private fun permissionObservations(): List<RuntimePermissionObservation> {
        val requestedBefore = preferences.getBoolean(KEY_REQUESTED_BEFORE, false)
        return runtimePermissions().map { permission ->
            val granted = checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
            RuntimePermissionObservation(
                granted = granted,
                requestedBefore = requestedBefore,
                shouldShowRationale = !granted && shouldShowRequestPermissionRationale(permission),
            )
        }
    }

    private fun runtimePermissions(): Array<String> = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        arrayOf(Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT)
    } else {
        arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
    }

    private fun permissionMessage(permission: DiscoveryPermissionState): String = when (permission) {
        DiscoveryPermissionState.NOT_REQUESTED -> "Bluetooth permission has not been requested. Nearby discovery has not started."
        DiscoveryPermissionState.GRANTED -> "Bluetooth access is granted."
        DiscoveryPermissionState.DENIED -> "Bluetooth access was denied. Nearby discovery is off; review the reason and try again if you choose."
        DiscoveryPermissionState.PERMANENTLY_DENIED -> "Bluetooth access is blocked. Open app settings to allow nearby discovery."
        DiscoveryPermissionState.REVOKED -> "Bluetooth access was revoked. Nearby discovery is off until access is restored."
    }

    private fun bluetoothMessage(readiness: BluetoothReadiness): String = when (readiness) {
        BluetoothReadiness.PERMISSION_REQUIRED -> "Bluetooth status is not checked until the required permission is granted."
        BluetoothReadiness.READY -> "Bluetooth is on and a Bluetooth LE scanner is available. Discovery has not started."
        BluetoothReadiness.BLUETOOTH_OFF -> "Bluetooth is off. Turn it on, then tap Find nearby service."
        BluetoothReadiness.ADAPTER_UNAVAILABLE -> "No Bluetooth adapter is available on this device."
        BluetoothReadiness.SCANNER_UNAVAILABLE -> "This device does not currently provide a Bluetooth LE scanner."
        BluetoothReadiness.ACCESS_UNAVAILABLE -> "Android did not allow access to Bluetooth status. Review permissions or Bluetooth settings."
    }

    private fun permissionRationaleText(): String = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        "Android will ask for nearby-device Bluetooth permissions. Lattice uses them only to check Bluetooth and scan for one generic service. It will not connect to a device or exchange data. A found service is not an authenticated Lattice peer."
    } else {
        "Android requires location permission for Bluetooth LE scanning on this Android version. Lattice requests it only for BLE discovery and does not access or save your location. The scan looks only for one generic service, does not connect, and exchanges no data."
    }

    private fun openAppSettings() {
        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
    }

    private fun openBluetoothSettings() {
        try {
            startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
        } catch (_: android.content.ActivityNotFoundException) {
            screenState = screenState.copy(
                message = "Bluetooth settings are not available on this device. Turn Bluetooth on in system settings, then try again.",
            )
        }
    }

    private companion object {
        const val PREFERENCES_NAME = "nearby_discovery_permissions"
        const val KEY_REQUESTED_BEFORE = "permission_requested_before"
        const val KEY_PREVIOUSLY_GRANTED = "permission_previously_granted"
    }
}
internal fun ByteArray.toLowerHex(): String {
    val digits = "0123456789abcdef"
    return buildString(size * 2) {
        for (byte in this@toLowerHex) {
            val value = byte.toInt() and 0xff
            append(digits[value ushr 4])
            append(digits[value and 0x0f])
        }
    }
}


@Composable
private fun NearbyReadinessScreen(
    state: NearbyScreenState,
    permissionRationale: String,
    onPrimaryAction: () -> Unit,
    onPersistentNearbyAction: () -> Unit,
    onDismissRationale: () -> Unit,
    onContinuePermission: () -> Unit,
    onRefreshLocalSpaces: () -> Unit,
    onLoadMoreSpaces: (MobileSpaceCursor) -> Unit,
    onCredentialVectorHexChanged: (String) -> Unit,
    onSpaceChannelNameChanged: (String) -> Unit,
    onCreateLocalSpace: () -> Unit,
    onWelcomeBootstrapBase64Changed: (String) -> Unit,
    onWelcomeInviterFingerprintChanged: (String) -> Unit,
    onWelcomeCredentialVectorChanged: (String) -> Unit,
    onJoinSpaceFromWelcome: () -> Unit,
    onRecoverySpaceSelected: (String) -> Unit,
    onRecoveryCredentialChanged: (String) -> Unit,
    onRecoverLocalSpace: () -> Unit,
    onPeerBundleHexChanged: (String) -> Unit,
    onPeerFingerprintHexChanged: (String) -> Unit,
    onPinPeerIdentity: () -> Unit,
    onLookupPinnedIdentity: () -> Unit,
    onUnpinPeerIdentity: () -> Unit,
    onCopyPinnedBundle: (String) -> Unit,
    onGenerateCertificateRequest: () -> Unit,
    onCopyCertificateRequest: () -> Unit,
    onCopyIdentityBundle: () -> Unit,
    onCopyIdentityFingerprint: () -> Unit,
    onMessageCredentialHexChanged: (String, String) -> Unit,
    onMessageContentChanged: (String, String) -> Unit,
    onMessageChannelSelected: (String, String) -> Unit,
    onQueueLocalMessage: (String) -> Unit,
    onLoadMessageHistory: (String) -> Unit,
    onEditLocalMessage: (String, MobileLocalTextMessage) -> Unit,
    onCancelMessageEdit: (String) -> Unit,
) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp, vertical = 32.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.Top,
        ) {
            Text("Lattice", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(8.dp))
            Text(
                "Nearby",
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineLarge,
            )
            Spacer(Modifier.height(20.dp))
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.large,
                tonalElevation = 2.dp,
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "Device identity",
                        modifier = Modifier.semantics { heading() },
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(state.profileStatus, style = MaterialTheme.typography.bodyMedium)
                    state.identityFingerprint?.let { fingerprint ->
                        SelectionContainer {
                            Text(
                                "Fingerprint: $fingerprint",
                                style = MaterialTheme.typography.bodySmall,
                            )
                        }
                    }
                    state.identityBundleHex?.let { publicBundle ->
                        Text("Public bundle (share with a peer)", style = MaterialTheme.typography.bodySmall)
                        SelectionContainer {
                            Text(publicBundle, style = MaterialTheme.typography.bodySmall)
                        }
                        Button(onClick = onCopyIdentityBundle, modifier = Modifier.fillMaxWidth()) {
                            Text("Copy device public bundle")
                        }
                    }
                    state.identityFingerprint?.let {
                        Button(onClick = onCopyIdentityFingerprint, modifier = Modifier.fillMaxWidth()) {
                            Text("Copy full device fingerprint")
                        }
                    }
                    state.identityClipboardStatus?.let { status ->
                        Text(status, style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            Spacer(Modifier.height(20.dp))
            IdentityPinCard(
                state = state.identityPin,
                profileReady = state.profileStatus == "Protected local identity is available on this device.",
                onPeerBundleHexChanged = onPeerBundleHexChanged,
                onPeerFingerprintHexChanged = onPeerFingerprintHexChanged,
                onPinPeerIdentity = onPinPeerIdentity,
                onLookupPinnedIdentity = onLookupPinnedIdentity,
                onUnpinPeerIdentity = onUnpinPeerIdentity,
                onCopyPinnedBundle = onCopyPinnedBundle,
            )
            Spacer(Modifier.height(20.dp))
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.large,
                tonalElevation = 2.dp,
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "Certificate request",
                        modifier = Modifier.semantics { heading() },
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text(
                        "Create a PKCS#10 request for certificate issuance. A certificate authority must return a trusted chain before local Space creation.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Button(
                        onClick = onGenerateCertificateRequest,
                        enabled = state.profileStatus == "Protected local identity is available on this device." &&
                            !state.generatingCertificateRequest,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(if (state.generatingCertificateRequest) "Generating…" else "Generate certificate request")
                    }
                    state.certificateRequestStatus?.let { status ->
                        Text(status, style = MaterialTheme.typography.bodyMedium)
                    }
                    state.certificateRequestPem?.let { pem ->
                        SelectionContainer {
                            Text(pem, style = MaterialTheme.typography.bodySmall)
                        }
                        Button(onClick = onCopyCertificateRequest, modifier = Modifier.fillMaxWidth()) {
                            Text("Copy certificate request")
                        }
                    }
                }
            }
            Spacer(Modifier.height(20.dp))
            SpaceCreationCard(
                state = state.spaceCreation,
                profileReady = state.profileStatus == "Protected local identity is available on this device.",
                onCredentialVectorHexChanged = onCredentialVectorHexChanged,
                onChannelNameChanged = onSpaceChannelNameChanged,
                onCreateLocalSpace = onCreateLocalSpace,
            )
            Spacer(Modifier.height(20.dp))
            SpaceWelcomeJoinCard(
                state = state.spaceWelcomeJoin,
                profileReady = state.profileStatus == "Protected local identity is available on this device.",
                onBootstrapPackageChanged = onWelcomeBootstrapBase64Changed,
                onInviterFingerprintChanged = onWelcomeInviterFingerprintChanged,
                onCredentialVectorChanged = onWelcomeCredentialVectorChanged,
                onJoin = onJoinSpaceFromWelcome,
            )
            Spacer(Modifier.height(20.dp))
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.large,
                tonalElevation = 2.dp,
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "Local Spaces",
                        modifier = Modifier.semantics { heading() },
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Button(
                        onClick = onRefreshLocalSpaces,
                        enabled = state.profileStatus == "Protected local identity is available on this device." &&
                            !state.loadingSpacePage,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(if (state.loadingSpacePage) "Restoring local snapshots…" else "Restore local snapshot list")
                    }
                    Text(
                        "Locally restored snapshots include generations imported from signed Welcome checkpoints. They retain the accepted policy view and local transition history; they are not independent historical MLS replay proofs. Relay publishing and synchronization remain separate.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(state.localSpacesStatus, style = MaterialTheme.typography.bodyMedium)
                    state.localSpaces.forEachIndexed { index, space ->
                        Text("Local Genesis snapshot ${index + 1}", style = MaterialTheme.typography.titleSmall)
                        SelectionContainer {
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text("Space ID: ${space.spaceId.toLowerHex()}", style = MaterialTheme.typography.bodySmall)
                                Text(
                                    "Generation group reference: ${space.groupReference.toLowerHex()}",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                        val spaceKey = localSpaceKey(space)
                        SpaceMessageComposer(
                            channels = space.channels,
                            state = state.messageComposers[spaceKey] ?: LocalMessageComposerState(),
                            profileReady = state.profileStatus == "Protected local identity is available on this device.",
                            onCredentialVectorHexChanged = { onMessageCredentialHexChanged(spaceKey, it) },
                            onContentChanged = { onMessageContentChanged(spaceKey, it) },
                            onChannelSelected = { onMessageChannelSelected(spaceKey, it) },
                            onQueue = { onQueueLocalMessage(spaceKey) },
                            onLoadHistory = { onLoadMessageHistory(spaceKey) },
                            onEditMessage = { message -> onEditLocalMessage(spaceKey, message) },
                            onCancelEdit = { onCancelMessageEdit(spaceKey) },
                            profileIdentityHex = state.identityFingerprint.orEmpty(),
                        )
                    }
                    state.nextSpaceCursor?.let { cursor ->
                        Button(
                            onClick = { onLoadMoreSpaces(cursor) },
                            enabled = !state.loadingSpacePage,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(if (state.loadingSpacePage) "Loading Spaces…" else "Load more Spaces")
                        }
                    }
                }
            }
            LocalSpaceRecoveryCard(
                spaces = state.localSpaces,
                state = state.spaceRecovery,
                profileReady = state.profileStatus == "Protected local identity is available on this device.",
                onSpaceSelected = onRecoverySpaceSelected,
                onCredentialVectorHexChanged = onRecoveryCredentialChanged,
                onRecover = onRecoverLocalSpace,
            )
            Spacer(Modifier.height(20.dp))

            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.large,
                tonalElevation = 2.dp,
            ) {
                Column(
                    modifier = Modifier.padding(20.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(
                        "Readiness",
                        modifier = Modifier.semantics { heading() },
                        style = MaterialTheme.typography.titleMedium,
                    )
                    Text("Bluetooth permission: ${state.permission.label()}", style = MaterialTheme.typography.bodyMedium)
                    Text("Bluetooth: ${state.bluetooth.label()}", style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "Wi-Fi upgrade capability (local device only)",
                        modifier = Modifier.semantics { heading() },
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text("Wi-Fi Aware: ${state.wifiCapabilities.aware.label()}", style = MaterialTheme.typography.bodyMedium)
                    Text("Wi-Fi Direct: ${state.wifiCapabilities.direct.label()}", style = MaterialTheme.typography.bodyMedium)
                    Text("LAN interface: ${state.wifiCapabilities.lan.label()}", style = MaterialTheme.typography.bodyMedium)
                    Text(
                        "A local capability is not a reachable or authenticated peer path. No Wi-Fi data path is active; Bluetooth discovery remains the baseline only.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(state.message, style = MaterialTheme.typography.bodyLarge)
                    if (state.scanning) {
                        Text(
                            if (state.sightings >= 1024) "Unverified service sightings: 1,024+"
                            else "Unverified service sightings: ${state.sightings}",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                    Spacer(Modifier.height(4.dp))
                    Button(onClick = onPrimaryAction, modifier = Modifier.fillMaxWidth()) {
                        Text(if (state.scanning) "Stop nearby scan" else primaryLabel(state))
                    }
                    Text(
                        "Persistent nearby mode",
                        modifier = Modifier.semantics { heading() },
                        style = MaterialTheme.typography.titleSmall,
                    )
                    Text(
                        state.persistentNearbyStatus,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        "This opt-in foreground service keeps generic BLE discovery active while the app is backgrounded. Signals remain unverified; there is no GATT connection or message exchange.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Button(
                        onClick = onPersistentNearbyAction,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(
                            if (state.persistentNearbyEnabled) {
                                "Stop persistent nearby mode"
                            } else {
                                "Start persistent nearby mode"
                            },
                        )
                    }
                }
            }
            Spacer(Modifier.height(20.dp))
            Text(
                "Nearby sightings remain unverified and no peer connection or transport is available. Space messages can be queued locally only; forwarding and recipient delivery are unknown.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }

    if (state.showPermissionRationale) {
        val permanentlyDenied = state.permission == DiscoveryPermissionState.PERMANENTLY_DENIED
        AlertDialog(
            onDismissRequest = onDismissRationale,
            title = { Text("Before nearby discovery") },
            text = { Text(permissionRationale) },
            confirmButton = {
                TextButton(onClick = onContinuePermission) {
                    Text(if (permanentlyDenied) "Open app settings" else "Continue")
                }
            },
            dismissButton = { TextButton(onClick = onDismissRationale) { Text("Not now") } },
        )
    }
}

private fun DiscoveryPermissionState.label(): String = when (this) {
    DiscoveryPermissionState.NOT_REQUESTED -> "Not requested"
    DiscoveryPermissionState.GRANTED -> "Granted"
    DiscoveryPermissionState.DENIED -> "Denied"
    DiscoveryPermissionState.PERMANENTLY_DENIED -> "Blocked in Android permission settings"
    DiscoveryPermissionState.REVOKED -> "Revoked"
}

private fun BluetoothReadiness.label(): String = when (this) {
    BluetoothReadiness.PERMISSION_REQUIRED -> "Not checked (permission required)"
    BluetoothReadiness.READY -> "On; scanner available"
    BluetoothReadiness.BLUETOOTH_OFF -> "Off"
    BluetoothReadiness.ADAPTER_UNAVAILABLE -> "No adapter"
    BluetoothReadiness.SCANNER_UNAVAILABLE -> "No BLE scanner"
    BluetoothReadiness.ACCESS_UNAVAILABLE -> "Status unavailable"
}

private fun WifiCapabilityState.label(): String = when (this) {
    WifiCapabilityState.NOT_PROBED -> "Not probed"
    WifiCapabilityState.AVAILABLE -> "Capability available locally"
    WifiCapabilityState.TEMPORARILY_UNAVAILABLE -> "Temporarily unavailable"
    WifiCapabilityState.PERMISSION_REQUIRED -> "Permission required"
    WifiCapabilityState.UNSUPPORTED -> "Unsupported on this device"
}

private fun primaryLabel(state: NearbyScreenState): String = when {
    state.permission != DiscoveryPermissionState.GRANTED -> "Find nearby service"
    state.bluetooth == BluetoothReadiness.BLUETOOTH_OFF -> "Open Bluetooth settings"
    state.bluetooth == BluetoothReadiness.READY -> "Find nearby service"
    else -> "Check availability"
}

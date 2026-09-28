package com.astraive.lattice

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
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
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.PrimaryTabRow
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
import uniffi.lattice_uniffi.MobileSyncEventResult
import com.astraive.lattice.identity.IdentityPinCard
import com.astraive.lattice.identity.IdentityPinUiState
import com.astraive.lattice.identity.decodeIdentityHex

internal enum class BluetoothReadiness {
    PERMISSION_REQUIRED,
    READY,
    BLUETOOTH_OFF,
    ADAPTER_UNAVAILABLE,
    SCANNER_UNAVAILABLE,
    ADVERTISER_UNAVAILABLE,
    ACCESS_UNAVAILABLE,
}
internal enum class NearbyDestination {
    IDENTITY,
    SPACES,
    DIAGNOSTICS,
}

internal data class NearbyScreenState(
    val destination: NearbyDestination = NearbyDestination.IDENTITY,
    val selectedSpaceKey: String? = null,
    val permission: DiscoveryPermissionState = DiscoveryPermissionState.NOT_REQUESTED,
    val bluetooth: BluetoothReadiness = BluetoothReadiness.PERMISSION_REQUIRED,
    val scanning: Boolean = false,
    val sightings: Int = 0,
    val nearbyCandidates: List<BleExp0PeerCandidate> = emptyList(),
    val bleConnectionStatus: String = "No authenticated BLE session.",
    val lastCoreIngressResult: String? = null,
    val pendingIdentitySafetyNumber: String? = null,
    val pendingIdentityFingerprint: String? = null,
    val pendingRouteConsent: Boolean = false,
    val persistentNearbyEnabled: Boolean = false,
    val persistentNearbyStatus: String = "Persistent nearby mode is off.",
    val wifiCapabilities: AndroidWifiCapabilities = AndroidWifiCapabilities(),
    val message: String = "Bluetooth permission has not been requested. Nearby discovery has not started.",
    val showPermissionRationale: Boolean = false,
    val profileStatus: String = "Preparing protected device profile.",
    val keystoreProtectionLevel: AndroidKeyProtectionLevel? = null,
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
    val spaceMembership: SpaceMembershipUiState = SpaceMembershipUiState(),
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
    private lateinit var nearbyAdvertiser: NearbyBleAdvertiser
    private var receiverRegistered = false
    private var persistentReceiverRegistered = false
    private var permissionHistoryBeforePrompt = false
    private var wifiNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private var peripheralSession: BleExp0PeripheralSession? = null
    private var centralSession: BleExp0CentralSession? = null
    private var pendingBleIdentityDecision: ((Boolean) -> Unit)? = null
    private var pendingBleRouteDecision: ((Boolean) -> Unit)? = null
    private var activityStarted = false
    private var projectionSubscription: AutoCloseable? = null
    private val pendingHistoryRefreshes = mutableMapOf<String, Boolean>()
    private var pendingSpaceRefresh = false

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
                    "Bluetooth access is granted. Tap Find nearby service to scan and advertise."
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
                            message = "Scanning for exp0 discovery tokens. $count unverified token sighting${if (count == 1) "" else "s"} found.",
                        )
                    }
                }
            },
            onFailure = { failure ->
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) stopScanning(failure)
                }
            },
            onCandidatesChanged = ::onNearbyCandidatesChanged,
        )
        nearbyAdvertiser = NearbyBleAdvertiser(
            context = this,
            onFailure = { failure ->
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) stopScanning(failure)
                }
            },
        )
        refreshReadiness()
        setContent {
            MaterialTheme {
                NearbyReadinessScreen(
                    state = screenState,
                    permissionRationale = permissionRationaleText(),
                    destination = screenState.destination,
                    selectedSpaceKey = screenState.selectedSpaceKey,
                    onDestinationSelected = { destination ->
                        screenState = screenState.copy(destination = destination)
                    },
                    onOpenLocalSpace = { spaceKey ->
                        screenState = screenState.copy(selectedSpaceKey = spaceKey)
                        if (spaceKey != null) loadLocalMessageHistory(spaceKey)
                    },
                    onPrimaryAction = ::onPrimaryAction,
                    onConnectCandidate = ::connectNearbyCandidate,
                    onApproveBleIdentity = { resolveBleIdentity(true) },
                    onRejectBleIdentity = { resolveBleIdentity(false) },
                    onApproveRoute = { resolveBleRoute(true) },
                    onRejectRoute = { resolveBleRoute(false) },
                    onPersistentNearbyAction = ::onPersistentNearbyAction,
                    onDismissRationale = { screenState = screenState.copy(showPermissionRationale = false) },
                    onContinuePermission = ::continuePermissionFlow,
                    onMessageCredentialHexChanged = ::onMessageCredentialHexChanged,
                    onMessageContentChanged = ::onMessageContentChanged,
                    onMessageReactionTokenChanged = ::onMessageReactionTokenChanged,
                    onMessageMutationTagHexChanged = ::onMessageMutationTagHexChanged,
                    onMessageChannelSelected = ::onMessageChannelSelected,
                    onQueueLocalMessage = ::queueLocalMessage,
                    onLoadMessageHistory = ::loadLocalMessageHistory,
                    onEditLocalMessage = ::editLocalMessage,
                    onReplyLocalMessage = ::replyLocalMessage,
                    onQueueMessageMutation = ::queueLocalMessageMutation,
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
                    onKeyPackageCredentialChanged = ::onKeyPackageCredentialChanged,
                    onPublishSpaceKeyPackage = ::publishSpaceKeyPackage,
                    onInvitationKeyPackageChanged = ::onInvitationKeyPackageChanged,
                    onInvitationCredentialChanged = ::onInvitationCredentialChanged,
                    onInvitationExpiryHoursChanged = ::onInvitationExpiryHoursChanged,
                    onInvitationMaxUsesChanged = ::onInvitationMaxUsesChanged,
                    onCreateSpaceInvitation = ::createSpaceInvitation,
                    onCopyMembershipValue = ::copyPublicValue,
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
                val keyProtectionLevel = withContext(Dispatchers.IO) {
                    profile.keyProtectionLevel()
                }
                if (isFinishing || isDestroyed) {
                    profile.close()
                    return@launch
                }
                mobileProfile = profile
                screenState = screenState.copy(
                    profileStatus = "Protected local identity is available on this device.",
                    keystoreProtectionLevel = keyProtectionLevel,
                    identityFingerprint = identity.fingerprint.toLowerHex(),
                    identityBundleHex = identity.publicBundle.toLowerHex(),
                    localSpaces = firstSpacePage.spaces,
                    localSpacesStatus = localSpacesStatus(firstSpacePage.spaces.size, firstSpacePage.nextCursor != null),
                    nextSpaceCursor = firstSpacePage.nextCursor,
                )
                attachCoreProjectionSubscription()
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
    private fun attachCoreProjectionSubscription() {
        if (!activityStarted || projectionSubscription != null) return
        val profile = mobileProfile ?: return
        val dispatcher = CoreProjectionChangeDispatcher(
            post = { action -> runOnUiThread { action() } },
            observer = { change ->
                if (activityStarted && !isFinishing && !isDestroyed && mobileProfile === profile) {
                    when (change) {
                        CoreProjectionChange.SPACES -> refreshLocalSpaces()
                        CoreProjectionChange.MESSAGES -> refreshLoadedMessageHistories()
                        CoreProjectionChange.ALL -> {
                            refreshLocalSpaces()
                            refreshLoadedMessageHistories()
                        }
                        CoreProjectionChange.SYNCED_EVENTS -> {
                            refreshLocalSpaces()
                            refreshLoadedMessageHistories(notifyIncomingMessages = true)
                        }
                    }
                }
            },
        )
        val nativeSubscription = profile.subscribeProjectionChanges(dispatcher::offer)
        projectionSubscription = AutoCloseable {
            dispatcher.close()
            nativeSubscription.close()
        }
        refreshLocalSpaces()
        refreshLoadedMessageHistories()
    }

    private fun refreshLoadedMessageHistories(notifyIncomingMessages: Boolean = false) {
        screenState.messageComposers
            .filterValues { it.historyChannelIdHex != null }
            .keys
            .forEach { loadLocalMessageHistory(it, notifyIncomingMessages) }
    }


    private fun refreshLocalSpaces() {
        val profile = mobileProfile ?: return
        if (screenState.loadingSpacePage) {
            pendingSpaceRefresh = true
            return
        }
        screenState = screenState.copy(loadingSpacePage = true)
        lifecycleScope.launch {
            try {
                val loadedCount = screenState.localSpaces.size.coerceAtLeast(1)
                val (spaces, nextCursor) = withContext(Dispatchers.IO) {
                    val spaces = ArrayList<MobileSpaceSummary>()
                    var cursor: MobileSpaceCursor? = null
                    var nextCursor: MobileSpaceCursor? = null
                    do {
                        val page = profile.localSpaces(cursor)
                        spaces.addAll(page.spaces)
                        cursor = page.nextCursor
                        nextCursor = page.nextCursor
                    } while (cursor != null && spaces.size < loadedCount)
                    spaces to nextCursor
                }
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        localSpaces = spaces,
                        localSpacesStatus = localSpacesStatus(spaces.size, nextCursor != null),
                        nextSpaceCursor = nextCursor,
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
            finally {
                if (activityStarted && pendingSpaceRefresh && !isFinishing && !isDestroyed) {
                    pendingSpaceRefresh = false
                    refreshLocalSpaces()
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
            finally {
                if (activityStarted && pendingSpaceRefresh && !isFinishing && !isDestroyed) {
                    pendingSpaceRefresh = false
                    refreshLocalSpaces()
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

    private fun onMessageReactionTokenChanged(spaceKey: String, value: String) {
        if (value.toByteArray(Charsets.UTF_8).size > 64) return
        updateMessageComposer(spaceKey) {
            it.copy(reactionToken = value, status = "Reaction token changed; not yet queued.")
        }
    }

    private fun onMessageMutationTagHexChanged(spaceKey: String, value: String) {
        if (value.length > 64) return
        updateMessageComposer(spaceKey) {
            it.copy(mutationTagHex = value.trim(), status = "Mutation tag changed; not yet used.")
        }
    }

    private fun onMessageChannelSelected(spaceKey: String, channelIdHex: String) {
        updateMessageComposer(spaceKey) {
            it.copy(
                selectedChannelIdHex = channelIdHex,
                editTargetMessageIdHex = null,
                replyTargetMessageIdHex = null,
                eventIdHex = null,
                historyChannelIdHex = null,
                historyStatus = null,
                status = "Channel selected; message not yet queued.",
            )
        }
        loadLocalMessageHistory(spaceKey)
    }

    private fun editLocalMessage(spaceKey: String, message: MobileLocalTextMessage) {
        val composer = screenState.messageComposers[spaceKey] ?: LocalMessageComposerState()
        if (composer.submitting || message.authorId.toLowerHex() != screenState.identityFingerprint) return
        updateMessageComposer(spaceKey) {
            it.copy(
                content = message.content,
                editTargetMessageIdHex = message.eventId.toLowerHex(),
                replyTargetMessageIdHex = null,
                eventIdHex = null,
                status = "Editing your local message. The original event remains immutable.",
            )
        }
    }

    private fun replyLocalMessage(spaceKey: String, message: MobileLocalTextMessage) {
        val composer = screenState.messageComposers[spaceKey] ?: LocalMessageComposerState()
        if (composer.submitting) return
        updateMessageComposer(spaceKey) {
            it.copy(
                content = "",
                editTargetMessageIdHex = null,
                replyTargetMessageIdHex = message.eventId.toLowerHex(),
                eventIdHex = null,
                status = "Replying in thread rooted at ${message.eventId.toLowerHex()}.",
            )
        }
    }

    private fun cancelLocalMessageEdit(spaceKey: String) {
        updateMessageComposer(spaceKey) {
            it.copy(
                content = "",
                editTargetMessageIdHex = null,
                replyTargetMessageIdHex = null,
                eventIdHex = null,
                status = "Edit cancelled; original message remains unchanged.",
            )
        }
    }
    private fun loadLocalMessageHistory(spaceKey: String, notifyIncomingMessages: Boolean = false) {
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
        if (composer.loadingHistory) {
            pendingHistoryRefreshes[spaceKey] =
                pendingHistoryRefreshes[spaceKey] == true || notifyIncomingMessages
            return
        }
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
                if (
                    (notifyIncomingMessages || pendingHistoryRefreshes[spaceKey] == true) &&
                    composer.historyChannelIdHex == channelIdHex
                ) {
                    newlyProjectedIncomingMessages(
                        previous = composer.history,
                        current = history,
                        localFingerprintHex = screenState.identityFingerprint,
                    ).forEach(::notifyAuthorizedMessage)
                }
                if (!isFinishing && !isDestroyed) {
                    updateMessageComposer(spaceKey) {
                        it.copy(
                            loadingHistory = false,
                            history = history,
                            historyChannelIdHex = channelIdHex,
                            historyStatus = if (history.isEmpty()) {
                                "No locally retained authorized messages for this channel."
                            } else {
                                "Showing ${history.size} recent locally retained authorized message(s)."
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
            finally {
                val refreshAsNotificationEligible = pendingHistoryRefreshes.remove(spaceKey)
                if (
                    activityStarted &&
                    refreshAsNotificationEligible != null &&
                    !isFinishing &&
                    !isDestroyed
                ) {
                    loadLocalMessageHistory(spaceKey, refreshAsNotificationEligible)
                }
            }
        }
    }
    private fun notifyAuthorizedMessage(message: MobileLocalTextMessage) {
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        val manager = getSystemService(NotificationManager::class.java) ?: return
        if (
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            manager.getNotificationChannel(MESSAGE_NOTIFICATION_CHANNEL_ID) == null
        ) {
            manager.createNotificationChannel(
                NotificationChannel(
                    MESSAGE_NOTIFICATION_CHANNEL_ID,
                    MESSAGE_NOTIFICATION_CHANNEL_NAME,
                    NotificationManager.IMPORTANCE_DEFAULT,
                ),
            )
        }
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val notification = Notification.Builder(this, MESSAGE_NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_chat)
            .setContentTitle("New Lattice message")
            .setContentText(message.content)
            .setStyle(Notification.BigTextStyle().bigText(message.content))
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setAutoCancel(true)
            .setContentIntent(contentIntent)
            .build()
        try {
            manager.notify(message.eventId.toLowerHex(), 0, notification)
        } catch (_: SecurityException) {
            // Notification permission can be revoked after the runtime check.
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
                    val editTarget = composer.editTargetMessageIdHex?.let { decodeIdentityHex(it, 32) }
                    if (composer.editTargetMessageIdHex != null && editTarget == null) {
                        throw IllegalArgumentException("The selected message ID is malformed.")
                    }
                    val replyRoot = composer.replyTargetMessageIdHex?.let { decodeIdentityHex(it, 32) }
                    if (composer.replyTargetMessageIdHex != null && replyRoot == null) {
                        throw IllegalArgumentException("The selected thread root ID is malformed.")
                    }
                    when {
                        editTarget != null -> profile.queueLocalTextMessageEdit(
                            space.spaceId,
                            space.groupReference,
                            credentialVector,
                            channel.id,
                            editTarget,
                            composer.content,
                        )
                        replyRoot != null -> profile.queueLocalTextMessageReply(
                            space.spaceId,
                            space.groupReference,
                            credentialVector,
                            channel.id,
                            replyRoot,
                            composer.content,
                        )
                        else -> profile.queueLocalTextMessage(
                            space.spaceId,
                            space.groupReference,
                            credentialVector,
                            channel.id,
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
                            replyTargetMessageIdHex = null,
                            eventIdHex = queued.eventId.toLowerHex(),
                            status = when {
                                composer.editTargetMessageIdHex != null ->
                                    "Edit committed locally as a new immutable event. Network forwarding and recipient delivery are unknown."
                                composer.replyTargetMessageIdHex != null ->
                                    "Thread reply committed locally. Network forwarding and recipient delivery are unknown."
                                else ->
                                    "Queued locally in the durable outbox. Network forwarding and recipient delivery are unknown."
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
            }
        }
    }

    private fun queueLocalMessageMutation(
        spaceKey: String,
        message: MobileLocalTextMessage,
        mutation: LocalTextMessageMutation,
        add: Boolean,
    ) {
        val profile = mobileProfile ?: return updateMessageComposer(spaceKey) {
            it.copy(status = "The protected profile is not ready.")
        }
        val space = screenState.localSpaces.firstOrNull { localSpaceKey(it) == spaceKey }
            ?: return updateMessageComposer(spaceKey) {
                it.copy(status = "This local Space is no longer available.")
            }
        val composer = screenState.messageComposers[spaceKey] ?: LocalMessageComposerState()
        if (composer.submitting) return
        val messageChannels = space.channels.filter {
            !it.archived &&
                (it.channelType == MobileChannelType.TEXT ||
                    it.channelType == MobileChannelType.ANNOUNCEMENT)
        }
        val channel = messageChannels.firstOrNull {
            it.id.toLowerHex() == composer.selectedChannelIdHex
        } ?: (if (composer.selectedChannelIdHex == null) messageChannels.firstOrNull() else null)
            ?: return updateMessageComposer(spaceKey) {
                it.copy(status = "Select an active channel before queueing a message update.")
            }
        val credentialVector = decodeStrictBoundedHex(composer.credentialVectorHex)
            ?: return updateMessageComposer(spaceKey) {
                it.copy(status = "Enter a valid trusted X.509 credential vector before queueing.")
            }
        val target = message.eventId
        val tag = if (!add && mutation != LocalTextMessageMutation.TOMBSTONE) {
            decodeIdentityHex(composer.mutationTagHex, 32)
        } else {
            null
        }
        val token = composer.reactionToken
        if (!add && mutation != LocalTextMessageMutation.TOMBSTONE && tag == null) {
            credentialVector.fill(0)
            return updateMessageComposer(spaceKey) {
                it.copy(status = "The selected message or mutation tag is malformed.")
            }
        }
        if (mutation == LocalTextMessageMutation.REACTION &&
            token.toByteArray(Charsets.UTF_8).size !in 1..64
        ) {
            credentialVector.fill(0)
            return updateMessageComposer(spaceKey) {
                it.copy(status = "Reaction token must contain 1 to 64 UTF-8 bytes.")
            }
        }
        updateMessageComposer(spaceKey) {
            it.copy(submitting = true, eventIdHex = null, status = "Committing message update locally…")
        }
        lifecycleScope.launch {
            try {
                val queued = withContext(Dispatchers.IO) {
                    when (mutation) {
                        LocalTextMessageMutation.TOMBSTONE ->
                            profile.queueLocalTextMessageTombstone(
                                space.spaceId,
                                space.groupReference,
                                credentialVector,
                                channel.id,
                                target,
                            )
                        LocalTextMessageMutation.REACTION ->
                            profile.queueLocalTextMessageReaction(
                                space.spaceId,
                                space.groupReference,
                                credentialVector,
                                channel.id,
                                target,
                                token,
                                add,
                                tag,
                            )
                        LocalTextMessageMutation.PIN ->
                            profile.queueLocalTextMessagePin(
                                space.spaceId,
                                space.groupReference,
                                credentialVector,
                                channel.id,
                                target,
                                add,
                                tag,
                            )
                    }
                }
                if (!isFinishing && !isDestroyed) {
                    updateMessageComposer(spaceKey) {
                        it.copy(
                            submitting = false,
                            eventIdHex = queued.eventId.toLowerHex(),
                            mutationTagHex = if (add && mutation != LocalTextMessageMutation.TOMBSTONE) {
                                queued.eventId.toLowerHex()
                            } else {
                                it.mutationTagHex
                            },
                            status = when (mutation) {
                                LocalTextMessageMutation.TOMBSTONE ->
                                    "Tombstone queued locally. Forwarding and remote display changes are unknown."
                                LocalTextMessageMutation.REACTION ->
                                    "Reaction ${if (add) "add" else "removal"} committed locally. Forwarding and recipient delivery are unknown."
                                LocalTextMessageMutation.PIN ->
                                    "Pin ${if (add) "add" else "removal"} committed locally. Forwarding and recipient delivery are unknown."
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
                        it.copy(submitting = false, status = "The message update could not be confirmed as queued locally.")
                    }
                }
            } finally {
                credentialVector.fill(0)
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

    private fun updateSpaceMembership(update: (SpaceMembershipUiState) -> SpaceMembershipUiState) {
        screenState = screenState.copy(spaceMembership = update(screenState.spaceMembership))
    }

    private fun onKeyPackageCredentialChanged(value: String) {
        if (value.length > MAX_CREDENTIAL_HEX_LENGTH) {
            updateSpaceMembership {
                it.copy(keyPackageStatus = "The credential vector exceeds the 16 KiB input limit.")
            }
            return
        }
        updateSpaceMembership {
            it.copy(
                keyPackageCredentialHex = value,
                publishedKeyPackageBase64 = null,
                keyPackageStatus = "Credential input changed; it has not been validated.",
            )
        }
    }

    private fun publishSpaceKeyPackage() {
        val profile = mobileProfile ?: return updateSpaceMembership {
            it.copy(keyPackageStatus = "The protected profile is not ready.")
        }
        val current = screenState.spaceMembership
        if (current.publishingKeyPackage) return
        val credential = decodeStrictBoundedHex(current.keyPackageCredentialHex) ?: return updateSpaceMembership {
            it.copy(keyPackageStatus = "Enter a valid, bounded X.509 credential vector.")
        }
        updateSpaceMembership {
            it.copy(
                publishingKeyPackage = true,
                publishedKeyPackageBase64 = null,
                keyPackageStatus = "Validating this device credential and publishing a one-time package locally.",
            )
        }
        lifecycleScope.launch {
            try {
                val keyPackage = withContext(Dispatchers.IO) {
                    try {
                        profile.publishSpaceKeyPackage(credential)
                    } finally {
                        credential.fill(0)
                    }
                }
                val encoded = Base64.encodeToString(keyPackage, Base64.NO_WRAP)
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        spaceMembership = screenState.spaceMembership.copy(
                            keyPackageCredentialHex = "",
                            publishedKeyPackageBase64 = encoded,
                            keyPackageStatus = "KeyPackage published locally; its private material stays on this device. No network was contacted.",
                        ),
                    )
                }
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    updateSpaceMembership {
                        it.copy(keyPackageStatus = mobileErrorStatus(error))
                    }
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    updateSpaceMembership {
                        it.copy(keyPackageStatus = "The local KeyPackage could not be published.")
                    }
                }
            } finally {
                if (!isFinishing && !isDestroyed) {
                    updateSpaceMembership { it.copy(publishingKeyPackage = false) }
                }
            }
        }
    }

    private fun onInvitationKeyPackageChanged(value: String) {
        if (value.length > MAX_SPACE_KEY_PACKAGE_BASE64_CHARS) {
            updateSpaceMembership {
                it.copy(invitationStatus = "The KeyPackage exceeds the 256 KiB decoded input limit.")
            }
            return
        }
        updateSpaceMembership {
            it.copy(
                invitationKeyPackageBase64 = value,
                invitation = null,
                invitationStatus = "KeyPackage input changed; it has not been validated.",
            )
        }
    }

    private fun onInvitationCredentialChanged(value: String) {
        if (value.length > MAX_CREDENTIAL_HEX_LENGTH) {
            updateSpaceMembership {
                it.copy(invitationStatus = "The credential vector exceeds the 16 KiB input limit.")
            }
            return
        }
        updateSpaceMembership {
            it.copy(
                invitationCredentialHex = value,
                invitation = null,
                invitationStatus = "Credential input changed; it has not been validated.",
            )
        }
    }

    private fun onInvitationExpiryHoursChanged(value: String) {
        if (value.length > 3 || value.any { !it.isDigit() }) return
        updateSpaceMembership {
            it.copy(expiryHours = value, invitation = null, invitationStatus = "Invite expiry changed.")
        }
    }

    private fun onInvitationMaxUsesChanged(value: String) {
        if (value.length > 5 || value.any { !it.isDigit() }) return
        updateSpaceMembership {
            it.copy(maxUses = value, invitation = null, invitationStatus = "Maximum uses changed.")
        }
    }

    private fun createSpaceInvitation() {
        val profile = mobileProfile ?: return updateSpaceMembership {
            it.copy(invitationStatus = "The protected profile is not ready.")
        }
        val current = screenState.spaceMembership
        if (current.creatingInvitation) return
        val space = screenState.selectedSpaceKey?.let { key ->
            screenState.localSpaces.firstOrNull { localSpaceKey(it) == key }
        } ?: return updateSpaceMembership {
            it.copy(invitationStatus = "Open the intended local Space before creating an invitation.")
        }
        val keyPackage = decodeBoundedBase64(
            current.invitationKeyPackageBase64,
            MAX_SPACE_KEY_PACKAGE_BYTES,
            MAX_SPACE_KEY_PACKAGE_BASE64_CHARS,
        ) ?: return updateSpaceMembership {
            it.copy(invitationStatus = "Enter a canonical Base64 KeyPackage no larger than 256 KiB.")
        }
        val credential = decodeStrictBoundedHex(current.invitationCredentialHex) ?: run {
            keyPackage.fill(0)
            return updateSpaceMembership {
                it.copy(invitationStatus = "Enter a valid, bounded X.509 credential vector.")
            }
        }
        val expiryHours = current.expiryHours.toLongOrNull()
        val maxUses = current.maxUses.toUIntOrNull()
        if (expiryHours == null || expiryHours !in 1..720 || maxUses == null || maxUses !in 1u..65_535u) {
            keyPackage.fill(0)
            credential.fill(0)
            return updateSpaceMembership {
                it.copy(invitationStatus = "Expiry must be 1–720 hours and maximum uses 1–65,535.")
            }
        }
        val expiresAt = System.currentTimeMillis() / 1000L + expiryHours * 3600L
        updateSpaceMembership {
            it.copy(
                creatingInvitation = true,
                invitation = null,
                invitationStatus = "Checking inviter trust and target KeyPackage; committing the membership transition.",
            )
        }
        lifecycleScope.launch {
            try {
                val invitation = withContext(Dispatchers.IO) {
                    try {
                        profile.createSpaceInvitation(
                            space.spaceId,
                            space.groupReference,
                            credential,
                            keyPackage,
                            expiresAt.toULong(),
                            maxUses,
                        )
                    } finally {
                        credential.fill(0)
                        keyPackage.fill(0)
                    }
                }
                if (!isFinishing && !isDestroyed) {
                    updateSpaceMembership {
                        it.copy(
                            invitationKeyPackageBase64 = "",
                            invitationCredentialHex = "",
                            invitation = invitation,
                            invitationStatus = "Invitation committed locally; share the Welcome bootstrap with the matching target fingerprint. No network was contacted.",
                        )
                    }
                }
                refreshLocalSpaces()
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    updateSpaceMembership { it.copy(invitationStatus = mobileErrorStatus(error)) }
                }
            } catch (_: Exception) {
                if (!isFinishing && !isDestroyed) {
                    updateSpaceMembership { it.copy(invitationStatus = "The signed Space invitation could not be committed.") }
                }
            } finally {
                if (!isFinishing && !isDestroyed) {
                    updateSpaceMembership { it.copy(creatingInvitation = false) }
                }
            }
        }
    }

    private fun decodeBoundedBase64(value: String, maxBytes: Int, maxChars: Int): ByteArray? {
        if (value.isEmpty() || value.length > maxChars || value.length % 4 != 0) return null
        val decoded = try {
            Base64.decode(value, Base64.NO_WRAP)
        } catch (_: IllegalArgumentException) {
            return null
        }
        if (decoded.isEmpty() || decoded.size > maxBytes ||
            Base64.encodeToString(decoded, Base64.NO_WRAP) != value
        ) {
            decoded.fill(0)
            return null
        }
        return decoded
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
        is MobileException.ProjectionObserverLimit -> "Too many active local projection subscriptions."
        is MobileException.InvalidProjectionWait -> "The local projection observer wait interval is invalid."
        is MobileException.ProjectionObserverUnavailable -> "The local projection observer is unavailable."
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
        is MobileException.InvalidOutboxCursor -> "The durable outbox cursor is invalid."
        is MobileException.InvalidOutboxPage -> "The durable outbox page limit is invalid."
        is MobileException.OutboxUnavailable -> "The durable outbox could not be read."
        is MobileException.InvalidOutboxEventId -> "The durable outbox event identifier is invalid."
        is MobileException.InvalidOutboxSchedule -> "The outbox retry time must be a nonnegative Unix timestamp."
        is MobileException.OutboxTransitionRejected -> "The durable outbox rejected the forwarding or receipt transition."
        is MobileException.SyncIngestFailed -> "Rust Core rejected or could not store the received event."
        is MobileException.SpaceRecoveryFailed -> "The prior local generation could not be restored or authorized for recovery."
        is MobileException.InvalidSpaceBootstrap -> "The Welcome bootstrap package is invalid or exceeds its size bound."
        is MobileException.UntrustedSpaceInviter -> "The inviter identity is not pinned to the exact expected bundle."
        is MobileException.SpaceJoinFailed -> "The signed Welcome or policy checkpoint could not be imported."
        is MobileException.InvalidSpaceKeyPackage -> "The target KeyPackage is invalid or exceeds its size bound."
        is MobileException.SpaceKeyPackagePublicationFailed -> "The target device KeyPackage could not be published."
        is MobileException.SpaceInvitationFailed -> "The signed membership invitation could not be committed."
        is MobileException.InvalidBleDiscoveryToken -> "The BLE discovery token is invalid; no session was started."
        is MobileException.BleSessionFailed -> "BLE authentication or transport failed; delivery is not confirmed."
        is MobileException.BleRecordRejected -> "The BLE peer sent an unexpected or malformed record."
        is MobileException.BlePeerNotPinned -> "Verify the BLE safety number and pin the full peer fingerprint first."
        is MobileException.BlePeerIdentityMismatch -> "The BLE peer differs from the saved identity pin; the pin was not replaced."
        is MobileException.BlePeerNotAuthenticated -> "BLE application data is blocked until identity confirmation completes."
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
        activityStarted = true
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
        attachCoreProjectionSubscription()
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
        activityStarted = false
        projectionSubscription?.close()
        projectionSubscription = null
        stopScanning("BLE discovery stopped because the app left the foreground. No sightings are retained.")
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
        stopScanning("BLE session closed with the activity.")
        projectionSubscription?.close()
        projectionSubscription = null
        mobileProfile?.close()
        mobileProfile = null
        super.onDestroy()
    }

    private fun onPrimaryAction() {
        if (screenState.scanning) {
            stopScanning("BLE discovery stopped. Temporary token sightings were cleared.")
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
            BluetoothReadiness.ADVERTISER_UNAVAILABLE,
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

    private fun onNearbyCandidatesChanged(candidates: List<BleExp0PeerCandidate>) {
        runOnUiThread {
            if (isFinishing || isDestroyed) {
                candidates.forEach { it.responderToken.fill(0) }
                return@runOnUiThread
            }
            screenState.nearbyCandidates.forEach { it.responderToken.fill(0) }
            screenState = screenState.copy(nearbyCandidates = candidates)
        }
    }

    private fun connectNearbyCandidate(selectionId: Int) {
        val profile = mobileProfile ?: run {
            screenState = screenState.copy(bleConnectionStatus = "The protected identity profile is not ready.")
            return
        }
        val candidate = screenState.nearbyCandidates.firstOrNull { it.selectionId == selectionId } ?: run {
            screenState = screenState.copy(bleConnectionStatus = "This token sighting expired. Scan again before connecting.")
            return
        }
        centralSession?.close()
        pendingBleRouteDecision?.invoke(false)
        pendingBleRouteDecision = null
        val connection = BleExp0CentralSession(
            context = applicationContext,
            profile = profile,
            device = candidate.device,
            observedResponderToken = candidate.responderToken,
            isRoutedToPeer = { true },
            retryAt = ::bleRetryAt,
            onPeerVerificationRequired = ::requestBlePeerApproval,
            onAuthenticated = ::onBleAuthenticated,
            onCoreIngressResult = ::onBleCoreIngressResult,
            onFailure = { failure ->
                runOnUiThread {
                    screenState = screenState.copy(
                        bleConnectionStatus = failure,
                        pendingRouteConsent = false,
                    )
                }
            },
        )
        candidate.responderToken.fill(0)
        centralSession = connection
        screenState.nearbyCandidates.forEach { it.responderToken.fill(0) }
        screenState = screenState.copy(
            nearbyCandidates = emptyList(),
            bleConnectionStatus = "Connecting to the selected exp0 peer; identity is not yet authenticated.",
        )
        connection.connect()
    }

    private fun startPeripheralGattSession() {
        if (peripheralSession != null) return
        val profile = mobileProfile ?: run {
            screenState = screenState.copy(
                bleConnectionStatus = "GATT server unavailable until the protected identity profile is ready.",
            )
            return
        }
        val server = BleExp0PeripheralSession(
            context = applicationContext,
            profile = profile,
            activeResponderToken = nearbyAdvertiser::activeTokenSnapshot,
            isRoutedToPeer = { true },
            retryAt = ::bleRetryAt,
            onPeerVerificationRequired = ::requestBlePeerApproval,
            onAuthenticated = ::onBleAuthenticated,
            onCoreIngressResult = ::onBleCoreIngressResult,
            onFailure = { failure ->
                runOnUiThread {
                    screenState = screenState.copy(
                        bleConnectionStatus = failure,
                        pendingRouteConsent = false,
                    )
                }
            },
        )
        peripheralSession = server
        when (server.start()) {
            BleGattStatus.STARTED -> screenState = screenState.copy(
                bleConnectionStatus = "Experimental GATT service is listening; peers remain unauthenticated until verified.",
            )
            else -> {
                peripheralSession = null
                server.close()
            }
        }
    }

    private fun requestBlePeerApproval(
        peer: uniffi.lattice_uniffi.MobileBlePeerInfo,
        respond: (Boolean) -> Unit,
    ) {
        runOnUiThread {
            pendingBleIdentityDecision?.invoke(false)
            pendingBleIdentityDecision = respond
            screenState = screenState.copy(
                pendingIdentitySafetyNumber = peer.safetyNumber,
                pendingIdentityFingerprint = peer.fingerprint.toLowerHex(),
                bleConnectionStatus = "Compare the safety number before trusting this first-contact peer.",
            )
        }
    }

    private fun onBleAuthenticated(pump: BleExp0OutboxPump, decideRoute: (Boolean) -> Unit) {
        runOnUiThread {
            pendingBleRouteDecision?.invoke(false)
            pendingBleRouteDecision = decideRoute
            screenState = screenState.copy(
                pendingRouteConsent = true,
                bleConnectionStatus = "Peer identity authenticated. Encrypted outbox forwarding is disabled pending consent.",
            )
        }
    }

    private fun onBleCoreIngressResult(result: MobileSyncEventResult) {
        runOnUiThread {
            screenState = screenState.copy(
                lastCoreIngressResult = "${result.state.name}: ${result.eventId.toLowerHex()}",
            )
        }
    }

    private fun resolveBleIdentity(approved: Boolean) {
        val decision = pendingBleIdentityDecision
        pendingBleIdentityDecision = null
        screenState = screenState.copy(
            pendingIdentitySafetyNumber = null,
            pendingIdentityFingerprint = null,
        )
        decision?.invoke(approved)
    }

    private fun resolveBleRoute(allowed: Boolean) {
        val decision = pendingBleRouteDecision
        pendingBleRouteDecision = null
        screenState = screenState.copy(
            pendingRouteConsent = false,
            bleConnectionStatus = if (allowed) {
                "Authenticated BLE peer approved to carry opaque encrypted envelopes; peer-ingress acknowledgements are not destination delivery."
            } else {
                "Peer remains authenticated; encrypted outbox forwarding was not approved."
            },
        )
        decision?.invoke(allowed)
    }

    private fun bleRetryAt(attemptCount: UInt, nowUnixMillis: Long): Long {
        val exponent = attemptCount.coerceAtMost(10u).toInt()
        val delayMillis = (BASE_BLE_RETRY_MS shl exponent).coerceAtMost(MAX_BLE_RETRY_MS)
        return nowUnixMillis + delayMillis
    }

    private fun startScanning() {
        when (nearbyScanner.start()) {
            NearbyServiceScanner.StartResult.STARTED -> {
                if (!startAdvertising()) {
                    nearbyScanner.stop()
                    return
                }
                screenState = screenState.copy(
                    scanning = true,
                    sightings = 0,
                    message = "Scanning and advertising exp0 discovery tokens. Token matches are unverified until a GATT handshake completes.",
                )
                startPeripheralGattSession()
            }
            NearbyServiceScanner.StartResult.PERMISSION_MISSING -> {
                if (refreshReadiness() == DiscoveryPermissionState.GRANTED) {
                    setBluetoothFailure(
                        BluetoothReadiness.ACCESS_UNAVAILABLE,
                        "Android refused to start BLE discovery. Check app permissions and Bluetooth settings.",
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
                "Bluetooth is off. Turn it on to discover nearby exp0 peers.",
            )
            NearbyServiceScanner.StartResult.SCANNER_UNAVAILABLE -> setBluetoothFailure(
                BluetoothReadiness.SCANNER_UNAVAILABLE,
                "This device does not currently provide a Bluetooth LE scanner.",
            )
            NearbyServiceScanner.StartResult.FAILED -> setBluetoothFailure(
                BluetoothReadiness.ACCESS_UNAVAILABLE,
                "Android could not start BLE scanning. Check Bluetooth availability and try again.",
            )
        }
    }

    private fun startAdvertising(): Boolean = when (nearbyAdvertiser.start()) {
        NearbyBleAdvertiser.StartResult.STARTED -> true
        NearbyBleAdvertiser.StartResult.PERMISSION_MISSING -> {
            if (refreshReadiness() == DiscoveryPermissionState.GRANTED) {
                setBluetoothFailure(
                    BluetoothReadiness.ACCESS_UNAVAILABLE,
                    "Android refused to start BLE advertising. Check app permissions and Bluetooth settings.",
                )
            } else {
                screenState = screenState.copy(showPermissionRationale = true)
            }
            false
        }
        NearbyBleAdvertiser.StartResult.ADAPTER_UNAVAILABLE -> {
            setBluetoothFailure(BluetoothReadiness.ADAPTER_UNAVAILABLE, "No Bluetooth adapter is available on this device.")
            false
        }
        NearbyBleAdvertiser.StartResult.BLUETOOTH_OFF -> {
            setBluetoothFailure(BluetoothReadiness.BLUETOOTH_OFF, "Bluetooth is off. Turn it on to discover nearby exp0 peers.")
            false
        }
        NearbyBleAdvertiser.StartResult.ADVERTISER_UNAVAILABLE -> {
            setBluetoothFailure(
                BluetoothReadiness.ADVERTISER_UNAVAILABLE,
                "This device does not currently provide a Bluetooth LE advertiser.",
            )
            false
        }
        NearbyBleAdvertiser.StartResult.FAILED -> {
            setBluetoothFailure(
                BluetoothReadiness.ACCESS_UNAVAILABLE,
                "Android could not start BLE advertising. Check Bluetooth availability and try again.",
            )
            false
        }
    }

    private fun setBluetoothFailure(readiness: BluetoothReadiness, message: String) {
        stopScanning(message)
        screenState = screenState.copy(
            bluetooth = readiness,
            scanning = false,
            sightings = 0,
            message = message,
        )
    }

    private fun stopScanning(message: String) {
        if (::nearbyScanner.isInitialized) nearbyScanner.stop()
        if (::nearbyAdvertiser.isInitialized) nearbyAdvertiser.stop()
        centralSession?.close()
        centralSession = null
        peripheralSession?.close()
        peripheralSession = null
        pendingBleIdentityDecision?.invoke(false)
        pendingBleIdentityDecision = null
        pendingBleRouteDecision?.invoke(false)
        pendingBleRouteDecision = null
        screenState.nearbyCandidates.forEach { it.responderToken.fill(0) }
        screenState = screenState.copy(
            scanning = false,
            sightings = 0,
            nearbyCandidates = emptyList(),
            pendingIdentitySafetyNumber = null,
            pendingIdentityFingerprint = null,
            pendingRouteConsent = false,
            message = message,
        )
    }

    /** Updates permission and radio state without starting or resuming a scan. */
    private fun refreshReadiness(): DiscoveryPermissionState {
        val wasPreviouslyGranted = preferences.getBoolean(KEY_PREVIOUSLY_GRANTED, false)
        val permission = DiscoveryPermissionClassifier.classify(permissionObservations(), wasPreviouslyGranted)
        if (permission == DiscoveryPermissionState.GRANTED) {
            preferences.edit().putBoolean(KEY_PREVIOUSLY_GRANTED, true).apply()
        }

        if (permission != DiscoveryPermissionState.GRANTED) {
            if (screenState.scanning || centralSession != null || peripheralSession != null) {
                stopScanning("Nearby BLE stopped because a required permission is unavailable.")
            }
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
                adapter.bluetoothLeAdvertiser == null -> BluetoothReadiness.ADVERTISER_UNAVAILABLE
                else -> BluetoothReadiness.READY
            }
        } catch (_: SecurityException) {
            BluetoothReadiness.ACCESS_UNAVAILABLE
        }
        if (screenState.scanning && bluetooth != BluetoothReadiness.READY) {
            stopScanning("Nearby BLE stopped because Bluetooth is unavailable.")
        }
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

    private fun runtimePermissions(): Array<String> =
        BleDiscoveryPermissionPolicy.requiredRuntimePermissions(Build.VERSION.SDK_INT).toTypedArray()

    private fun permissionMessage(permission: DiscoveryPermissionState): String = when (permission) {
        DiscoveryPermissionState.NOT_REQUESTED -> "Bluetooth permission has not been requested. Nearby discovery has not started."
        DiscoveryPermissionState.GRANTED -> "Bluetooth access is granted."
        DiscoveryPermissionState.DENIED -> "Bluetooth access was denied. Nearby discovery is off; review the reason and try again if you choose."
        DiscoveryPermissionState.PERMANENTLY_DENIED -> "Bluetooth access is blocked. Open app settings to allow nearby discovery."
        DiscoveryPermissionState.REVOKED -> "Bluetooth access was revoked. Nearby discovery is off until access is restored."
    }

    private fun bluetoothMessage(readiness: BluetoothReadiness): String = when (readiness) {
        BluetoothReadiness.PERMISSION_REQUIRED -> "Bluetooth status is not checked until the required permissions are granted."
        BluetoothReadiness.READY -> "Bluetooth scanner and advertiser are available. Discovery has not started."
        BluetoothReadiness.BLUETOOTH_OFF -> "Bluetooth is off. Turn it on, then tap Find nearby service."
        BluetoothReadiness.ADAPTER_UNAVAILABLE -> "No Bluetooth adapter is available on this device."
        BluetoothReadiness.SCANNER_UNAVAILABLE -> "This device does not currently provide a Bluetooth LE scanner."
        BluetoothReadiness.ADVERTISER_UNAVAILABLE -> "This device does not currently provide a Bluetooth LE advertiser."
        BluetoothReadiness.ACCESS_UNAVAILABLE -> "Android did not allow access to Bluetooth status. Review permissions or Bluetooth settings."
    }

    private fun permissionRationaleText(): String = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        "Android will ask for nearby-device Bluetooth scan, connect, and advertise permissions. Lattice scans and advertises an experimental rotating discovery token; sightings are unauthenticated. A connection starts only after explicit candidate selection, and message forwarding requires identity verification and consent."
    } else {
        "Android requires location permission for Bluetooth LE scanning on this Android version. Lattice does not access or save your location. Sightings are unauthenticated; a connection starts only after explicit candidate selection, and message forwarding requires identity verification and consent."
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
        const val BASE_BLE_RETRY_MS = 5_000L
        const val MAX_BLE_RETRY_MS = 60 * 60 * 1_000L
        const val MESSAGE_NOTIFICATION_CHANNEL_ID = "authorized_messages"
        const val MESSAGE_NOTIFICATION_CHANNEL_NAME = "Authorized messages"
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
    destination: NearbyDestination,
    selectedSpaceKey: String?,
    onDestinationSelected: (NearbyDestination) -> Unit,
    onOpenLocalSpace: (String?) -> Unit,
    onPrimaryAction: () -> Unit,
    onConnectCandidate: (Int) -> Unit,
    onApproveBleIdentity: () -> Unit,
    onRejectBleIdentity: () -> Unit,
    onApproveRoute: () -> Unit,
    onRejectRoute: () -> Unit,
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
    onKeyPackageCredentialChanged: (String) -> Unit,
    onPublishSpaceKeyPackage: () -> Unit,
    onInvitationKeyPackageChanged: (String) -> Unit,
    onInvitationCredentialChanged: (String) -> Unit,
    onInvitationExpiryHoursChanged: (String) -> Unit,
    onInvitationMaxUsesChanged: (String) -> Unit,
    onCreateSpaceInvitation: () -> Unit,
    onCopyMembershipValue: (String, String) -> Unit,
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
    onMessageReactionTokenChanged: (String, String) -> Unit,
    onMessageMutationTagHexChanged: (String, String) -> Unit,
    onMessageChannelSelected: (String, String) -> Unit,
    onQueueLocalMessage: (String) -> Unit,
    onLoadMessageHistory: (String) -> Unit,
    onEditLocalMessage: (String, MobileLocalTextMessage) -> Unit,
    onReplyLocalMessage: (String, MobileLocalTextMessage) -> Unit,
    onQueueMessageMutation: (String, MobileLocalTextMessage, LocalTextMessageMutation, Boolean) -> Unit,
    onCancelMessageEdit: (String) -> Unit,
) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(modifier = Modifier.fillMaxSize().safeDrawingPadding()) {
            PrimaryTabRow(selectedTabIndex = destination.ordinal) {
                NearbyDestination.entries.forEach { page ->
                    Tab(
                        selected = destination == page,
                        onClick = { onDestinationSelected(page) },
                        text = { Text(page.label()) },
                    )
                }
            }
            Column(
                modifier = Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = 24.dp, vertical = 32.dp),
                verticalArrangement = Arrangement.Top,
            ) {
            Text("Lattice", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(8.dp))
            Text(
                destination.label(),
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.headlineLarge,
            )
            Spacer(Modifier.height(20.dp))
            if (destination == NearbyDestination.IDENTITY) {
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
            }
            if (destination == NearbyDestination.SPACES) {
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
                    val selectedSpace = selectedSpaceKey?.let { key ->
                        state.localSpaces.firstOrNull { localSpaceKey(it) == key }
                    }
                    if (selectedSpaceKey != null && selectedSpace == null) {
                        Text("The selected Space is not in the current local page.")
                        Button(onClick = { onOpenLocalSpace(null) }, modifier = Modifier.fillMaxWidth()) {
                            Text("Back to local Spaces")
                        }
                    } else if (selectedSpace == null) {
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
                            Button(
                                onClick = { onOpenLocalSpace(localSpaceKey(space)) },
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text("Open channels for local Space ${index + 1}")
                            }
                        }
                    } else {
                        val spaceKey = localSpaceKey(selectedSpace)
                        Button(onClick = { onOpenLocalSpace(null) }, modifier = Modifier.fillMaxWidth()) {
                            Text("Back to local Spaces")
                        }
                        Text(
                            "Local Space channels",
                            modifier = Modifier.semantics { heading() },
                            style = MaterialTheme.typography.titleMedium,
                        )
                        SelectionContainer {
                            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text("Space ID: ${selectedSpace.spaceId.toLowerHex()}", style = MaterialTheme.typography.bodySmall)
                                Text(
                                    "Generation group reference: ${selectedSpace.groupReference.toLowerHex()}",
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                        }
                        SpaceMessageComposer(
                            channels = selectedSpace.channels,
                            state = state.messageComposers[spaceKey] ?: LocalMessageComposerState(),
                            profileReady = state.profileStatus == "Protected local identity is available on this device.",
                            onCredentialVectorHexChanged = { onMessageCredentialHexChanged(spaceKey, it) },
                            onContentChanged = { onMessageContentChanged(spaceKey, it) },
                            onReactionTokenChanged = { onMessageReactionTokenChanged(spaceKey, it) },
                            onMutationTagHexChanged = { onMessageMutationTagHexChanged(spaceKey, it) },
                            onChannelSelected = { onMessageChannelSelected(spaceKey, it) },
                            onQueue = { onQueueLocalMessage(spaceKey) },
                            onLoadHistory = { onLoadMessageHistory(spaceKey) },
                            onEditMessage = { message -> onEditLocalMessage(spaceKey, message) },
                            onReplyMessage = { message -> onReplyLocalMessage(spaceKey, message) },
                            onQueueMutation = { message, mutation, add ->
                                onQueueMessageMutation(spaceKey, message, mutation, add)
                            },
                            onCancelEdit = { onCancelMessageEdit(spaceKey) },
                            profileIdentityHex = state.identityFingerprint.orEmpty(),
                        )
                    }
                    SpaceMembershipCard(
                        state = state.spaceMembership,
                        selectedSpace = selectedSpace,
                        profileReady = state.profileStatus == "Protected local identity is available on this device.",
                        onKeyPackageCredentialChanged = onKeyPackageCredentialChanged,
                        onPublishKeyPackage = onPublishSpaceKeyPackage,
                        onInvitationKeyPackageChanged = onInvitationKeyPackageChanged,
                        onInvitationCredentialChanged = onInvitationCredentialChanged,
                        onExpiryHoursChanged = onInvitationExpiryHoursChanged,
                        onMaxUsesChanged = onInvitationMaxUsesChanged,
                        onCreateInvitation = onCreateSpaceInvitation,
                        onCopyValue = onCopyMembershipValue,
                    )
                    Spacer(Modifier.height(20.dp))
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
            }

            if (destination == NearbyDestination.DIAGNOSTICS) {
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
                    Text(
                        "Android Keystore wrapping key: ${state.keystoreProtectionLevel?.diagnosticLabel ?: "not checked"}",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        "Hardware backing describes the wrapping key only; this status does not identify StrongBox or claim the identity signing keys are hardware-resident.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
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
                            if (state.sightings >= 1024) "Unverified token sightings: 1,024+"
                            else "Unverified token sightings: ${state.sightings}",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                    Text(
                        state.bleConnectionStatus,
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    state.lastCoreIngressResult?.let { result ->
                        Text(
                            "Last Core ingress: $result",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                    state.nearbyCandidates.forEach { candidate ->
                        Text(
                            "Nearby peer ${candidate.selectionId}: rotating token match only; identity remains unverified.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Button(
                            onClick = { onConnectCandidate(candidate.selectionId) },
                            enabled = state.profileStatus == "Protected local identity is available on this device.",
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Connect and verify peer ${candidate.selectionId}")
                        }
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
                        "This opt-in foreground service scans and advertises experimental rotating BLE discovery tokens while the app is backgrounded. Signals remain unverified; there is no GATT connection or message exchange.",
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
                "A selected peer is not trusted until its Noise identity proof is verified and pinned. Encrypted outbox forwarding requires separate consent. LBFA records authenticated peer acceptance of a complete envelope into bounded ingress, not destination delivery.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            }
        }
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
    state.pendingIdentitySafetyNumber?.let { safetyNumber ->
        AlertDialog(
            onDismissRequest = onRejectBleIdentity,
            title = { Text("Verify first-contact BLE peer") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Compare this safety number with the peer through a separate trusted channel before approving the identity.")
                    SelectionContainer {
                        Column {
                            Text("Safety number: $safetyNumber")
                            Text("Fingerprint: ${state.pendingIdentityFingerprint.orEmpty()}")
                        }
                    }
                    Text("Approval pins this exact Lattice identity. It does not authorize forwarding messages.")
                }
            },
            confirmButton = {
                TextButton(onClick = onApproveBleIdentity) { Text("I verified this identity") }
            },
            dismissButton = {
                TextButton(onClick = onRejectBleIdentity) { Text("Reject") }
            },
        )
    }
    if (state.pendingRouteConsent) {
        AlertDialog(
            onDismissRequest = onRejectRoute,
            title = { Text("Allow encrypted event forwarding?") },
            text = {
                Text(
                    "This authenticated peer may carry opaque encrypted outbox envelopes over this BLE session. It does not prove shared Space membership or recipient delivery; the receiving Core must still validate each event.",
                )
            },
            confirmButton = {
                TextButton(onClick = onApproveRoute) { Text("Allow forwarding") }
            },
            dismissButton = {
                TextButton(onClick = onRejectRoute) { Text("Keep forwarding off") }
            },
        )
    }
}

private fun NearbyDestination.label(): String = when (this) {
    NearbyDestination.IDENTITY -> "Identity"
    NearbyDestination.SPACES -> "Spaces"
    NearbyDestination.DIAGNOSTICS -> "Diagnostics"
}

private fun DiscoveryPermissionState.label(): String = when (this) {
    DiscoveryPermissionState.NOT_REQUESTED -> "Not requested"
    DiscoveryPermissionState.GRANTED -> "Granted"
    DiscoveryPermissionState.DENIED -> "Denied"
    DiscoveryPermissionState.PERMANENTLY_DENIED -> "Blocked in Android permission settings"
    DiscoveryPermissionState.REVOKED -> "Revoked"
}

private fun BluetoothReadiness.label(): String = when (this) {
    BluetoothReadiness.PERMISSION_REQUIRED -> "Not checked (permissions required)"
    BluetoothReadiness.READY -> "On; scanner and advertiser available"
    BluetoothReadiness.BLUETOOTH_OFF -> "Off"
    BluetoothReadiness.ADAPTER_UNAVAILABLE -> "No adapter"
    BluetoothReadiness.SCANNER_UNAVAILABLE -> "No BLE scanner"
    BluetoothReadiness.ADVERTISER_UNAVAILABLE -> "No BLE advertiser"
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

package com.astraive.lattice

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.lattice_uniffi.MobileException

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
    val message: String = "Bluetooth permission has not been requested. Nearby discovery has not started.",
    val showPermissionRationale: Boolean = false,
    val profileStatus: String = "Preparing protected device profile.",
    val identityFingerprint: String? = null,
)

class MainActivity : ComponentActivity() {
    private val preferences by lazy { getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE) }
    private var screenState by mutableStateOf(NearbyScreenState())
    private var mobileProfile: AndroidMobileProfile? = null
    private lateinit var nearbyScanner: NearbyServiceScanner
    private var receiverRegistered = false
    private var permissionHistoryBeforePrompt = false

    private val permissionRequest = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions(),
    ) { result ->
        handlePermissionResult(result)
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
                    onDismissRationale = { screenState = screenState.copy(showPermissionRationale = false) },
                    onContinuePermission = ::continuePermissionFlow,
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
                val identity = try {
                    profile.identityInfo()
                } catch (error: Exception) {
                    profile.close()
                    throw error
                }
                mobileProfile = profile
                screenState = screenState.copy(
                    profileStatus = "Protected device identity is ready.",
                    identityFingerprint = identity.fingerprint.toLowerHex(),
                )
            } catch (error: CancellationException) {
                throw error
            } catch (error: MobileException) {
                if (!isFinishing && !isDestroyed) {
                    screenState = screenState.copy(
                        profileStatus = when (error) {
                            is MobileException.InvalidProfileId -> "The local profile identifier is invalid."
                            is MobileException.KeyProtectionFailed -> "Android Keystore access failed; no software-key fallback was used."
                            is MobileException.ProfileOpenFailed -> "The protected local profile could not be opened."
                            is MobileException.ProfileUnavailable -> "The protected local profile is unavailable."
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

    private fun ByteArray.toLowerHex(): String {
        val digits = "0123456789abcdef"
        return buildString(size * 2) {
            for (byte in this@toLowerHex) {
                val value = byte.toInt() and 0xff
                append(digits[value ushr 4])
                append(digits[value and 0x0f])
            }
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
        refreshReadiness()
    }

    override fun onResume() {
        super.onResume()
        refreshReadiness()
    }

    override fun onStop() {
        stopScanning("Nearby scan stopped because the app left the foreground. No sightings are retained.")
        if (receiverRegistered) {
            unregisterReceiver(bluetoothReceiver)
            receiverRegistered = false
        }
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

@Composable
private fun NearbyReadinessScreen(
    state: NearbyScreenState,
    permissionRationale: String,
    onPrimaryAction: () -> Unit,
    onDismissRationale: () -> Unit,
    onContinuePermission: () -> Unit,
) {
    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 24.dp, vertical = 32.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.Center,
        ) {
            Text("Lattice", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
            Spacer(Modifier.height(8.dp))
            Text("Nearby", style = MaterialTheme.typography.headlineLarge)
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
                    Text("Device identity", style = MaterialTheme.typography.titleMedium)
                    Text(state.profileStatus, style = MaterialTheme.typography.bodyMedium)
                    state.identityFingerprint?.let { fingerprint ->
                        Text(
                            "Fingerprint: $fingerprint",
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            }
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
                    Text("Readiness", style = MaterialTheme.typography.titleMedium)
                    Text("Bluetooth permission: ${state.permission.label()}", style = MaterialTheme.typography.bodyMedium)
                    Text("Bluetooth: ${state.bluetooth.label()}", style = MaterialTheme.typography.bodyMedium)
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
                }
            }
            Spacer(Modifier.height(20.dp))
            Text(
                "A found service is an unverified sighting, not an authenticated Lattice peer. No device is connected and no data is exchanged. Pairing, GATT, and messaging are not implemented.",
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

private fun primaryLabel(state: NearbyScreenState): String = when {
    state.permission != DiscoveryPermissionState.GRANTED -> "Find nearby service"
    state.bluetooth == BluetoothReadiness.BLUETOOTH_OFF -> "Open Bluetooth settings"
    state.bluetooth == BluetoothReadiness.READY -> "Find nearby service"
    else -> "Check availability"
}

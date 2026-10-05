package com.astraive.lattice.ui

import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/** Presentation-safe readiness values; Android capability/domain types stay in the application. */
data class LatticeNearbyPageState(
    val keystoreStatus: String,
    val permissionStatus: String,
    val bluetoothStatus: String,
    val wifiAwareStatus: String,
    val wifiDirectStatus: String,
    val lanStatus: String,
    val message: String,
    val scanning: Boolean,
    val sightings: Int,
    val bleConnectionStatus: String,
    val lastCoreIngressResult: String?,
    val candidateIds: List<Int>,
    val profileReady: Boolean,
    val persistentStatus: String,
    val persistentEnabled: Boolean,
    val primaryActionLabel: String,
)

@Composable
fun LatticeNearbyPage(
    state: LatticeNearbyPageState,
    onConnectCandidate: (Int) -> Unit,
    onPrimaryAction: () -> Unit,
    onPersistentNearbyAction: () -> Unit,
    modifier: Modifier = Modifier,
) {
    LatticeDestinationPage("Nearby", modifier) {
        LatticeSurface {
            Text("Readiness", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleMedium)
            Text("Android Keystore wrapping key: ${state.keystoreStatus}", style = MaterialTheme.typography.bodyMedium)
            Text("Hardware backing describes the wrapping key only; this status does not identify StrongBox or claim the identity signing keys are hardware-resident.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("Bluetooth permission: ${state.permissionStatus}", style = MaterialTheme.typography.bodyMedium)
            Text("Bluetooth: ${state.bluetoothStatus}", style = MaterialTheme.typography.bodyMedium)
            Text("Wi-Fi upgrade capability (local device only)", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleSmall)
            Text("Wi-Fi Aware: ${state.wifiAwareStatus}", style = MaterialTheme.typography.bodyMedium)
            Text("Wi-Fi Direct: ${state.wifiDirectStatus}", style = MaterialTheme.typography.bodyMedium)
            Text("LAN interface: ${state.lanStatus}", style = MaterialTheme.typography.bodyMedium)
            Text("A local capability is not a reachable or authenticated peer path. No Wi-Fi data path is active; Bluetooth discovery remains the baseline only.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(state.message, style = MaterialTheme.typography.bodyLarge)
            if (state.scanning) Text(if (state.sightings >= 1024) "Unverified token sightings: 1,024+" else "Unverified token sightings: ${state.sightings}", style = MaterialTheme.typography.bodyMedium)
            Text(state.bleConnectionStatus, style = MaterialTheme.typography.bodyMedium)
            state.lastCoreIngressResult?.let { Text("Last Core ingress: $it", style = MaterialTheme.typography.bodySmall) }
            state.candidateIds.forEach { id ->
                Text("Nearby peer $id: rotating token match only; identity remains unverified.", style = MaterialTheme.typography.bodySmall)
                LatticeActionButton("Connect and verify peer $id", { onConnectCandidate(id) }, enabled = state.profileReady)
            }
            LatticeActionButton(if (state.scanning) "Stop nearby scan" else state.primaryActionLabel, onPrimaryAction, tone = LatticeActionTone.PRIMARY)
            Text("Persistent nearby mode", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleSmall)
            Text(state.persistentStatus, style = MaterialTheme.typography.bodyMedium)
            Text("This opt-in foreground service scans and advertises experimental rotating BLE discovery tokens while the app is backgrounded. Signals remain unverified; there is no GATT connection or message exchange.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            LatticeActionButton(if (state.persistentEnabled) "Stop persistent nearby mode" else "Start persistent nearby mode", onPersistentNearbyAction)
        }
        Spacer(Modifier.height(20.dp))
        Text("A selected peer is not trusted until its Noise identity proof is verified and pinned. Encrypted outbox forwarding requires separate consent. LBFA records authenticated peer acceptance of a complete envelope into bounded ingress, not destination delivery.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

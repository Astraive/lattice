package com.astraive.lattice.identity

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

internal data class IdentityPinUiState(
    val peerBundleHexInput: String = "",
    val peerFingerprintHexInput: String = "",
    val identityPinStatus: String = "No peer identity is pinned in this profile.",
    val pinnedPeerFingerprint: String? = null,
    val pinnedPeerBundleHex: String? = null,
    val pinningIdentity: Boolean = false,
    val lookingUpPinnedIdentity: Boolean = false,
)

@Composable
internal fun IdentityPinCard(
    state: IdentityPinUiState,
    profileReady: Boolean,
    onPeerBundleHexChanged: (String) -> Unit,
    onPeerFingerprintHexChanged: (String) -> Unit,
    onPinPeerIdentity: () -> Unit,
    onLookupPinnedIdentity: () -> Unit,
    onCopyPinnedBundle: (String) -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        tonalElevation = 2.dp,
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Pin a peer identity", style = MaterialTheme.typography.titleMedium)
            Text(
                "Compare the peer's full fingerprint out of band before saving these exact public bytes. A pin does not connect to that peer or add it to a Space.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.peerBundleHexInput,
                onValueChange = onPeerBundleHexChanged,
                label = { Text("65-byte public bundle (hex)") },
                enabled = profileReady && !state.pinningIdentity && !state.lookingUpPinnedIdentity,
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = state.peerFingerprintHexInput,
                onValueChange = onPeerFingerprintHexChanged,
                label = { Text("Full 32-byte fingerprint (hex)") },
                enabled = profileReady && !state.pinningIdentity && !state.lookingUpPinnedIdentity,
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = onLookupPinnedIdentity,
                enabled = !state.lookingUpPinnedIdentity && !state.pinningIdentity && profileReady,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (state.lookingUpPinnedIdentity) "Checking saved pin…" else "Look up saved pin")
            }
            Button(
                onClick = onPinPeerIdentity,
                enabled = !state.pinningIdentity && !state.lookingUpPinnedIdentity && profileReady,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (state.pinningIdentity) "Saving identity pin…" else "Pin exact identity")
            }
            Text(state.identityPinStatus, style = MaterialTheme.typography.bodySmall)
            state.pinnedPeerFingerprint?.let { fingerprint ->
                SelectionContainer {
                    Text(
                        "Saved full fingerprint: $fingerprint",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            }
            state.pinnedPeerBundleHex?.let { bundle ->
                Text("Exact saved public bundle", style = MaterialTheme.typography.bodySmall)
                SelectionContainer {
                    Text(bundle, style = MaterialTheme.typography.bodySmall)
                }
                Button(
                    onClick = { onCopyPinnedBundle(bundle) },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Copy saved public bundle")
                }
            }
        }
    }
}

internal fun decodeIdentityHex(value: String, expectedBytes: Int): ByteArray? {
    if (expectedBytes < 0 || value.length != expectedBytes * 2) return null
    val bytes = ByteArray(expectedBytes)
    for (index in bytes.indices) {
        val high = value[index * 2].hexNibble() ?: return null
        val low = value[index * 2 + 1].hexNibble() ?: return null
        bytes[index] = ((high shl 4) or low).toByte()
    }
    return bytes
}

private fun Char.hexNibble(): Int? = when (this) {
    in '0'..'9' -> code - '0'.code
    in 'a'..'f' -> code - 'a'.code + 10
    in 'A'..'F' -> code - 'A'.code + 10
    else -> null
}

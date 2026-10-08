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
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.astraive.lattice.ui.LatticeSurface
import com.astraive.lattice.ui.LatticeActionButton
import com.astraive.lattice.ui.LatticeFormField
import com.astraive.lattice.ui.LatticeStatusNotice
import com.astraive.lattice.ui.LatticeNoticeKind

internal data class IdentityPinUiState(
    val peerBundleHexInput: String = "",
    val peerFingerprintHexInput: String = "",
    val identityPinStatus: String = "No peer identity is pinned in this profile.",
    val pinnedPeerFingerprint: String? = null,
    val pinnedPeerBundleHex: String? = null,
    val pinningIdentity: Boolean = false,
    val lookingUpPinnedIdentity: Boolean = false,
    val unpinningIdentity: Boolean = false,
)

@Composable
internal fun IdentityPinCard(
    state: IdentityPinUiState,
    profileReady: Boolean,
    onPeerBundleHexChanged: (String) -> Unit,
    onPeerFingerprintHexChanged: (String) -> Unit,
    onPinPeerIdentity: () -> Unit,
    onLookupPinnedIdentity: () -> Unit,
    onUnpinPeerIdentity: () -> Unit,
    onCopyPinnedBundle: (String) -> Unit,
) {
    LatticeSurface {
        Text("Pin a peer identity", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleMedium)
        Text(
            "Compare the peer's full fingerprint out of band before saving these exact public bytes. A pin does not connect to that peer or add it to a Space.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        LatticeFormField(
            state.peerBundleHexInput, onPeerBundleHexChanged, "65-byte public bundle (hex)",
            error = if (state.peerBundleHexInput.isNotEmpty() && state.peerBundleHexInput.length != 130) "Enter exactly 130 hexadecimal characters." else null,
            enabled = profileReady && !state.pinningIdentity && !state.lookingUpPinnedIdentity && !state.unpinningIdentity,
        )
        LatticeFormField(
            state.peerFingerprintHexInput, onPeerFingerprintHexChanged, "Full 32-byte fingerprint (hex)",
            error = if (state.peerFingerprintHexInput.isNotEmpty() && state.peerFingerprintHexInput.length != 64) "Enter exactly 64 hexadecimal characters." else null,
            enabled = profileReady && !state.pinningIdentity && !state.lookingUpPinnedIdentity && !state.unpinningIdentity,
        )
        LatticeActionButton(
            if (state.lookingUpPinnedIdentity) "Checking saved pin" else "Look up saved pin",
            onLookupPinnedIdentity,
            enabled = profileReady && !state.lookingUpPinnedIdentity && !state.pinningIdentity && !state.unpinningIdentity,
            busy = state.lookingUpPinnedIdentity,
        )
        LatticeActionButton(
            "Pin exact identity",
            onPinPeerIdentity,
            enabled = profileReady && !state.pinningIdentity && !state.lookingUpPinnedIdentity && !state.unpinningIdentity,
            busy = state.pinningIdentity,
            tone = com.astraive.lattice.ui.LatticeActionTone.PRIMARY,
        )
        state.pinnedPeerFingerprint?.let {
            LatticeActionButton("Remove local pin", onUnpinPeerIdentity, enabled = !state.pinningIdentity && !state.lookingUpPinnedIdentity && !state.unpinningIdentity && profileReady, busy = state.unpinningIdentity, tone = com.astraive.lattice.ui.LatticeActionTone.DANGER)
            Text("Removes trust only from this device. Remote identity and Space membership are unchanged.", style = MaterialTheme.typography.bodySmall)
        }
        LatticeStatusNotice(com.astraive.lattice.ui.LatticeNoticeKind.INFO, message = state.identityPinStatus)
        state.pinnedPeerFingerprint?.let { fingerprint ->
            SelectionContainer { Text("Saved full fingerprint: $fingerprint", style = MaterialTheme.typography.bodySmall) }
        }
        state.pinnedPeerBundleHex?.let { bundle ->
            Text("Exact saved public bundle", style = MaterialTheme.typography.bodySmall)
            SelectionContainer { Text(bundle, style = MaterialTheme.typography.bodySmall) }
            LatticeActionButton("Copy saved public bundle", onClick = { onCopyPinnedBundle(bundle) })
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

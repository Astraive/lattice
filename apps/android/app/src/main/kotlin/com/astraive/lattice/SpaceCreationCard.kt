package com.astraive.lattice

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import uniffi.lattice_uniffi.MobileCreatedSpace

internal data class SpaceCreationUiState(
    val credentialVectorHex: String = "",
    val channelName: String = "general",
    val creating: Boolean = false,
    val status: String = "A trusted device credential is required.",
    val created: MobileCreatedSpace? = null,
)

@Composable
internal fun SpaceCreationCard(
    state: SpaceCreationUiState,
    profileReady: Boolean,
    onCredentialVectorHexChanged: (String) -> Unit,
    onChannelNameChanged: (String) -> Unit,
    onCreateLocalSpace: () -> Unit,
) {
    val credentialIsValid = isCredentialVectorHex(state.credentialVectorHex)
    val channelNameIsValid = isValidInitialChannelName(state.channelName)
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        tonalElevation = 2.dp,
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Create a local Space", style = MaterialTheme.typography.titleMedium)
            Text(
                "Paste the exact leaf-first RFC 9420 TLS X.509 credential vector as hexadecimal. The OS trust chain and local signing identity are checked before local MLS state is committed. This does not join another member or contact a network.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.credentialVectorHex,
                onValueChange = onCredentialVectorHexChanged,
                label = { Text("Trusted X.509 credential vector (hex)") },
                supportingText = { Text("Up to 16 KiB decoded. Do not paste a PEM-encoded certificate.") },
                enabled = profileReady && !state.creating,
                isError = state.credentialVectorHex.isNotEmpty() && !credentialIsValid,
                minLines = 4,
                maxLines = 8,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Ascii,
                ),
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = state.channelName,
                onValueChange = onChannelNameChanged,
                label = { Text("Initial text channel name") },
                supportingText = { Text("Nonblank, up to 128 UTF-8 bytes; NUL is not allowed.") },
                enabled = profileReady && !state.creating,
                isError = !channelNameIsValid,
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = onCreateLocalSpace,
                enabled = profileReady && !state.creating && credentialIsValid && channelNameIsValid,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (state.creating) "Creating local Space…" else "Create local Space")
            }
            Text(state.status, style = MaterialTheme.typography.bodySmall)
            state.created?.let { created ->
                SelectionContainer {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Local Genesis event committed. Remote membership is not established.")
                        Text("Space ID: ${created.spaceId.toLowerHex()}")
                        Text("MLS group reference: ${created.groupReference.toLowerHex()}")
                        Text("Genesis event ID: ${created.genesisEventId.toLowerHex()}")
                    }
                }
            }
        }
    }
}

internal fun isCredentialVectorHex(value: String): Boolean =
    value.isNotEmpty() && value.length <= MAX_CREDENTIAL_HEX_LENGTH &&
        value.length % 2 == 0 && value.all { it.isHexDigit() }

private fun Char.isHexDigit(): Boolean =
    this in '0'..'9' || this in 'a'..'f' || this in 'A'..'F'

internal const val MAX_CREDENTIAL_HEX_LENGTH = 32_768

internal const val MAX_INITIAL_CHANNEL_NAME_BYTES = 128

internal fun isValidInitialChannelName(value: String): Boolean =
    value.isNotBlank() && value.length <= MAX_INITIAL_CHANNEL_NAME_BYTES &&
        '\u0000' !in value && value.toByteArray(Charsets.UTF_8).size <= MAX_INITIAL_CHANNEL_NAME_BYTES

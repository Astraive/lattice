package com.astraive.lattice

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import uniffi.lattice_uniffi.MobileCreatedSpace
import uniffi.lattice_uniffi.MobileSpaceSummary


internal data class LocalSpaceRecoveryUiState(
    val selectedSpaceKey: String? = null,
    val credentialVectorHex: String = "",
    val recovering: Boolean = false,
    val status: String = "Select a locally stored generation to recover.",
    val recovered: MobileCreatedSpace? = null,
)

internal fun recoverySpaceKey(space: MobileSpaceSummary): String =
    "${space.spaceId.toLowerHex()}:${space.groupReference.toLowerHex()}"

@Composable
internal fun LocalSpaceRecoveryCard(
    spaces: List<MobileSpaceSummary>,
    state: LocalSpaceRecoveryUiState,
    profileReady: Boolean,
    onSpaceSelected: (String) -> Unit,
    onCredentialVectorHexChanged: (String) -> Unit,
    onRecover: () -> Unit,
) {
    val selectedSpace = spaces.firstOrNull { recoverySpaceKey(it) == state.selectedSpaceKey }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        tonalElevation = 2.dp,
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Recover a local Space generation", style = MaterialTheme.typography.titleMedium)
            Text(
                "Recovery requires a generation already stored locally and its trusted X.509 credential. It creates a new local one-member recovery root; it does not import a Space, restore membership, contact a relay, or synchronize.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            if (spaces.isEmpty()) {
                Text("No locally stored generation is available to recover.")
            } else {
                spaces.forEachIndexed { index, space ->
                    val key = recoverySpaceKey(space)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = state.selectedSpaceKey == key,
                            onClick = { onSpaceSelected(key) },
                            enabled = !state.recovering,
                        )
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text("Local generation ${index + 1}", style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "Space ${space.spaceId.toLowerHex()} · group ${space.groupReference.toLowerHex()}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                    }
                }
                OutlinedTextField(
                    value = state.credentialVectorHex,
                    onValueChange = onCredentialVectorHexChanged,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Trusted X.509 credential vector (hex)") },
                    supportingText = { Text("Up to 16 KiB decoded. Do not paste a PEM-encoded certificate.") },
                    enabled = profileReady && !state.recovering,
                    keyboardOptions = KeyboardOptions(
                        capitalization = KeyboardCapitalization.None,
                        autoCorrectEnabled = false,
                        keyboardType = KeyboardType.Ascii,
                    ),
                    minLines = 4,
                    maxLines = 8,
                )
                Button(
                    onClick = onRecover,
                    enabled = profileReady && selectedSpace != null &&
                        isCredentialVectorHex(state.credentialVectorHex) && !state.recovering,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (state.recovering) "Recovering locally…" else "Create local recovery generation")
                }
            }
            Text(state.status, style = MaterialTheme.typography.bodySmall)
            state.recovered?.let { recovered ->
                SelectionContainer {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("A new local recovery generation was committed. No network was contacted.")
                        Text("Space ID: ${recovered.spaceId.toLowerHex()}")
                        Text("New group reference: ${recovered.groupReference.toLowerHex()}")
                        Text("Recovery Genesis event ID: ${recovered.genesisEventId.toLowerHex()}")
                    }
                }
            }
        }
    }
}

internal const val MAX_SPACE_WELCOME_BOOTSTRAP_BYTES = 1_048_576
internal const val MAX_SPACE_WELCOME_BOOTSTRAP_BASE64_CHARS = 1_398_104

internal data class SpaceWelcomeJoinUiState(
    val bootstrapPackageBase64: String = "",
    val inviterFingerprintHex: String = "",
    val credentialVectorHex: String = "",
    val joining: Boolean = false,
    val status: String = "A pinned inviter's signed Welcome bootstrap is required.",
    val joined: MobileCreatedSpace? = null,
)

internal fun isSpaceWelcomeBootstrapBase64Input(value: String): Boolean {
    if (value.isEmpty() ||
        value.length > MAX_SPACE_WELCOME_BOOTSTRAP_BASE64_CHARS ||
        value.length % 4 != 0
    ) {
        return false
    }
    var padding = 0
    for (character in value) {
        when {
            character in 'A'..'Z' || character in 'a'..'z' ||
                character in '0'..'9' || character == '+' || character == '/' -> {
                if (padding != 0) return false
            }
            character == '=' -> padding++
            else -> return false
        }
    }
    return padding <= 2 && (value.length / 4) * 3 - padding <= MAX_SPACE_WELCOME_BOOTSTRAP_BYTES
}

@Composable
internal fun SpaceWelcomeJoinCard(
    state: SpaceWelcomeJoinUiState,
    profileReady: Boolean,
    onBootstrapPackageChanged: (String) -> Unit,
    onInviterFingerprintChanged: (String) -> Unit,
    onCredentialVectorChanged: (String) -> Unit,
    onJoin: () -> Unit,
) {
    val packageIsBounded = isSpaceWelcomeBootstrapBase64Input(state.bootstrapPackageBase64)
    val inviterFingerprintIsValid =
        state.inviterFingerprintHex.length == 64 &&
            state.inviterFingerprintHex.all { it.digitToIntOrNull(16) != null }
    val credentialIsValid = isCredentialVectorHex(state.credentialVectorHex)
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        tonalElevation = 2.dp,
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text("Join from a pinned Welcome", style = MaterialTheme.typography.titleMedium)
            Text(
                "Import a signed Welcome package from a peer whose complete identity bundle is already pinned in this profile. The package carries a signed policy checkpoint; it is not independent MLS history replay or a delivery confirmation.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = state.bootstrapPackageBase64,
                onValueChange = onBootstrapPackageChanged,
                label = { Text("Welcome bootstrap package (base64)") },
                supportingText = { Text("Maximum 1 MiB decoded. Paste unwrapped standard Base64.") },
                enabled = profileReady && !state.joining,
                isError = state.bootstrapPackageBase64.isNotEmpty() && !packageIsBounded,
                minLines = 4,
                maxLines = 8,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = state.inviterFingerprintHex,
                onValueChange = onInviterFingerprintChanged,
                label = { Text("Pinned inviter's full fingerprint (hex)") },
                enabled = profileReady && !state.joining,
                isError = state.inviterFingerprintHex.isNotEmpty() && !inviterFingerprintIsValid,
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = state.credentialVectorHex,
                onValueChange = onCredentialVectorChanged,
                label = { Text("Trusted X.509 credential vector (hex)") },
                supportingText = { Text("Up to 16 KiB decoded. Do not paste a PEM-encoded certificate.") },
                enabled = profileReady && !state.joining,
                isError = state.credentialVectorHex.isNotEmpty() && !credentialIsValid,
                minLines = 4,
                maxLines = 8,
                modifier = Modifier.fillMaxWidth(),
            )
            Button(
                onClick = onJoin,
                enabled = profileReady && !state.joining && packageIsBounded &&
                    inviterFingerprintIsValid && credentialIsValid,
                modifier = Modifier.fillMaxWidth(),
            ) {
                Text(if (state.joining) "Validating and joining…" else "Import verified Welcome")
            }
            Text(state.status, style = MaterialTheme.typography.bodySmall)
            state.joined?.let { joined ->
                SelectionContainer {
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("The signed checkpoint and Welcome generation were imported locally.")
                        Text("Space ID: ${joined.spaceId.toLowerHex()}")
                        Text("Group reference: ${joined.groupReference.toLowerHex()}")
                        Text("Root event ID: ${joined.genesisEventId.toLowerHex()}")
                    }
                }
            }
        }
    }
}
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

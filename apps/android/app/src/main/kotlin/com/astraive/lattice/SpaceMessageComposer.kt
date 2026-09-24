package com.astraive.lattice

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import uniffi.lattice_uniffi.MobileChannelSummary
import uniffi.lattice_uniffi.MobileChannelType
import uniffi.lattice_uniffi.MobileLocalTextMessage

internal data class LocalMessageComposerState(
    val credentialVectorHex: String = "",
    val content: String = "",
    val selectedChannelIdHex: String? = null,
    val submitting: Boolean = false,
    val loadingHistory: Boolean = false,
    val history: List<MobileLocalTextMessage> = emptyList(),
    val historyChannelIdHex: String? = null,
    val historyStatus: String? = null,
    val status: String = "Enter the trusted X.509 credential vector to queue a local message.",
    val eventIdHex: String? = null,
)

@Composable
internal fun SpaceMessageComposer(
    channels: List<MobileChannelSummary>,
    state: LocalMessageComposerState,
    profileReady: Boolean,
    onCredentialVectorHexChanged: (String) -> Unit,
    onContentChanged: (String) -> Unit,
    onChannelSelected: (String) -> Unit,
    onQueue: () -> Unit,
    onLoadHistory: () -> Unit,
) {
    val availableChannels = channels.filter {
        !it.archived && (it.channelType == MobileChannelType.TEXT || it.channelType == MobileChannelType.ANNOUNCEMENT)
    }
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.medium,
        tonalElevation = 1.dp,
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Queue a local text message", style = MaterialTheme.typography.titleSmall)
            Text(
                "The recent outgoing history is local-only and bounded. Incoming messages, later policy changes, and network delivery are not shown.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text("Channels from local Genesis", style = MaterialTheme.typography.labelMedium)
            channels.forEach { channel ->
                val channelType = when (channel.channelType) {
                    MobileChannelType.TEXT -> "Text"
                    MobileChannelType.ANNOUNCEMENT -> "Announcement"
                    MobileChannelType.VOICE -> "Voice"
                }
                Text(
                    "${channel.name} · ${channel.id.toLowerHex()} · $channelType${if (channel.archived) " · archived" else ""}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (availableChannels.isEmpty()) {
                Text("No active text or announcement channels are available.", style = MaterialTheme.typography.bodySmall)
            } else {
                Text("Choose a channel", style = MaterialTheme.typography.labelMedium)
                availableChannels.forEach { channel ->
                    val idHex = channel.id.toLowerHex()
                    androidx.compose.foundation.layout.Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = state.selectedChannelIdHex == idHex ||
                                (state.selectedChannelIdHex == null && channel == availableChannels.first()),
                            onClick = { onChannelSelected(idHex) },
                            enabled = !state.submitting,
                        )
                        Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(channel.name, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "${if (channel.channelType == MobileChannelType.TEXT) "Text" else "Announcement"} · $idHex",
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
                    supportingText = { Text("Even-length hexadecimal, at most 16 KiB decoded") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, capitalization = KeyboardCapitalization.None),
                    enabled = !state.submitting,
                    singleLine = false,
                )
                OutlinedTextField(
                    value = state.content,
                    onValueChange = onContentChanged,
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Message") },
                    supportingText = { Text("UTF-8 message, at most 16 KiB") },
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                    enabled = !state.submitting,
                    minLines = 3,
                )
                Button(
                    onClick = onQueue,
                    enabled = profileReady && !state.submitting && availableChannels.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (state.submitting) "Queueing locally…" else "Queue locally")
                }
                Button(
                    onClick = onLoadHistory,
                    enabled = profileReady && !state.loadingHistory,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (state.loadingHistory) "Loading history…" else "Load recent history")
                }
                state.historyStatus?.let { status ->
                    Text(status, style = MaterialTheme.typography.bodySmall)
                }
                if (state.historyChannelIdHex == (state.selectedChannelIdHex ?: availableChannels.first().id.toLowerHex())) {
                    state.history.forEach { message ->
                        Surface(
                            modifier = Modifier.fillMaxWidth(),
                            shape = MaterialTheme.shapes.small,
                            tonalElevation = 2.dp,
                        ) {
                            Column(
                                modifier = Modifier.padding(12.dp),
                                verticalArrangement = Arrangement.spacedBy(4.dp),
                            ) {
                                Text(message.content, style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "${message.outboxState ?: "retained locally"} · ${message.eventId.toLowerHex()}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }
            Text(state.status, style = MaterialTheme.typography.bodySmall)
            state.eventIdHex?.let { eventId ->
                Text("Event ID (queued locally)", style = MaterialTheme.typography.labelMedium)
                Text(eventId, style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

internal const val MAX_LOCAL_MESSAGE_BYTES = 16 * 1024
internal const val MAX_LOCAL_MESSAGE_CREDENTIAL_BYTES = 16 * 1024
internal const val MAX_LOCAL_MESSAGE_CREDENTIAL_HEX_LENGTH = MAX_LOCAL_MESSAGE_CREDENTIAL_BYTES * 2

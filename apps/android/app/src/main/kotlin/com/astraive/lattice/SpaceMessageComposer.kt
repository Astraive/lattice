package com.astraive.lattice

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import com.astraive.lattice.ui.LatticeActionButton as Button
import androidx.compose.material3.MaterialTheme
import com.astraive.lattice.ui.LatticeFormField as OutlinedTextField
import androidx.compose.material3.RadioButton
import com.astraive.lattice.ui.LatticeSurface as Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import uniffi.lattice_uniffi.MobileChannelSummary
import uniffi.lattice_uniffi.MobileChannelType
import uniffi.lattice_uniffi.MobileLocalTextMessage
import com.astraive.lattice.ui.LatticeSurface
import com.astraive.lattice.ui.LatticeActionButton
import com.astraive.lattice.ui.LatticeActionTone
import com.astraive.lattice.ui.LatticeStatusNotice
import com.astraive.lattice.ui.LatticeNoticeKind
import com.astraive.lattice.ui.LatticeFormField

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
    val editTargetMessageIdHex: String? = null,
    val replyTargetMessageIdHex: String? = null,
    val reactionToken: String = "👍",
    val mutationTagHex: String = "",
)

internal enum class LocalTextMessageMutation { TOMBSTONE, REACTION, PIN }


@Composable
internal fun SpaceMessageComposer(
    channels: List<MobileChannelSummary>,
    state: LocalMessageComposerState,
    profileReady: Boolean,
    onCredentialVectorHexChanged: (String) -> Unit,
    onContentChanged: (String) -> Unit,
    onReactionTokenChanged: (String) -> Unit,
    onMutationTagHexChanged: (String) -> Unit,
    onChannelSelected: (String) -> Unit,
    onQueue: () -> Unit,
    onLoadHistory: () -> Unit,
    onEditMessage: (MobileLocalTextMessage) -> Unit,
    onReplyMessage: (MobileLocalTextMessage) -> Unit,
    onQueueMutation: (MobileLocalTextMessage, LocalTextMessageMutation, Boolean) -> Unit,
    onCancelEdit: () -> Unit,
    profileIdentityHex: String,
) {
    val availableChannels = channels.filter {
        !it.archived && (it.channelType == MobileChannelType.TEXT || it.channelType == MobileChannelType.ANNOUNCEMENT)
    }
    val reactionTokenIsValid = state.reactionToken.toByteArray().size in 1..64
    val mutationTagIsValid = state.mutationTagHex.length == 64 &&
        state.mutationTagHex.all { it.digitToIntOrNull(16) != null }
    LatticeSurface {
            Text(
                when {
                    state.editTargetMessageIdHex != null -> "Edit local text message"
                    state.replyTargetMessageIdHex != null -> "Reply in a message thread"
                    else -> "Queue a local text message"
                },
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                when {
                    state.editTargetMessageIdHex != null ->
                        "Editing commits a new immutable encrypted event; the original remains unchanged."
                    state.replyTargetMessageIdHex != null ->
                        "This commits a reply rooted at ${state.replyTargetMessageIdHex}; history remains a flat local list."
                    else ->
                        "Messages and outbox state are local records. Authorized incoming messages appear after Core accepts them; an outbox state does not prove that a destination received or read an event."
                },
            )
            Text(
                "Channels from the locally restored Genesis snapshot",
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.labelMedium,
            )
            Text(
                "Local outbox/history is not evidence of forwarding or delivery to a recipient.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
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
                    val selected = state.selectedChannelIdHex == idHex ||
                        (state.selectedChannelIdHex == null && channel == availableChannels.first())
                    val enabled = !state.submitting &&
                        state.editTargetMessageIdHex == null &&
                        state.replyTargetMessageIdHex == null
                    androidx.compose.foundation.layout.Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(
                                selected = selected,
                                enabled = enabled,
                                role = Role.RadioButton,
                                onClick = { onChannelSelected(idHex) },
                            ),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                    ) {
                        RadioButton(
                            selected = selected,
                            onClick = null,
                            enabled = enabled,
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
                LatticeFormField(
                    state.credentialVectorHex, onCredentialVectorHexChanged, "Trusted X.509 credential vector (hex)",
                    supportingText = "Even-length hexadecimal, at most 16 KiB decoded",
                    enabled = !state.submitting, singleLine = false,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, capitalization = KeyboardCapitalization.None),
                )
                LatticeFormField(
                    state.content, onContentChanged,
                    when {
                        state.editTargetMessageIdHex != null -> "Replacement text"
                        state.replyTargetMessageIdHex != null -> "Reply"
                        else -> "Message"
                    },
                    enabled = !state.submitting, singleLine = false, minLines = 3,
                    keyboardOptions = KeyboardOptions(capitalization = KeyboardCapitalization.Sentences),
                )
                LatticeFormField(
                    state.reactionToken, onReactionTokenChanged, "Reaction token",
                    supportingText = "1–64 UTF-8 bytes", enabled = !state.submitting,
                )
                LatticeFormField(
                    state.mutationTagHex, onMutationTagHexChanged,
                    "Reaction or pin add-event ID for removal (32-byte hex)", enabled = !state.submitting,
                )
                LatticeActionButton(
                    when {
                        state.editTargetMessageIdHex != null -> "Queue edit locally"
                        state.replyTargetMessageIdHex != null -> "Queue reply locally"
                        else -> "Queue locally"
                    },
                    onQueue,
                    enabled = profileReady && !state.submitting && availableChannels.isNotEmpty(),
                    busy = state.submitting,
                    tone = LatticeActionTone.PRIMARY,
                )
                if (
                    state.editTargetMessageIdHex != null ||
                    state.replyTargetMessageIdHex != null
                ) {
                    Button(
                        onClick = onCancelEdit,
                        enabled = !state.submitting,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(if (state.editTargetMessageIdHex != null) "Cancel edit" else "Cancel reply")
                    }
                }
                Button(
                    onClick = onLoadHistory,
                    enabled = profileReady && !state.loadingHistory,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (state.loadingHistory) "Loading history…" else "Refresh recent history")
                }
                state.historyStatus?.let { status ->
                    LatticeStatusNotice(LatticeNoticeKind.INFO, message = status)
                }
                val historyChannelId = state.selectedChannelIdHex
                    ?: availableChannels.firstOrNull()?.id?.toLowerHex()
                if (state.historyChannelIdHex != null && state.historyChannelIdHex == historyChannelId) {
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
                                    when (message.outboxState) {
                                        "queued" -> "Queued locally; not yet sent"
                                        "forwarding" -> "Forwarding attempt recorded; delivery unconfirmed"
                                        "forwarded" -> "Next hop accepted; delivery unconfirmed"
                                        "peer_ingress_accepted" ->
                                            "Peer accepted bounded ingress; not recipient delivery"
                                        "delivered" -> "Verified destination receipt recorded"
                                        "failed" -> "Failed or expired; retained locally"
                                        null -> "No queued state; retained locally"
                                        else -> "Unknown local outbox status"
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    "Event ID: ${message.eventId.toLowerHex()}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Text(
                                    "Author sequence ${message.authorSequence} · local Lamport value ${message.lamport}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                                Button(
                                    onClick = { onReplyMessage(message) },
                                    enabled = !state.submitting,
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Text("Reply in thread")
                                }
                                Button(
                                    onClick = {
                                        onQueueMutation(message, LocalTextMessageMutation.REACTION, true)
                                    },
                                    enabled = profileReady && !state.submitting && reactionTokenIsValid,
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Text("Add reaction")
                                }
                                Button(
                                    onClick = {
                                        onQueueMutation(message, LocalTextMessageMutation.REACTION, false)
                                    },
                                    enabled = profileReady && !state.submitting && mutationTagIsValid &&
                                        reactionTokenIsValid,
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Text("Remove reaction by tag")
                                }
                                Button(
                                    onClick = {
                                        onQueueMutation(message, LocalTextMessageMutation.PIN, true)
                                    },
                                    enabled = profileReady && !state.submitting,
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Text("Pin message")
                                }
                                Button(
                                    onClick = {
                                        onQueueMutation(message, LocalTextMessageMutation.PIN, false)
                                    },
                                    enabled = profileReady && !state.submitting && mutationTagIsValid,
                                    modifier = Modifier.fillMaxWidth(),
                                ) {
                                    Text("Remove pin by tag")
                                }
                                if (message.authorId.toLowerHex() == profileIdentityHex) {
                                    Button(
                                        onClick = { onEditMessage(message) },
                                        enabled = !state.submitting,
                                        modifier = Modifier.fillMaxWidth(),
                                    ) {
                                        Text("Edit locally")
                                    }
                                    Button(
                                        onClick = {
                                            onQueueMutation(message, LocalTextMessageMutation.TOMBSTONE, true)
                                        },
                                        enabled = profileReady && !state.submitting,
                                        modifier = Modifier.fillMaxWidth(),
                                    ) {
                                        Text("Queue delete tombstone")
                                    }
                                }
                            }
                        }
                    }
                }
            }
            LatticeStatusNotice(LatticeNoticeKind.INFO, message = state.status)
            state.eventIdHex?.let { eventId ->
                Text("Event ID (queued locally)", style = MaterialTheme.typography.labelMedium)
                Text(eventId, style = MaterialTheme.typography.bodySmall)
            }
    }
}

internal const val MAX_LOCAL_MESSAGE_BYTES = 16 * 1024
internal const val MAX_LOCAL_MESSAGE_CREDENTIAL_BYTES = 16 * 1024
internal const val MAX_LOCAL_MESSAGE_CREDENTIAL_HEX_LENGTH = MAX_LOCAL_MESSAGE_CREDENTIAL_BYTES * 2

package com.astraive.lattice

import android.util.Base64
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.text.selection.SelectionContainer
import com.astraive.lattice.ui.LatticeActionButton as Button
import androidx.compose.material3.MaterialTheme
import com.astraive.lattice.ui.LatticeFormField as OutlinedTextField
import com.astraive.lattice.ui.LatticeSurface as Surface
import com.astraive.lattice.ui.LatticeStatusNotice
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.lattice_uniffi.MobileDirectMessageConversation
import uniffi.lattice_uniffi.MobileDirectMessageHistoryEntry
import uniffi.lattice_uniffi.MobileDirectMessagePendingInvitation
import com.astraive.lattice.ui.LatticeDirectMessageLayout
import com.astraive.lattice.ui.LatticeActionSheet

@Composable
internal fun DirectMessageCard(profile: AndroidMobileProfile?, refreshVersion: Int) {
    var credentialHex by rememberSaveable { mutableStateOf("") }
    var peerFingerprintHex by rememberSaveable { mutableStateOf("") }
    var peerKeyPackageBase64 by rememberSaveable { mutableStateOf("") }
    var lanPeerFingerprintHex by rememberSaveable { mutableStateOf("") }
    var lanPeerAddress by rememberSaveable { mutableStateOf("") }
    var lanListenAddress by rememberSaveable { mutableStateOf("127.0.0.1:7332") }
    var keyPackageBase64 by rememberSaveable { mutableStateOf<String?>(null) }
    var messageDraft by rememberSaveable { mutableStateOf("") }
    var selectedGroupReference by rememberSaveable { mutableStateOf<String?>(null) }
    var pendingInvitations by remember(profile) {
        mutableStateOf(emptyList<MobileDirectMessagePendingInvitation>())
    }
    var conversations by remember(profile) { mutableStateOf(emptyList<MobileDirectMessageConversation>()) }
    var history by remember(profile) { mutableStateOf(emptyList<MobileDirectMessageHistoryEntry>()) }
    var status by rememberSaveable { mutableStateOf("Direct messages use pairwise MLS packets over authenticated transports.") }
    var busy by rememberSaveable { mutableStateOf(false) }
    var activeSheet by rememberSaveable { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    fun refresh(updateStatus: Boolean = true) {
        val activeProfile = profile ?: return
        scope.launch {
            try {
                val (pending, localConversations) = withContext(Dispatchers.IO) {
                    activeProfile.pendingDirectMessageInvitations() to
                        activeProfile.directMessageConversations()
                }
                pendingInvitations = pending
                conversations = localConversations
                val selected = selectedGroupReference
                if (selected != null) {
                    val groupReference = decodeFixedHex(selected, 32)
                    history = if (groupReference == null) emptyList() else withContext(Dispatchers.IO) {
                        activeProfile.directMessageHistory(groupReference)
                    }
                }
                if (updateStatus) status = "Local direct-message inbox refreshed."
            } catch (error: Exception) {
                if (updateStatus) {
                    status = "Direct-message inbox could not be refreshed: ${error.message ?: "Core error"}"
                }
            }
        }
    }

    LaunchedEffect(profile, refreshVersion) { refresh() }

    val statusKind = when {
        status.contains("failed", ignoreCase = true) || status.contains("could not", ignoreCase = true) -> com.astraive.lattice.ui.LatticeNoticeKind.ERROR
        status.startsWith("Encrypted packet queued") || status.startsWith("Invitation accepted") ||
            status.startsWith("Invitation declined") || status.startsWith("Local direct-message inbox refreshed") ||
            status.startsWith("Authenticated peer ingress complete") -> com.astraive.lattice.ui.LatticeNoticeKind.SUCCESS
        status.startsWith("Invitation queued") -> com.astraive.lattice.ui.LatticeNoticeKind.WARNING
        else -> com.astraive.lattice.ui.LatticeNoticeKind.INFO
    }
    LatticeDirectMessageLayout(
        description = "Pairwise encrypted messages use authenticated transports. Invitations are queued locally until you explicitly accept a Welcome; queueing does not confirm forwarding or recipient delivery.",
        actions = buildList {
            add("New conversation" to { activeSheet = "setup" })
            add("Authenticated LAN" to { activeSheet = "lan" })
            if (pendingInvitations.isNotEmpty()) add("Invitations (${pendingInvitations.size})" to { activeSheet = "invitations" })
            add("Refresh inbox" to { refresh() })
        },
    ) {
        LatticeActionSheet("Authenticated LAN exchange", activeSheet == "lan", { activeSheet = null }) {
            Text(
                "Run this on both pinned peers at the same time. Enter the other device's IP:port and a local listen address; use a reachable Wi-Fi interface explicitly. Noise verifies the exact saved identity pin before one bounded opaque packet can be sent each way. A peer-ingress ACK is not destination delivery.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = lanPeerFingerprintHex,
                onValueChange = { lanPeerFingerprintHex = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Pinned peer fingerprint (64 hex characters)") },
                enabled = profile != null && !busy,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Ascii,
                ),
            )
            OutlinedTextField(
                value = lanPeerAddress,
                onValueChange = { lanPeerAddress = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Peer TCP address (IP:port)") },
                enabled = profile != null && !busy,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Ascii,
                ),
            )
            OutlinedTextField(
                value = lanListenAddress,
                onValueChange = { lanListenAddress = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Local TCP listen address (IP:port)") },
                enabled = profile != null && !busy,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Ascii,
                ),
            )
            Button(
                onClick = {
                    val activeProfile = profile ?: return@Button
                    val peerFingerprint = decodeFixedHex(lanPeerFingerprintHex, 32)
                    if (peerFingerprint == null || lanPeerAddress.isBlank() || lanListenAddress.isBlank()) {
                        status = "Enter the exact pinned peer fingerprint and both TCP endpoints."
                    } else {
                        busy = true
                        scope.launch {
                            try {
                                val exchange = withContext(Dispatchers.IO) {
                                    activeProfile.exchangeDirectMessagesOnce(
                                        lanPeerAddress.trim(),
                                        lanListenAddress.trim(),
                                        peerFingerprint,
                                    )
                                }
                                status =
                                    "Authenticated peer ingress complete; sent ${exchange.outgoingIngressState ?: "no due packet"}; received ${exchange.incomingIngressState ?: "no packet"}. This is not a destination-delivery receipt."
                                refresh(updateStatus = false)
                            } catch (error: Exception) {
                                status = "Authenticated LAN exchange failed: ${error.message ?: "transport or Core error"}"
                            } finally {
                                busy = false
                            }
                        }
                    }
                },
                enabled = profile != null && !busy,
            ) { Text(if (busy) "Connecting…" else "Run authenticated LAN exchange") }
            LatticeStatusNotice(statusKind, message = status)
        }
        LatticeActionSheet("Create a conversation", activeSheet == "setup", { activeSheet = null }) {
            OutlinedTextField(
                value = credentialHex,
                onValueChange = { credentialHex = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Trusted local X.509 credential vector (hex)") },
                enabled = profile != null && !busy,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Ascii,
                ),
                minLines = 3,
                maxLines = 5,
            )
            Button(
                onClick = {
                    val activeProfile = profile ?: return@Button
                    val credential = decodeHex(credentialHex)
                    if (credential == null || credential.size > MAX_SPACE_CREDENTIAL_VECTOR_BYTES) {
                        status = "Enter a valid credential vector of at most 16 KiB."
                    } else {
                        busy = true
                        scope.launch {
                            try {
                                val wire = withContext(Dispatchers.IO) {
                                    activeProfile.publishDirectMessageKeyPackage(credential)
                                }
                                keyPackageBase64 = Base64.encodeToString(wire, Base64.NO_WRAP)
                                status = "KeyPackage published locally. Share its bytes and your fingerprint with the intended peer."
                            } catch (error: Exception) {
                                status = "KeyPackage publication failed: ${error.message ?: "Core error"}"
                            } finally {
                                busy = false
                            }
                        }
                    }
                },
                enabled = profile != null && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (busy) "Working…" else "Publish local KeyPackage") }
            keyPackageBase64?.let { value ->
                Text("Your public KeyPackage (Base64)", style = MaterialTheme.typography.labelMedium)
                SelectionContainer { Text(value, style = MaterialTheme.typography.bodySmall) }
            }
            OutlinedTextField(
                value = peerFingerprintHex,
                onValueChange = { peerFingerprintHex = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Peer fingerprint (64 hex characters)") },
                enabled = profile != null && !busy,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Ascii,
                ),
            )
            OutlinedTextField(
                value = peerKeyPackageBase64,
                onValueChange = { peerKeyPackageBase64 = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Peer KeyPackage (Base64)") },
                enabled = profile != null && !busy,
                keyboardOptions = KeyboardOptions(
                    capitalization = KeyboardCapitalization.None,
                    autoCorrectEnabled = false,
                    keyboardType = KeyboardType.Ascii,
                ),
                minLines = 3,
                maxLines = 6,
            )
            Button(
                onClick = {
                    val activeProfile = profile ?: return@Button
                    val credential = decodeHex(credentialHex)
                    val fingerprint = decodeFixedHex(peerFingerprintHex, 32)
                    val keyPackage = runCatching {
                        Base64.decode(peerKeyPackageBase64.trim(), Base64.DEFAULT)
                    }.getOrNull()
                    if (credential == null || credential.size > MAX_SPACE_CREDENTIAL_VECTOR_BYTES ||
                        fingerprint == null || keyPackage == null || keyPackage.isEmpty() ||
                        keyPackage.size > MAX_DIRECT_MESSAGE_PACKET_BYTES
                    ) {
                        status = "Check the local credential, peer fingerprint, and KeyPackage input bounds."
                    } else {
                        busy = true
                        scope.launch {
                            try {
                                val created = withContext(Dispatchers.IO) {
                                    activeProfile.createDirectMessage(
                                        credential,
                                        fingerprint,
                                        keyPackage,
                                        System.currentTimeMillis(),
                                    )
                                }
                                selectedGroupReference = created.conversation.groupReference.toLowerHex()
                                refresh()
                                status = "Invitation queued locally for the pinned peer. It is not yet accepted or delivered."
                            } catch (error: Exception) {
                                status = "Conversation creation failed: ${error.message ?: "Core error"}"
                            } finally {
                                busy = false
                            }
                        }
                    }
                },
                enabled = profile != null && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Create pairwise conversation") }

            LatticeStatusNotice(statusKind, message = status)
        }
        LatticeActionSheet("Invitation requests", activeSheet == "invitations", { activeSheet = null }) {
            if (pendingInvitations.isNotEmpty()) {
                Text("Invitation requests", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleSmall)
                if (credentialHex.isBlank()) {
                    Text("Accepting an invitation requires the trusted local credential.")
                    TextButton(onClick = { activeSheet = "setup" }) { Text("Enter trusted credential") }
                }
                pendingInvitations.forEach { invitation ->
                    val packetId = invitation.packetId
                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text("Peer ${invitation.peerIdentity.toLowerHex()}", style = MaterialTheme.typography.bodySmall)
                        Text("Group ${invitation.groupReference.toLowerHex()}", style = MaterialTheme.typography.bodySmall)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            TextButton(
                                enabled = profile != null && !busy,
                                onClick = {
                                    val activeProfile = profile ?: return@TextButton
                                    val credential = decodeHex(credentialHex)
                                    if (credential == null || credential.size > MAX_SPACE_CREDENTIAL_VECTOR_BYTES) {
                                        status = "Enter the trusted local X.509 credential before accepting."
                                    } else {
                                        busy = true
                                        scope.launch {
                                            try {
                                                val groupReference = withContext(Dispatchers.IO) {
                                                    activeProfile.acceptPendingDirectMessageInvitation(
                                                        credential,
                                                        invitation.peerIdentity,
                                                        packetId,
                                                        true,
                                                    )
                                                }
                                                selectedGroupReference = groupReference.toLowerHex()
                                                refresh()
                                                status = "Invitation accepted. The Welcome was imported locally."
                                            } catch (error: Exception) {
                                                status = "Invitation could not be accepted: ${error.message ?: "Core error"}"
                                            } finally {
                                                busy = false
                                            }
                                        }
                                    }
                                },
                            ) { Text("Accept") }
                            TextButton(
                                enabled = profile != null && !busy,
                                onClick = {
                                    val activeProfile = profile ?: return@TextButton
                                    scope.launch {
                                        try {
                                            withContext(Dispatchers.IO) {
                                                activeProfile.declinePendingDirectMessageInvitation(packetId)
                                            }
                                            refresh()
                                            status = "Invitation declined without importing the Welcome."
                                        } catch (error: Exception) {
                                            status = "Invitation could not be declined: ${error.message ?: "Core error"}"
                                        }
                                    }
                                },
                            ) { Text("Decline") }
                        }
                    }
                }
            }
            LatticeStatusNotice(statusKind, message = status)
        }
        Text("Conversations", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleSmall)

            if (conversations.isEmpty()) {
                Text("No local conversations yet. Start a new pairwise conversation to exchange messages.")
            }
            conversations.forEach { conversation ->
                TextButton(
                    onClick = {
                        selectedGroupReference = conversation.groupReference.toLowerHex()
                        refresh()
                    },
                    enabled = !conversation.closed,
                ) {
                    Text("Peer ${conversation.peerIdentity.toLowerHex()} · ${conversation.groupReference.toLowerHex()}")
                }
            }
            selectedGroupReference?.let { groupHex ->
                Text("Selected ${groupHex}", style = MaterialTheme.typography.labelMedium)
                history.forEach { item ->
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = MaterialTheme.shapes.medium,
                    ) {
                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text(item.authorIdentity.toLowerHex(), style = MaterialTheme.typography.labelSmall)
                            Text(item.content, style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
                OutlinedTextField(
                    value = messageDraft,
                    onValueChange = { messageDraft = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Message") },
                    enabled = profile != null && !busy,
                    minLines = 2,
                    maxLines = 5,
                )
                Button(
                    onClick = {
                        val activeProfile = profile ?: return@Button
                        val credential = decodeHex(credentialHex)
                        val groupReference = decodeFixedHex(groupHex, 32)
                        if (credential == null || credential.size > MAX_SPACE_CREDENTIAL_VECTOR_BYTES ||
                            groupReference == null || messageDraft.isBlank() || messageDraft.toByteArray().size > MAX_DIRECT_MESSAGE_TEXT_BYTES
                        ) {
                            status = "Enter a bounded message and the trusted local credential."
                        } else {
                            busy = true
                            scope.launch {
                                try {
                                    withContext(Dispatchers.IO) {
                                        activeProfile.queueDirectMessageText(
                                            credential,
                                            groupReference,
                                            messageDraft,
                                            System.currentTimeMillis(),
                                        )
                                    }
                                    messageDraft = ""
                                    history = withContext(Dispatchers.IO) {
                                        activeProfile.directMessageHistory(groupReference)
                                    }
                                    status = "Encrypted packet queued. Forwarding and recipient delivery are not confirmed."
                                } catch (error: Exception) {
                                    status = "Message could not be queued: ${error.message ?: "Core error"}"
                                } finally {
                                    busy = false
                                }
                            }
                        }
                    },
                    enabled = profile != null && !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (busy) "Queue encrypted message" else "Encrypt and queue message") }
            }
            LatticeStatusNotice(statusKind, message = status)
        }
}

private const val MAX_SPACE_CREDENTIAL_VECTOR_BYTES = 16 * 1024
private const val MAX_DIRECT_MESSAGE_PACKET_BYTES = 1024 * 1024
private const val MAX_DIRECT_MESSAGE_TEXT_BYTES = 64 * 1024

private fun decodeHex(value: String): ByteArray? {
    val compact = value.trim().removePrefix("0x").replace(" ", "").replace("\n", "").replace("\r", "")
    if (compact.isEmpty() || compact.length % 2 != 0 || compact.length > MAX_SPACE_CREDENTIAL_VECTOR_BYTES * 2) return null
    return runCatching {
        ByteArray(compact.length / 2) { index -> compact.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }.getOrNull()
}

private fun decodeFixedHex(value: String, expectedBytes: Int): ByteArray? {
    val compact = value.trim().removePrefix("0x").replace(" ", "").replace("\n", "").replace("\r", "")
    if (compact.length != expectedBytes * 2) return null
    return runCatching {
        ByteArray(expectedBytes) { index -> compact.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }.getOrNull()
}

package com.astraive.lattice

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import com.astraive.lattice.ui.LatticeActionButton as Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.MaterialTheme
import com.astraive.lattice.ui.LatticeFormField as OutlinedTextField
import com.astraive.lattice.ui.LatticeSurface as Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import uniffi.lattice_uniffi.MobileAttachmentExport
import uniffi.lattice_uniffi.MobileAttachmentManifest
import uniffi.lattice_uniffi.MobileAuthorizedAttachmentManifest
import uniffi.lattice_uniffi.MobileChannelType
import uniffi.lattice_uniffi.MobileSpaceSummary
import uniffi.lattice_uniffi.MobileAttachmentStagingStatus
import com.astraive.lattice.ui.LatticeSurface
import com.astraive.lattice.ui.LatticeStatusNotice
import com.astraive.lattice.ui.LatticeNoticeKind

@Composable
internal fun AttachmentTransferCard(
    profile: AndroidMobileProfile?,
    spaces: List<MobileSpaceSummary>,
) {
    var selectedSpaceKey by rememberSaveable { mutableStateOf<String?>(null) }
    var selectedChannelIdHex by rememberSaveable { mutableStateOf<String?>(null) }
    var spaceMenuExpanded by remember { mutableStateOf(false) }
    var channelMenuExpanded by remember { mutableStateOf(false) }
    var credentialHex by rememberSaveable { mutableStateOf("") }
    var source by remember(profile) { mutableStateOf<MobileImportedAttachment?>(null) }
    var sourceManifest by remember(profile) { mutableStateOf<MobileAttachmentManifest?>(null) }
    var queuedManifest by remember(profile) { mutableStateOf<MobileAuthorizedAttachmentManifest?>(null) }
    var sendEventIdHex by rememberSaveable { mutableStateOf("") }
    var sendManifest by remember(profile) { mutableStateOf<MobileAuthorizedAttachmentManifest?>(null) }
    var receiveEventIdHex by rememberSaveable { mutableStateOf("") }
    var receiveManifest by remember(profile) { mutableStateOf<MobileAuthorizedAttachmentManifest?>(null) }
    var receiveStagingStatus by remember(profile) {
        mutableStateOf<MobileAttachmentStagingStatus?>(null)
    }
    var peerFingerprintHex by rememberSaveable { mutableStateOf("") }
    var connectAddress by rememberSaveable { mutableStateOf("") }
    var listenAddress by rememberSaveable { mutableStateOf("0.0.0.0:7333") }
    var receiveConsent by rememberSaveable { mutableStateOf(false) }
    var busy by rememberSaveable { mutableStateOf(false) }
    var status by rememberSaveable {
        mutableStateOf("Choose a source or review a Core-authorized attachment event.")
    }
    var preparedExport by remember(profile) { mutableStateOf<MobileAttachmentExport?>(null) }
    val scope = rememberCoroutineScope()

    val activeSpaces = spaces
    LaunchedEffect(activeSpaces) {
        if (activeSpaces.none { attachmentSpaceKey(it) == selectedSpaceKey }) {
            val first = activeSpaces.firstOrNull()
            selectedSpaceKey = first?.let(::attachmentSpaceKey)
            selectedChannelIdHex = first?.channels
                ?.firstOrNull { !it.archived && it.channelType.isAttachmentChannel() }
                ?.id?.toLowerHex()
        }
    }
    val selectedSpace = spaces.firstOrNull { attachmentSpaceKey(it) == selectedSpaceKey }
    val availableChannels = selectedSpace?.channels.orEmpty()
        .filter { !it.archived && it.channelType.isAttachmentChannel() }
    val selectedChannel = availableChannels.firstOrNull { it.id.toLowerHex() == selectedChannelIdHex }
        ?: availableChannels.firstOrNull()

    fun clearSelectedSpacePreviews() {
        sendManifest = null
        receiveManifest = null
        receiveConsent = false
        preparedExport = null
        receiveStagingStatus = null
    }

    val openDocument = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri: Uri? ->
        val activeProfile = profile
        if (uri != null && activeProfile != null) {
            busy = true
            status = "Copying the selected document into private app storage…"
            scope.launch {
                try {
                    val result = withContext(Dispatchers.IO) {
                        val imported = activeProfile.importSelectedAttachment(uri)
                        imported to activeProfile.createAttachmentManifest(imported.sourceId, imported.filename)
                    }
                    source = result.first
                    sourceManifest = result.second
                    queuedManifest = null
                    sendManifest = null
                    status = "Private source verified. Choose its Space and channel, then queue the signed manifest."
                } catch (error: Exception) {
                    source = null
                    sourceManifest = null
                    status = "The selected document could not be imported: ${error.message ?: "private storage error"}"
                } finally {
                    busy = false
                }
            }
        }
    }

    val createDocument = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("application/octet-stream"),
    ) { uri: Uri? ->
        val activeProfile = profile
        val export = preparedExport
        if (activeProfile != null && export != null) {
            if (uri == null) {
                scope.launch {
                    withContext(Dispatchers.IO) { activeProfile.finishAttachmentExport(export.exportId) }
                    preparedExport = null
                    status = "Export cancelled. The verified private staging copy remains available."
                }
            } else {
                busy = true
                status = "Copying verified bytes to the document you selected…"
                scope.launch {
                    try {
                        withContext(Dispatchers.IO) {
                            activeProfile.copyAttachmentExportToDocument(export, uri)
                        }
                        preparedExport = null
                        status = "Verified attachment exported. This confirms local integrity, not peer delivery or reading."
                    } catch (error: Exception) {
                        status = "Export failed: ${error.message ?: "destination write failed"}"
                    } finally {
                        busy = false
                    }
                }
            }
        }
    }

    LatticeSurface {
            Text(
                "Space attachments",
                modifier = Modifier.semantics { heading() },
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                "Signed Space events authorize the file metadata. File bytes move separately over pinned TCP/Noise; BLE or relay acceptance is not file delivery.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Text("Send a file", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleSmall)
            Button(
                onClick = { openDocument.launch(arrayOf("*/*")) },
                enabled = profile != null && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (source == null) "Choose a source file" else "Choose a different source file") }
            sourceManifest?.let { manifest ->
                Text("Private source: ${manifest.filename} · ${manifest.fileSize} bytes")
                Text("SHA-256: ${manifest.fileHash.toLowerHex()}", style = MaterialTheme.typography.bodySmall)
            }

            if (spaces.isEmpty()) {
                Text("No locally restored Space is available. Restore a Space before queueing an attachment.")
            } else {
                Button(
                    onClick = { spaceMenuExpanded = true },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(selectedSpace?.let { "Space ${it.spaceId.toLowerHex().take(12)}" } ?: "Choose a Space")
                }
                DropdownMenu(expanded = spaceMenuExpanded, onDismissRequest = { spaceMenuExpanded = false }) {
                    spaces.forEach { space ->
                        DropdownMenuItem(
                            text = { Text("Space ${space.spaceId.toLowerHex()}") },
                            onClick = {
                                selectedSpaceKey = attachmentSpaceKey(space)
                                selectedChannelIdHex = space.channels
                                    .firstOrNull { !it.archived && it.channelType.isAttachmentChannel() }
                                    ?.id?.toLowerHex()
                                spaceMenuExpanded = false
                                clearSelectedSpacePreviews()
                            },
                        )
                    }
                }
                if (selectedSpace != null) {
                    Button(
                        onClick = { channelMenuExpanded = true },
                        enabled = !busy && availableChannels.isNotEmpty(),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(selectedChannel?.let { "Channel: ${it.name}" } ?: "Choose a channel")
                    }
                    DropdownMenu(expanded = channelMenuExpanded, onDismissRequest = { channelMenuExpanded = false }) {
                        availableChannels.forEach { channel ->
                            DropdownMenuItem(
                                text = { Text("${channel.name} · ${channel.id.toLowerHex()}") },
                                onClick = {
                                    selectedChannelIdHex = channel.id.toLowerHex()
                                    channelMenuExpanded = false
                                },
                            )
                        }
                    }
                    if (availableChannels.isEmpty()) {
                        Text("This Space has no active text or announcement channel for attachments.")
                    }
                }
                OutlinedTextField(
                    value = credentialHex,
                    onValueChange = { credentialHex = it },
                    modifier = Modifier.fillMaxWidth(),
                    label = { Text("Trusted local X.509 credential (hex)") },
                    enabled = profile != null && !busy,
                    keyboardOptions = asciiHexKeyboardOptions(),
                    minLines = 2,
                    maxLines = 4,
                )
                Button(
                    onClick = {
                        val activeProfile = profile ?: return@Button
                        val space = selectedSpace ?: return@Button
                        val channel = selectedChannel ?: return@Button
                        val privateSource = source ?: return@Button
                        val preview = sourceManifest ?: return@Button
                        val credential = decodeAttachmentHex(credentialHex, MAX_ATTACHMENT_CREDENTIAL_BYTES)
                        if (credential == null) {
                            status = "Enter a valid trusted credential vector no larger than 16 KiB."
                            return@Button
                        }
                        busy = true
                        status = "Checking the source again and queueing the signed Space manifest…"
                        scope.launch {
                            try {
                                val receipt = withContext(Dispatchers.IO) {
                                    activeProfile.queueAttachmentManifest(
                                        space.spaceId,
                                        space.groupReference,
                                        credential,
                                        channel.id,
                                        privateSource.sourceId,
                                        preview,
                                    )
                                }
                                queuedManifest = receipt.manifest
                                sendManifest = receipt.manifest
                                sendEventIdHex = receipt.manifest.eventId.toLowerHex()
                                source = null
                                sourceManifest = null
                                status = if (receipt.sourceRetained) {
                                    "Signed manifest queued as ${receipt.manifest.eventId.toLowerHex()}. Its verified source is retained in bounded private staging."
                                } else {
                                    "Manifest queued as ${receipt.manifest.eventId.toLowerHex()}, but the source could not be retained. Do not send it from this device."
                                }
                            } catch (error: Exception) {
                                status = "Manifest was not queued: ${error.message ?: "Core or source integrity check failed"}"
                            } finally {
                                busy = false
                            }
                        }
                    },
                    enabled = profile != null && source != null && sourceManifest != null &&
                        selectedSpace != null && selectedChannel != null && !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (busy) "Working…" else "Queue signed attachment manifest") }
            }

            queuedManifest?.let { manifest ->
                Text(
                    "Queued event ${manifest.eventId.toLowerHex()} · ${manifest.filename} · ${manifest.fileSize} bytes",
                    style = MaterialTheme.typography.bodySmall,
                )
            }

            Text("Send over pinned TCP/Noise", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleSmall)
            OutlinedTextField(
                value = sendEventIdHex,
                onValueChange = { sendEventIdHex = it; sendManifest = null },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Authorized attachment event ID (64 hex characters)") },
                enabled = profile != null && !busy,
                keyboardOptions = asciiHexKeyboardOptions(),
            )
            Button(
                onClick = {
                    val activeProfile = profile ?: return@Button
                    val space = selectedSpace ?: return@Button
                    val eventId = decodeAttachmentFixedHex(sendEventIdHex, 32)
                    if (eventId == null) {
                        status = "Enter a 32-byte attachment event ID."
                        return@Button
                    }
                    busy = true
                    scope.launch {
                        try {
                            sendManifest = withContext(Dispatchers.IO) {
                                activeProfile.authorizedAttachmentManifest(space.spaceId, space.groupReference, eventId)
                            }
                            status = "Core authorized this event and its manifest. Confirm the exact pinned peer before sending."
                        } catch (error: Exception) {
                            sendManifest = null
                            status = "This event is not an authorized attachment in the selected Space: ${error.message ?: "Core rejected it"}"
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = profile != null && selectedSpace != null && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Review authorized send manifest") }
            sendManifest?.let { manifest ->
                Text("${manifest.filename} · ${manifest.fileSize} bytes", style = MaterialTheme.typography.bodyMedium)
                Text("Event ${manifest.eventId.toLowerHex()}", style = MaterialTheme.typography.bodySmall)
            }

            OutlinedTextField(
                value = peerFingerprintHex,
                onValueChange = { peerFingerprintHex = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Exact saved peer fingerprint (64 hex characters)") },
                enabled = profile != null && !busy,
                keyboardOptions = asciiHexKeyboardOptions(),
            )
            Text(
                "The fingerprint must match a saved full identity pin and an active member of the selected Space.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            OutlinedTextField(
                value = connectAddress,
                onValueChange = { connectAddress = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Receiver TCP address (IP:port)") },
                enabled = profile != null && !busy,
                keyboardOptions = asciiHexKeyboardOptions(),
            )
            Button(
                onClick = {
                    val activeProfile = profile ?: return@Button
                    val space = selectedSpace ?: return@Button
                    val manifest = sendManifest ?: return@Button
                    val eventId = decodeAttachmentFixedHex(sendEventIdHex, 32)
                    val peer = decodeAttachmentFixedHex(peerFingerprintHex, 32)
                    if (eventId == null || peer == null || connectAddress.isBlank() ||
                        manifest.eventId.toLowerHex() != eventId.toLowerHex()
                    ) {
                        status = "Review the authorized event, exact peer fingerprint, and receiver IP:port first."
                        return@Button
                    }
                    busy = true
                    status = "Authenticating the exact pinned receiver and sending missing chunks…"
                    scope.launch {
                        try {
                            val receipt = withContext(Dispatchers.IO) {
                                activeProfile.sendAttachmentOnce(
                                    space.spaceId,
                                    space.groupReference,
                                    eventId,
                                    peer,
                                    connectAddress.trim(),
                                )
                            }
                            status = "Pinned peer verified. Receiver verified the complete file after ${receipt.chunksTransferred} new chunks. This is not destination delivery or reading."
                        } catch (error: Exception) {
                            status = "Authenticated attachment send failed: ${error.message ?: "pin, authorization, source, or transport error"}"
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = profile != null && sendManifest != null && selectedSpace != null && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (busy) "Sending…" else "Send missing attachment chunks") }

            Text("Receive an authorized file", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleSmall)
            OutlinedTextField(
                value = receiveEventIdHex,
                onValueChange = {
                    receiveEventIdHex = it
                    receiveManifest = null
                    receiveConsent = false
                    receiveStagingStatus = null
                    preparedExport = null
                },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Attachment event ID (64 hex characters)") },
                enabled = profile != null && !busy,
                keyboardOptions = asciiHexKeyboardOptions(),
            )
            Button(
                onClick = {
                    val activeProfile = profile ?: return@Button
                    val space = selectedSpace ?: return@Button
                    val eventId = decodeAttachmentFixedHex(receiveEventIdHex, 32)
                    if (eventId == null) {
                        status = "Enter a 32-byte event ID from the selected Space."
                        return@Button
                    }
                    busy = true
                    scope.launch {
                        try {
                            val reviewed = withContext(Dispatchers.IO) {
                                val manifest = activeProfile.authorizedAttachmentManifest(
                                    space.spaceId,
                                    space.groupReference,
                                    eventId,
                                )
                                val staging = activeProfile.attachmentStagingStatus(
                                    space.spaceId,
                                    space.groupReference,
                                    eventId,
                                )
                                manifest to staging
                            }
                            receiveManifest = reviewed.first
                            receiveStagingStatus = reviewed.second
                            receiveConsent = false
                            status = if (reviewed.second.complete) {
                                "Previously staged bytes were rechecked against the signed manifest. Export is available."
                            } else {
                                "Review the authorized filename and size. No new bytes are stored until you consent."
                            }
                        } catch (error: Exception) {
                            receiveManifest = null
                            receiveStagingStatus = null
                            status = "No Core-authorized attachment matches this event in the selected Space: ${error.message ?: "Core rejected it"}"
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = profile != null && selectedSpace != null && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text("Review authorized receive manifest") }
            receiveManifest?.let { manifest ->
                Text("${manifest.filename} · ${manifest.fileSize} bytes", style = MaterialTheme.typography.bodyMedium)
                Text("Event ${manifest.eventId.toLowerHex()}", style = MaterialTheme.typography.bodySmall)
                receiveStagingStatus?.let { staging ->
                    Text(
                        "Verified staged chunks: ${staging.verifiedChunks} of ${staging.totalChunks}" +
                            if (staging.complete) " · complete" else " · resumable",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Checkbox(
                        checked = receiveConsent,
                        onCheckedChange = { receiveConsent = it },
                        enabled = !busy,
                    )
                    Text("I consent to storing these bytes in private app staging.")
                }
            }
            OutlinedTextField(
                value = listenAddress,
                onValueChange = { listenAddress = it },
                modifier = Modifier.fillMaxWidth(),
                label = { Text("Local receive listen address (IP:port)") },
                enabled = profile != null && !busy,
                keyboardOptions = asciiHexKeyboardOptions(),
            )
            Button(
                onClick = {
                    val activeProfile = profile ?: return@Button
                    val space = selectedSpace ?: return@Button
                    val manifest = receiveManifest ?: return@Button
                    val eventId = decodeAttachmentFixedHex(receiveEventIdHex, 32)
                    val peer = decodeAttachmentFixedHex(peerFingerprintHex, 32)
                    if (!receiveConsent) {
                        status = "Consent is required before received bytes can enter private staging."
                        return@Button
                    }
                    if (eventId == null || peer == null || listenAddress.isBlank() ||
                        manifest.eventId.toLowerHex() != eventId.toLowerHex()
                    ) {
                        status = "Review the authorized event, exact peer fingerprint, and listen address first."
                        return@Button
                    }
                    busy = true
                    status = "Listening for the pinned sender. Private staging is enabled by your consent."
                    scope.launch {
                        try {
                            val receipt = withContext(Dispatchers.IO) {
                                activeProfile.receiveAttachmentOnce(
                                    space.spaceId,
                                    space.groupReference,
                                    eventId,
                                    peer,
                                    listenAddress.trim(),
                                    true,
                                )
                            }
                            val staged = withContext(Dispatchers.IO) {
                                activeProfile.attachmentStagingStatus(
                                    space.spaceId,
                                    space.groupReference,
                                    eventId,
                                )
                            }
                            receiveStagingStatus = staged
                            preparedExport = null
                            status = if (staged.complete) {
                                "Pinned peer verified. The complete file passed local integrity checks after ${receipt.chunksTransferred} new chunks and is resumably staged."
                            } else {
                                "Pinned peer verified; ${staged.verifiedChunks} of ${staged.totalChunks} chunks are verified. Run receive again to resume."
                            }
                        } catch (error: Exception) {
                            try {
                                receiveStagingStatus = withContext(Dispatchers.IO) {
                                    activeProfile.attachmentStagingStatus(
                                        space.spaceId,
                                        space.groupReference,
                                        eventId,
                                    )
                                }
                            } catch (_: Exception) {
                                receiveStagingStatus = null
                            }
                            status = "Authenticated attachment receive failed: ${error.message ?: "pin, authorization, consent, or transport error"}"
                        } finally {
                            busy = false
                        }
                    }
                },
                enabled = profile != null && receiveManifest != null && receiveConsent && !busy,
                modifier = Modifier.fillMaxWidth(),
            ) { Text(if (busy) "Receiving…" else "Accept and receive file") }

            if (receiveManifest != null && receiveStagingStatus?.complete == true) {
                Button(
                    onClick = {
                        val activeProfile = profile ?: return@Button
                        val space = selectedSpace ?: return@Button
                        val eventId = decodeAttachmentFixedHex(receiveEventIdHex, 32) ?: return@Button
                        busy = true
                        scope.launch {
                            try {
                                val export = withContext(Dispatchers.IO) {
                                    activeProfile.prepareAttachmentExport(space.spaceId, space.groupReference, eventId)
                                }
                                preparedExport = export
                                createDocument.launch(export.filename)
                            } catch (error: Exception) {
                                status = "Verified staging could not be prepared for export: ${error.message ?: "integrity check failed"}"
                            } finally {
                                busy = false
                            }
                        }
                    },
                    enabled = profile != null && !busy,
                    modifier = Modifier.fillMaxWidth(),
                ) { Text(if (preparedExport == null) "Export verified file…" else "Choose export destination…") }
            }

            LatticeStatusNotice(LatticeNoticeKind.INFO, message = status)
            Spacer(Modifier.height(2.dp))
    }
}

private fun attachmentSpaceKey(space: MobileSpaceSummary): String =
    "${space.spaceId.toLowerHex()}:${space.groupReference.toLowerHex()}"

private fun MobileChannelType.isAttachmentChannel(): Boolean =
    this == MobileChannelType.TEXT || this == MobileChannelType.ANNOUNCEMENT

private fun asciiHexKeyboardOptions() = KeyboardOptions(
    capitalization = KeyboardCapitalization.None,
    autoCorrectEnabled = false,
    keyboardType = KeyboardType.Ascii,
)

private fun decodeAttachmentFixedHex(value: String, byteCount: Int): ByteArray? {
    val compact = value.trim().removePrefix("0x").filterNot(Char::isWhitespace)
    if (compact.length != byteCount * 2) return null
    return decodeAttachmentHex(compact, byteCount)
}

private fun decodeAttachmentHex(value: String, maximumBytes: Int): ByteArray? {
    val compact = value.trim().removePrefix("0x").filterNot(Char::isWhitespace)
    if (compact.isEmpty() || compact.length % 2 != 0 || compact.length > maximumBytes * 2) return null
    return runCatching {
        ByteArray(compact.length / 2) { index ->
            compact.substring(index * 2, index * 2 + 2).toInt(16).toByte()
        }
    }.getOrNull()
}

private const val MAX_ATTACHMENT_CREDENTIAL_BYTES = 16 * 1024

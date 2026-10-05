package com.astraive.lattice.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

data class LatticeSpaceItem(val key: String, val spaceId: String, val groupReference: String)

@Composable
fun LatticeSpacesPage(
    items: List<LatticeSpaceItem>,
    selectedKey: String?,
    status: String,
    profileReady: Boolean,
    loading: Boolean,
    hasMore: Boolean,
    onRefresh: () -> Unit,
    onLoadMore: () -> Unit,
    onOpenSpace: (String?) -> Unit,
    createSpace: @Composable ColumnScope.() -> Unit,
    attachments: @Composable ColumnScope.() -> Unit,
    welcome: @Composable ColumnScope.() -> Unit,
    selectedSpaceContent: @Composable ColumnScope.(LatticeSpaceItem?) -> Unit,
    recovery: @Composable ColumnScope.() -> Unit,
    modifier: Modifier = Modifier,
) {
    LatticeDestinationPage("Spaces", modifier) {
        createSpace()
        Spacer(Modifier.height(20.dp))
        attachments()
        Spacer(Modifier.height(20.dp))
        welcome()
        Spacer(Modifier.height(20.dp))
        LatticeSurface {
            Text("Local Spaces", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleMedium)
            LatticeActionButton(if (loading) "Restoring local snapshots…" else "Restore local snapshot list", onRefresh, enabled = profileReady && !loading)
            Text("Locally restored snapshots include generations imported from signed Welcome checkpoints. They retain the accepted policy view and local transition history; they are not independent historical MLS replay proofs. Relay publishing and synchronization remain separate.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(status, style = MaterialTheme.typography.bodyMedium)
            val selected = items.firstOrNull { it.key == selectedKey }
            if (selectedKey != null && selected == null) {
                Text("The selected Space is not in the current local page.")
                LatticeActionButton("Back to local Spaces", { onOpenSpace(null) })
            } else if (selected == null) {
                items.forEachIndexed { index, item ->
                    Text("Local Genesis snapshot ${index + 1}", style = MaterialTheme.typography.titleSmall)
                    SelectionContainer {
                        Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Space ID: ${item.spaceId}", style = MaterialTheme.typography.bodySmall)
                            Text("Generation group reference: ${item.groupReference}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                    LatticeActionButton("Open channels for local Space ${index + 1}", { onOpenSpace(item.key) })
                }
            } else {
                LatticeActionButton("Back to local Spaces", { onOpenSpace(null) })
                Text("Local Space channels", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleMedium)
                SelectionContainer {
                    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        Text("Space ID: ${selected.spaceId}", style = MaterialTheme.typography.bodySmall)
                        Text("Generation group reference: ${selected.groupReference}", style = MaterialTheme.typography.bodySmall)
                    }
                }
            }
            selectedSpaceContent(selected)
            if (hasMore) {
                Spacer(Modifier.height(20.dp))
                LatticeActionButton(if (loading) "Loading Spaces…" else "Load more Spaces", onLoadMore, enabled = !loading)
            }
        }
        recovery()
        Spacer(Modifier.height(20.dp))
    }
}

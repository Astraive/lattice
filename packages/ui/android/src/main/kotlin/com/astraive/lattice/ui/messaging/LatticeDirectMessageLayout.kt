package com.astraive.lattice.ui

import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun LatticeDirectMessageLayout(
    description: String,
    actions: List<Pair<String, () -> Unit>>,
    content: @Composable ColumnScope.() -> Unit,
) {
    LatticeSurface(color = Raised) {
        Text(description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        actions.chunked(2).forEach { rowActions ->
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                rowActions.forEach { (label, action) ->
                    TextButton(onClick = action, modifier = Modifier.weight(1f)) { Text(label) }
                }
            }
        }
        content()
    }
}

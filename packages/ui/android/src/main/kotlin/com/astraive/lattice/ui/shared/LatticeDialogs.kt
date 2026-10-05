package com.astraive.lattice.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

@Composable
fun LatticeConsentDialog(
    title: String,
    message: String,
    confirmLabel: String,
    rejectLabel: String,
    onConfirm: () -> Unit,
    onReject: () -> Unit,
    content: (@Composable () -> Unit)? = null,
) {
    AlertDialog(
        onDismissRequest = onReject, title = { Text(title) }, text = content ?: { Text(message) },
        confirmButton = { TextButton(onClick = onConfirm) { Text(confirmLabel) } },
        dismissButton = { TextButton(onClick = onReject) { Text(rejectLabel) } },
        shape = RectangleShape,
    )
}

@Composable
fun LatticeActionSheet(
    title: String,
    open: Boolean,
    onClose: () -> Unit,
    content: @Composable ColumnScope.() -> Unit,
) {
    if (open) AlertDialog(
        onDismissRequest = onClose,
        title = { Text(title, modifier = Modifier.semantics { heading() }) },
        text = {
            Column(
                Modifier.heightIn(max = 560.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(12.dp),
                content = content,
            )
        },
        confirmButton = { TextButton(onClick = onClose) { Text("Close") } },
        shape = RectangleShape,
    )
}

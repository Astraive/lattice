package com.astraive.lattice.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

enum class LatticeNoticeKind { INFO, SUCCESS, WARNING, ERROR }

@Composable
fun LatticeStatusNotice(kind: LatticeNoticeKind, title: String? = null, message: String) {
    val tint = when (kind) {
        LatticeNoticeKind.INFO -> Information
        LatticeNoticeKind.SUCCESS -> Success
        LatticeNoticeKind.WARNING -> Warning
        LatticeNoticeKind.ERROR -> Error
    }
    Surface(color = Raised, shape = RectangleShape, modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            title?.let { Text(it, color = tint, style = MaterialTheme.typography.titleSmall, modifier = Modifier.semantics { heading() }) }
            Text(message, color = tint, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

package com.astraive.lattice.ui

import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.RectangleShape


enum class LatticeActionTone { PRIMARY, SECONDARY, DANGER }

@Composable
fun LatticeActionButton(
    label: String,
    onClick: () -> Unit,
    enabled: Boolean = true,
    busy: Boolean = false,
    tone: LatticeActionTone = LatticeActionTone.SECONDARY,
) {
    val colors = when (tone) {
        LatticeActionTone.PRIMARY -> ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Canvas)
        LatticeActionTone.SECONDARY -> ButtonDefaults.buttonColors(containerColor = Raised, contentColor = Foreground)
        LatticeActionTone.DANGER -> ButtonDefaults.buttonColors(containerColor = Error, contentColor = Canvas)
    }
    Button(onClick = onClick, enabled = enabled && !busy, colors = colors, shape = RectangleShape, modifier = Modifier.fillMaxWidth()) {
        Text(if (busy) "$label…" else label)
    }
}

@Composable
fun LatticeActionButton(
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    busy: Boolean = false,
    tone: LatticeActionTone = LatticeActionTone.SECONDARY,
    content: @Composable RowScope.() -> Unit,
) {
    val colors = when (tone) {
        LatticeActionTone.PRIMARY -> ButtonDefaults.buttonColors(containerColor = Accent, contentColor = Canvas)
        LatticeActionTone.SECONDARY -> ButtonDefaults.buttonColors(containerColor = Raised, contentColor = Foreground)
        LatticeActionTone.DANGER -> ButtonDefaults.buttonColors(containerColor = Error, contentColor = Canvas)
    }
    Button(onClick = onClick, modifier = modifier.fillMaxWidth(), enabled = enabled && !busy, colors = colors, shape = RectangleShape, content = content)
}

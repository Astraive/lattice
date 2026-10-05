package com.astraive.lattice.ui

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp

internal val Canvas = Color(0xFF000000)
internal val SurfaceColor = Color(0xFF090F0B)
internal val Raised = Color(0xFF121A14)
internal val Foreground = Color(0xFFEDF5EF)
internal val Muted = Color(0xFF9AA99D)
internal val Accent = Color(0xFF8FE3A4)
internal val Success = Color(0xFF66E98B)
internal val Warning = Color(0xFFF2C66D)
internal val Error = Color(0xFFFF8F86)
internal val Information = Color(0xFF8FC8FF)

private val LatticeColors = darkColorScheme(
    primary = Accent, onPrimary = Canvas, background = Canvas, onBackground = Foreground,
    surface = SurfaceColor, onSurface = Foreground, surfaceVariant = Raised, onSurfaceVariant = Muted,
    error = Error, onError = Canvas,
)

@Composable
fun LatticeTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = LatticeColors,
        shapes = Shapes(
            small = RoundedCornerShape(0.dp),
            medium = RoundedCornerShape(0.dp),
            large = RoundedCornerShape(0.dp),
        ),
        content = content,
    )
}

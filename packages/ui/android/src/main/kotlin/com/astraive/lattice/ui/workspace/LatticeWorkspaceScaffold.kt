package com.astraive.lattice.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.union
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp

@Composable
fun LatticeDestinationIcon(id: String, modifier: Modifier = Modifier) {
    val icon = when (id) {
        "IDENTITY" -> R.drawable.phosphor_identification_badge
        "SPACES" -> R.drawable.phosphor_squares_four
        "DIRECT_MESSAGES" -> R.drawable.phosphor_chat_circle_text
        else -> R.drawable.phosphor_bluetooth
    }
    androidx.compose.material3.Icon(
        painter = painterResource(icon),
        contentDescription = null,
        modifier = modifier.size(24.dp),
    )
}

data class LatticeDestinationItem(val id: String, val label: String, val icon: @Composable () -> Unit)

@Composable
fun LatticeWorkspaceScaffold(
    items: List<LatticeDestinationItem>,
    selectedId: String,
    onSelect: (String) -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable (PaddingValues) -> Unit,
) {
    BoxWithConstraints(modifier.fillMaxSize()) {
        val expanded = maxWidth >= 600.dp
        Row(Modifier.fillMaxSize().windowInsetsPadding(WindowInsets.safeDrawing.union(WindowInsets.ime))) {
            if (expanded) {
                NavigationRail(
                    modifier = Modifier.width(80.dp),
                    windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Vertical + WindowInsetsSides.Start),
                ) {
                    items.forEach { item ->
                        NavigationRailItem(
                            selected = selectedId == item.id,
                            onClick = { onSelect(item.id) },
                            icon = {
                                Box(
                                    modifier = Modifier
                                        .background(if (selectedId == item.id) MaterialTheme.colorScheme.surfaceVariant else androidx.compose.ui.graphics.Color.Transparent)
                                        .padding(8.dp),
                                ) { item.icon() }
                            },
                            label = { Text(item.label) },
                            colors = NavigationRailItemDefaults.colors(indicatorColor = androidx.compose.ui.graphics.Color.Transparent),
                        )
                    }
                }
                Box(Modifier.weight(1f).fillMaxSize()) { content(PaddingValues()) }
            } else {
                Column(Modifier.fillMaxSize()) {
                    Box(Modifier.weight(1f).fillMaxWidth()) { content(PaddingValues()) }
                    NavigationBar(windowInsets = WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal + WindowInsetsSides.Bottom)) {
                        items.forEach { item ->
                            NavigationBarItem(
                                selected = selectedId == item.id,
                                onClick = { onSelect(item.id) },
                                icon = {
                                    Box(
                                        modifier = Modifier
                                            .background(if (selectedId == item.id) MaterialTheme.colorScheme.surfaceVariant else androidx.compose.ui.graphics.Color.Transparent)
                                            .padding(8.dp),
                                    ) { item.icon() }
                                },
                                label = { Text(item.label) },
                                colors = NavigationBarItemDefaults.colors(indicatorColor = androidx.compose.ui.graphics.Color.Transparent),
                            )
                        }
                    }
                }
            }
        }
    }
}

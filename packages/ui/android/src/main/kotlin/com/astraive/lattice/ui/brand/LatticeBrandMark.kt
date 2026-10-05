package com.astraive.lattice.ui

import androidx.compose.foundation.Image
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.size

@Composable
fun LatticeBrandMark(modifier: Modifier = Modifier, contentDescription: String? = "Lattice") {
    Image(
        painter = painterResource(R.drawable.lattice_mark),
        contentDescription = contentDescription,
        modifier = modifier.size(32.dp),
    )
}

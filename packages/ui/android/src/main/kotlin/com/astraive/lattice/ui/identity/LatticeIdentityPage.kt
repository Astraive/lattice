package com.astraive.lattice.ui

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

/** Plain presentation data for the device-identity destination. */
data class LatticeIdentityPageState(
    val profileStatus: String,
    val fingerprint: String?,
    val publicBundle: String?,
    val clipboardStatus: String?,
    val certificateRequestStatus: String?,
    val certificateRequestPem: String?,
    val generatingCertificateRequest: Boolean,
    val canUseIdentity: Boolean,
)

@Composable
fun LatticeIdentityPage(
    state: LatticeIdentityPageState,
    onCopyIdentityBundle: () -> Unit,
    onCopyIdentityFingerprint: () -> Unit,
    onGenerateCertificateRequest: () -> Unit,
    onCopyCertificateRequest: () -> Unit,
    identityPin: @Composable ColumnScope.() -> Unit,
    modifier: Modifier = Modifier,
) {
    LatticeDestinationPage("Identity", modifier) {
        LatticeSurface {
            Text("Device identity", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleMedium)
            Text(state.profileStatus, style = MaterialTheme.typography.bodyMedium)
            state.fingerprint?.let { value -> SelectionContainer { Text("Fingerprint: $value", style = MaterialTheme.typography.bodySmall) } }
            state.publicBundle?.let { value ->
                Text("Public bundle (share with a peer)", style = MaterialTheme.typography.bodySmall)
                SelectionContainer { Text(value, style = MaterialTheme.typography.bodySmall) }
                LatticeActionButton("Copy device public bundle", onCopyIdentityBundle)
            }
            if (state.fingerprint != null) LatticeActionButton("Copy full device fingerprint", onCopyIdentityFingerprint)
            state.clipboardStatus?.let { LatticeStatusNotice(LatticeNoticeKind.INFO, message = it) }
        }
        Spacer(Modifier.height(20.dp))
        identityPin()
        Spacer(Modifier.height(20.dp))
        LatticeSurface {
            Text("Certificate request", modifier = Modifier.semantics { heading() }, style = MaterialTheme.typography.titleMedium)
            Text("Create a PKCS#10 request for certificate issuance. A certificate authority must return a trusted chain before local Space creation.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            LatticeActionButton("Generate certificate request", onGenerateCertificateRequest, enabled = state.canUseIdentity && !state.generatingCertificateRequest, busy = state.generatingCertificateRequest)
            state.certificateRequestStatus?.let { LatticeStatusNotice(LatticeNoticeKind.INFO, message = it) }
            state.certificateRequestPem?.let { value ->
                SelectionContainer { Text(value, style = MaterialTheme.typography.bodySmall) }
                LatticeActionButton("Copy certificate request", onCopyCertificateRequest)
            }
        }
    }
}

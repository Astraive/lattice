package com.astraive.lattice

import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.saveable.rememberSaveableStateHolder
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import com.astraive.lattice.ui.LatticeConsentDialog
import com.astraive.lattice.ui.LatticeDestinationItem
import com.astraive.lattice.ui.LatticeNoticeKind
import com.astraive.lattice.ui.LatticeStatusNotice
import com.astraive.lattice.ui.LatticeTheme
import com.astraive.lattice.ui.LatticeWorkspaceScaffold
import com.astraive.lattice.ui.LatticeDirectMessageLayout
import com.astraive.lattice.ui.LatticeDirectMessagesPage
import com.astraive.lattice.ui.LatticeActionSheet
import org.junit.Rule
import org.junit.Test

class WorkspaceNavigationTest {
    @get:Rule val compose = createComposeRule()

    private val destinations = listOf("IDENTITY", "SPACES", "DIRECT_MESSAGES", "NEARBY")
        .map { id -> LatticeDestinationItem(id, id.replace('_', ' ').lowercase().replaceFirstChar(Char::uppercase)) { com.astraive.lattice.ui.LatticeDestinationIcon(id) } }


    @Test fun navigationSwitchesDestinationAndPreservesOpenSpaceForBack() {
        compose.setContent {
            LatticeTheme {
                var selected by rememberSaveable { mutableStateOf("IDENTITY") }
                val stateHolder = rememberSaveableStateHolder()
                LatticeWorkspaceScaffold(destinations, selected, { selected = it }) { _: PaddingValues ->
                    stateHolder.SaveableStateProvider(selected) {
                        if (selected == "SPACES") {
                            var opened by rememberSaveable { mutableStateOf(false) }
                            if (opened) androidx.compose.material3.TextButton(onClick = { opened = false }) { Text("Back to local Spaces") }
                            else androidx.compose.material3.TextButton(onClick = { opened = true }) { Text("Open channels for local Space 1") }
                        } else if (selected == "DIRECT_MESSAGES") {
                            LatticeDirectMessagesPage { Text("DIRECT_MESSAGES page") }
                        } else Text("${selected} page")
                    }
                }
            }
        }
        compose.onNodeWithText("Spaces").performClick()
        compose.onNodeWithText("Open channels for local Space 1").performClick()
        compose.onNodeWithText("Identity").performClick()
        compose.onNodeWithText("Spaces").performClick()
        compose.onNodeWithText("Back to local Spaces").assertIsDisplayed().performClick()
        compose.onNodeWithText("Open channels for local Space 1").assertIsDisplayed()
        compose.onNodeWithText("Direct messages").performClick()
        compose.onNodeWithText("DIRECT_MESSAGES page").assertIsDisplayed()
        compose.onNodeWithText("Nearby").performClick()
        compose.onNodeWithText("NEARBY page").assertIsDisplayed()
    }

    @Test fun forwardingDialogRejectButtonKeepsForwardingOff() {
        compose.setContent {
            LatticeTheme {
                var pending by rememberSaveable { mutableStateOf(true) }
                Text(if (pending) "Forwarding pending" else "Forwarding off")
                if (pending) LatticeConsentDialog(
                    title = "Allow encrypted event forwarding?",
                    message = "Forwarding requires explicit consent.",
                    confirmLabel = "Allow forwarding",
                    rejectLabel = "Keep forwarding off",
                    onConfirm = { pending = false },
                    onReject = { pending = false },
                )
            }
        }
        compose.onNodeWithText("Forwarding pending").assertIsDisplayed()
        compose.onNodeWithText("Keep forwarding off").performClick()
        compose.onNodeWithText("Forwarding off").assertIsDisplayed()
    }

    @Test fun safetyNumberDialogRejectButtonRejectsPeer() {
        compose.setContent {
            LatticeTheme {
                var pending by rememberSaveable { mutableStateOf(true) }
                Text(if (pending) "Identity unverified" else "Peer rejected")
                if (pending) LatticeConsentDialog(
                    title = "Verify first-contact BLE peer",
                    message = "Compare safety numbers out of band.",
                    confirmLabel = "I verified this identity",
                    rejectLabel = "Reject",
                    onConfirm = { pending = false },
                    onReject = { pending = false },
                    content = { Text("Safety number: 1234") },
                )
            }
        }
        compose.onNodeWithText("Safety number: 1234").assertIsDisplayed()
        compose.onNodeWithText("Reject").performClick()
        compose.onNodeWithText("Peer rejected").assertIsDisplayed()
    }

    @Test fun statusNoticeKeepsWarningTextAndLabelVisible() {
        compose.setContent {
            LatticeTheme {
                LatticeStatusNotice(
                    kind = LatticeNoticeKind.WARNING,
                    title = "Permission required",
                    message = "Nearby discovery remains off until permission is granted.",
                )
            }
        }
        compose.onNodeWithText("Permission required").assertIsDisplayed()
        compose.onNodeWithText("Nearby discovery remains off until permission is granted.").assertIsDisplayed()
    }

    @Test fun directMessageWorkspaceOpensAndClosesRealConversationSetupSheet() {
        compose.setContent {
            LatticeTheme {
                var sheet by rememberSaveable { mutableStateOf(false) }
                LatticeDirectMessageLayout(
                    description = "Queued packets are not delivery receipts.",
                    actions = listOf("New conversation" to { sheet = true }),
                ) {
                    androidx.compose.material3.Text("Conversations")
                    androidx.compose.material3.Text("No local conversations yet.")
                    LatticeActionSheet("Create a conversation", sheet, { sheet = false }) {
                        androidx.compose.material3.Text("Trusted local X.509 credential vector")
                        androidx.compose.material3.Text("Peer KeyPackage (Base64)")
                    }
                }
            }
        }
        compose.onNodeWithText("No local conversations yet.").assertIsDisplayed()
        compose.onNodeWithText("New conversation").performClick()
        compose.onNodeWithText("Create a conversation").assertIsDisplayed()
        compose.onNodeWithText("Trusted local X.509 credential vector").assertIsDisplayed()
        compose.onNodeWithText("Close").performClick()
        compose.onNodeWithText("No local conversations yet.").assertIsDisplayed()
    }
}

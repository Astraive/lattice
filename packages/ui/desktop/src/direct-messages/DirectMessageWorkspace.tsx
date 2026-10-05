import { useRef, useState } from "react";
import { ConversationList, type SupplementaryDialog } from "./ConversationList";
import { PairingSetupPane } from "./PairingSetupPane";
import { SelectedThread } from "./SelectedThread";
import { SupplementaryDialogs } from "./SupplementaryDialogs";
import type { DirectMessageWorkspaceProps } from "./types";

export function DirectMessageWorkspace(props: DirectMessageWorkspaceProps) {
  const [dialog, setDialog] = useState<SupplementaryDialog>(null);
  const credentialInput = useRef<HTMLTextAreaElement | null>(null);
  const setupHeading = useRef<HTMLHeadingElement | null>(null);
  const selected = props.conversations.find((item) => item.groupReference === props.selectedGroup);
  const eligible = props.runtimeAvailable && props.identityReady && !props.busy;
  return (
    <div className="dm-workspace">
      <ConversationList
        conversations={props.conversations}
        invitationsCount={props.invitations.length}
        selectedGroup={props.selectedGroup}
        onSelectConversation={props.onSelectConversation}
        onOpenDialog={setDialog}
        credentialInputRef={credentialInput}
        setupHeadingRef={setupHeading}
        eligible={eligible}
      />
      <SelectedThread
        peerIdentity={selected?.peerIdentity}
        groupReference={selected?.groupReference}
        history={props.history}
        identityReady={props.identityReady}
        busy={props.busy}
        messageDraft={props.messageDraft}
        onMessageDraftChange={props.onMessageDraftChange}
        onSendMessage={props.onSendMessage}
      />
      <PairingSetupPane
        {...props}
        credentialInputRef={credentialInput}
        setupHeadingRef={setupHeading}
      />
      <SupplementaryDialogs {...props} dialog={dialog} onClose={() => setDialog(null)} />
    </div>
  );
}

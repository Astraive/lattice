import { DirectMessageWorkspace } from "@lattice/ui-desktop";
import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useRef, useState } from "react";

type Conversation = {
  groupReference: string;
  peerIdentity: string;
  closed: boolean;
};

type Invitation = {
  packetId: string;
  groupReference: string;
  peerIdentity: string;
};

type HistoryItem = {
  packetId: string;
  authorIdentity: string;
  content: string;
};

type ConversationHistory = { groupReference: string; items: HistoryItem[] } | null;

export function historyForConversation(
  selectedGroup: string,
  history: ConversationHistory,
): HistoryItem[] {
  return selectedGroup && history?.groupReference === selectedGroup ? history.items : [];
}

type ExchangeResult = {
  state: "authenticated_direct_message_round_completed";
  peerFingerprint: string;
  listenAddress: string;
  sentPacketId: string | null;
  peerIngressState: "accepted" | "invitation_pending_user_consent" | "duplicate" | null;
  receivedPacketId: string | null;
  receivedIngressState: "accepted" | "invitation_pending_user_consent" | "duplicate" | null;
  networkContacted: true;
};

type Props = {
  runtimeAvailable: boolean;
  identityReady: boolean;
};

export function DirectMessagePanel({ runtimeAvailable, identityReady }: Props) {
  const [credentialHex, setCredentialHex] = useState("");
  const [peerFingerprint, setPeerFingerprint] = useState("");
  const [peerKeyPackage, setPeerKeyPackage] = useState("");
  const [publishedKeyPackage, setPublishedKeyPackage] = useState("");
  const [connectAddress, setConnectAddress] = useState("");
  const [listenAddress, setListenAddress] = useState("127.0.0.1:7332");
  const [messageDraft, setMessageDraft] = useState("");
  const [conversations, setConversations] = useState<Conversation[]>([]);
  const [invitations, setInvitations] = useState<Invitation[]>([]);
  const [history, setHistory] = useState<ConversationHistory>(null);
  const historyRequestId = useRef(0);
  const [selectedGroup, setSelectedGroup] = useState("");
  const [exchange, setExchange] = useState<ExchangeResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState(
    "Direct messages use pairwise MLS packets over pinned authenticated TCP sessions.",
  );
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    const historyRequestIdForRefresh = ++historyRequestId.current;
    if (!runtimeAvailable || !identityReady) return;
    try {
      const [nextConversations, nextInvitations] = await Promise.all([
        invoke<Conversation[]>("list_local_direct_message_conversations"),
        invoke<Invitation[]>("list_pending_local_direct_message_invitations"),
      ]);
      setConversations(nextConversations);
      setSelectedGroup((current) =>
        nextConversations.some((item) => item.groupReference === current && !item.closed)
          ? current
          : (nextConversations.find((item) => !item.closed)?.groupReference ?? ""),
      );
      setInvitations(nextInvitations);
      if (selectedGroup) {
        const items = await invoke<HistoryItem[]>("list_local_direct_message_history", {
          groupReferenceHex: selectedGroup,
        });
        if (historyRequestIdForRefresh === historyRequestId.current) {
          setHistory({ groupReference: selectedGroup, items });
        }
      } else if (historyRequestIdForRefresh === historyRequestId.current) {
        setHistory(null);
      }
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [runtimeAvailable, identityReady, selectedGroup]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function runTask(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(false);
    }
  }

  async function publishKeyPackage() {
    await runTask(async () => {
      const result = await invoke<string>("publish_local_direct_message_key_package", {
        credentialHex,
      });
      setPublishedKeyPackage(result);
      setStatus(
        "KeyPackage published locally. Share its public bytes and this device's full fingerprint out of band.",
      );
    });
  }

  async function createConversation() {
    await runTask(async () => {
      const result = await invoke<{
        groupReference: string;
        peerIdentity: string;
        invitationPacketId: string;
      }>("create_local_direct_message", {
        credentialHex,
        peerFingerprintHex: peerFingerprint.trim(),
        peerKeyPackageBase64: peerKeyPackage.trim(),
      });
      setSelectedGroup(result.groupReference);
      setStatus(
        `Invitation ${result.invitationPacketId} is queued for ${result.peerIdentity}; no delivery is claimed yet.`,
      );
      await refresh();
    });
  }

  async function acceptInvitation(invitation: Invitation) {
    await runTask(async () => {
      const groupReference = await invoke<string>("accept_local_direct_message_invitation", {
        credentialHex,
        peerFingerprintHex: invitation.peerIdentity,
        packetIdHex: invitation.packetId,
      });
      setSelectedGroup(groupReference);
      setStatus("Invitation accepted after explicit consent; the Welcome is imported locally.");
      await refresh();
    });
  }

  async function declineInvitation(invitation: Invitation) {
    await runTask(async () => {
      await invoke<boolean>("decline_local_direct_message_invitation", {
        packetIdHex: invitation.packetId,
      });
      setStatus("Invitation declined without importing its Welcome.");
      await refresh();
    });
  }

  async function sendMessage() {
    if (!selectedGroup || messageDraft.trim().length === 0) return;
    await runTask(async () => {
      const result = await invoke<{ packetId: string; ingressState: string }>(
        "queue_local_direct_message_text",
        { credentialHex, groupReferenceHex: selectedGroup, content: messageDraft },
      );
      setMessageDraft("");
      setStatus(
        `Encrypted packet ${result.packetId} is queued locally; forwarding and peer acceptance are not confirmed.`,
      );
      await refresh();
    });
  }

  async function syncOnce() {
    if (!peerFingerprint.trim()) return;
    await runTask(async () => {
      const result = await invoke<ExchangeResult>("sync_local_direct_messages_once", {
        connectAddress: connectAddress.trim(),
        listenAddress: listenAddress.trim(),
        peerFingerprintHex: peerFingerprint.trim(),
      });
      if (
        result.state !== "authenticated_direct_message_round_completed" ||
        result.networkContacted !== true
      ) {
        throw new Error("Desktop returned an invalid authenticated DM exchange result.");
      }
      setExchange(result);
      setStatus(
        result.sentPacketId
          ? `Sent ${result.sentPacketId}; authenticated peer-ingress status: ${result.peerIngressState ?? "unconfirmed"}.`
          : `Authenticated with ${result.peerFingerprint}; no due DM packet was queued for this peer.`,
      );
      await refresh();
    });
  }

  return (
    <DirectMessageWorkspace
      runtimeAvailable={runtimeAvailable}
      identityReady={identityReady}
      credentialHex={credentialHex}
      onCredentialHexChange={setCredentialHex}
      peerFingerprint={peerFingerprint}
      onPeerFingerprintChange={setPeerFingerprint}
      peerKeyPackage={peerKeyPackage}
      onPeerKeyPackageChange={setPeerKeyPackage}
      publishedKeyPackage={publishedKeyPackage}
      connectAddress={connectAddress}
      onConnectAddressChange={setConnectAddress}
      listenAddress={listenAddress}
      onListenAddressChange={setListenAddress}
      messageDraft={messageDraft}
      onMessageDraftChange={setMessageDraft}
      conversations={conversations}
      invitations={invitations}
      history={historyForConversation(selectedGroup, history)}
      selectedGroup={selectedGroup}
      onSelectConversation={(groupReference) => setSelectedGroup(groupReference)}
      onPublishKeyPackage={() => void publishKeyPackage()}
      onCreateConversation={() => void createConversation()}
      onRefresh={() => void refresh()}
      onAcceptInvitation={(invitation) => void acceptInvitation(invitation)}
      onDeclineInvitation={(invitation) => void declineInvitation(invitation)}
      onSendMessage={() => void sendMessage()}
      onSyncOnce={() => void syncOnce()}
      busy={busy}
      status={status}
      error={error}
      exchange={exchange}
    />
  );
}

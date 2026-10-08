import { ActionButton, FormField } from "@lattice/ui-shared";
import { Plus } from "@phosphor-icons/react";
import { type RefObject, useState } from "react";
import type { Conversation } from "./types";

export type SupplementaryDialog =
  | "conversations"
  | "invitations"
  | "credential"
  | "exchange"
  | null;
export function ConversationList({
  conversations,
  invitationsCount,
  selectedGroup,
  onSelectConversation,
  onOpenDialog,
  credentialInputRef,
  setupHeadingRef,
  eligible,
}: {
  conversations: Conversation[];
  invitationsCount: number;
  selectedGroup: string;
  onSelectConversation: (groupReference: string) => void;
  onOpenDialog: (dialog: SupplementaryDialog) => void;
  credentialInputRef: RefObject<HTMLTextAreaElement | null>;
  setupHeadingRef: RefObject<HTMLHeadingElement | null>;
  eligible: boolean;
}) {
  const [search, setSearch] = useState("");
  const filtered = conversations.filter((item) =>
    `${item.peerIdentity} ${item.groupReference}`.toLowerCase().includes(search.toLowerCase()),
  );
  return (
    <aside className="dm-list" aria-label="Conversations">
      <header className="dm-list__heading">
        <h2>Conversations</h2>
        <ActionButton
          aria-label="Focus pairing and setup"
          title="Focus pairing and setup"
          tone="quiet"
          onClick={() => (eligible ? credentialInputRef.current : setupHeadingRef.current)?.focus()}
        >
          <Plus size={18} aria-hidden="true" />
        </ActionButton>
      </header>
      <FormField label="Search conversations" htmlFor="dm-conversation-search">
        <input
          id="dm-conversation-search"
          value={search}
          onChange={(event) => setSearch(event.currentTarget.value)}
          placeholder="Search conversations"
        />
      </FormField>
      <nav className="dm-list__items" aria-label="Conversation list">
        {filtered.length === 0 ? (
          <p>
            {conversations.length
              ? "No matching conversations."
              : "No accepted pairwise conversations."}
          </p>
        ) : (
          filtered.map((conversation) => (
            <button
              key={conversation.groupReference}
              type="button"
              disabled={conversation.closed}
              aria-current={conversation.groupReference === selectedGroup ? "page" : undefined}
              onClick={() => onSelectConversation(conversation.groupReference)}
            >
              <span className="dm-list__avatar" aria-hidden="true">
                {conversation.peerIdentity.slice(0, 1).toUpperCase()}
              </span>
              <span className="dm-list__peer">
                <strong>{conversation.peerIdentity}</strong>
                <small>{conversation.closed ? "Closed" : "Pairwise conversation"}</small>
              </span>
              <span className="dm-list__fingerprint">{conversation.groupReference}</span>
            </button>
          ))
        )}
      </nav>
      <section className="dm-list__tools" aria-label="Supplementary direct message details">
        <button type="button" onClick={() => onOpenDialog("conversations")}>
          Current conversations <span>{conversations.length}</span>
        </button>
        <button type="button" onClick={() => onOpenDialog("invitations")}>
          Pending invitations <span>{invitationsCount}</span>
        </button>
        <button type="button" onClick={() => onOpenDialog("credential")}>
          KeyPackage &amp; credential
        </button>
        <button type="button" onClick={() => onOpenDialog("exchange")}>
          Authenticated exchange
        </button>
      </section>
    </aside>
  );
}

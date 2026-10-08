import { ActionButton, FormField } from "@lattice/ui-shared";
import { useState } from "react";

type HistoryMessage = { id: string; author: string; content: string };

export function filterMessages(
  messages: readonly HistoryMessage[],
  query: string,
): readonly HistoryMessage[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) return messages;
  return messages.filter((message) => message.content.toLowerCase().includes(normalizedQuery));
}

export function WebMessageHistory({
  channelName,
  messages,
  draft,
  onDraftChange,
  onSend,
  disabled,
  loading,
}: {
  channelName: string;
  messages: readonly HistoryMessage[];
  draft: string;
  onDraftChange: (value: string) => void;
  onSend: () => void;
  disabled: boolean;
  loading: boolean;
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const visibleMessages = filterMessages(messages, searchQuery);
  return (
    <div className="message-workspace lattice-web-message-history">
      <div className="control-heading">
        <p className="eyebrow">#{channelName}</p>
        <h2>Messages</h2>
      </div>
      <FormField label="Search messages" htmlFor="message-history-search">
        <input
          id="message-history-search"
          type="search"
          value={searchQuery}
          onChange={(event) => setSearchQuery(event.target.value)}
        />
      </FormField>
      <ol className="message-list" aria-live="polite" aria-busy={loading}>
        {visibleMessages.map((message) => (
          <li key={message.id}>
            <code>{message.author}</code>
            <p>{message.content}</p>
          </li>
        ))}
        {loading ? (
          <li className="empty-state" role="status">
            Loading local message history…
          </li>
        ) : (
          visibleMessages.length === 0 && (
            <li className="empty-state">
              {searchQuery.trim()
                ? "No locally accepted messages match this search."
                : "No locally accepted messages yet."}
            </li>
          )
        )}
      </ol>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          onSend();
        }}
      >
        <FormField label="New message" htmlFor="message-draft">
          <textarea
            id="message-draft"
            value={draft}
            onChange={(event) => onDraftChange(event.target.value)}
            maxLength={4096}
          />
        </FormField>
        <ActionButton
          className="button button-primary"
          type="submit"
          disabled={disabled || !draft.trim()}
        >
          Encrypt and send
        </ActionButton>
      </form>
    </div>
  );
}

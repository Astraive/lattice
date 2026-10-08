import { ActionButton, FormField } from "@lattice/ui-shared";

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
  messages: readonly { id: string; author: string; content: string }[];
  draft: string;
  onDraftChange: (value: string) => void;
  onSend: () => void;
  disabled: boolean;
  loading: boolean;
}) {
  return (
    <div className="message-workspace lattice-web-message-history">
      <div className="control-heading">
        <p className="eyebrow">#{channelName}</p>
        <h2>Messages</h2>
      </div>
      <ol className="message-list" aria-live="polite" aria-busy={loading}>
        {messages.map((message) => (
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
          messages.length === 0 && (
            <li className="empty-state">No locally accepted messages yet.</li>
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

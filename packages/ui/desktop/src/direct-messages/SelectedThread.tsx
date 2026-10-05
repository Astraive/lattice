import { ActionButton, FormField } from "@lattice/ui-shared";
import { ChatCircleText, PaperPlaneTilt } from "@phosphor-icons/react";
import type { HistoryItem } from "./types";

export function SelectedThread({
  peerIdentity,
  groupReference,
  history,
  identityReady,
  busy,
  messageDraft,
  onMessageDraftChange,
  onSendMessage,
}: {
  peerIdentity: string | undefined;
  groupReference: string | undefined;
  history: HistoryItem[];
  identityReady: boolean;
  busy: boolean;
  messageDraft: string;
  onMessageDraftChange: (value: string) => void;
  onSendMessage: () => void;
}) {
  return (
    <section className="dm-thread" aria-label="Selected direct-message conversation">
      <header className="dm-thread__header">
        <span className="dm-list__avatar" aria-hidden="true">
          {peerIdentity?.slice(0, 1).toUpperCase() ?? <ChatCircleText size={20} />}
        </span>
        <div>
          <h2>{peerIdentity ?? "Select a conversation"}</h2>
          <p>
            {peerIdentity
              ? "Pairwise MLS conversation"
              : "Messages remain local until an authenticated exchange."}
          </p>
        </div>
        {groupReference && <span className="dm-thread__group">{groupReference}</span>}
      </header>
      <div className="dm-thread__history" aria-live="polite">
        {peerIdentity ? (
          history.length ? (
            history.map((item) => (
              <article className="dm-message" key={item.packetId}>
                <div className="dm-message__meta">
                  <strong>{item.authorIdentity}</strong>
                  <code>{item.packetId}</code>
                </div>
                <p>{item.content}</p>
              </article>
            ))
          ) : (
            <p className="dm-thread__empty">No message history in this conversation yet.</p>
          )
        ) : (
          <p className="dm-thread__empty">
            Choose a conversation or create one in Pairing &amp; setup.
          </p>
        )}
      </div>
      {peerIdentity && (
        <form
          className="dm-composer"
          onSubmit={(event) => {
            event.preventDefault();
            onSendMessage();
          }}
        >
          <FormField label="Message" htmlFor="dm-message">
            <textarea
              id="dm-message"
              value={messageDraft}
              onChange={(event) => onMessageDraftChange(event.currentTarget.value)}
              rows={2}
              placeholder="Write an encrypted message"
            />
          </FormField>
          <ActionButton
            type="submit"
            tone="primary"
            disabled={!identityReady || busy || messageDraft.trim().length === 0}
          >
            <PaperPlaneTilt size={17} aria-hidden="true" /> Encrypt and queue
          </ActionButton>
          <p>Queued locally. Forwarding and peer acceptance are not confirmed.</p>
        </form>
      )}
    </section>
  );
}

import { ActionButton, FormField, ModalDialog } from "@lattice/ui-shared";
import type { SupplementaryDialog } from "./ConversationList";
import type { DirectMessageWorkspaceProps } from "./types";

export function SupplementaryDialogs({
  dialog,
  onClose,
  ...props
}: DirectMessageWorkspaceProps & { dialog: SupplementaryDialog; onClose: () => void }) {
  return (
    <>
      <ModalDialog
        open={dialog === "conversations"}
        title="Current conversations"
        description="Accepted pairwise conversations stored on this device."
        onClose={onClose}
      >
        {props.conversations.length ? (
          <ul className="dm-dialog-list">
            {props.conversations.map((item) => (
              <li key={item.groupReference}>
                <strong>{item.peerIdentity}</strong>
                <code>{item.groupReference}</code>
                <span>{item.closed ? "Closed" : "Open"}</span>
                <ActionButton
                  tone="quiet"
                  disabled={item.closed}
                  onClick={() => {
                    props.onSelectConversation(item.groupReference);
                    onClose();
                  }}
                >
                  Open conversation
                </ActionButton>
              </li>
            ))}
          </ul>
        ) : (
          <p>No accepted pairwise conversations.</p>
        )}
      </ModalDialog>
      <ModalDialog
        open={dialog === "invitations"}
        title="Pending invitations"
        description="Review each invitation and explicitly accept or decline it."
        onClose={onClose}
      >
        {props.invitations.length ? (
          <ul className="dm-dialog-list">
            {props.invitations.map((item) => (
              <li key={item.packetId}>
                <strong>{item.peerIdentity}</strong>
                <code>Group {item.groupReference}</code>
                <code>Packet {item.packetId}</code>
                <div>
                  <ActionButton
                    tone="primary"
                    disabled={props.busy}
                    onClick={() => props.onAcceptInvitation(item)}
                  >
                    Accept invitation
                  </ActionButton>
                  <ActionButton
                    tone="quiet"
                    disabled={props.busy}
                    onClick={() => props.onDeclineInvitation(item)}
                  >
                    Decline invitation
                  </ActionButton>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p>No pending invitations.</p>
        )}
      </ModalDialog>
      <ModalDialog
        open={dialog === "credential"}
        title="KeyPackage &amp; credential"
        description="Protected local credential input and published public KeyPackage."
        onClose={onClose}
      >
        <FormField label="Trusted credential vector (hex)" htmlFor="dm-dialog-credential">
          <textarea id="dm-dialog-credential" value={props.credentialHex} readOnly rows={4} />
        </FormField>
        {props.publishedKeyPackage ? (
          <FormField
            label="Published public KeyPackage (Base64)"
            htmlFor="dm-published-key-package"
          >
            <textarea
              id="dm-published-key-package"
              readOnly
              value={props.publishedKeyPackage}
              rows={6}
              spellCheck={false}
            />
          </FormField>
        ) : (
          <p>No KeyPackage has been published in this session.</p>
        )}
        <p>Share public bytes and this device&apos;s full fingerprint out of band.</p>
      </ModalDialog>
      <ModalDialog
        open={dialog === "exchange"}
        title="Authenticated exchange"
        description="Details from the most recent authenticated one-shot exchange."
        onClose={onClose}
      >
        {props.exchange ? (
          <dl className="dm-exchange-details">
            <dt>Authenticated peer</dt>
            <dd>
              <code>{props.exchange.peerFingerprint}</code>
            </dd>
            <dt>Local listener</dt>
            <dd>
              <code>{props.exchange.listenAddress}</code>
            </dd>
            <dt>Sent packet</dt>
            <dd>
              {props.exchange.sentPacketId ? (
                <code>{props.exchange.sentPacketId}</code>
              ) : (
                "No packet sent"
              )}
            </dd>
            <dt>Peer ingress state</dt>
            <dd>{props.exchange.peerIngressState ?? "Unconfirmed"}</dd>
            <dt>Received packet</dt>
            <dd>
              {props.exchange.receivedPacketId ? (
                <code>{props.exchange.receivedPacketId}</code>
              ) : (
                "No packet received"
              )}
            </dd>
            <dt>Received ingress state</dt>
            <dd>{props.exchange.receivedIngressState ?? "No ingress state"}</dd>
          </dl>
        ) : (
          <p>No authenticated exchange has been completed in this session.</p>
        )}
        <p>
          Ingress states describe peer processing only; invitation-pending means stored before user
          consent, not accepted.
        </p>
      </ModalDialog>
    </>
  );
}

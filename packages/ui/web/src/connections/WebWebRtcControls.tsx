import { ActionButton, FormField, StatusNotice } from "@lattice/ui-shared";

export function WebWebRtcControls({
  status,
  iceServers,
  signal,
  onIceServersChange,
  onSignalChange,
  onCreateOffer,
  onRestartIce,
  onAcceptOffer,
  onAcceptAnswer,
  onDisconnect,
}: {
  status: string;
  iceServers: string;
  signal: string;
  onIceServersChange: (value: string) => void;
  onSignalChange: (value: string) => void;
  onCreateOffer: () => void;
  onRestartIce: () => void;
  onAcceptOffer: () => void;
  onAcceptAnswer: () => void;
  onDisconnect: () => void;
}) {
  return (
    <section className="web-controls" aria-labelledby="webrtc-title">
      <div className="control-heading">
        <p className="eyebrow">Direct peer transport</p>
        <h2 id="webrtc-title">WebRTC event sync</h2>
      </div>
      <StatusNotice kind="info">{status}</StatusNotice>
      <FormField label="Optional ICE servers · JSON" htmlFor="webrtc-ice-servers">
        <textarea
          id="webrtc-ice-servers"
          value={iceServers}
          onChange={(event) => onIceServersChange(event.target.value)}
          spellCheck={false}
          autoComplete="off"
          placeholder='[{"urls":"stun:stun.example.net:3478"}]'
        />
      </FormField>
      <div className="button-row">
        <ActionButton className="button button-quiet" type="button" onClick={onCreateOffer}>
          Create offer
        </ActionButton>
        <ActionButton className="button button-quiet" type="button" onClick={onRestartIce}>
          Restart ICE
        </ActionButton>
        <ActionButton className="button button-quiet" type="button" onClick={onAcceptOffer}>
          Accept offer
        </ActionButton>
        <ActionButton className="button button-quiet" type="button" onClick={onAcceptAnswer}>
          Accept answer
        </ActionButton>
        <ActionButton className="button button-quiet" type="button" onClick={onDisconnect}>
          Disconnect
        </ActionButton>
      </div>
      <FormField label="WebRTC offer or answer · transfer out of band" htmlFor="webrtc-signal">
        <textarea
          id="webrtc-signal"
          value={signal}
          onChange={(event) => onSignalChange(event.target.value)}
          spellCheck={false}
          autoComplete="off"
        />
      </FormField>
      <p className="field-hint">
        One side creates an offer and transfers it to the other side, which accepts it and returns
        the answer. No signaling service or ICE server is configured; direct connectivity depends on
        browser/network support. SDP reveals candidate network addresses, so transfer it only
        through a channel you trust. Core verifies signed events and current membership
        independently of the connection.
      </p>
    </section>
  );
}

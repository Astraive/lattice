import { ActionButton, FormField, StatusNotice } from "@lattice/ui-shared";
import {
  ArrowsClockwise,
  ArrowsLeftRight,
  GearSix,
  IdentificationCard,
  Key,
  Network,
  Plus,
} from "@phosphor-icons/react";
import type { RefObject } from "react";
import type { ExchangeResult } from "./types";

export function PairingSetupPane({
  runtimeAvailable,
  identityReady,
  credentialHex,
  onCredentialHexChange,
  peerFingerprint,
  onPeerFingerprintChange,
  peerKeyPackage,
  onPeerKeyPackageChange,
  connectAddress,
  onConnectAddressChange,
  listenAddress,
  onListenAddressChange,
  busy,
  status,
  error,
  exchange,
  onPublishKeyPackage,
  onRefresh,
  onCreateConversation,
  onSyncOnce,
  credentialInputRef,
  setupHeadingRef,
}: {
  runtimeAvailable: boolean;
  identityReady: boolean;
  credentialHex: string;
  onCredentialHexChange: (value: string) => void;
  peerFingerprint: string;
  onPeerFingerprintChange: (value: string) => void;
  peerKeyPackage: string;
  onPeerKeyPackageChange: (value: string) => void;
  connectAddress: string;
  onConnectAddressChange: (value: string) => void;
  listenAddress: string;
  onListenAddressChange: (value: string) => void;
  busy: boolean;
  status: string;
  error: string | null;
  exchange: ExchangeResult | null;
  onPublishKeyPackage: () => void;
  onRefresh: () => void;
  onCreateConversation: () => void;
  onSyncOnce: () => void;
  credentialInputRef: RefObject<HTMLTextAreaElement | null>;
  setupHeadingRef: RefObject<HTMLHeadingElement | null>;
}) {
  const eligible = runtimeAvailable && identityReady && !busy;
  return (
    <aside className="dm-setup" aria-label="Pairing and setup">
      <header className="dm-setup__heading">
        <GearSix size={20} aria-hidden="true" />
        <h2 ref={setupHeadingRef} tabIndex={-1}>
          Pairing &amp; setup
        </h2>
      </header>
      {!runtimeAvailable && (
        <StatusNotice kind="warning">
          Open the Tauri Desktop app to manage protected direct messages.
        </StatusNotice>
      )}
      {runtimeAvailable && !identityReady && (
        <StatusNotice kind="warning">
          Initialize or reopen the protected device identity first.
        </StatusNotice>
      )}
      <fieldset disabled={!eligible}>
        <legend>
          <Key size={15} aria-hidden="true" /> Local X.509 credential
        </legend>
        <FormField label="Trusted credential vector (hex)" htmlFor="dm-credential-vector">
          <textarea
            ref={credentialInputRef}
            id="dm-credential-vector"
            value={credentialHex}
            onChange={(event) => onCredentialHexChange(event.currentTarget.value)}
            rows={3}
            spellCheck={false}
          />
        </FormField>
        <div className="dm-setup__actions">
          <ActionButton tone="primary" disabled={!eligible} onClick={onPublishKeyPackage}>
            <Key size={15} aria-hidden="true" /> Publish KeyPackage
          </ActionButton>
          <ActionButton tone="quiet" disabled={!eligible} onClick={onRefresh}>
            <ArrowsClockwise size={15} aria-hidden="true" /> Refresh local inbox
          </ActionButton>
        </div>
      </fieldset>
      <section className="dm-setup__group" aria-labelledby="dm-peer-title">
        <h3 id="dm-peer-title">
          <IdentificationCard size={16} aria-hidden="true" /> Peer information
        </h3>
        <div className="dm-setup__fields">
          <FormField
            label="Peer fingerprint (64 hex characters; pin it first)"
            htmlFor="dm-peer-fingerprint"
          >
            <input
              id="dm-peer-fingerprint"
              value={peerFingerprint}
              onChange={(event) => onPeerFingerprintChange(event.currentTarget.value)}
            />
          </FormField>
          <FormField label="Peer KeyPackage (Base64)" htmlFor="dm-peer-key-package">
            <textarea
              id="dm-peer-key-package"
              value={peerKeyPackage}
              onChange={(event) => onPeerKeyPackageChange(event.currentTarget.value)}
              rows={2}
            />
          </FormField>
        </div>
        <ActionButton
          tone="primary"
          disabled={!identityReady || busy}
          onClick={onCreateConversation}
        >
          <Plus size={15} aria-hidden="true" /> Create pairwise conversation
        </ActionButton>
      </section>
      <section className="dm-setup__group" aria-labelledby="dm-network-title">
        <h3 id="dm-network-title">
          <Network size={16} aria-hidden="true" /> Network configuration
        </h3>
        <div className="dm-setup__fields">
          <FormField label="Peer TCP listener address" htmlFor="dm-peer-listener-address">
            <input
              id="dm-peer-listener-address"
              value={connectAddress}
              onChange={(event) => onConnectAddressChange(event.currentTarget.value)}
              placeholder="192.168.1.20:7332"
            />
          </FormField>
          <FormField label="Local listener address" htmlFor="dm-local-listener-address">
            <input
              id="dm-local-listener-address"
              value={listenAddress}
              onChange={(event) => onListenAddressChange(event.currentTarget.value)}
            />
          </FormField>
        </div>
        <p>
          Run the authenticated exchange on both peers concurrently. Listener defaults to loopback;
          choose a reachable local interface for another device.
        </p>
        <ActionButton
          tone="primary"
          disabled={
            !identityReady ||
            busy ||
            !connectAddress.trim() ||
            !/^[\da-f]{64}$/i.test(peerFingerprint.trim())
          }
          onClick={onSyncOnce}
        >
          <ArrowsLeftRight size={15} aria-hidden="true" /> Run one authenticated DM exchange
        </ActionButton>
      </section>
      {exchange && (
        <StatusNotice kind="info">
          Authenticated peer {exchange.peerFingerprint}; received state{" "}
          {exchange.receivedIngressState ?? "no packet"}. Peer ingress for sent packet:{" "}
          {exchange.peerIngressState ?? "none"}. Invitation-pending means stored before user
          consent, not accepted.
        </StatusNotice>
      )}
      {error ? (
        <StatusNotice kind="error" title="Direct-message action failed">
          {error}
        </StatusNotice>
      ) : (
        <StatusNotice kind="info">{status}</StatusNotice>
      )}
    </aside>
  );
}

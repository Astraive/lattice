import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { DirectMessageWorkspace } from "../src";

test("direct-message workspace shows pairing setup beside chat and keeps extra details closed", () => {
  const markup = renderToStaticMarkup(
    createElement(DirectMessageWorkspace, {
      runtimeAvailable: false,
      identityReady: false,
      credentialHex: "",
      onCredentialHexChange: () => {},
      peerFingerprint: "",
      onPeerFingerprintChange: () => {},
      peerKeyPackage: "",
      onPeerKeyPackageChange: () => {},
      publishedKeyPackage: "",
      connectAddress: "",
      onConnectAddressChange: () => {},
      listenAddress: "127.0.0.1:7332",
      onListenAddressChange: () => {},
      messageDraft: "",
      onMessageDraftChange: () => {},
      conversations: [{ groupReference: "a1b2", peerIdentity: "Alice", closed: false }],
      invitations: [],
      history: [{ packetId: "c3d4", authorIdentity: "Alice", content: "Ready to exchange." }],
      selectedGroup: "a1b2",
      onSelectConversation: () => {},
      onPublishKeyPackage: () => {},
      onCreateConversation: () => {},
      onRefresh: () => {},
      onAcceptInvitation: () => {},
      onDeclineInvitation: () => {},
      onSendMessage: () => {},
      onSyncOnce: () => {},
      busy: false,
      status: "Local inbox refreshed.",
      error: null,
      exchange: null,
    }),
  );

  const setupIndex = markup.indexOf('<aside class="dm-setup"');
  const firstPopupIndex = markup.indexOf("<dialog");
  expect(setupIndex).toBeGreaterThan(-1);
  expect(setupIndex).toBeLessThan(firstPopupIndex);
  expect(markup).toContain("Pairing &amp; setup");
  expect(markup).toContain("Ready to exchange.");
  expect(markup).toContain("Encrypt and queue");
  expect(markup).toContain("Current conversations");
  expect(markup).toContain("Pending invitations");
  expect(markup).not.toMatch(/<dialog[^>]*\sopen(?:\s|>)/);
});

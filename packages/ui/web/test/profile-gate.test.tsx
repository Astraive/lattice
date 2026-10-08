import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { WebProfileGate, WebWorkspaceShell } from "../src";

test("closed profile gate renders setup without workspace-only navigation", () => {
  const markup = renderToStaticMarkup(
    createElement(WebProfileGate, {
      isOpen: false,
      setup: createElement(
        "form",
        null,
        createElement("button", { type: "button" }, "Open profile"),
      ),
      workspace: createElement("nav", null, "Connections"),
    }),
  );
  expect(markup).toContain("Open profile");
  expect(markup).not.toContain("Connections");
});

test("open profile gate renders workspace destinations", () => {
  const markup = renderToStaticMarkup(
    createElement(WebProfileGate, {
      isOpen: true,
      setup: createElement("form", null, "Setup"),
      workspace: createElement("nav", null, "Spaces · Connections · Identity"),
    }),
  );
  expect(markup).toContain("Spaces · Connections · Identity");
  expect(markup).not.toContain("Setup");
});

test("mobile workspace keeps navigation labelled and its scroll region keyboard-focusable", () => {
  const markup = renderToStaticMarkup(
    createElement(
      WebWorkspaceShell,
      {
        destinations: [{ id: "spaces", label: "Spaces", icon: "S" }],
        activeDestination: "spaces",
        onDestinationChange: () => {},
        spaces: [],
        activeSpace: null,
        onSpaceChange: () => {},
        channels: [],
        activeChannel: null,
        onChannelChange: () => {},
        onLockProfile: () => {},
      },
      createElement("p", null, "Workspace content"),
    ),
  );
  expect(markup).toContain('aria-label="Open spaces and channels"');
  expect(markup).toContain('aria-controls="lattice-space-drawer"');
  expect(markup).toContain('id="lattice-space-drawer"');
  expect(markup).toContain('aria-label="Space and channel navigation"');
  expect(markup).toContain('id="workspace-content" tabindex="0"');
  expect(markup).toContain('aria-current="page"');
  expect(markup).toContain("No Spaces yet");
});

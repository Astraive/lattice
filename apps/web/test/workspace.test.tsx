import { expect, test } from "bun:test";
import { WebProfileGate, WebWorkspaceShell } from "@lattice/ui-web";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

const destinations = [
  { id: "spaces", label: "Spaces", icon: createElement("span", null, "S") },
  { id: "connections", label: "Connections", icon: createElement("span", null, "C") },
  { id: "identity", label: "Identity", icon: createElement("span", null, "I") },
];

function workspace(activeDestination: string) {
  return createElement(
    WebWorkspaceShell,
    {
      destinations,
      activeDestination,
      onDestinationChange: () => undefined,
      spaces: [],
      activeSpace: null,
      onSpaceChange: () => undefined,
      channels: [],
      activeChannel: null,
      onChannelChange: () => undefined,
      onLockProfile: () => undefined,
    },
    createElement(
      "h1",
      null,
      `${destinations.find((destination) => destination.id === activeDestination)?.label} page`,
    ),
  );
}

test("closed profile gate exposes setup without workspace navigation", () => {
  const markup = renderToStaticMarkup(
    createElement(WebProfileGate, {
      isOpen: false,
      setup: createElement(
        "form",
        null,
        createElement("button", { type: "button" }, "Open profile"),
      ),
      workspace: workspace("spaces"),
    }),
  );
  expect(markup).toContain("Open profile");
  expect(markup).not.toContain('aria-label="Main navigation"');
  expect(markup).not.toContain("Connections page");
});

test("active Web destination is exposed as the current page", () => {
  const markup = renderToStaticMarkup(workspace("connections"));
  expect(markup).toContain("Connections page");
  expect(markup).toContain('aria-current="page"');
  expect(markup).toContain("Identity");
});

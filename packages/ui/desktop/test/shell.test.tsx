import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { DesktopWorkspaceShell } from "../src";

const baseProps = {
  destinations: [
    { id: "spaces", label: "Spaces", icon: "S" },
    { id: "identity", label: "Identity", icon: "I" },
  ],
  activeDestination: "identity",
  onDestinationChange: () => {},
  spaces: [{ id: "space-a", label: "Studio" }],
  activeSpace: "space-a",
  onSpaceChange: () => {},
  channels: [{ id: "general", label: "General", kind: "text" as const }],
  activeChannel: "general",
  onChannelChange: () => {},
  children: createElement("p", null, "Identity controls"),
};

test("shell exposes the selected destination and current channel to assistive technology", () => {
  const markup = renderToStaticMarkup(createElement(DesktopWorkspaceShell, baseProps));
  expect(markup).toContain('aria-current="page"');
  expect(markup).toContain("Identity controls");
  expect(markup).toContain("General");
  expect(markup).toContain('aria-label="Main navigation"');
  expect(markup).toContain('id="workspace-content" tabindex="0"');
});

import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  DeliveryStatus,
  FormField,
  IconActionButton,
  LatticeLogo,
  LatticeMark,
  ModalDialog,
  PlainText,
  StatusNotice,
} from "../src";

describe("DeliveryStatus", () => {
  test.each([
    ["queued", "Queued"],
    ["forwarded", "Forwarded"],
    ["delivered-to-device", "Delivered to device"],
    ["read-local", "Read on this device"],
    ["error", "Error"],
  ] as const)("announces the %s state in text", (state, label) => {
    const markup = renderToStaticMarkup(createElement(DeliveryStatus, { state }));

    expect(markup).toContain(`role="status"`);
    expect(markup).toContain(`aria-label="Delivery status: ${label}"`);
    expect(markup).toContain(`>${label}</span>`);
    expect(markup).toContain(`delivery-status--${state}`);
  });
});

test("PlainText renders malicious markup as text rather than elements", () => {
  const maliciousText = '<img src="x" onerror="alert(1)">';
  const markup = renderToStaticMarkup(createElement(PlainText, null, maliciousText));

  expect(markup).toContain("&lt;img");
  expect(markup).toContain("&gt;");
  expect(markup).not.toContain("<img");
});
test("FormField associates hints and errors with its control", () => {
  const markup = renderToStaticMarkup(
    createElement(
      FormField,
      { label: "Profile name", htmlFor: "profile-name", error: "Name is required" },
      createElement("input", { id: "profile-name" }),
    ),
  );

  expect(markup).toContain('for="profile-name"');
  expect(markup).toContain('aria-describedby="profile-name-description"');
  expect(markup).toContain('aria-invalid="true"');
  expect(markup).toContain("Name is required");
});

test("IconActionButton exposes its operation to assistive technology", () => {
  const markup = renderToStaticMarkup(
    createElement(IconActionButton, { label: "Show invitations" }, "Icon"),
  );

  expect(markup).toContain('aria-label="Show invitations"');
  expect(markup).toContain('title="Show invitations"');
  expect(markup).toContain(">Icon</button>");
});

test("LatticeLogo references the shared SVG instead of duplicating path markup", () => {
  const markup = renderToStaticMarkup(createElement(LatticeLogo));

  expect(markup).toContain('src="/lattice-logo.svg"');
  expect(markup).not.toContain("<svg");
});

test("LatticeMark references the shared SVG symbol", () => {
  const markup = renderToStaticMarkup(createElement(LatticeMark));

  expect(markup).toContain('src="/lattice-mark.svg"');
  expect(markup).not.toContain("<svg");
});

test("StatusNotice presents an icon alongside textual meaning", () => {
  const markup = renderToStaticMarkup(
    createElement(StatusNotice, { kind: "warning" }, "Check the pinned identity."),
  );

  expect(markup).toContain('role="status"');
  expect(markup).toContain('aria-hidden="true"');
  expect(markup).toContain("Check the pinned identity.");
});

test("ModalDialog names the dismiss action and exposes its heading", () => {
  const markup = renderToStaticMarkup(
    createElement(
      ModalDialog,
      {
        open: false,
        title: "Pending invitations",
        description: "Review the invitation before accepting it.",
        onClose: () => {},
      },
      "Invitation list",
    ),
  );

  expect(markup).toContain("<dialog");
  expect(markup).toMatch(/aria-labelledby="[^"]+"/);
  expect(markup).toContain("Pending invitations");
  expect(markup).toContain('aria-label="Close Pending invitations"');
  expect(markup).toContain("Review the invitation before accepting it.");
});

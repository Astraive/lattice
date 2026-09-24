import { describe, expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { DeliveryStatus, PlainText } from "../src/components";

describe("DeliveryStatus", () => {
  test.each([
    ["queued", "Queued"],
    ["forwarded", "Forwarded"],
    ["delivered", "Delivered"],
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

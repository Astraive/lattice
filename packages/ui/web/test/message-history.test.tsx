import { expect, test } from "bun:test";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { filterMessages, WebMessageHistory } from "../src/spaces/WebMessageHistory";

function renderHistory(loading: boolean) {
  return renderToStaticMarkup(
    createElement(WebMessageHistory, {
      channelName: "general",
      messages: [],
      draft: "",
      onDraftChange: () => {},
      onSend: () => {},
      disabled: false,
      loading,
    }),
  );
}

test("distinguishes pending history from a completed empty history", () => {
  const loadingMarkup = renderHistory(true);
  expect(loadingMarkup).toContain('aria-busy="true"');
  expect(loadingMarkup).toContain('role="status">Loading local message history…</li>');
  expect(loadingMarkup).not.toContain("No locally accepted messages yet.");

  const emptyMarkup = renderHistory(false);
  expect(emptyMarkup).toContain('aria-busy="false"');
  expect(emptyMarkup).toContain("No locally accepted messages yet.");
  expect(emptyMarkup).not.toContain("Loading local message history…");
});

test("message search is local, case-insensitive, and ignores blank queries", () => {
  const messages = [
    { id: "one", author: "alice", content: "hello from Lattice" },
    { id: "two", author: "bob", content: "checkpoint received" },
  ];

  expect(filterMessages(messages, "  CHECKPOINT ")).toEqual([messages[1]]);
  expect(filterMessages(messages, " ")).toEqual(messages);
  expect(filterMessages(messages, "not present")).toEqual([]);
});

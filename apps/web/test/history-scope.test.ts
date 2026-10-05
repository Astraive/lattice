import { expect, test } from "bun:test";
import { messagesForScope } from "../src/history-scope";

const history = {
  scope: "space-a:channel-a",
  messages: [{ id: "message-a", content: "private channel content" }],
  loading: false,
};

test("withholds history from a different selected channel", () => {
  expect(messagesForScope("space-a:channel-b", history)).toEqual([]);
});

test("shows history for its matching channel scope", () => {
  expect(messagesForScope("space-a:channel-a", history)).toEqual(history.messages);
});

import { expect, test } from "bun:test";
import { historyForConversation } from "../src/features/identity/DirectMessagePanel";

const history = {
  groupReference: "group-a",
  items: [{ packetId: "packet-a", authorIdentity: "peer-a", content: "private message" }],
};

test("does not render one conversation's history under another selected conversation", () => {
  expect(historyForConversation("group-b", history)).toEqual([]);
});

test("renders history only for its selected conversation", () => {
  expect(historyForConversation("group-a", history)).toEqual(history.items);
});

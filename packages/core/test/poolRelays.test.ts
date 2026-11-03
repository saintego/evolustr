import { SimplePool } from "nostr-tools/pool";
import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { afterAll, describe, expect, it } from "vitest";
import { VAULT_KIND, fetchReplaceable, poolRelays, publishReplaceable, secretKeySigner } from "../src/index.ts";
import { startTestRelay } from "./support/relay.ts";

const relay = startTestRelay(7790);
const pool = new SimplePool();
afterAll(async () => {
  pool.destroy();
  await relay.close();
});

// Unreachable relays are covered with memoryRelays: in Node, nostr-tools closes a
// still-connecting WebSocket on error, which Node reports as an uncaught error.
describe("poolRelays against a real WebSocket relay", () => {
  it("counts a relay that sent EOSE as answered (regression: closing used to mark it failed)", async () => {
    const relays = poolRelays(pool);
    const r = await relays.query(["ws://localhost:7790"], { kinds: [VAULT_KIND], "#d": ["nothing"] }, 3000);
    expect(r).toMatchObject({ answered: ["ws://localhost:7790"], failed: [] });
  });

  it("publishes and fetches a replaceable event", async () => {
    const sk = generateSecretKey();
    const relays = poolRelays(pool);
    const event = { kind: VAULT_KIND, created_at: 10, tags: [["d", "evolustr:test"]], content: "hello" };
    await publishReplaceable(relays, ["ws://localhost:7790"], secretKeySigner(sk), event, 3000);
    const f = await fetchReplaceable(relays, ["ws://localhost:7790"], { author: getPublicKey(sk), kind: VAULT_KIND, d: "evolustr:test" }, 3000);
    expect(f.kind === "found" && f.event.content).toBe("hello");
  });
});

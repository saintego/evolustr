import { SimplePool } from "nostr-tools/pool";
import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { afterAll, describe, expect, it } from "vitest";
import { VAULT_KIND, fetchReplaceable, poolRelays, publishReplaceable, secretKeySigner } from "../src/index.ts";
import { startTestRelay } from "./support/relay.ts";

const relay = startTestRelay(7790);
const silent = startTestRelay(7791, { silent: true });
const pool = new SimplePool();
afterAll(async () => {
  pool.destroy();
  await relay.close();
  await silent.close();
});

// Unreachable relays are covered with memoryRelays: in Node, nostr-tools closes a
// still-connecting WebSocket on error, which Node reports as an uncaught error.
describe("poolRelays against a real WebSocket relay", () => {
  it("counts a relay that sent EOSE as answered (regression: closing used to mark it failed)", async () => {
    const relays = poolRelays(pool);
    const r = await relays.query(["ws://localhost:7790"], { kinds: [VAULT_KIND], "#d": ["nothing"] }, 3000);
    expect(r).toMatchObject({ answered: ["ws://localhost:7790"], failed: [] });
  });

  it("with a quorum, doesn't wait for a relay that never answers (#60), but keeps it pending (#62)", async () => {
    const relays = poolRelays(pool);
    const urls = ["ws://localhost:7790", "ws://localhost:7791"];
    const start = Date.now();
    const r = await relays.query(urls, { kinds: [VAULT_KIND], "#d": ["nothing"] }, 3000, { quorum: 1 });
    expect(Date.now() - start).toBeLessThan(2000);
    expect(r).toMatchObject({ answered: ["ws://localhost:7790"], failed: ["ws://localhost:7791"], pending: ["ws://localhost:7791"] });
    // The rest: the silent relay times out, still pending (it may hold the event).
    expect(await r.rest).toMatchObject({ answered: ["ws://localhost:7790"], pending: ["ws://localhost:7791"] });
    // Nothing found at the quorum: the silent relay might have it, so not "none".
    const f = await fetchReplaceable(relays, urls, { author: "00".repeat(32), kind: VAULT_KIND, d: "nothing" }, 3000, 1);
    expect(f).toEqual({ kind: "incomplete" });
  }, 15000);

  it("with a quorum, a found event returns without waiting (#60)", async () => {
    const sk = generateSecretKey();
    const relays = poolRelays(pool);
    const event = { kind: VAULT_KIND, created_at: 11, tags: [["d", "evolustr:quorum"]], content: "here" };
    await publishReplaceable(relays, ["ws://localhost:7790"], secretKeySigner(sk), event, 3000);
    const start = Date.now();
    const f = await fetchReplaceable(relays, ["ws://localhost:7790", "ws://localhost:7791"], { author: getPublicKey(sk), kind: VAULT_KIND, d: "evolustr:quorum" }, 3000, 1);
    expect(Date.now() - start).toBeLessThan(2000);
    expect(f.kind === "found" && f.event.content).toBe("here");
  }, 10000);

  it("publishes and fetches a replaceable event", async () => {
    const sk = generateSecretKey();
    const relays = poolRelays(pool);
    const event = { kind: VAULT_KIND, created_at: 10, tags: [["d", "evolustr:test"]], content: "hello" };
    await publishReplaceable(relays, ["ws://localhost:7790"], secretKeySigner(sk), event, 3000);
    const f = await fetchReplaceable(relays, ["ws://localhost:7790"], { author: getPublicKey(sk), kind: VAULT_KIND, d: "evolustr:test" }, 3000);
    expect(f.kind === "found" && f.event.content).toBe("hello");
  });
});

import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import {
  VAULT_KIND,
  appVaultDTag,
  createCompatibleVault,
  fetchReplaceable,
  memoryRelays,
  nip07Signer,
  nip44OpenSecret,
  nip44SealSecret,
  publishReplaceable,
  randomBytes,
  readVaultEvent,
  secretKeySigner,
  unwrap,
  vaultEvent,
} from "../src/index.ts";

const URLS = ["wss://r1", "wss://r2", "wss://r3"];
const user = () => {
  const sk = generateSecretKey();
  const pubkey = getPublicKey(sk);
  return { signer: secretKeySigner(sk), pubkey, ctx: { pubkey, appId: "https://app.example" } };
};

describe("vault events over relays", () => {
  it("publishes and fetches a vault; NIP-44 wrap opens through the signer", async () => {
    const { signer, pubkey, ctx } = user();
    const { relays } = memoryRelays();
    const s = randomBytes(16);
    const vault = unwrap(createCompatibleVault(ctx, { s, nip44Ct: await nip44SealSecret(signer, pubkey, s), now: 10 }));
    await publishReplaceable(relays, URLS, signer, vaultEvent(ctx, vault, 10));

    const fetched = await fetchReplaceable(relays, URLS, { author: pubkey, kind: VAULT_KIND, d: appVaultDTag(pubkey, ctx.appId) });
    expect(fetched.kind).toBe("found");
    if (fetched.kind !== "found") return;
    expect(fetched.complete).toBe(true);
    const parsed = unwrap(readVaultEvent(ctx, fetched.event));
    expect(parsed).toEqual(vault);
    expect(unwrap(await nip44OpenSecret(signer, pubkey, parsed))).toEqual(s);
  });

  it("reports none only when every relay answered", async () => {
    const { pubkey } = user();
    const down = new Set(["wss://r3"]);
    const { relays } = memoryRelays({ down });
    const addr = { author: pubkey, kind: VAULT_KIND, d: "evolustr:v1:x" };
    expect(await fetchReplaceable(relays, URLS, addr)).toEqual({ kind: "incomplete" });
    down.clear();
    expect(await fetchReplaceable(relays, URLS, addr)).toEqual({ kind: "none" });
  });

  it("picks the newest version when relays disagree", async () => {
    const { signer, pubkey } = user();
    const mem = memoryRelays();
    const base = { kind: VAULT_KIND, tags: [["d", "evolustr:v1:x"]] };
    const old = await signer.signEvent({ ...base, created_at: 1, content: "old" });
    const recent = await signer.signEvent({ ...base, created_at: 2, content: "new" });
    mem.put("wss://r1", old);
    mem.put("wss://r2", recent);
    const f = await fetchReplaceable(mem.relays, URLS, { author: pubkey, kind: VAULT_KIND, d: "evolustr:v1:x" });
    expect(f.kind === "found" && f.event.content).toBe("new");
  });

  it("ignores events from another author or with a bad signature", async () => {
    const a = user();
    const b = user();
    const mem = memoryRelays();
    const d = appVaultDTag(a.pubkey, a.ctx.appId);
    const forged = { ...(await b.signer.signEvent({ kind: VAULT_KIND, created_at: 5, tags: [["d", d]], content: "{}" })), pubkey: a.pubkey };
    mem.store("wss://r1").push(forged);
    expect(await fetchReplaceable(mem.relays, URLS, { author: a.pubkey, kind: VAULT_KIND, d })).toEqual({ kind: "none" });
  });

  it("rejects a vault event for another app", async () => {
    const { signer, ctx } = user();
    const vault = unwrap(createCompatibleVault(ctx, { s: randomBytes(16), nip44Ct: "x", now: 1 }));
    const event = await signer.signEvent(vaultEvent(ctx, vault, 1));
    expect(readVaultEvent({ ...ctx, appId: "https://other.example" }, event).ok).toBe(false);
  });

  it("nip07Signer fails clearly without NIP-44", async () => {
    const s = nip07Signer({ getPublicKey: async () => "pk", signEvent: async () => { throw new Error("x"); } });
    await expect(s.nip44Encrypt("pk", "x")).rejects.toThrow("NIP-44");
  });
});

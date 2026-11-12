import { VAULT_KIND, appVaultDTag, createCompatibleVault, memoryRelays, nip44SealSecret, publishReplaceable, randomBytes, secretKeySigner, unwrap, vaultEvent, type Signer } from "@evolustr/core";
import { generateSecretKey } from "nostr-tools/pure";
import { OwnerSecret, createAppOwner, ownerSecretToMnemonic } from "@evolu/common";
import { describe, expect, it } from "vitest";
import { type ClientOptions, createEvolustr, memoryCache, memoryDatabases } from "../src/index.ts";

const URLS = ["wss://r1", "wss://r2"];
const APP = "https://notes.example";

/** One user, several devices sharing relays. */
const world = () => {
  const sk = generateSecretKey();
  const mem = memoryRelays();
  let clock = 1000;
  const decrypts = { count: 0 };
  const base = secretKeySigner(sk);
  const signer: Signer = { ...base, nip44Decrypt: (p, c) => (decrypts.count++, base.nip44Decrypt(p, c)) };
  const device = (opts: Partial<ClientOptions> = {}) => {
    const dbs = memoryDatabases(["notes"], () => clock * 1000);
    const cache = memoryCache();
    const make = () =>
      createEvolustr(
        { signer, relays: mem.relays, openDatabase: dbs.open, cache, now: () => ++clock },
        { appId: APP, relayUrls: URLS, ...opts },
      );
    return { dbs, cache, make };
  };
  return { sk, signer, mem, device, decrypts, tick: (n = 1) => (clock += n) };
};

/** Connects; confirms the weak-vault prompt on a new device, as a user would. */
const ready = async (p: ReturnType<ReturnType<ReturnType<typeof world>["device"]>["make"]>) => {
  const r = unwrap(await p.connect());
  if (r.state === "needsUserAction" && r.action === "confirmWeak") return { state: "ready" as const, ...unwrap(await p.unlock()) };
  if (r.state !== "ready") throw new Error(`expected ready, got ${JSON.stringify(r)}`);
  return r;
};

describe("client, compatible mode", () => {
  it("first use creates a weak vault and opens the database", async () => {
    const w = world();
    const r = await ready(w.device().make());
    expect(r.status).toMatchObject({ mode: "compatible", level: "weak", unlockedWith: "created", canAddStrongMethod: true });
    expect(await r.db.getMeta("vault")).not.toBeNull();
  });

  it("a second device opens the same data through NIP-44", async () => {
    const w = world();
    const a = await ready(w.device().make());
    const b = await ready(w.device().make());
    expect(b.db.sHash).toBe(a.db.sHash);
    expect(b.status.unlockedWith).toBe("nip44");
  });

  it("a reload uses the cache without a decrypt prompt; logout clears it", async () => {
    const w = world();
    const d = w.device();
    await ready(d.make());
    await ready(w.device().make()); // other device: one decrypt
    const before = w.decrypts.count;
    const again = await ready(d.make());
    expect(again.status.unlockedWith).toBe("cache");
    expect(w.decrypts.count).toBe(before);
    const client = d.make();
    await ready(client);
    await client.logout();
    expect(await d.cache.get(again.pubkey, APP)).toBeNull();
  });

  it("recovery phrase: creates R, other nip44 devices can't add strong methods until unlockRoot", async () => {
    const w = world();
    const a = w.device().make();
    await ready(a);
    const phrase = unwrap(await a.showRecoveryPhrase());
    expect(phrase.split(" ")).toHaveLength(12);
    expect(a.status()?.canMakeStrict).toBe(true);

    const b = w.device().make();
    const rb = await ready(b);
    expect(rb.status).toMatchObject({ unlockedWith: "nip44", canAddStrongMethod: false });
    expect((await b.showRecoveryPhrase()).ok).toBe(false);
    expect((await b.unlockRoot({ recoveryPhrase: "abandon ".repeat(11) + "about" })).ok).toBe(false);
    const st = unwrap(await b.unlockRoot({ recoveryPhrase: phrase }));
    expect(st.canAddStrongMethod).toBe(true);
    expect(unwrap(await b.showRecoveryPhrase())).toBe(phrase);
  });

  it("confirming the phrase checks the words", async () => {
    const w = world();
    const a = w.device().make();
    const r = await ready(a);
    const phrase = unwrap(await a.showRecoveryPhrase());
    expect((await a.confirmRecoveryPhrase("abandon ".repeat(11) + "about")).ok).toBe(false);
    expect((await a.confirmRecoveryPhrase(phrase.toUpperCase())).ok).toBe(true);
    expect(await r.db.getMeta("phraseConfirmed")).toBe("1");
  });

  it("restoreFromPhrase opens the data on a new device", async () => {
    const w = world();
    const a = w.device().make();
    const ra = await ready(a);
    const phrase = unwrap(await a.showRecoveryPhrase());
    const restored = unwrap(await w.device().make().restoreFromPhrase(phrase));
    expect(restored.db.sHash).toBe(ra.db.sHash);
    expect(restored.status.unlockedWith).toBe("recovery");
  });

  it("a replaced vault is detected by a device with R and the copy is republished", async () => {
    const w = world();
    const d = w.device({ cacheRootKey: true });
    const a = d.make();
    const ra = await ready(a);
    await a.showRecoveryPhrase();
    // Another app with signing permission overwrites the vault.
    const ctx = { pubkey: ra.pubkey, appId: APP };
    const evilS = randomBytes(16);
    const evil = unwrap(createCompatibleVault(ctx, { s: evilS, nip44Ct: await nip44SealSecret(w.signer, ra.pubkey, evilS), now: 5000 }));
    await publishReplaceable(w.mem.relays, URLS, w.signer, vaultEvent(ctx, evil, 5000));

    const again = d.make();
    const r = unwrap(await again.connect());
    expect(r).toMatchObject({ state: "vaultChanged", reason: "replaced" });
    w.tick(10000);
    const fixed = unwrap(await again.resolveVaultChange("republishCopy"));
    expect(fixed.db.sHash).toBe(ra.db.sHash);
    // A new device now gets the original data again.
    expect((await ready(w.device().make())).db.sHash).toBe(ra.db.sHash);
  });

  it("a device without R facing a different compatible vault lets the user decide", async () => {
    const w = world();
    const d = w.device();
    const ra = await ready(d.make());
    const ctx = { pubkey: ra.pubkey, appId: APP };
    const otherS = randomBytes(16);
    const other = unwrap(createCompatibleVault(ctx, { s: otherS, nip44Ct: await nip44SealSecret(w.signer, ra.pubkey, otherS), now: 5000 }));
    await publishReplaceable(w.mem.relays, URLS, w.signer, vaultEvent(ctx, other, 5000));
    await d.dbs.write((await d.cache.get(ra.pubkey, APP))!.s, "notes", "n1", { text: "mine" });

    const c = d.make();
    expect(unwrap(await c.connect())).toMatchObject({ state: "vaultChanged", reason: "ambiguous", options: ["followRelay", "republishCopy"] });
    const followed = unwrap(await c.resolveVaultChange("followRelay"));
    expect(followed.db.sHash).not.toBe(ra.db.sHash);
    // Local rows were copied (only missing ones), not lost.
    expect((await followed.db.readRows("notes")).map((r) => r.id)).toEqual(["n1"]);
  });

  it("missing vault: offers to republish this device's copy", async () => {
    const w = world();
    const d = w.device();
    const ra = await ready(d.make());
    for (const u of URLS) w.mem.store(u).length = 0;
    const c = d.make();
    expect(unwrap(await c.connect())).toMatchObject({ state: "vaultChanged", reason: "missing", options: ["republishCopy", "restorePhrase", "startNew"] });
    expect(unwrap(await c.resolveVaultChange("republishCopy")).db.sHash).toBe(ra.db.sHash);
    const f = await w.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [appVaultDTag(ra.pubkey, APP)] }, 100);
    expect(f.events.length).toBeGreaterThan(0);
  });

  it("doesn't create a vault while a relay is unreachable", async () => {
    const w = world();
    w.mem.down.add("wss://r2");
    const r = unwrap(await w.device().make().connect());
    expect(r).toMatchObject({ state: "vaultChanged", reason: "missing" });
  });

  it("requireStrong asks for a strong setup instead of creating a weak vault", async () => {
    const w = world();
    expect(unwrap(await w.device({ requireStrong: true }).make().connect())).toEqual({ state: "needsUserAction", action: "setupStrong" });
  });

  it("downgrade refuses an already compatible vault", async () => {
    const w = world();
    const a = w.device().make();
    await ready(a);
    expect((await a.downgrade()).ok).toBe(false);
  });

  it("exports the Evolu mnemonic that Evolu itself derives from S", async () => {
    const w = world();
    const d = w.device();
    const c = d.make();
    const r = await ready(c);
    const s = (await d.cache.get(r.pubkey, APP))!.s;
    const words = unwrap(c.exportEvoluMnemonic());
    expect(words).toBe(ownerSecretToMnemonic(OwnerSecret.orThrow(s)));
    expect(words).not.toBe(unwrap(await c.showRecoveryPhrase()));
    expect(createAppOwner(OwnerSecret.orThrow(s)).mnemonic).toBe(words);
  });
});

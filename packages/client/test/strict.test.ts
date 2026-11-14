import { type Bytes, VAULT_KIND, addRootKey, appVaultDTag, parseVault, createCompatibleVault, createStrictVault, memoryRelays, nip44SealSecret, randomBytes, secretKeySigner, unwrap, vaultEvent } from "@evolustr/core";
import { generateSecretKey } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import { memoryPasskeys } from "@evolustr/core";
import { type ClientOptions, createEvolustr, memoryCache, memoryDatabases } from "../src/index.ts";

const URLS = ["wss://r1"];
const APP = "https://notes.example";
const RP = "notes.example";

const world = () => {
  const sk = generateSecretKey();
  const signer = secretKeySigner(sk);
  const mem = memoryRelays();
  let clock = 1000;
  const synced = new Map<string, Bytes>(); // one passkey provider account shared by devices
  const device = (
    o: {
      passkeys?: "synced" | "local" | "none";
      prfAtCreate?: boolean;
      options?: Partial<ClientOptions>;
      /** A device-local store that survives reloads (`hints`). */
      hints?: Map<string, string>;
      /** Share another device's databases, as Evolu sync would. */
      dbs?: ReturnType<typeof memoryDatabases>;
    } = {},
  ) => {
    const dbs = o.dbs ?? memoryDatabases(["notes"], () => clock * 1000);
    const cache = memoryCache();
    const store = o.hints;
    const hints = store === undefined ? undefined : { get: async (k: string) => store.get(k) ?? null, set: async (k: string, v: string) => void store.set(k, v) };
    const kind = o.passkeys ?? "synced";
    const passkeys =
      kind === "none"
        ? undefined
        : memoryPasskeys({ rpId: RP, store: kind === "synced" ? synced : new Map(), synced: kind === "synced", prfAtCreate: o.prfAtCreate ?? true });
    const make = () =>
      createEvolustr(
        { signer, relays: mem.relays, openDatabase: dbs.open, cache, now: () => ++clock, ...(passkeys ? { passkeys } : {}), ...(hints ? { hints } : {}) },
        { appId: APP, relayUrls: URLS, ...o.options },
      );
    return { dbs, cache, make };
  };
  return { device, tick: (n: number) => (clock += n), signer, mem, now: () => clock };
};

/** Connects; confirms the weak-vault prompt on a new device, as a user would. */
const connectReady = async (c: ReturnType<ReturnType<ReturnType<typeof world>["device"]>["make"]>) => {
  const r = unwrap(await c.connect());
  if (r.state === "needsUserAction" && r.action === "confirmWeak") return { state: "ready" as const, ...unwrap(await c.unlock()) };
  if (r.state !== "ready") throw new Error(`not ready: ${JSON.stringify(r)}`);
  return r;
};

describe("client passkeys and strict mode", () => {
  it("enrolling a passkey keeps the level; strict is the user's choice", async () => {
    const w = world();
    const a = w.device().make();
    await connectReady(a);
    expect(unwrap(await a.enrollPasskey())).toEqual({ done: true });
    expect(a.status()).toMatchObject({ mode: "compatible", level: "weak", canMakeStrict: true });
    const st = unwrap(await a.makeStrict());
    expect(st).toMatchObject({ mode: "strict", level: "strong", backupRecommended: true });
  });

  it("a second device with the synced passkey opens the strict vault from a click", async () => {
    const w = world();
    const a = w.device().make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    await a.makeStrict();
    const b = w.device().make();
    expect(unwrap(await b.connect())).toEqual({ state: "needsUserAction", action: "passkey" });
    const rb = unwrap(await b.unlock());
    expect(rb.status).toMatchObject({ unlockedWith: "passkey", mode: "strict" });
    expect(rb.db.sHash).toBe((await connectReady(a)).db.sHash);
    expect(rb.db.sHash).not.toBe(ra.db.sHash); // S was replaced
  });

  it("strict data moves to the new secret on the device that made it strict", async () => {
    const w = world();
    const d = w.device();
    const a = d.make();
    const ra = await connectReady(a);
    await ra.db.upsertRows("notes", [{ id: "n1", isDeleted: false, changedAt: 0, values: { text: "keep me" } }]);
    await a.enrollPasskey();
    await a.makeStrict();
    const after = await connectReady(d.make());
    expect((await after.db.readRows("notes")).map((r) => r.values["text"])).toEqual(["keep me"]);
  });

  it("a device-bound passkey needs a backup before strict", async () => {
    const w = world();
    const a = w.device({ passkeys: "local" }).make();
    await connectReady(a);
    await a.enrollPasskey();
    expect(await a.makeStrict()).toMatchObject({ ok: false, error: { type: "backupRequired" } });
    const phrase = unwrap(await a.showRecoveryPhrase());
    unwrap(await a.confirmRecoveryPhrase(phrase));
    expect(unwrap(await a.makeStrict())).toMatchObject({ mode: "strict", backupRecommended: false });
  });

  it("or the user explicitly accepts losing the data with the device", async () => {
    const w = world();
    const a = w.device({ passkeys: "local" }).make();
    await connectReady(a);
    await a.enrollPasskey();
    expect((await a.makeStrict({ acceptDeviceLoss: true })).ok).toBe(true);
  });

  it("a device without a passkey can't open a strict vault except with the phrase", async () => {
    const w = world();
    const a = w.device().make();
    await connectReady(a);
    await a.enrollPasskey();
    const phrase = unwrap(await a.showRecoveryPhrase());
    await a.makeStrict();
    const b = w.device({ passkeys: "none" }).make();
    expect(unwrap(await b.connect())).toEqual({ state: "needsUserAction", action: "recoveryPhrase" });
    expect(unwrap(await b.unlock({ recoveryPhrase: phrase })).status.mode).toBe("strict");
  });

  it("an offline device migrates its rows after two rotations", async () => {
    const w = world();
    const a = w.device().make();
    await connectReady(a);
    await a.enrollPasskey();
    // Device C opens the vault with the synced passkey (so it has R), then goes offline.
    const c = w.device({ options: { cacheRootKey: true } });
    const cc = c.make();
    const rc = await connectReady(cc);
    unwrap(await cc.unlockRoot());
    await rc.db.upsertRows("notes", [{ id: "offline", isDeleted: false, changedAt: 0, values: { text: "written offline" } }]);
    // Meanwhile A rotates twice.
    await a.makeStrict();
    await a.downgrade();
    w.tick(100);
    await a.makeStrict();
    const back = await connectReady(c.make());
    expect(back.status.mode).toBe("strict");
    expect((await back.db.readRows("notes")).map((r) => r.id)).toContain("offline");
  });

  it("a nip44-only device must unlock R before adding a passkey", async () => {
    const w = world();
    const a = w.device().make();
    await connectReady(a);
    await a.enrollPasskey();
    const b = w.device({ passkeys: "local" }).make();
    await connectReady(b);
    expect(b.status()?.canAddStrongMethod).toBe(false);
    expect(await b.enrollPasskey()).toMatchObject({ ok: false, error: { type: "rootLocked" } });
  });

  it("two-click setup when PRF output isn't returned at creation", async () => {
    const w = world();
    const a = w.device({ prfAtCreate: false }).make();
    await connectReady(a);
    expect(unwrap(await a.enrollPasskey())).toEqual({ done: false });
    expect(unwrap(await a.finishPasskeySetup()).canMakeStrict).toBe(true);
  });

  it("requireStrong creates the first vault strict, and a second device opens it", async () => {
    const w = world();
    const a = w.device({ options: { requireStrong: true } }).make();
    expect(unwrap(await a.connect())).toEqual({ state: "needsUserAction", action: "setupStrong" });
    const ra = unwrap(await a.unlock());
    expect(ra.status).toMatchObject({ mode: "strict", unlockedWith: "passkey" });
    const b = w.device({ options: { requireStrong: true } }).make();
    expect(unwrap(await b.connect())).toEqual({ state: "needsUserAction", action: "passkey" });
    expect(unwrap(await b.unlock()).db.sHash).toBe(ra.db.sHash);
  });

  it("a replayed pre-strict vault doesn't undo strict mode on a device with R (#25)", async () => {
    const w = world();
    const d = w.device({ options: { cacheRootKey: true } });
    const a = d.make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    // An app with signing permission keeps a copy of the vault from before strict…
    const before = (await w.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [appVaultDTag(ra.pubkey, APP)] }, 100)).events[0]!;
    await a.makeStrict();
    const strictSHash = (await connectReady(d.make())).db.sHash;
    // …and re-signs it later.
    w.tick(1000);
    const replay = await w.signer.signEvent({ kind: VAULT_KIND, created_at: w.now(), tags: before.tags, content: before.content });
    await w.mem.relays.publish(URLS, replay, 100);

    const again = d.make();
    const r = unwrap(await again.connect());
    expect(r).toMatchObject({ state: "vaultChanged", reason: "replaced" });
    const fixed = unwrap(await again.resolveVaultChange("republishCopy"));
    expect(fixed.status.mode).toBe("strict");
    expect(fixed.db.sHash).toBe(strictSHash);
  });

  it("a new device asks before using a compatible vault it can't verify (#26)", async () => {
    const w = world();
    await connectReady(w.device().make());
    const b = w.device().make();
    expect(unwrap(await b.connect())).toEqual({ state: "needsUserAction", action: "confirmWeak" });
    expect(unwrap(await b.unlock()).status).toMatchObject({ mode: "compatible", unlockedWith: "nip44" });
    // Apps that never offer strict mode can turn the prompt off.
    const c = w.device({ options: { confirmWeakOnNewDevice: false } }).make();
    expect(unwrap(await c.connect()).state).toBe("ready");
  });

  it("R isn't cached by default; a replay is still refused using the local copy (#27)", async () => {
    const w = world();
    const d = w.device();
    const a = d.make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    const before = (await w.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [appVaultDTag(ra.pubkey, APP)] }, 100)).events[0]!;
    await a.makeStrict();
    const cached = await d.cache.get(ra.pubkey, APP);
    expect(cached?.s).toBeDefined();
    expect(cached?.r).toBeUndefined();
    w.tick(1000);
    await w.mem.relays.publish(URLS, await w.signer.signEvent({ kind: VAULT_KIND, created_at: w.now(), tags: before.tags, content: before.content }), 100);
    expect(unwrap(await d.make().connect())).toMatchObject({ state: "vaultChanged", reason: "replaced" });
  });

  it("a rotation only counts when every relay took it; connect re-sends it later (#32)", async () => {
    const w = world();
    const d = w.device({ options: { relayUrls: ["wss://r1", "wss://r2"] } });
    const a = d.make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    w.mem.down.add("wss://r2");
    expect(await a.makeStrict()).toMatchObject({ ok: false, error: { type: "partialPublish" } });
    expect(a.status()?.mode).toBe("strict"); // continues on the new secret
    w.mem.down.delete("wss://r2");
    const dTag = appVaultDTag(ra.pubkey, APP);
    const onR2 = () => w.mem.store("wss://r2").filter((e) => e.tags.some((t) => t[1] === dTag));
    expect(JSON.parse(onR2()[0]!.content).mode).toBe("compatible");
    // The next connect sends the strict vault to the relay that missed it.
    await connectReady(d.make());
    expect(JSON.parse(onR2()[0]!.content).mode).toBe("strict");
  });

  /** The attacker re-signs the current vault with its JSON changed by `edit`. */
  const tamper = async (w: ReturnType<typeof world>, pubkey: string, edit: (v: Record<string, unknown>) => void) => {
    const current = (await w.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [appVaultDTag(pubkey, APP)] }, 100)).events[0]!;
    const json = JSON.parse(current.content) as Record<string, unknown>;
    edit(json);
    w.tick(100);
    await w.mem.relays.publish(URLS, await w.signer.signEvent({ kind: VAULT_KIND, created_at: w.now(), tags: current.tags, content: JSON.stringify(json) }), 100);
  };
  const relayVault = async (w: ReturnType<typeof world>, pubkey: string) =>
    JSON.parse((await w.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [appVaultDTag(pubkey, APP)] }, 100)).events[0]!.content) as { rootWraps: Array<{ credId?: string; ct: string }> };
  const settle = () => new Promise((r) => setTimeout(r, 20));

  it("stripped root wraps come back from the local copy (#37 strip)", async () => {
    const w = world();
    const d = w.device();
    const a = d.make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    await a.makeStrict();
    await tamper(w, ra.pubkey, (v) => (v["rootWraps"] = []));
    const again = await connectReady(d.make());
    const copy = JSON.parse((await again.db.getMeta("vault"))!) as { rootWraps: unknown[] };
    expect(copy.rootWraps).toHaveLength(1);
    await settle();
    expect((await relayVault(w, ra.pubkey)).rootWraps).toHaveLength(1);
  });

  it("a corrupted passkey wrap is repaired, and another device can still unlock (#37 corrupt)", async () => {
    const w = world();
    const d = w.device();
    const a = d.make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    await a.makeStrict();
    await tamper(w, ra.pubkey, (v) => {
      const wraps = v["rootWraps"] as Array<{ ct: string }>;
      wraps[0]!.ct = "AAAAAAAAAAAAAAAAAAAAAAAA";
    });
    await connectReady(d.make());
    await settle();
    const b = w.device().make();
    expect(unwrap(await b.connect())).toEqual({ state: "needsUserAction", action: "passkey" });
    expect(unwrap(await b.unlock()).status.unlockedWith).toBe("passkey");
  });

  it("a junk wrap is pruned once R is known (#37 prune)", async () => {
    const w = world();
    const d = w.device();
    const a = d.make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    await a.makeStrict();
    await tamper(w, ra.pubkey, (v) => {
      const wraps = v["rootWraps"] as Array<Record<string, string>>;
      wraps.push({ ...wraps[0]!, credId: "junk" });
    });
    const c = d.make();
    await connectReady(c);
    unwrap(await c.unlockRoot());
    expect((await relayVault(w, ra.pubkey)).rootWraps.map((x) => x.credId)).not.toContain("junk");
  });

  /** The forged same-secret compatible vault from #38 step 1. */
  const poison = (w: ReturnType<typeof world>, pubkey: string) =>
    tamper(w, pubkey, (v) => {
      v["mode"] = "compatible";
      v["history"] = [];
      v["rootWraps"] = [];
      v["dataWraps"] = [{ type: "nip44", ct: "x" }];
    });
  const strictDevice = async (w: ReturnType<typeof world>, opts: Partial<ClientOptions> = {}) => {
    const d = w.device({ options: opts });
    const a = d.make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    const phrase = unwrap(await a.showRecoveryPhrase());
    await a.makeStrict();
    return { d, a, pubkey: ra.pubkey, phrase };
  };

  it("poison without R: a strong unlock is required and the local copy is unchanged (#38)", async () => {
    const w = world();
    const { d, pubkey } = await strictDevice(w);
    const before = await (await d.make().connect().then((r) => (unwrap(r) as { db: { getMeta: (k: string) => Promise<string | null> } }).db)).getMeta("vault");
    await poison(w, pubkey);
    const c = d.make();
    expect(unwrap(await c.connect())).toMatchObject({ state: "needsUserAction" });
    const db = await d.dbs.open((await d.cache.get(pubkey, APP))!.s);
    expect(await db.getMeta("vault")).toBe(before);
    expect(JSON.parse(before!).mode).toBe("strict");
  });

  it("poison with R: replaced (#38)", async () => {
    const w = world();
    const { d, pubkey } = await strictDevice(w, { cacheRootKey: true });
    await poison(w, pubkey);
    expect(unwrap(await d.make().connect())).toMatchObject({ state: "vaultChanged", reason: "replaced" });
  });

  it("two-step attack: no followRelay to the attacker's weak vault (#38)", async () => {
    const w = world();
    const { d, pubkey } = await strictDevice(w);
    await poison(w, pubkey);
    await d.make().connect();
    const ctx = { pubkey, appId: APP };
    const evilS = randomBytes(16);
    const evil = unwrap(createCompatibleVault(ctx, { s: evilS, nip44Ct: await nip44SealSecret(w.signer, pubkey, evilS), now: w.now() + 500 }));
    w.tick(1000);
    await w.mem.relays.publish(URLS, await w.signer.signEvent(vaultEvent(ctx, evil, w.now())), 100);
    const r = unwrap(await d.make().connect());
    expect(r).toMatchObject({ state: "vaultChanged", reason: "replaced" });
    if (r.state === "vaultChanged") expect(r.options).not.toContain("followRelay");
  });

  it("the recovery phrase stays the same through a poison attempt (#38)", async () => {
    const w = world();
    const { d, pubkey, phrase } = await strictDevice(w);
    await poison(w, pubkey);
    const c = d.make();
    await c.connect();
    // The real phrase doesn't open the forged vault, but it opens this device's copy (#39).
    expect(await c.unlock({ recoveryPhrase: phrase })).toMatchObject({ ok: false, error: { type: "vaultReplaced" } });
    const ready = unwrap(await c.resolveVaultChange("republishCopy"));
    expect(ready.status.mode).toBe("strict");
    expect(unwrap(await c.showRecoveryPhrase())).toBe(phrase);
  });

  it("legit: another device adding R doesn't trigger a prompt (#38)", async () => {
    const w = world();
    const a = w.device().make();
    await connectReady(a);
    const bd = w.device();
    await connectReady(bd.make());
    await a.showRecoveryPhrase();
    expect(unwrap(await bd.make().connect()).state).toBe("ready");
  });

  it("legit downgrade elsewhere: a strong unlock, then compatible (#38)", async () => {
    const w = world();
    const { a } = await strictDevice(w);
    const bd = w.device();
    const b = bd.make();
    expect(unwrap(await b.connect())).toEqual({ state: "needsUserAction", action: "passkey" });
    unwrap(await b.unlock());
    unwrap(await a.downgrade());
    const b2 = bd.make();
    expect(unwrap(await b2.connect())).toMatchObject({ state: "needsUserAction" });
    expect(unwrap(await b2.unlock()).status.mode).toBe("compatible");
  });

  /** An attacker's own strict vault that carries copies of the user's passkey wraps (#39). */
  const foreignStrict = async (w: ReturnType<typeof world>, pubkey: string, corrupt: boolean) => {
    const current = (await w.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [appVaultDTag(pubkey, APP)] }, 100)).events[0]!;
    const real = JSON.parse(current.content) as { rootWraps: Array<Record<string, string>> };
    const ctx = { pubkey, appId: APP };
    const fake = unwrap(createStrictVault(ctx, { s: randomBytes(16), r: randomBytes(16), now: w.now() + 500, rootWraps: [] }));
    const wraps = real.rootWraps.map((x) => (corrupt ? { ...x, ct: "AAAAAAAAAAAAAAAAAAAAAAAA" } : x));
    w.tick(1000);
    await w.mem.relays.publish(URLS, await w.signer.signEvent({ kind: VAULT_KIND, created_at: w.now(), tags: current.tags, content: JSON.stringify({ ...fake, rootWraps: wraps }) }), 100);
  };

  it("a foreign strict vault with the user's passkey wraps: vaultReplaced, then restore (#39)", async () => {
    const w = world();
    const { d, pubkey } = await strictDevice(w);
    const before = (await connectReady(d.make())).db.sHash;
    await foreignStrict(w, pubkey, false);
    const c = d.make();
    expect(unwrap(await c.connect())).toMatchObject({ state: "needsUserAction" });
    expect(await c.unlock()).toMatchObject({ ok: false, error: { type: "vaultReplaced" } });
    const restored = unwrap(await c.resolveVaultChange("republishCopy"));
    expect(restored.status.mode).toBe("strict");
    expect(restored.db.sHash).toBe(before);
    expect(unwrap(await d.make().connect()).state).not.toBe("vaultChanged");
  });

  it("the copy's passkey wrap is used when the fetched one is corrupted (#39)", async () => {
    const w = world();
    const { d, pubkey } = await strictDevice(w);
    await foreignStrict(w, pubkey, true);
    const c = d.make();
    await c.connect();
    expect(await c.unlock()).toMatchObject({ ok: false, error: { type: "vaultReplaced" } });
  });

  it("a wrong recovery phrase is still wrongPhrase (#39)", async () => {
    const w = world();
    const { d, pubkey } = await strictDevice(w);
    await foreignStrict(w, pubkey, false);
    const c = d.make();
    await c.connect();
    expect(await c.unlock({ recoveryPhrase: "abandon ".repeat(11) + "about" })).toMatchObject({ ok: false, error: { type: "wrongPhrase" } });
  });

  it("after logout, a strict vault swapped for a weak one is still caught with hints (#44)", async () => {
    const w = world();
    const hintStore = new Map<string, string>();
    const hints = { get: async (k: string) => hintStore.get(k) ?? null, set: async (k: string, v: string) => void hintStore.set(k, v) };
    const dbs = memoryDatabases(["notes"]);
    const cache = memoryCache();
    const make = (withHints: boolean) =>
      createEvolustr(
        { signer: w.signer, relays: w.mem.relays, openDatabase: dbs.open, cache, now: () => w.tick(1), passkeys: memoryPasskeys({ rpId: RP }), ...(withHints ? { hints } : {}) },
        { appId: APP, relayUrls: URLS },
      );
    const a = make(true);
    const ra = await connectReady(a);
    await a.enrollPasskey();
    await a.showRecoveryPhrase().then((p) => a.confirmRecoveryPhrase(unwrap(p)));
    unwrap(await a.makeStrict());
    await a.logout();
    const ctx = { pubkey: ra.pubkey, appId: APP };
    const evilS = randomBytes(16);
    const evil = unwrap(createCompatibleVault(ctx, { s: evilS, nip44Ct: await nip44SealSecret(w.signer, ra.pubkey, evilS), now: w.now() + 500 }));
    w.tick(1000);
    await w.mem.relays.publish(URLS, await w.signer.signEvent(vaultEvent(ctx, evil, w.now())), 100);
    expect(unwrap(await make(true).connect())).toMatchObject({ state: "vaultChanged", reason: "replaced" });
    // Without hints it's a first use, behind the weak-vault confirmation.
    expect(unwrap(await make(false).connect())).toEqual({ state: "needsUserAction", action: "confirmWeak" });
  });

  /** A strict-looking forgery with the victim's sHash and a foreign header (#50). */
  const foreignHeader = (w: ReturnType<typeof world>, pubkey: string) =>
    tamper(w, pubkey, (v) => {
      v["mode"] = "strict";
      v["created"] = 1;
      v["history"] = [{ sHash: "00", created: 1 }];
      v["dataWraps"] = (v["dataWraps"] as Array<{ type: string }>).filter((x) => x.type === "root");
    });

  it("republishing the copy keeps this device's header, so R still opens it (#50)", async () => {
    const w = world();
    const d = w.device();
    const a = d.make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    const original = JSON.parse((await ra.db.getMeta("vault"))!) as { created: number; history: unknown[] };
    await foreignHeader(w, ra.pubkey);
    const c = d.make();
    expect(unwrap(await c.connect())).toMatchObject({ state: "needsUserAction" });
    expect(await c.unlock()).toMatchObject({ ok: false, error: { type: "vaultReplaced" } });
    unwrap(await c.resolveVaultChange("republishCopy"));
    expect(unwrap(await c.unlockRoot()).canMakeStrict).toBe(true);
    const onRelay = (await relayVault(w, ra.pubkey)) as unknown as { mode: string; created: number; history: unknown[] };
    expect(onRelay).toMatchObject({ mode: "compatible", created: original.created, history: original.history });
  });

  it("a forged header that appears mid-session isn't mixed into the next publish (#50)", async () => {
    const w = world();
    const a = w.device().make();
    const ra = await connectReady(a);
    const phrase = unwrap(await a.showRecoveryPhrase());
    await foreignHeader(w, ra.pubkey);
    expect(unwrap(await a.enrollPasskey())).toEqual({ done: true });
    const fresh = w.device({ passkeys: "none" }).make();
    expect(unwrap(await fresh.restoreFromPhrase(phrase)).status.mode).toBe("compatible");
  });


  it("forged backup facts in the app database don't skip the backup check (#53)", async () => {
    const w = world();
    const a = w.device({ passkeys: "local" }).make();
    const ra = await connectReady(a);
    await a.enrollPasskey();
    // An app that decrypted the nip44 wrap writes these through Evolu sync.
    await ra.db.setMeta("phraseConfirmed", "1");
    await ra.db.setMeta("strongMethods", JSON.stringify([
      { id: "passkey:x", method: { kind: "passkey", synced: true } },
      { id: "passkey:y", method: { kind: "passkey", synced: true } },
    ]));
    await connectReady(a); // a reload reads whatever is there
    unwrap(await a.unlockRoot());
    expect(await a.makeStrict()).toMatchObject({ ok: false, error: { type: "backupRequired" } });
  });

  it("a confirmed phrase is remembered on the device through hints, not elsewhere (#53)", async () => {
    const w = world();
    const hints = new Map<string, string>();
    const d = w.device({ passkeys: "local", hints });
    const a = d.make();
    await connectReady(a);
    await a.enrollPasskey();
    unwrap(await a.confirmRecoveryPhrase(unwrap(await a.showRecoveryPhrase())));
    expect(unwrap(await a.makeStrict())).toMatchObject({ mode: "strict", backupRecommended: false });
    // A reload on the same device still knows.
    expect((await connectReady(d.make())).status.backupRecommended).toBe(false);
    // Another device doesn't (its own hints are empty).
    hints.clear();
    expect((await connectReady(d.make())).status.backupRecommended).toBe(true);
  });

  it("two verified passkey wraps need no backup, without any stored record (#53)", async () => {
    const w = world();
    const a = w.device({ passkeys: "local" }).make();
    await connectReady(a);
    await a.enrollPasskey();
    // Device B, with its own device-bound passkey, joins through the phrase (not confirmed).
    const phrase = unwrap(await a.showRecoveryPhrase());
    const b = w.device({ passkeys: "local" }).make();
    unwrap(await b.restoreFromPhrase(phrase));
    unwrap(await b.enrollPasskey());
    // A has no record of B's passkey, but its wrap verifies with R: two methods.
    await connectReady(a);
    unwrap(await a.unlockRoot({ recoveryPhrase: phrase }));
    expect(unwrap(await a.makeStrict())).toMatchObject({ mode: "strict" });
  });


  /** The attacker decrypts S through NIP-44 and adds a root key of its own (#49). */
  const plantRoot = async (w: ReturnType<typeof world>, d: ReturnType<ReturnType<typeof world>["device"]>, pubkey: string) => {
    const ctx = { pubkey, appId: APP };
    const current = (await w.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [appVaultDTag(pubkey, APP)] }, 100)).events[0]!;
    const s = (await d.cache.get(pubkey, APP))!.s;
    const planted = unwrap(addRootKey(ctx, unwrap(parseVault(current.content)), randomBytes(16), s));
    w.tick(100);
    await w.mem.relays.publish(URLS, await w.signer.signEvent(vaultEvent(ctx, planted, w.now())), 100);
  };

  it("a planted root key: the device can still go strict with a new one (#49)", async () => {
    const w = world();
    const d = w.device();
    const a = d.make();
    const ra = await connectReady(a);
    await ra.db.upsertRows("notes", [{ id: "n1", isDeleted: false, changedAt: 0, values: { text: "mine" } }]);
    await plantRoot(w, d, ra.pubkey);
    const again = d.make();
    expect((await connectReady(again)).status).toMatchObject({ canAddStrongMethod: false, canReplaceRoot: true });
    expect(await again.makeStrict()).toMatchObject({ ok: false, error: { type: "rootLocked" } });
    expect(unwrap(await again.makeStrict({ replaceRoot: true }))).toMatchObject({ mode: "strict", canReplaceRoot: false });
    const phrase = unwrap(await again.showRecoveryPhrase());
    const fresh = w.device({ passkeys: "none", dbs: d.dbs }).make();
    const restored = unwrap(await fresh.restoreFromPhrase(phrase));
    expect(restored.status.mode).toBe("strict");
    expect((await restored.db.readRows("notes")).map((r) => r.values["text"])).toEqual(["mine"]);
  });

  it("after a root reset, another device opens it with the new passkey (#49)", async () => {
    const w = world();
    const d = w.device();
    const a = d.make();
    const ra = await connectReady(a);
    await ra.db.upsertRows("notes", [{ id: "n1", isDeleted: false, changedAt: 0, values: { text: "mine" } }]);
    await plantRoot(w, d, ra.pubkey);
    const again = d.make();
    await connectReady(again);
    unwrap(await again.makeStrict({ replaceRoot: true }));
    const b = w.device({ dbs: d.dbs }).make();
    expect(unwrap(await b.connect())).toEqual({ state: "needsUserAction", action: "passkey" });
    const rb = unwrap(await b.unlock());
    expect(rb.status.mode).toBe("strict");
    expect((await rb.db.readRows("notes")).map((r) => r.values["text"])).toEqual(["mine"]);
  });

  it("replaceRoot is refused on a strict vault or while R is known (#49)", async () => {
    const w = world();
    const a = w.device().make();
    await connectReady(a);
    await a.enrollPasskey();
    expect(await a.makeStrict({ replaceRoot: true })).toMatchObject({ ok: false, error: { type: "rootKnown" } });
    unwrap(await a.makeStrict());
    // A reload has only S cached: strict, and R not known here.
    const d = w.device();
    const c = d.make();
    const first = unwrap(await c.connect());
    if (first.state === "needsUserAction") unwrap(await c.unlock());
    const reloaded = d.make();
    expect((await connectReady(reloaded)).status).toMatchObject({ mode: "strict", canReplaceRoot: false });
    expect(await reloaded.makeStrict({ replaceRoot: true })).toMatchObject({ ok: false, error: { type: "rootLocked" } });
  });

});

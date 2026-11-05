import { type Bytes, memoryRelays, secretKeySigner, unwrap } from "@evolustr/core";
import { generateSecretKey } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import { memoryPasskeys } from "@evolustr/core";
import { type ClientOptions, createEvolustr, memoryCache, memoryDatabases } from "../src/index.ts";

const URLS = ["wss://r1"];
const APP = "https://notes.example";
const RP = "notes.example";

const world = () => {
  const signer = secretKeySigner(generateSecretKey());
  const mem = memoryRelays();
  let clock = 1000;
  const synced = new Map<string, Bytes>(); // one passkey provider account shared by devices
  const device = (o: { passkeys?: "synced" | "local" | "none"; prfAtCreate?: boolean; options?: Partial<ClientOptions> } = {}) => {
    const dbs = memoryDatabases(["notes"], () => clock * 1000);
    const cache = memoryCache();
    const kind = o.passkeys ?? "synced";
    const passkeys =
      kind === "none"
        ? undefined
        : memoryPasskeys({ rpId: RP, store: kind === "synced" ? synced : new Map(), synced: kind === "synced", prfAtCreate: o.prfAtCreate ?? true });
    const make = () =>
      createEvolustr(
        { signer, relays: mem.relays, openDatabase: dbs.open, cache, now: () => ++clock, ...(passkeys ? { passkeys } : {}) },
        { appId: APP, relayUrls: URLS, ...o.options },
      );
    return { dbs, cache, make };
  };
  return { device, tick: (n: number) => (clock += n) };
};

const connectReady = async (c: ReturnType<ReturnType<ReturnType<typeof world>["device"]>["make"]>) => {
  const r = unwrap(await c.connect());
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
    const c = w.device();
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
});

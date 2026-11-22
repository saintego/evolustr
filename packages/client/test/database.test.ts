import { randomBytes, toBase64Url } from "@evolustr/core";
import { describe, expect, it } from "vitest";
import { encryptedCache, keyValueCache, memoryCache, memoryDatabases, memoryKeyStore, migrateRows } from "../src/index.ts";

describe("migrateRows (SPEC §3.4)", () => {
  it("copies everything in 'all' mode, keeping ids and deletion flags", async () => {
    let t = 1000;
    const mem = memoryDatabases(["notes"], () => t);
    const s1 = randomBytes(16);
    const s2 = randomBytes(16);
    await mem.write(s1, "notes", "a", { text: "one" });
    const from = await mem.open(s1);
    await from.upsertRows("notes", [{ id: "b", isDeleted: true, changedAt: t, values: { text: "gone" } }]);
    const to = await mem.open(s2);
    expect((await migrateRows(from, to, { kind: "all" })).copied).toBe(2);
    const rows = await to.readRows("notes");
    expect(rows.map((r) => [r.id, r.isDeleted, r.values["text"]])).toEqual([["a", false, "one"], ["b", true, "gone"]]);
  });

  it("after a rotation, copies only missing rows or rows changed after the cut-off", async () => {
    let t = 1000;
    const mem = memoryDatabases(["notes"], () => t);
    const old = randomBytes(16);
    const current = randomBytes(16);
    await mem.write(old, "notes", "synced", { text: "old value" }); // t=1000, already migrated by the other device
    await mem.write(current, "notes", "synced", { text: "newer edit in S'" });
    t = 5000;
    await mem.write(old, "notes", "offline", { text: "made offline" }); // changed after the cut-off
    const n = await migrateRows(await mem.open(old), await mem.open(current), { kind: "since", cutoffMs: 3000, marginMs: 0 });
    expect(n).toEqual({ copied: 1, skippedChanged: 1 });
    const rows = await (await mem.open(current)).readRows("notes");
    expect(rows.find((r) => r.id === "synced")?.values["text"]).toBe("newer edit in S'");
    expect(rows.find((r) => r.id === "offline")?.values["text"]).toBe("made offline");
  });

  it("the clock margin includes rows just before the cut-off", async () => {
    let t = 2900;
    const mem = memoryDatabases(["notes"], () => t);
    const old = randomBytes(16);
    const current = randomBytes(16);
    await mem.write(old, "notes", "x", { text: "edge" });
    await mem.write(current, "notes", "x", { text: "other" });
    t = 9000;
    expect((await migrateRows(await mem.open(old), await mem.open(current), { kind: "since", cutoffMs: 3000, marginMs: 200 })).copied).toBe(1);
  });
});

describe("migrateRows missingOnly (#51)", () => {
  it("never overwrites an existing id, and counts the changed ones it left", async () => {
    let t = 1000;
    const mem = memoryDatabases(["notes"], () => t);
    const old = randomBytes(16);
    const current = randomBytes(16);
    await mem.write(current, "notes", "same", { text: "a" });
    await mem.write(current, "notes", "x", { text: "good" });
    t = 9000;
    await mem.write(old, "notes", "same", { text: "a" });
    await mem.write(old, "notes", "x", { text: "evil" });
    await mem.write(old, "notes", "y", { text: "new" });
    expect(await migrateRows(await mem.open(old), await mem.open(current), { kind: "missingOnly" })).toEqual({ copied: 1, skippedChanged: 1 });
    const rows = await (await mem.open(current)).readRows("notes");
    expect(Object.fromEntries(rows.map((r) => [r.id, r.values["text"]]))).toEqual({ same: "a", x: "good", y: "new" });
  });
});

describe("secret cache", () => {
  it("stores S and R per (pubkey, appId) and removes them", async () => {
    const c = memoryCache();
    const s = randomBytes(16);
    const r = randomBytes(16);
    await c.set("pk", "app", { s, r });
    expect(await c.get("pk", "app")).toEqual({ s, r });
    expect(await c.get("pk", "other")).toBeNull();
    await c.remove("pk", "app");
    expect(await c.get("pk", "app")).toBeNull();
  });
  it("treats failing storage as empty", async () => {
    const broken = keyValueCache({
      getItem: () => { throw new Error("blocked"); },
      setItem: () => { throw new Error("blocked"); },
      removeItem: () => { throw new Error("blocked"); },
    });
    await broken.set("pk", "app", { s: randomBytes(16) });
    expect(await broken.get("pk", "app")).toBeNull();
  });
});

describe("encrypted cache (#27)", () => {
  const kv = () => {
    const m = new Map<string, string>();
    return { m, store: { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) } };
  };
  it("round-trips, and storage holds only ciphertext", async () => {
    const { m, store } = kv();
    const c = encryptedCache(store, memoryKeyStore());
    const s = randomBytes(16);
    await c.set("pk", "app", { s });
    expect(await c.get("pk", "app")).toEqual({ s });
    const stored = [...m.values()][0]!;
    expect(stored).not.toContain(toBase64Url(s));
    expect(Object.keys(JSON.parse(stored))).toEqual(["iv", "ct"]);
  });
  it("another key can't read it", async () => {
    const { store } = kv();
    await encryptedCache(store, memoryKeyStore()).set("pk", "app", { s: randomBytes(16) });
    expect(await encryptedCache(store, memoryKeyStore()).get("pk", "app")).toBeNull();
  });
  it("the generated key isn't extractable", async () => {
    const ks = memoryKeyStore();
    await encryptedCache(kv().store, ks).set("pk", "app", { s: randomBytes(16) });
    expect((await ks.get())?.extractable).toBe(false);
  });
});

describe("encrypted cache slot binding (#44)", () => {
  it("an entry copied to another slot doesn't decrypt", async () => {
    const m = new Map<string, string>();
    const store = { getItem: (k: string) => m.get(k) ?? null, setItem: (k: string, v: string) => void m.set(k, v), removeItem: (k: string) => void m.delete(k) };
    const c = encryptedCache(store, memoryKeyStore());
    await c.set("pk", "app1", { s: randomBytes(16) });
    await c.set("pk", "app2", { s: randomBytes(16) });
    const [k1, k2] = [...m.keys()];
    m.set(k2!, m.get(k1!)!);
    expect(await c.get("pk", "app2")).toBeNull();
    expect(await c.get("pk", "app1")).not.toBeNull();
  });
});

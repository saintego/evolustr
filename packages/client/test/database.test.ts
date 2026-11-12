import { randomBytes } from "@evolustr/core";
import { describe, expect, it } from "vitest";
import { keyValueCache, memoryCache, memoryDatabases, migrateRows } from "../src/index.ts";

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
    expect(await migrateRows(from, to, { kind: "all" })).toBe(2);
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
    expect(n).toBe(1);
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
    expect(await migrateRows(await mem.open(old), await mem.open(current), { kind: "since", cutoffMs: 3000, marginMs: 200 })).toBe(1);
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

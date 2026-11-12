import { describe, expect, it } from "vitest";
import { defaultSettings, emptySettings, mergeSettings, parseSettings, resolveSetting, setSetting, unwrap } from "../src/index.ts";

describe("shared settings (SPEC §9)", () => {
  it("merges per field: two devices changing different keys keep both", () => {
    const a = unwrap(setSetting(emptySettings, "theme", "dark", 10));
    const b = unwrap(setSetting(emptySettings, "language", "cs", 11));
    const m = mergeSettings(a, b);
    expect(m.values["theme"]?.value).toBe("dark");
    expect(m.values["language"]?.value).toBe("cs");
  });
  it("newer change wins for the same key, in either merge order", () => {
    const older = unwrap(setSetting(emptySettings, "theme", "dark", 10));
    const newer = unwrap(setSetting(emptySettings, "theme", "light", 20));
    expect(mergeSettings(older, newer).values["theme"]?.value).toBe("light");
    expect(mergeSettings(newer, older).values["theme"]?.value).toBe("light");
  });
  it("validates known keys and keeps namespaced unknown keys", () => {
    expect(setSetting(emptySettings, "theme", "purple", 1).ok).toBe(false);
    expect(setSetting(emptySettings, "fontScale", 5, 1).ok).toBe(false);
    expect(setSetting(emptySettings, "random", 1, 1).ok).toBe(false);
    const doc = unwrap(setSetting(emptySettings, "x-acme-layout", { cols: 2 }, 1));
    expect(unwrap(parseSettings(JSON.stringify(doc)))).toEqual(doc);
  });
  it("resolves app ?? shared ?? default", () => {
    const d = defaultSettings();
    const shared = unwrap(setSetting(emptySettings, "theme", "dark", 1));
    const app = unwrap(setSetting(emptySettings, "theme", "light", 1));
    expect(resolveSetting("theme", emptySettings, emptySettings, d)).toBe("system");
    expect(resolveSetting("theme", emptySettings, shared, d)).toBe("dark");
    expect(resolveSetting("theme", app, shared, d)).toBe("light");
    const bad = { v: 1 as const, values: { theme: { value: "purple", at: 1 } } };
    expect(resolveSetting("theme", bad, shared, d)).toBe("dark");
  });

  it("ignores prototype keys like constructor and __proto__ (#33)", () => {
    expect(setSetting(emptySettings, "constructor", 1, 1).ok).toBe(false);
    expect(setSetting(emptySettings, "toString", "x", 1).ok).toBe(false);
    const doc = unwrap(parseSettings('{"v":1,"values":{"__proto__":{"value":"x","at":1},"theme":{"value":"dark","at":2}}}'));
    expect(Object.getPrototypeOf(doc.values)).toBeNull();
    expect(resolveSetting("theme", emptySettings, doc, defaultSettings())).toBe("dark");
  });
});

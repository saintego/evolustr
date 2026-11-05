import { memoryRelays, secretKeySigner, unwrap } from "@evolustr/core";
import { generateSecretKey } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import { createEvolustr, memoryCache, memoryDatabases } from "../src/index.ts";

const URLS = ["wss://r1"];

const setup = () => {
  const signer = secretKeySigner(generateSecretKey());
  const mem = memoryRelays();
  let clock = 1000;
  const client = (appId: string) =>
    createEvolustr(
      { signer, relays: mem.relays, openDatabase: memoryDatabases(["notes"]).open, cache: memoryCache(), now: () => ++clock },
      { appId, relayUrls: URLS },
    );
  return { client };
};

describe("settings in the client (SPEC §9)", () => {
  it("shared settings set in one app show up in another after refresh", async () => {
    const { client } = setup();
    const a = client("https://a.example");
    const b = client("https://b.example");
    unwrap(await a.connect());
    unwrap(await b.connect());
    expect(b.settings.get("theme")).toBe("system");
    unwrap(await a.settings.setShared("theme", "dark"));
    expect(a.settings.get("theme")).toBe("dark");
    unwrap(await b.settings.refresh());
    expect(b.settings.get("theme")).toBe("dark");
  });

  it("app overrides win over shared values and stay in that app", async () => {
    const { client } = setup();
    const a = client("https://a.example");
    const b = client("https://b.example");
    unwrap(await a.connect());
    unwrap(await b.connect());
    unwrap(await a.settings.setShared("theme", "dark"));
    unwrap(await b.settings.setApp("theme", "light"));
    unwrap(await b.settings.refresh());
    expect(b.settings.get("theme")).toBe("light");
    expect(a.settings.get("theme")).toBe("dark");
  });

  it("two apps changing different keys keep both", async () => {
    const { client } = setup();
    const a = client("https://a.example");
    const b = client("https://b.example");
    unwrap(await a.connect());
    unwrap(await b.connect());
    unwrap(await a.settings.setShared("theme", "dark"));
    unwrap(await b.settings.setShared("language", "cs"));
    unwrap(await a.settings.refresh());
    expect([a.settings.get("theme"), a.settings.get("language")]).toEqual(["dark", "cs"]);
  });

  it("rejects invalid values", async () => {
    const { client } = setup();
    const a = client("https://a.example");
    unwrap(await a.connect());
    expect((await a.settings.setShared("theme", "purple")).ok).toBe(false);
  });
});

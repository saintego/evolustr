import { createEvolustr, memoryCache, memoryDatabases } from "@evolustr/client";
import { memoryRelays, secretKeySigner } from "@evolustr/core";
import { generateSecretKey } from "nostr-tools/pure";
import { createElement } from "react";
import { renderToString } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { EvolustrProvider, useEvolustr, useSetting } from "../src/index.ts";

const client = () =>
  createEvolustr(
    { signer: secretKeySigner(generateSecretKey()), relays: memoryRelays().relays, openDatabase: memoryDatabases(["notes"]).open, cache: memoryCache() },
    { appId: "https://app.example", relayUrls: ["wss://r1"] },
  );

describe("@evolustr/react", () => {
  it("starts in the connecting state and reads settings defaults", () => {
    const Probe = () => {
      const { state, status } = useEvolustr();
      const theme = useSetting("theme");
      return createElement("p", null, `${state.kind}|${status === null ? "none" : status.level}|${theme}`);
    };
    const html = renderToString(createElement(EvolustrProvider, { client: client() }, createElement(Probe)));
    expect(html).toContain("connecting|none|system");
  });

  it("hooks fail clearly outside the provider", () => {
    const Probe = () => (useEvolustr(), null);
    expect(() => renderToString(createElement(Probe))).toThrow("inside <EvolustrProvider>");
  });
});

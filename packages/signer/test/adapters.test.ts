import { memoryRelays, unwrap } from "@evolustr/core";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import { createEvolustrSigner, handleIframeMessage, handleNip46Request } from "../src/index.ts";

const signer = () => {
  const sk = generateSecretKey();
  return createEvolustrSigner({
    relays: memoryRelays().relays,
    relayUrls: ["wss://r1"],
    signerKey: "https://signer.example",
    sign: async (e) => finalizeEvent({ ...e, tags: e.tags.map((t) => [...t]) }, sk),
    getPublicKey: async () => getPublicKey(sk),
    getSecretKey: () => sk,
    ui: { confirm: async () => true, requestGesture: async () => {} },
  });
};

describe("adapters", () => {
  it("iframe: the caller is event.origin; other messages and null origins are ignored", async () => {
    const s = signer();
    const req = { type: "evolustr", id: "1", method: "evolustr_capabilities" };
    const r = await handleIframeMessage(s, { origin: "https://a.example", data: req }, ["https://a.example"]);
    expect(r).toMatchObject({ id: "1", result: { appId: "https://a.example" } });
    expect(await handleIframeMessage(s, { origin: "null", data: req }, () => true)).toBeNull();
    expect(await handleIframeMessage(s, { origin: "https://a.example", data: { hello: 1 } }, "https://a.example")).toBeNull();
    expect(await handleIframeMessage(s, { origin: "https://b.example", data: req }, "https://a.example")).toBeNull();
    expect(await handleIframeMessage(s, { origin: "https://b.example", data: req }, ["https://a.example"])).toBeNull();
    expect(await handleIframeMessage(s, { origin: "https://b.example", data: req }, (o) => o.endsWith(".example"))).not.toBeNull();
  });

  it("iframe: errors come back as data", async () => {
    const r = await handleIframeMessage(signer(), { origin: "https://a.example", data: { type: "evolustr", id: "2", method: "nope" } }, "https://a.example");
    expect(r).toMatchObject({ id: "2", error: { type: "unknownMethod" } });
  });

  it("NIP-46: connection-scoped app id, string results", async () => {
    const s = signer();
    const pk = "c".repeat(64);
    const r = await handleNip46Request(s, pk, { id: "x", method: "evolustr_capabilities", params: [] });
    expect(JSON.parse(r.result!)).toMatchObject({ identity: "connection", appId: `nip46:${pk}` });
    const key = await handleNip46Request(s, pk, { id: "y", method: "evolustr_get_wrap_key", params: [] });
    expect(key.result).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(unwrap(await s.getWrapKey({ identity: "connection", clientPubkey: "d".repeat(64) }))).toHaveLength(32);
  });
});

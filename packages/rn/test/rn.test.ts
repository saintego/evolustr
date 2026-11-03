import { createEvolustr, memoryDatabases } from "@evolustr/client";
import { type Bytes, memoryRelays, randomBytes, secretKeySigner, toBase64Url, unwrap } from "@evolustr/core";
import { createEvolustrSigner } from "@evolustr/signer";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import { type NativePasskeyModule, type Nip55Bridge, nativeAppId, nativePasskeys, nip46Signer, nip55CapableSigner, nip55Signer, secureStoreCache } from "../src/index.ts";

const URLS = ["wss://r1"];
const APP = nativeAppId("android", "com.example.notes");

/** Fake react-native-passkey: binary values as base64url strings, PRF as number[]. */
const fakeNativePasskey = (store: Map<string, Bytes>, synced = true): NativePasskeyModule => {
  const authData = () => {
    const a = new Uint8Array(37);
    a[32] = 0x05 | (synced ? 0x18 : 0x08);
    return toBase64Url(a);
  };
  const prf = (id: string, first: unknown) =>
    Array.from(hmac(sha256, store.get(id)!, Uint8Array.from(atob(String(first).replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0))));
  return {
    isSupported: () => true,
    create: async (req) => {
      const id = toBase64Url(randomBytes(16));
      store.set(id, randomBytes(32));
      return { rawId: id, response: { authenticatorData: authData() }, clientExtensionResults: { prf: { enabled: true, results: { first: prf(id, req.extensions?.prf?.eval?.first) } } } };
    },
    get: async (req) => {
      const id = req.allowCredentials?.find((c) => store.has(c.id))?.id;
      if (id === undefined) throw new Error("NotAllowed");
      return { id, rawId: id, response: { authenticatorData: authData() }, clientExtensionResults: { prf: { results: { first: prf(id, req.extensions?.prf?.eval?.first) } } } };
    },
  };
};

/** Fake expo-secure-store that enforces its key rules. */
const fakeSecureStore = () => {
  const m = new Map<string, string>();
  const check = (k: string) => {
    if (!/^[\w.-]+$/.test(k)) throw new Error(`Invalid key ${k}`);
  };
  return {
    getItemAsync: async (k: string) => (check(k), m.get(k) ?? null),
    setItemAsync: async (k: string, v: string) => void (check(k), m.set(k, v)),
    deleteItemAsync: async (k: string) => void (check(k), m.delete(k)),
  };
};

describe("@evolustr/rn", () => {
  it("native passkeys: strict mode works and a second phone with the synced passkey opens it", async () => {
    const signer = secretKeySigner(generateSecretKey());
    const mem = memoryRelays();
    const synced = new Map<string, Bytes>();
    const phone = () =>
      createEvolustr(
        {
          signer,
          relays: mem.relays,
          openDatabase: memoryDatabases(["notes"]).open,
          cache: secureStoreCache(fakeSecureStore()),
          passkeys: nativePasskeys(fakeNativePasskey(synced), { rpId: "notes.example", rpName: "Notes" }),
        },
        { appId: APP, relayUrls: URLS },
      );
    const a = phone();
    expect(unwrap(await a.connect()).state).toBe("ready");
    expect(unwrap(await a.enrollPasskey())).toEqual({ done: true });
    expect(unwrap(await a.makeStrict())).toMatchObject({ mode: "strict", backupRecommended: true });
    const b = phone();
    expect(unwrap(await b.connect())).toEqual({ state: "needsUserAction", action: "passkey" });
    expect(unwrap(await b.unlock()).status.unlockedWith).toBe("passkey");
  });

  it("NIP-46 bunker as the signer (compatible mode)", async () => {
    const sk = generateSecretKey();
    const inner = secretKeySigner(sk);
    const bunker = { getPublicKey: inner.getPublicKey, signEvent: inner.signEvent, nip44Encrypt: inner.nip44Encrypt, nip44Decrypt: inner.nip44Decrypt };
    const c = createEvolustr(
      { signer: nip46Signer(bunker), relays: memoryRelays().relays, openDatabase: memoryDatabases(["notes"]).open, cache: secureStoreCache(fakeSecureStore()) },
      { appId: APP, relayUrls: URLS },
    );
    expect(unwrap(await c.connect())).toMatchObject({ state: "ready", status: { mode: "compatible" } });
  });

  it("NIP-55 capable signer: Android's calling package becomes the app id", async () => {
    const sk = generateSecretKey();
    const pubkey = getPublicKey(sk);
    const mem = memoryRelays();
    const inner = secretKeySigner(sk);
    const evolustr = createEvolustrSigner({
      relays: mem.relays, relayUrls: URLS, signerKey: "com.greenart7c3.nostrsigner",
      sign: async (e) => finalizeEvent({ ...e, tags: e.tags.map((t) => [...t]) }, sk),
      getPublicKey: async () => pubkey, getSecretKey: () => sk,
      ui: { confirm: async () => true, requestGesture: async () => {} },
    });
    // The signer app sees the caller's package from Android, not from the request.
    const bridgeFor = (callingPackage: string): Nip55Bridge => ({
      getPublicKey: async () => pubkey,
      signEvent: async (json) => JSON.stringify(await inner.signEvent(JSON.parse(json))),
      nip44Encrypt: (pt, pk) => inner.nip44Encrypt(pk, pt),
      nip44Decrypt: (ct, pk) => inner.nip44Decrypt(pk, ct),
      request: async (type, params) => {
        const r = await evolustr.handle(type, params, { identity: "verified", androidPackage: callingPackage });
        if (!r.ok) throw new Error(r.error.message);
        return typeof r.value === "string" ? r.value : JSON.stringify(r.value);
      },
    });
    const bridge = bridgeFor("com.example.notes");
    const capable = await nip55CapableSigner(bridge);
    expect((await capable!.capabilities()).appId).toBe(APP);
    const c = createEvolustr(
      { signer: nip55Signer(bridge), relays: mem.relays, openDatabase: memoryDatabases(["notes"]).open, cache: secureStoreCache(fakeSecureStore()), capableSigner: capable },
      { appId: APP, relayUrls: URLS },
    );
    expect(unwrap(await c.connect())).toMatchObject({ state: "ready", status: { signer: "capable-verified", canMakeStrict: true } });
    expect(unwrap(await c.makeStrict()).mode).toBe("strict");
    // A standard NIP-55 signer (no custom requests) isn't treated as capable.
    expect(await nip55CapableSigner({ ...bridge, request: async () => { throw new Error("unknown"); } })).toBeUndefined();
  });
});

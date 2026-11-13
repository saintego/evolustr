import { memoryRelays, randomBytes, unwrap } from "@evolustr/core";
import { createEvolustrSigner, listenForIframeRequests } from "@evolustr/signer";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { secretKeySigner } from "@evolustr/core";
import { describe, expect, it } from "vitest";
import { createEvolustr, iframeCapableSigner, memoryCache, memoryDatabases } from "../src/index.ts";

const URLS = ["wss://r1"];
const SIGNER_ORIGIN = "https://signer.example";

/** A tiny postMessage simulation: each fake window has an origin and listeners. */
const fakeWindow = (origin: string) => {
  const listeners = new Set<(e: Event) => void>();
  return {
    origin,
    addEventListener: (_: string, l: (e: Event) => void) => void listeners.add(l),
    removeEventListener: (_: string, l: (e: Event) => void) => void listeners.delete(l),
    deliver: (data: unknown, fromOrigin: string) => {
      for (const l of [...listeners]) l({ origin: fromOrigin, data } as unknown as Event);
    },
  };
};

const world = () => {
  const sk = generateSecretKey();
  const pubkey = getPublicKey(sk);
  const mem = memoryRelays();
  let clock = 1000;
  const now = () => ++clock;
  const nostrSigner = secretKeySigner(sk);

  /** One device: an app page embedding the signer iframe. */
  const device = (appOrigin: string, opts: { requireStrong?: boolean } = {}) => {
    const appWin = fakeWindow(appOrigin);
    const signerWin = fakeWindow(SIGNER_ORIGIN);
    const signer = createEvolustrSigner({
      relays: mem.relays,
      relayUrls: URLS,
      signerKey: SIGNER_ORIGIN,
      sign: async (e) => finalizeEvent({ ...e, tags: e.tags.map((t) => [...t]) }, sk),
      getPublicKey: async () => pubkey,
      getSecretKey: () => sk,
      ui: { confirm: async () => true, requestGesture: async () => {} },
      now,
    });
    listenForIframeRequests(signer, signerWin, (response) => appWin.deliver(response, SIGNER_ORIGIN), appOrigin);
    const capableSigner = iframeCapableSigner({
      target: { postMessage: (msg) => queueMicrotask(() => signerWin.deliver(msg, appOrigin)) },
      signerOrigin: SIGNER_ORIGIN,
      self: appWin,
    });
    const dbs = memoryDatabases(["notes"]);
    return createEvolustr(
      { signer: nostrSigner, relays: mem.relays, openDatabase: dbs.open, cache: memoryCache(), now, capableSigner },
      { appId: appOrigin, relayUrls: URLS, ...(opts.requireStrong ? { requireStrong: true } : {}) },
    );
  };
  return { device };
};

const ready = async (c: ReturnType<ReturnType<typeof world>["device"]>) => {
  const r = unwrap(await c.connect());
  if (r.state !== "ready") throw new Error(JSON.stringify(r));
  return r;
};

describe("client with a capable iframe signer", () => {
  it("adds the signer's wrap on first use, so strict needs no passkey", async () => {
    const w = world();
    const a = w.device("https://notes.example");
    const r = await ready(a);
    expect(r.status).toMatchObject({ signer: "capable-verified", canMakeStrict: true, mode: "compatible" });
    expect(r.status.dependsOnNsec).toBe(false);
    // The signer holds the nsec (sk wrap), so strict data depends on the nsec (#43).
    expect(unwrap(await a.makeStrict())).toMatchObject({ mode: "strict", level: "strong", dependsOnNsec: true });
  });

  it("a new device with the same signer opens a strict vault without any prompt", async () => {
    const w = world();
    const a = w.device("https://notes.example");
    const ra = await ready(a);
    await a.makeStrict();
    const b = await ready(w.device("https://notes.example"));
    expect(b.status).toMatchObject({ unlockedWith: "signer", mode: "strict" });
    expect(b.db.sHash).toBe((await ready(a)).db.sHash);
    expect(b.db.sHash).not.toBe(ra.db.sHash);
  });

  it("two apps on the same signer get separate databases", async () => {
    const w = world();
    const notes = await ready(w.device("https://notes.example"));
    const todo = await ready(w.device("https://todo.example"));
    expect(notes.db.sHash).not.toBe(todo.db.sHash);
  });

  it("requireStrong uses the signer for the first, strict vault", async () => {
    const w = world();
    const a = w.device("https://notes.example", { requireStrong: true });
    expect(unwrap(await a.connect())).toEqual({ state: "needsUserAction", action: "setupStrong" });
    expect(unwrap(await a.unlock()).status).toMatchObject({ mode: "strict", unlockedWith: "signer" });
    expect((await ready(w.device("https://notes.example", { requireStrong: true }))).status.unlockedWith).toBe("signer");
  });
});

describe("backup check with a capable signer (#42)", () => {
  /** A capable signer that reports whatever `recoverable` the test wants. */
  const fakeSigner = (recoverable: boolean | undefined) => {
    const key = randomBytes(32);
    return {
      capabilities: async () => ({ identity: "verified" as const, appId: "https://notes.example", signerId: "0123456789abcdef", ready: true, signerPasskey: true, ...(recoverable === undefined ? {} : { recoverable }) }),
      getWrapKey: async () => key,
    };
  };
  const client = (recoverable: boolean | undefined, requireStrong = false) =>
    createEvolustr(
      {
        signer: secretKeySigner(generateSecretKey()),
        relays: memoryRelays().relays,
        openDatabase: memoryDatabases(["notes"]).open,
        cache: memoryCache(),
        capableSigner: fakeSigner(recoverable),
      },
      { appId: "https://notes.example", relayUrls: ["wss://r1"], ...(requireStrong ? { requireStrong: true } : {}) },
    );

  it("a signer that isn't recoverable needs a backup before strict", async () => {
    const c = client(false);
    expect(unwrap(await c.connect()).state).toBe("ready");
    expect(await c.makeStrict()).toMatchObject({ ok: false, error: { type: "backupRequired" } });
    expect((await c.makeStrict({ acceptDeviceLoss: true })).ok).toBe(true);
  });
  it("a signer that doesn't report it counts as not recoverable", async () => {
    const c = client(undefined);
    unwrap(await c.connect());
    expect(await c.makeStrict()).toMatchObject({ ok: false, error: { type: "backupRequired" } });
  });
  it("a recoverable signer only gets the reminder", async () => {
    const c = client(true);
    unwrap(await c.connect());
    expect(unwrap(await c.makeStrict())).toMatchObject({ mode: "strict", backupRecommended: true });
  });
  it("requireStrong with a non-recoverable signer needs acceptDeviceLoss", async () => {
    const c = client(false, true);
    expect(unwrap(await c.connect())).toEqual({ state: "needsUserAction", action: "setupStrong" });
    expect(await c.unlock()).toMatchObject({ ok: false, error: { type: "backupRequired" } });
    expect(unwrap(await c.unlock({ acceptDeviceLoss: true })).status.mode).toBe("strict");
  });
});

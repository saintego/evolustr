import { type Bytes, VAULT_KIND, appVaultDTag, memoryPasskeys, memoryRelays, signerVaultDTag, unwrap } from "@evolustr/core";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import { type SignerHost, createEvolustrSigner, mergeSignerVaults } from "../src/index.ts";

const URLS = ["wss://r1"];
const SIGNER = "https://signer.example";
const NPUB = "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m";

const setup = () => {
  const sk = generateSecretKey();
  const pubkey = getPublicKey(sk);
  const mem = memoryRelays();
  let clock = 1000;
  const gestures: string[] = [];
  const passkeyStore = new Map<string, Bytes>();
  const host = (o: Partial<SignerHost> & { holdsNsec?: boolean; refuse?: boolean } = {}): SignerHost => ({
    relays: mem.relays,
    relayUrls: URLS,
    signerKey: SIGNER,
    sign: async (e) => finalizeEvent({ ...e, tags: e.tags.map((t) => [...t]) }, sk),
    getPublicKey: async () => pubkey,
    ...(o.holdsNsec === false ? {} : { getSecretKey: () => sk }),
    ui: { confirm: async () => o.refuse !== true, requestGesture: async (r) => void gestures.push(r) },
    knownNsiteGateways: ["nsite.lol", "other.gw"],
    now: () => ++clock,
    ...o,
  });
  return { sk, pubkey, mem, host, gestures, passkeyStore };
};

const web = (origin: string) => ({ identity: "verified" as const, origin });

describe("@evolustr/signer", () => {
  it("gives each app its own key, derived only from the caller", async () => {
    const t = setup();
    const s = createEvolustrSigner(t.host());
    const a = unwrap(await s.getWrapKey(web("https://a.example")));
    const b = unwrap(await s.getWrapKey(web("https://b.example")));
    expect(a).not.toEqual(b);
    // Params can't pick another app's key.
    const viaHandle = unwrap(await s.handle("evolustr_get_wrap_key", [{ appId: "https://a.example" }], web("https://b.example")));
    const viaHandleA = unwrap(await s.handle("evolustr_get_wrap_key", [], web("https://a.example")));
    expect(viaHandle).not.toBe(viaHandleA);
  });

  it("the same nsite on two known gateways gets the same key", async () => {
    const t = setup();
    const s = createEvolustrSigner(t.host());
    const k1 = unwrap(await s.getWrapKey(web(`https://${NPUB}.nsite.lol`)));
    const k2 = unwrap(await s.getWrapKey(web(`https://${NPUB}.other.gw`)));
    expect(k1).toEqual(k2);
    expect(unwrap(s.appIdFor(web(`https://${NPUB}.nsite.lol`)))).toBe(`nsite:${NPUB}`);
  });

  it("NIP-46 and Android callers get their own app ids", () => {
    const s = createEvolustrSigner(setup().host());
    expect(unwrap(s.appIdFor({ identity: "connection", clientPubkey: "a".repeat(64) }))).toBe(`nip46:${"a".repeat(64)}`);
    expect(unwrap(s.appIdFor({ identity: "verified", androidPackage: "com.example.notes" }))).toBe("android:com.example.notes");
  });

  it("a signer holding the nsec creates M once; a new device finds it via signerKey", async () => {
    const t = setup();
    const first = createEvolustrSigner(t.host());
    const k1 = unwrap(await first.getWrapKey(web("https://a.example")));
    const stored = await t.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [signerVaultDTag(t.pubkey, SIGNER)] }, 100);
    expect(stored.events).toHaveLength(1);
    const newDevice = createEvolustrSigner(t.host());
    expect(unwrap(await newDevice.getWrapKey(web("https://a.example")))).toEqual(k1);
    expect(t.gestures).toEqual([]); // no clicks needed with the nsec
  });

  it("a passthrough signer needs a signer passkey; it then works on another device with the synced passkey", async () => {
    const t = setup();
    const passkeys = () => memoryPasskeys({ rpId: "signer.example", store: t.passkeyStore });
    const a = createEvolustrSigner(t.host({ holdsNsec: false, passkeys: passkeys() }));
    expect(await a.getWrapKey(web("https://a.example"))).toMatchObject({ ok: false, error: { type: "signerLocked" } });
    unwrap(await a.enrollPasskey());
    const k1 = unwrap(await a.getWrapKey(web("https://a.example")));
    const b = createEvolustrSigner(t.host({ holdsNsec: false, passkeys: passkeys() }));
    expect(unwrap(await b.capabilities(web("https://a.example"))).ready).toBe(false);
    expect(unwrap(await b.getWrapKey(web("https://a.example")))).toEqual(k1);
    expect(t.gestures).toContain("unlock");
    expect(unwrap(await b.capabilities(web("https://a.example"))).signerPasskey).toBe(true);
  });

  it("with allowSkWrap false the nsec isn't used and no sk wrap is stored", async () => {
    const t = setup();
    const s = createEvolustrSigner(t.host({ allowSkWrap: false, passkeys: memoryPasskeys({ rpId: "signer.example" }) }));
    expect((await s.getWrapKey(web("https://a.example"))).ok).toBe(false);
    unwrap(await s.enrollPasskey());
    const stored = await t.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [signerVaultDTag(t.pubkey, SIGNER)] }, 100);
    expect(JSON.parse(stored.events[0]!.content).wraps.map((w: { type: string }) => w.type)).toEqual(["passkey"]);
  });

  it("the user can refuse an app", async () => {
    const t = setup();
    const s = createEvolustrSigner(t.host({ refuse: true }));
    expect(await s.getWrapKey(web("https://a.example"))).toMatchObject({ ok: false, error: { type: "userRefused" } });
  });

  it("capabilities report signerId once ready", async () => {
    const t = setup();
    const s = createEvolustrSigner(t.host());
    // Before any app was allowed, capabilities creates and publishes nothing (#29).
    expect(unwrap(await s.capabilities(web("https://a.example")))).toMatchObject({ ready: false, signerId: null });
    expect((await t.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [signerVaultDTag(t.pubkey, SIGNER)] }, 100)).events).toHaveLength(0);
    unwrap(await s.getWrapKey(web("https://a.example")));
    const caps = unwrap(await s.capabilities(web("https://a.example")));
    expect(caps).toMatchObject({ identity: "verified", appId: "https://a.example", ready: true });
    expect(caps.signerId).toMatch(/^[0-9a-f]{16}$/);
    // Different apps see different signer ids, so they can't link the user (#29).
    expect(unwrap(await s.capabilities(web("https://b.example"))).signerId).not.toBe(caps.signerId);
  });

  it("recognises Evolustr vault events for auto-approve lists", () => {
    const s = createEvolustrSigner(setup().host());
    expect(s.isProtectedEvent({ kind: VAULT_KIND, tags: [["d", appVaultDTag("pk", "app")]] })).toBe(true);
    expect(s.isProtectedEvent({ kind: VAULT_KIND, tags: [["d", "evolustr:settings:v1"]] })).toBe(true);
    expect(s.isProtectedEvent({ kind: VAULT_KIND, tags: [["d", "other-app-data"]] })).toBe(false);
    expect(s.isProtectedEvent({ kind: 1, tags: [] })).toBe(false);
  });

  it("enrolling on a locked device unlocks the existing key instead of creating a second one (#28)", async () => {
    const t = setup();
    const passkeys = () => memoryPasskeys({ rpId: "signer.example", store: t.passkeyStore });
    const a = createEvolustrSigner(t.host({ holdsNsec: false, passkeys: passkeys() }));
    unwrap(await a.enrollPasskey());
    const k1 = unwrap(await a.getWrapKey(web("https://a.example")));
    // Second device, locked: it unlocks with the synced passkey and enrolls a
    // different authenticator (e.g. a hardware key); the new wrap must hold the same M.
    const synced = passkeys();
    const hardware = memoryPasskeys({ rpId: "signer.example" });
    const both = { ...synced, create: hardware.create, get: async (a: Parameters<typeof synced.get>[0]) => (a.allowCredIds.some((id) => hardware.store.has(id)) ? hardware.get(a) : synced.get(a)) };
    const b = createEvolustrSigner(t.host({ holdsNsec: false, passkeys: both }));
    unwrap(await b.enrollPasskey());
    expect(unwrap(await b.getWrapKey(web("https://a.example")))).toEqual(k1);
    // The hardware key alone (no synced passkey) also opens the same M.
    const hwOnly = createEvolustrSigner(t.host({ holdsNsec: false, passkeys: { ...hardware, rpId: "signer.example" } }));
    expect(unwrap(await hwOnly.getWrapKey(web("https://a.example")))).toEqual(k1);
    // A third device whose passkeys can't open the vault can't add a wrap at all.
    const c = createEvolustrSigner(t.host({ holdsNsec: false, passkeys: memoryPasskeys({ rpId: "signer.example" }) }));
    expect(await c.enrollPasskey()).toMatchObject({ ok: false, error: { type: "signerLocked" } });
  });

  it("an empty or malformed signer vault is an error, not first use (#28)", async () => {
    const t = setup();
    const s = createEvolustrSigner(t.host());
    const k1 = unwrap(await s.getWrapKey(web("https://a.example")));
    // Someone publishes an empty signer vault over the real one.
    const host = t.host();
    await t.mem.relays.publish(URLS, await host.sign({ kind: VAULT_KIND, created_at: 99999, tags: [["d", signerVaultDTag(t.pubkey, SIGNER)]], content: JSON.stringify({ v: 1, wraps: [] }) }), 100);
    const fresh = createEvolustrSigner(t.host());
    expect(await fresh.getWrapKey(web("https://a.example"))).toMatchObject({ ok: false, error: { type: "invalidSignerVault" } });
    // No new M was published over it.
    const events = (await t.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [signerVaultDTag(t.pubkey, SIGNER)] }, 100)).events;
    expect(JSON.parse(events[0]!.content)).toEqual({ v: 1, wraps: [] });
    expect(k1).toHaveLength(32);
  });

  it("refuses insecure and malformed callers (#30)", async () => {
    const s = createEvolustrSigner(setup().host());
    expect(await s.getWrapKey(web("http://app.example"))).toMatchObject({ ok: false, error: { type: "insecureOrigin" } });
    expect(await s.getWrapKey({ identity: "connection", clientPubkey: "x|y" })).toMatchObject({ ok: false, error: { type: "invalidCaller" } });
    expect(await s.capabilities(web("not an origin"))).toMatchObject({ ok: false });
  });

  describe("M from the cache doesn't skip reading the signer vault (#40)", () => {
    const memCache = () => {
      const m = new Map<string, Bytes>();
      return { get: async (k: string) => m.get(k) ?? null, set: async (k: string, v: Bytes) => void m.set(k, v), remove: async (k: string) => void m.delete(k) };
    };
    const wrapsOnRelay = async (t: ReturnType<typeof setup>) =>
      JSON.parse((await t.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [signerVaultDTag(t.pubkey, SIGNER)] }, 100)).events[0]!.content).wraps as Array<{ type: string }>;

    it("enrolling with M cached keeps the sk wrap and the other passkeys", async () => {
      const t = setup();
      const cache = memCache();
      const pk1 = memoryPasskeys({ rpId: "signer.example" });
      const one = createEvolustrSigner(t.host({ cache, passkeys: pk1 }));
      unwrap(await one.getWrapKey(web("https://a.example")));
      unwrap(await one.enrollPasskey());
      expect((await wrapsOnRelay(t)).map((w) => w.type)).toEqual(["sk", "passkey"]);
      // A second instance starts with M in the cache.
      const two = createEvolustrSigner(t.host({ cache, passkeys: memoryPasskeys({ rpId: "signer.example" }) }));
      unwrap(await two.enrollPasskey());
      expect((await wrapsOnRelay(t)).map((w) => w.type)).toEqual(["sk", "passkey", "passkey"]);
    });

    it("with the relays down, enrolling fails and publishes nothing", async () => {
      const t = setup();
      const cache = memCache();
      unwrap(await createEvolustrSigner(t.host({ cache })).getWrapKey(web("https://a.example")));
      const before = await wrapsOnRelay(t);
      t.mem.down.add(URLS[0]!);
      const s = createEvolustrSigner(t.host({ cache, passkeys: memoryPasskeys({ rpId: "signer.example" }) }));
      expect((await s.enrollPasskey()).ok).toBe(false);
      t.mem.down.clear();
      expect(await wrapsOnRelay(t)).toEqual(before);
    });

    it("capabilities with M cached report the signer passkey", async () => {
      const t = setup();
      const cache = memCache();
      const one = createEvolustrSigner(t.host({ cache, passkeys: memoryPasskeys({ rpId: "signer.example" }) }));
      unwrap(await one.getWrapKey(web("https://a.example")));
      unwrap(await one.enrollPasskey());
      const two = createEvolustrSigner(t.host({ cache }));
      expect(unwrap(await two.capabilities(web("https://a.example")))).toMatchObject({ ready: true, signerPasskey: true });
    });
  });

  describe("local copy of the signer vault (#41)", () => {
    const fullCache = () => {
      const m = new Map<string, Bytes>();
      const v = new Map<string, string>();
      return {
        get: async (k: string) => m.get(k) ?? null,
        set: async (k: string, x: Bytes) => void m.set(k, x),
        remove: async (k: string) => void m.delete(k),
        getVault: async (k: string) => v.get(k) ?? null,
        setVault: async (k: string, x: string) => void v.set(k, x),
        forgetM: () => m.clear(),
      };
    };
    const publishSignerVault = async (t: ReturnType<typeof setup>, content: unknown) => {
      const host = t.host();
      await t.mem.relays.publish(URLS, await host.sign({ kind: VAULT_KIND, created_at: 99999, tags: [["d", signerVaultDTag(t.pubkey, SIGNER)]], content: JSON.stringify(content) }), 100);
    };
    const relayWraps = async (t: ReturnType<typeof setup>) =>
      (JSON.parse((await t.mem.relays.query(URLS, { kinds: [VAULT_KIND], "#d": [signerVaultDTag(t.pubkey, SIGNER)] }, 100)).events[0]!.content).wraps as Array<{ type: string; credId?: string }>);

    it("mergeSignerVaults: union, local wins on the same id", () => {
      const a = { v: 1 as const, wraps: [{ type: "sk" as const, iv: "a", ct: "local" }] };
      const b = { v: 1 as const, wraps: [{ type: "sk" as const, iv: "b", ct: "remote" }, { type: "passkey" as const, rpId: "r", credId: "c", iv: "x", ct: "y" }] };
      const merged = mergeSignerVaults(a, b);
      expect(merged.wraps).toHaveLength(2);
      expect(merged.wraps[0]).toMatchObject({ ct: "local" });
    });

    it("a replaced wrap list doesn't lock a device out, and the relays are repaired", async () => {
      const t = setup();
      const cache = fullCache();
      const a = createEvolustrSigner(t.host({ cache, passkeys: memoryPasskeys({ rpId: "signer.example" }) }));
      const k1 = unwrap(await a.getWrapKey(web("https://a.example")));
      unwrap(await a.enrollPasskey());
      await publishSignerVault(t, { v: 1, wraps: [{ type: "passkey", rpId: "signer.example", credId: "x", iv: "AAAA", ct: "AAAA" }] });
      cache.forgetM();
      const fresh = createEvolustrSigner(t.host({ cache }));
      expect(unwrap(await fresh.getWrapKey(web("https://a.example")))).toEqual(k1);
      const types = (await relayWraps(t)).map((w) => `${w.type}:${w.credId ?? ""}`);
      expect(types).toContain("sk:");
      expect(types).toContain("passkey:x");
      expect(types.filter((x) => x.startsWith("passkey:"))).toHaveLength(2);
    });

    it("a rolled-back wrap list gets the newer passkey back", async () => {
      const t = setup();
      const cache = fullCache();
      const a = createEvolustrSigner(t.host({ cache, passkeys: memoryPasskeys({ rpId: "signer.example" }) }));
      unwrap(await a.getWrapKey(web("https://a.example")));
      const before = await relayWraps(t);
      unwrap(await a.enrollPasskey());
      await publishSignerVault(t, { v: 1, wraps: before });
      const b = createEvolustrSigner(t.host({ cache }));
      unwrap(await b.getWrapKey(web("https://a.example")));
      expect((await relayWraps(t)).map((w) => w.type)).toEqual(["sk", "passkey"]);
    });

    it("without getVault/setVault the behaviour is unchanged: an empty vault is an error", async () => {
      const t = setup();
      unwrap(await createEvolustrSigner(t.host()).getWrapKey(web("https://a.example")));
      await publishSignerVault(t, { v: 1, wraps: [] });
      expect(await createEvolustrSigner(t.host()).getWrapKey(web("https://a.example"))).toMatchObject({ ok: false, error: { type: "invalidSignerVault" } });
    });
  });

  describe("recoverable (#42)", () => {
    it("true with the nsec (sk wrap)", async () => {
      const s = createEvolustrSigner(setup().host());
      unwrap(await s.getWrapKey(web("https://a.example")));
      expect(unwrap(await s.capabilities(web("https://a.example"))).recoverable).toBe(true);
    });
    it("true with only a synced signer passkey", async () => {
      const s = createEvolustrSigner(setup().host({ holdsNsec: false, passkeys: memoryPasskeys({ rpId: "signer.example", synced: true }) }));
      unwrap(await s.enrollPasskey());
      expect(unwrap(await s.capabilities(web("https://a.example"))).recoverable).toBe(true);
    });
    it("false with only a device-bound signer passkey", async () => {
      const s = createEvolustrSigner(setup().host({ holdsNsec: false, passkeys: memoryPasskeys({ rpId: "signer.example", synced: false }) }));
      unwrap(await s.enrollPasskey());
      expect(unwrap(await s.capabilities(web("https://a.example"))).recoverable).toBe(false);
    });
  });
});

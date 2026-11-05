import { type Bytes, VAULT_KIND, appVaultDTag, memoryPasskeys, memoryRelays, signerVaultDTag, unwrap } from "@evolustr/core";
import { finalizeEvent, generateSecretKey, getPublicKey } from "nostr-tools/pure";
import { describe, expect, it } from "vitest";
import { type SignerHost, createEvolustrSigner } from "../src/index.ts";

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
    expect(s.appIdFor(web(`https://${NPUB}.nsite.lol`))).toBe(`nsite:${NPUB}`);
  });

  it("NIP-46 and Android callers get their own app ids", () => {
    const s = createEvolustrSigner(setup().host());
    expect(s.appIdFor({ identity: "connection", clientPubkey: "abc" })).toBe("nip46:abc");
    expect(s.appIdFor({ identity: "verified", androidPackage: "com.example.notes" })).toBe("android:com.example.notes");
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
    expect((await b.capabilities(web("https://a.example"))).ready).toBe(false);
    expect(unwrap(await b.getWrapKey(web("https://a.example")))).toEqual(k1);
    expect(t.gestures).toContain("unlock");
    expect((await b.capabilities(web("https://a.example"))).signerPasskey).toBe(true);
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
    const caps = await s.capabilities(web("https://a.example"));
    expect(caps).toMatchObject({ identity: "verified", appId: "https://a.example", ready: true });
    expect(caps.signerId).toMatch(/^[0-9a-f]{16}$/);
  });

  it("recognises Evolustr vault events for auto-approve lists", () => {
    const s = createEvolustrSigner(setup().host());
    expect(s.isProtectedEvent({ kind: VAULT_KIND, tags: [["d", appVaultDTag("pk", "app")]] })).toBe(true);
    expect(s.isProtectedEvent({ kind: VAULT_KIND, tags: [["d", "evolustr:settings:v1"]] })).toBe(true);
    expect(s.isProtectedEvent({ kind: VAULT_KIND, tags: [["d", "other-app-data"]] })).toBe(false);
    expect(s.isProtectedEvent({ kind: 1, tags: [] })).toBe(false);
  });
});

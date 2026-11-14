import { describe, expect, it } from "vitest";
import {
  type Vault,
  addRootKey,
  createCompatibleVault,
  decideVault,
  makeStrict,
  randomBytes,
  sHash,
  unwrap,
} from "../src/index.ts";

const ctx = { pubkey: "a".repeat(64), appId: "https://app.example" };

const world = () => {
  const s = randomBytes(16);
  const r = randomBytes(16);
  const compat = unwrap(addRootKey(ctx, unwrap(createCompatibleVault(ctx, { s, nip44Ct: "x", now: 100 })), r, s));
  const s2 = randomBytes(16);
  const strict = unwrap(makeStrict(ctx, compat, { r, newS: s2, now: 200 }));
  return { s, r, compat, s2, strict };
};

describe("decideVault (SPEC §6.3)", () => {
  it("first use on this device, warning for weak vaults", () => {
    const { compat, strict } = world();
    expect(decideVault(ctx, { kind: "found", vault: compat }, null)).toMatchObject({ type: "firstUse", warnWeak: true });
    expect(decideVault(ctx, { kind: "found", vault: strict }, null)).toMatchObject({ type: "firstUse", warnWeak: false });
  });
  it("creates only when every relay answered and nothing exists", () => {
    expect(decideVault(ctx, { kind: "none" }, null)).toEqual({ type: "create" });
    expect(decideVault(ctx, { kind: "unreadable" }, null)).toMatchObject({ type: "choose", reason: "missing" });
  });
  it("same secret: nothing to do", () => {
    const s = randomBytes(16);
    const plain = unwrap(createCompatibleVault(ctx, { s, nip44Ct: "x", now: 100 }));
    expect(decideVault(ctx, { kind: "found", vault: plain }, { sHash: sHash(s) })).toEqual({ type: "same" });
  });
  it("rotation: device with R follows and migrates with the right cut-off", () => {
    const { s, r, s2, strict } = world();
    const d = decideVault(ctx, { kind: "found", vault: strict }, { sHash: sHash(s), r });
    expect(d).toMatchObject({ type: "follow", cutoff: 200 });
    if (d.type === "follow") expect(d.s).toEqual(s2);
  });
  it("a vault that doesn't name the local secret in its history isn't followed on its own", () => {
    const { r, strict } = world();
    expect(decideVault(ctx, { kind: "found", vault: strict }, { sHash: "unknown", r })).toMatchObject({
      type: "choose",
      reason: "ambiguous",
      options: ["followRelay", "restorePhrase"],
    });
  });
  it("a replayed pre-strict vault is a rollback, never followed (#25)", () => {
    const { r, s2, compat, strict } = world();
    // The device is on the strict database; someone re-signs the old compatible vault.
    const d = decideVault(ctx, { kind: "found", vault: compat }, { sHash: sHash(s2), r, copy: strict });
    expect(d).toMatchObject({ type: "choose", reason: "replaced", options: ["republishCopy", "restorePhrase", "startNew"] });
    // Without a local copy it still isn't followed: the user decides.
    expect(decideVault(ctx, { kind: "found", vault: compat }, { sHash: sHash(s2), r })).toMatchObject({ type: "choose" });
  });
  it("same secret with an edited header is treated as replaced", () => {
    const { r, s2, strict } = world();
    const flipped = { ...strict, mode: "compatible" as const, dataWraps: [...strict.dataWraps, { type: "nip44" as const, ct: "x" }] };
    expect(decideVault(ctx, { kind: "found", vault: flipped }, { sHash: sHash(s2), r, copy: strict })).toMatchObject({ type: "choose", reason: "replaced" });
  });
  it("replaced: device has R but the vault doesn't open with it", () => {
    const { s, compat } = world();
    const copy = compat;
    const attacker = unwrap(createCompatibleVault(ctx, { s: randomBytes(16), nip44Ct: "evil", now: 300 }));
    const d = decideVault(ctx, { kind: "found", vault: attacker }, { sHash: sHash(s), r: randomBytes(16), copy });
    expect(d).toMatchObject({ type: "choose", reason: "replaced" });
    if (d.type === "choose") expect(d.options).toContain("republishCopy");
  });
  it("device without R and a strict vault: never offers republishing", () => {
    const { s, compat, strict } = world();
    const d = decideVault(ctx, { kind: "found", vault: strict }, { sHash: sHash(s), copy: compat });
    expect(d).toEqual({ type: "needsStrongUnlock", vault: strict });
  });
  it("device without R, copy with a root key, different compatible vault: replaced (#38)", () => {
    const { s, compat } = world();
    const other = unwrap(createCompatibleVault(ctx, { s: randomBytes(16), nip44Ct: "y", now: 300 }));
    expect(decideVault(ctx, { kind: "found", vault: other }, { sHash: sHash(s), copy: compat })).toMatchObject({ type: "choose", reason: "replaced" });
  });
  it("device without R, copy without a root key, different compatible vault: user decides", () => {
    const s = randomBytes(16);
    const copy = unwrap(createCompatibleVault(ctx, { s, nip44Ct: "x", now: 100 }));
    const other = unwrap(createCompatibleVault(ctx, { s: randomBytes(16), nip44Ct: "y", now: 300 }));
    const d = decideVault(ctx, { kind: "found", vault: other }, { sHash: sHash(s), copy });
    expect(d).toMatchObject({ type: "choose", reason: "ambiguous", options: ["followRelay", "republishCopy"] });
  });
  it("vault missing: republish the copy if this device has one", () => {
    const { s, compat } = world();
    const withCopy = decideVault(ctx, { kind: "none" }, { sHash: sHash(s), copy: compat });
    expect(withCopy).toMatchObject({ type: "choose", reason: "missing", options: ["republishCopy", "restorePhrase", "startNew"] });
    const noCopy = decideVault(ctx, { kind: "none" }, { sHash: sHash(s) });
    expect(noCopy).toMatchObject({ options: ["restorePhrase", "startNew"] });
  });

  describe("same secret, the local copy as trust anchor (#38)", () => {
    const forgedWeak = (v: Vault): Vault => ({ v: 1, mode: "compatible", created: 1, sHash: v.sHash, history: [], rootWraps: [], dataWraps: [{ type: "nip44", ct: "x" }] });
    it("R + root wrap opens: same", () => {
      const { s2, r, strict } = world();
      expect(decideVault(ctx, { kind: "found", vault: strict }, { sHash: sHash(s2), r, copy: strict })).toEqual({ type: "same" });
    });
    it("R + root wrap doesn't open: replaced", () => {
      const { s2, strict } = world();
      expect(decideVault(ctx, { kind: "found", vault: strict }, { sHash: sHash(s2), r: randomBytes(16), copy: strict })).toMatchObject({ reason: "replaced" });
    });
    it("R + no root wrap while the copy has one: replaced", () => {
      const { s2, r, strict } = world();
      expect(decideVault(ctx, { kind: "found", vault: forgedWeak(strict) }, { sHash: sHash(s2), r, copy: strict })).toMatchObject({ reason: "replaced" });
    });
    it("R + no root wrap anywhere: same", () => {
      const s = randomBytes(16);
      const v = unwrap(createCompatibleVault(ctx, { s, nip44Ct: "x", now: 1 }));
      expect(decideVault(ctx, { kind: "found", vault: v }, { sHash: sHash(s), r: randomBytes(16), copy: v })).toEqual({ type: "same" });
    });
    it("no R, no copy: same only for a plain compatible vault (#54)", () => {
      const { s, s2, compat, strict } = world();
      const plainS = randomBytes(16);
      const plain = unwrap(createCompatibleVault(ctx, { s: plainS, nip44Ct: "x", now: 1 }));
      expect(decideVault(ctx, { kind: "found", vault: plain }, { sHash: sHash(plainS) })).toEqual({ type: "same" });
      expect(decideVault(ctx, { kind: "found", vault: strict }, { sHash: sHash(s2) })).toEqual({ type: "needsStrongUnlock", vault: strict });
      expect(decideVault(ctx, { kind: "found", vault: compat }, { sHash: sHash(s) })).toEqual({ type: "needsStrongUnlock", vault: compat });
    });
    it("no R, identical core: same", () => {
      const { s2, strict } = world();
      expect(decideVault(ctx, { kind: "found", vault: { ...strict, rootWraps: [] } }, { sHash: sHash(s2), copy: strict })).toEqual({ type: "same" });
    });
    it("no R, copy without root key, relay added R with the same header and nip44: same", () => {
      const s = randomBytes(16);
      const copy = unwrap(createCompatibleVault(ctx, { s, nip44Ct: "x", now: 1 }));
      const withR = unwrap(addRootKey(ctx, copy, randomBytes(16), s));
      expect(decideVault(ctx, { kind: "found", vault: withR }, { sHash: sHash(s), copy })).toEqual({ type: "same" });
    });
    it("no R, copy with root key, anything else: needs a strong unlock", () => {
      const { s2, strict } = world();
      expect(decideVault(ctx, { kind: "found", vault: forgedWeak(strict) }, { sHash: sHash(s2), copy: strict })).toMatchObject({ type: "needsStrongUnlock" });
    });
    it("no R, copy without root key, anything else: user decides", () => {
      const s = randomBytes(16);
      const copy = unwrap(createCompatibleVault(ctx, { s, nip44Ct: "x", now: 1 }));
      const other = { ...copy, created: 999 };
      expect(decideVault(ctx, { kind: "found", vault: other }, { sHash: sHash(s), copy })).toMatchObject({ type: "choose", reason: "ambiguous" });
    });
  });

  it("a vault whose secret is only in the device's seen list is a rollback (#44)", () => {
    const s = randomBytes(16);
    const old = unwrap(createCompatibleVault(ctx, { s: randomBytes(16), nip44Ct: "x", now: 1 }));
    expect(decideVault(ctx, { kind: "found", vault: old }, { sHash: sHash(s), seen: [old.sHash] })).toMatchObject({ type: "choose", reason: "replaced" });
  });
});

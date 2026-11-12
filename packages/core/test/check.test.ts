import { describe, expect, it } from "vitest";
import {
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
    const { s, compat } = world();
    expect(decideVault(ctx, { kind: "found", vault: compat }, { sHash: sHash(s) })).toEqual({ type: "same" });
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
  it("device without R and a different compatible vault: user decides", () => {
    const { s, compat } = world();
    const other = unwrap(createCompatibleVault(ctx, { s: randomBytes(16), nip44Ct: "y", now: 300 }));
    const d = decideVault(ctx, { kind: "found", vault: other }, { sHash: sHash(s), copy: compat });
    expect(d).toMatchObject({ type: "choose", reason: "ambiguous", options: ["followRelay", "republishCopy"] });
  });
  it("vault missing: republish the copy if this device has one", () => {
    const { s, compat } = world();
    const withCopy = decideVault(ctx, { kind: "none" }, { sHash: sHash(s), copy: compat });
    expect(withCopy).toMatchObject({ type: "choose", reason: "missing", options: ["republishCopy", "restorePhrase", "startNew"] });
    const noCopy = decideVault(ctx, { kind: "none" }, { sHash: sHash(s) });
    expect(noCopy).toMatchObject({ options: ["restorePhrase", "startNew"] });
  });
});

import { describe, expect, it } from "vitest";
import {
  type Vault,
  addRootKey,
  addRootWrap,
  headerBinding,
  verifyRootWrap,
  MAX_ROOT_WRAPS,
  backupRequirement,
  createCompatibleVault,
  createStrictVault,
  downgrade,
  hasRootKey,
  level,
  makeStrict,
  mergeVaults,
  migrationCutoff,
  nip44Wrap,
  openRootData,
  openRootWrap,
  parseVault,
  passkeyRootWrap,
  randomBytes,
  sHash,
  serializeVault,
  signerRootWrap,
  unwrap,
  validateVault,
} from "../src/index.ts";

const ctx = { pubkey: "a".repeat(64), appId: "https://app.example" };
const fresh = () => ({ s: randomBytes(16), r: randomBytes(16), key: randomBytes(32) });

const compatible = (s = randomBytes(16)) =>
  unwrap(createCompatibleVault(ctx, { s, nip44Ct: "nip44-ciphertext", now: 100 }));

describe("create", () => {
  it("starts compatible with one nip44 wrap and no root key (rule 1)", () => {
    const v = compatible();
    expect(v.mode).toBe("compatible");
    expect(level(v)).toBe("weak");
    expect(hasRootKey(v)).toBe(false);
    expect(nip44Wrap(v)?.ct).toBe("nip44-ciphertext");
  });
  it("creates strict directly for requireStrong, without nip44", () => {
    const { s, r, key } = fresh();
    const v = unwrap(
      createStrictVault(ctx, { s, r, now: 1, rootWraps: [signerRootWrap(ctx, key, "sid", r)] }),
    );
    expect(v.mode).toBe("strict");
    expect(nip44Wrap(v)).toBeUndefined();
    expect(unwrap(openRootData(ctx, v, r))).toEqual(s);
  });
});

describe("root key and wraps", () => {
  it("adds R later and opens S through it", () => {
    const { s, r } = fresh();
    const v = unwrap(addRootKey(ctx, compatible(s), r, s));
    expect(unwrap(openRootData(ctx, v, r))).toEqual(s);
    expect(addRootKey(ctx, v, r, s).ok).toBe(false);
  });
  it("refuses R with a data secret that doesn't match", () => {
    expect(addRootKey(ctx, compatible(), randomBytes(16), randomBytes(16)).ok).toBe(false);
  });
  it("adds and replaces root wraps by key id; each opens R with its own key", () => {
    const { s, r } = fresh();
    const k1 = randomBytes(32);
    const k2 = randomBytes(32);
    let v = unwrap(addRootKey(ctx, compatible(s), r, s));
    v = unwrap(addRootWrap(v, signerRootWrap(ctx, k1, "sig1", r)));
    v = unwrap(addRootWrap(v, passkeyRootWrap(ctx, k2, "app.example", "cred1", r)));
    v = unwrap(addRootWrap(v, signerRootWrap(ctx, k1, "sig1", r)));
    expect(v.rootWraps).toHaveLength(2);
    expect(unwrap(openRootWrap(ctx, v.rootWraps[0]!, k2))).toEqual(r);
    expect(openRootWrap(ctx, v.rootWraps[0]!, k1).ok).toBe(false);
  });
  it("a wrap copied to another user's or app's vault doesn't open", () => {
    const { r, key } = fresh();
    const wrap = signerRootWrap(ctx, key, "sig", r);
    expect(openRootWrap({ ...ctx, appId: "https://other.example" }, wrap, key).ok).toBe(false);
    expect(openRootWrap({ ...ctx, pubkey: "b".repeat(64) }, wrap, key).ok).toBe(false);
  });
  it("needs R before root wraps", () => {
    expect(addRootWrap(compatible(), signerRootWrap(ctx, randomBytes(32), "s", randomBytes(16))).ok).toBe(false);
  });
});

describe("strict (rules 4–7)", () => {
  const setup = () => {
    const { s, r, key } = fresh();
    let v = unwrap(addRootKey(ctx, compatible(s), r, s));
    v = unwrap(addRootWrap(v, passkeyRootWrap(ctx, key, "app.example", "cred", r)));
    return { s, r, key, v };
  };

  it("replaces S, drops nip44, keeps root wraps and R", () => {
    const { s, r, key, v } = setup();
    const newS = randomBytes(16);
    const strict = unwrap(makeStrict(ctx, v, { r, newS, now: 200 }));
    expect(strict.mode).toBe("strict");
    expect(nip44Wrap(strict)).toBeUndefined();
    expect(strict.sHash).toBe(sHash(newS));
    expect(strict.history).toEqual([{ sHash: sHash(s), created: 100 }]);
    // the same passkey still opens R, and R opens the new S
    const r2 = unwrap(openRootWrap(ctx, strict.rootWraps[0]!, key));
    expect(unwrap(openRootData(ctx, strict, r2))).toEqual(newS);
  });
  it("refuses a root key that doesn't belong to the vault", () => {
    const { v } = setup();
    expect(makeStrict(ctx, v, { r: randomBytes(16), newS: randomBytes(16), now: 2 }).ok).toBe(false);
  });
  it("never allows nip44 in a strict vault", () => {
    const { r, v } = setup();
    const strict = unwrap(makeStrict(ctx, v, { r, newS: randomBytes(16), now: 2 }));
    const tampered: Vault = { ...strict, dataWraps: [...strict.dataWraps, { type: "nip44", ct: "x" }] };
    expect(validateVault(tampered).ok).toBe(false);
    expect(parseVault(serializeVault(tampered)).ok).toBe(false);
  });
  it("downgrade adds nip44 back and becomes compatible", () => {
    const { r, v } = setup();
    const strictS = randomBytes(16);
    const strict = unwrap(makeStrict(ctx, v, { r, newS: strictS, now: 2 }));
    const back = unwrap(downgrade(ctx, strict, { r, s: strictS, nip44Ct: "ct2" }));
    expect(back.mode).toBe("compatible");
    expect(nip44Wrap(back)?.ct).toBe("ct2");
    expect(unwrap(openRootData(ctx, back, r))).toEqual(strictS);
    expect(downgrade(ctx, back, { r, s: strictS, nip44Ct: "ct3" }).ok).toBe(false);
    expect(downgrade(ctx, strict, { r: randomBytes(16), s: strictS, nip44Ct: "x" }).ok).toBe(false);
  });
  it("keeps at most 10 history entries", () => {
    let { r, v } = setup();
    for (let i = 0; i < 12; i++) {
      const newS = randomBytes(16);
      v = unwrap(makeStrict(ctx, v, { r, newS, now: 300 + i }));
      v = unwrap(downgrade(ctx, v, { r, s: newS, nip44Ct: "ct" }));
    }
    expect(v.history).toHaveLength(10);
  });
});

describe("authenticated header (#25)", () => {
  const setup = () => {
    const { s, r, key } = fresh();
    let v = unwrap(addRootKey(ctx, compatible(s), r, s));
    v = unwrap(addRootWrap(v, passkeyRootWrap(ctx, key, "app.example", "cred", r)));
    return { s, r, v };
  };
  it("an edited mode, created time or history no longer opens with R", () => {
    const { r, v } = setup();
    const strict = unwrap(makeStrict(ctx, v, { r, newS: randomBytes(16), now: 200 }));
    expect(openRootData(ctx, strict, r).ok).toBe(true);
    expect(openRootData(ctx, { ...strict, mode: "compatible" }, r).ok).toBe(false);
    expect(openRootData(ctx, { ...strict, created: 999 }, r).ok).toBe(false);
    expect(openRootData(ctx, { ...strict, history: [] }, r).ok).toBe(false);
  });
  it("an old vault replayed with a forged history doesn't open with R", () => {
    const { r, v } = setup();
    const strict = unwrap(makeStrict(ctx, v, { r, newS: randomBytes(16), now: 200 }));
    // The pre-strict vault opens; claiming it comes after the strict one doesn't.
    expect(openRootData(ctx, v, r).ok).toBe(true);
    expect(openRootData(ctx, { ...v, history: [{ sHash: strict.sHash, created: 200 }] }, r).ok).toBe(false);
  });
});

describe("merge (superset rule)", () => {
  it("unions root wraps of the same S", () => {
    const { s, r } = fresh();
    const base = unwrap(addRootKey(ctx, compatible(s), r, s));
    const a = unwrap(addRootWrap(base, signerRootWrap(ctx, randomBytes(32), "s1", r)));
    const b = unwrap(addRootWrap(base, passkeyRootWrap(ctx, randomBytes(32), "rp", "c1", r)));
    expect(unwrap(mergeVaults(a, b)).rootWraps).toHaveLength(2);
  });
  it("refuses different secrets, and never re-adds nip44 to strict", () => {
    expect(mergeVaults(compatible(), compatible()).ok).toBe(false);
    const { s, r } = fresh();
    const base = unwrap(addRootKey(ctx, compatible(s), r, s));
    const strict: Vault = { ...base, mode: "strict", dataWraps: base.dataWraps.filter((w) => w.type === "root") };
    expect(nip44Wrap(unwrap(mergeVaults(strict, base)))).toBeUndefined();
  });
});

describe("codec", () => {
  it("round-trips and rejects garbage", () => {
    const v = compatible();
    expect(unwrap(parseVault(serializeVault(v)))).toEqual(v);
    expect(parseVault("not json").ok).toBe(false);
    expect(parseVault(JSON.stringify({ ...v, v: 2 })).ok).toBe(false);
    expect(parseVault(JSON.stringify({ ...v, rootWraps: [{ type: "signer" }] })).ok).toBe(false);
  });
});

describe("migration cut-off (§3.4)", () => {
  const v: Vault = {
    v: 1, mode: "strict", created: 300, sHash: "c",
    history: [{ sHash: "a", created: 100 }, { sHash: "b", created: 200 }],
    rootWraps: [], dataWraps: [{ type: "root", iv: "", ct: "" }],
  };
  it("uses the creation time of the secret that replaced the local one", () => {
    expect(migrationCutoff(v, "a")).toBe(200);
    expect(migrationCutoff(v, "b")).toBe(300);
    expect(migrationCutoff(v, "zzz")).toBeNull();
  });
});

describe("backup check (§3.2 rule 3a)", () => {
  it("scales with the risk", () => {
    expect(backupRequirement([{ kind: "passkey", synced: true }], false)).toBe("reminder");
    expect(backupRequirement([{ kind: "signer", recoverable: true }], false)).toBe("reminder");
    expect(backupRequirement([{ kind: "passkey", synced: false }], false)).toBe("required");
    expect(backupRequirement([{ kind: "passkey", synced: false }], true)).toBe("none");
    expect(backupRequirement([{ kind: "passkey", synced: false }, { kind: "passkey", synced: false }], false)).toBe("none");
    expect(backupRequirement([], false)).toBe("required");
  });
});

describe("vault format v2 (#37)", () => {
  const setup = () => {
    const { s, r } = fresh();
    let v = unwrap(addRootKey(ctx, compatible(s), r, s));
    const pk = passkeyRootWrap(ctx, randomBytes(32), "app.example", "cred1", r);
    v = unwrap(addRootWrap(v, pk));
    return { s, r, v, pk };
  };
  it("binds the full 64-character history hash", () => {
    const { v } = setup();
    expect(headerBinding(v).split("|")[3]).toHaveLength(64);
  });
  it("verifies root-wrap tags and rejects any change", () => {
    const { r, pk } = setup();
    expect(verifyRootWrap(ctx, r, pk)).toBe(true);
    expect(verifyRootWrap(ctx, r, { ...pk, ct: pk.ct.slice(0, -2) + "AA" })).toBe(false);
    expect(verifyRootWrap(ctx, r, { ...pk, iv: "AAAAAAAAAAAAAAAA" })).toBe(false);
    expect(verifyRootWrap(ctx, r, { ...pk, rpId: "evil.example" } as typeof pk)).toBe(false);
    expect(verifyRootWrap(ctx, randomBytes(16), pk)).toBe(false);
  });
  it("merge: the local version wins on the same id; with R, bad tags are dropped from both sides", () => {
    const { r, v, pk } = setup();
    const forged = { ...pk, ct: "AAAA" };
    const remote: Vault = { ...v, rootWraps: [forged] };
    expect(unwrap(mergeVaults(v, remote)).rootWraps[0]).toEqual(pk);
    const junk = { ...passkeyRootWrap(ctx, randomBytes(32), "app.example", "junk", randomBytes(16)) };
    const withJunk: Vault = { ...v, rootWraps: [pk, junk] };
    expect(unwrap(mergeVaults(withJunk, withJunk, { ctx, r })).rootWraps).toEqual([pk]);
    expect(unwrap(mergeVaults(v, { ...v, rootWraps: [forged] }, { ctx, r })).rootWraps).toEqual([pk]);
  });
  it("rejects more than 32 root wraps, and wraps without a tag", () => {
    const { r, v } = setup();
    const many = Array.from({ length: MAX_ROOT_WRAPS + 1 }, (_, i) => passkeyRootWrap(ctx, randomBytes(32), "rp", `c${i}`, r));
    expect(validateVault({ ...v, rootWraps: many }).ok).toBe(false);
    const json = JSON.parse(serializeVault(v));
    delete json.rootWraps[0].tag;
    expect(parseVault(JSON.stringify(json)).ok).toBe(false);
  });
});

import { createHash, hkdfSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  appIdFromOrigin,
  appVaultDTag,
  appWrapAad,
  fromBase64Url,
  fromHex,
  hkdf,
  isProtectedDTag,
  open,
  phraseToRootKey,
  randomBytes,
  rootDataKey,
  rootKeyToPhrase,
  sHash,
  seal,
  sha256Hex,
  signerAppKey,
  signerId,
  signerVaultDTag,
  signerWrapAad,
  toBase64Url,
  toHex,
  unwrap,
  utf8,
} from "../src/index.ts";

const nodeHkdf = (ikm: Uint8Array, info: string) =>
  new Uint8Array(hkdfSync("sha256", ikm, new Uint8Array(0), utf8(info), 32));
const nodeSha = (data: Uint8Array | string) => createHash("sha256").update(data).digest("hex");

describe("encodings", () => {
  it("round-trips hex and base64url", () => {
    const b = randomBytes(33);
    expect(fromHex(toHex(b))).toEqual(b);
    expect(fromBase64Url(toBase64Url(b))).toEqual(b);
    expect(fromHex("zz")).toBeNull();
    expect(fromBase64Url("a+b")).toBeNull();
  });
});

describe("hashes and HKDF match Node's implementation", () => {
  const ikm = fromHex("000102030405060708090a0b0c0d0e0f")!;
  it("hkdf", () => {
    expect(toHex(hkdf(ikm, "evolustr/v1/data|app"))).toBe(toHex(nodeHkdf(ikm, "evolustr/v1/data|app")));
    expect(rootDataKey(ikm, "app")).toEqual(nodeHkdf(ikm, "evolustr/v1/data|app"));
    expect(signerAppKey(ikm, "https://a.example")).toEqual(nodeHkdf(ikm, "evolustr/v1|app|https://a.example"));
  });
  it("sha256 and sHash", () => {
    expect(sha256Hex("abc")).toBe(nodeSha("abc"));
    expect(sHash(ikm)).toBe(nodeSha(ikm).slice(0, 16));
  });
  it("signerId is HKDF(M, app) and differs per app (#29)", () => {
    const m = randomBytes(32);
    expect(signerId(m, "https://a.example")).toBe(toHex(new Uint8Array(hkdfSync("sha256", m, new Uint8Array(0), utf8("evolustr/v1/signer-id|https://a.example"), 8))));
    expect(signerId(m, "https://a.example")).not.toBe(signerId(m, "https://b.example"));
  });
});

describe("seal / open (AES-256-GCM)", () => {
  const key = randomBytes(32);
  const secret = randomBytes(16);
  const aad = appWrapAad("pk", "app", "root", "abcd");

  it("round-trips", () => {
    expect(unwrap(open(key, seal(key, secret, aad), aad))).toEqual(secret);
  });
  it("uses a fresh IV each time", () => {
    expect(seal(key, secret, aad).iv).not.toBe(seal(key, secret, aad).iv);
  });
  it("fails with the wrong key", () => {
    expect(open(randomBytes(32), seal(key, secret, aad), aad).ok).toBe(false);
  });
  it("fails with a different AAD (wrap moved to another vault, app or type)", () => {
    const sealed = seal(key, secret, aad);
    expect(open(key, sealed, appWrapAad("pk2", "app", "root", "abcd")).ok).toBe(false);
    expect(open(key, sealed, appWrapAad("pk", "app2", "root", "abcd")).ok).toBe(false);
    expect(open(key, sealed, appWrapAad("pk", "app", "passkey", "abcd")).ok).toBe(false);
  });
  it("fails when a byte is flipped", () => {
    const sealed = seal(key, secret, aad);
    const ct = fromBase64Url(sealed.ct)!;
    ct[0] = (ct[0] ?? 0) ^ 1;
    expect(open(key, { iv: sealed.iv, ct: toBase64Url(ct) }, aad).ok).toBe(false);
  });
  it("rejects malformed input without throwing", () => {
    expect(open(key, { iv: "!!", ct: "x" }, aad)).toMatchObject({ ok: false, error: { type: "malformedCiphertext" } });
  });
  it("signer-vault AAD never equals an app-vault AAD", () => {
    expect(signerWrapAad("pk", "k", "passkey", "c")).not.toBe(appWrapAad("pk", "k", "passkey", "c"));
  });
});

describe("recovery phrase", () => {
  it("round-trips R as 12 words", () => {
    const r = randomBytes(16);
    const phrase = rootKeyToPhrase(r);
    expect(phrase.split(" ")).toHaveLength(12);
    expect(unwrap(phraseToRootKey(`  ${phrase.toUpperCase()}  `))).toEqual(r);
  });
  it("rejects wrong words and wrong lengths", () => {
    expect(phraseToRootKey("hello world").ok).toBe(false);
    expect(phraseToRootKey(rootKeyToPhrase(randomBytes(32))).ok).toBe(false);
  });
});

describe("d-tags", () => {
  it("differ per user and per app, and are recognised as protected", () => {
    const a = appVaultDTag("pk1", "app");
    expect(a).not.toBe(appVaultDTag("pk2", "app"));
    expect(a).not.toBe(appVaultDTag("pk1", "app2"));
    expect(a).toBe(`evolustr:v1:${nodeSha("evolustr/v1/vault|pk1|app")}`);
    expect(isProtectedDTag(a)).toBe(true);
    expect(isProtectedDTag(signerVaultDTag("pk1", "https://signer.example"))).toBe(true);
    expect(isProtectedDTag("other")).toBe(false);
  });
});

describe("appIdFromOrigin", () => {
  const npub = "npub1sg6plzptd64u62a878hep2kev88swjh3tw00gjsfl8f237lmu63q0uf63m";
  it("uses the origin for normal sites", () => {
    expect(unwrap(appIdFromOrigin("https://app.example.com/path"))).toBe("https://app.example.com");
  });
  it("maps known nsite gateways to nsite:<npub>", () => {
    expect(unwrap(appIdFromOrigin(`https://${npub}.nsite.lol`, ["nsite.lol"]))).toBe(`nsite:${npub}`);
    expect(unwrap(appIdFromOrigin(`https://${npub}.other.gw`, ["nsite.lol", "other.gw"]))).toBe(`nsite:${npub}`);
  });
  it("keeps the origin on unknown gateways and for invalid npubs", () => {
    expect(unwrap(appIdFromOrigin(`https://${npub}.unknown.gw`, ["nsite.lol"]))).toBe(`https://${npub}.unknown.gw`);
    expect(unwrap(appIdFromOrigin("https://npub1bad.nsite.lol", ["nsite.lol"]))).toBe("https://npub1bad.nsite.lol");
  });
  it("refuses insecure and invalid origins, allowing http: only on localhost (#30)", () => {
    expect(appIdFromOrigin("http://app.example.com")).toMatchObject({ ok: false, error: { type: "insecureOrigin" } });
    expect(appIdFromOrigin("null")).toMatchObject({ ok: false, error: { type: "invalidOrigin" } });
    expect(appIdFromOrigin("ftp://app.example.com").ok).toBe(false);
    expect(unwrap(appIdFromOrigin("http://localhost:5173"))).toBe("http://localhost:5173");
  });
});

/**
 * App vault: plain data plus pure functions (SPEC §3, §6).
 *
 * Nothing here talks to relays, signers or browsers. NIP-44 ciphertext is
 * produced by the caller (it needs the user's signer) and passed in as a string.
 */
import { appWrapAad } from "./aad.ts";
import { type Bytes, bytesEqual, fromHex, toHex, utf8 } from "./bytes.ts";
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import { type Sealed, open, seal, sha256Hex } from "./crypto.ts";
import { DATA_SECRET_LENGTH, ROOT_KEY_LENGTH, rootDataKey, rootRotateKey, sHash, wrapAuthKey } from "./keys.ts";
import { type EvolustrError, type Result, error, flatMap, ok } from "./result.ts";

export type Mode = "compatible" | "strict";

/**
 * A wrap of R. `tag` is an HMAC under a key derived from R over the wrap's
 * fields (#37): only someone holding R can add or change a root wrap.
 */
export type RootWrap =
  | ({ readonly type: "signer"; readonly signerId: string; readonly tag: string } & Sealed)
  | ({ readonly type: "passkey"; readonly rpId: string; readonly credId: string; readonly tag: string } & Sealed);

/** A root wrap before its tag is computed. */
export type UntaggedRootWrap =
  | ({ readonly type: "signer"; readonly signerId: string } & Sealed)
  | ({ readonly type: "passkey"; readonly rpId: string; readonly credId: string } & Sealed);

export type DataWrap =
  | ({ readonly type: "root" } & Sealed)
  | { readonly type: "nip44"; readonly ct: string };

export interface HistoryEntry {
  readonly sHash: string;
  readonly created: number;
}

export interface Vault {
  readonly v: 1;
  readonly mode: Mode;
  /** Unix seconds when the current S was created. */
  readonly created: number;
  readonly sHash: string;
  /** Earlier data secrets, oldest first, at most {@link HISTORY_LIMIT}. */
  readonly history: ReadonlyArray<HistoryEntry>;
  readonly rootWraps: ReadonlyArray<RootWrap>;
  readonly dataWraps: ReadonlyArray<DataWrap>;
  /**
   * Set by {@link rotateRoot}: an HMAC by the previous root key over this
   * vault's `sHash` and `created`. A device holding the old R sees a rotation
   * it can check, instead of a vault R doesn't open (#52 phase C).
   */
  readonly rootRotation?: { readonly proof: string };
}

/** Who and which app a vault belongs to; part of every AAD. */
export interface VaultContext {
  readonly pubkey: string;
  readonly appId: string;
}

export const HISTORY_LIMIT = 10;
export const MAX_ROOT_WRAPS = 32;

// ── Queries ─────────────────────────────────────────────────────────────────

export const level = (vault: Vault): "strong" | "weak" =>
  vault.mode === "strict" ? "strong" : "weak";

export const nip44Wrap = (vault: Vault): Extract<DataWrap, { type: "nip44" }> | undefined =>
  vault.dataWraps.find((w): w is Extract<DataWrap, { type: "nip44" }> => w.type === "nip44");

export const rootDataWrap = (vault: Vault): Extract<DataWrap, { type: "root" }> | undefined =>
  vault.dataWraps.find((w): w is Extract<DataWrap, { type: "root" }> => w.type === "root");

/** True when the vault has a root key R (a `root` data wrap exists). */
export const hasRootKey = (vault: Vault): boolean => rootDataWrap(vault) !== undefined;

export const rootWrapKeyId = (wrap: RootWrap): string =>
  wrap.type === "signer" ? wrap.signerId : wrap.credId;

export const signerWrapFor = (vault: Vault, signerId: string): RootWrap | undefined =>
  vault.rootWraps.find((w) => w.type === "signer" && w.signerId === signerId);

export const passkeyWrapsFor = (
  vault: Vault,
  rpId: string,
): ReadonlyArray<Extract<RootWrap, { type: "passkey" }>> =>
  vault.rootWraps.filter(
    (w): w is Extract<RootWrap, { type: "passkey" }> => w.type === "passkey" && w.rpId === rpId,
  );

// ── Validation ──────────────────────────────────────────────────────────────

/** Checks the rules a stored vault must satisfy (SPEC §3.2, §6.1). */
export const validateVault = (vault: Vault): Result<Vault, EvolustrError> => {
  const nip44Count = vault.dataWraps.filter((w) => w.type === "nip44").length;
  const rootCount = vault.dataWraps.filter((w) => w.type === "root").length;
  if (rootCount > 1) return error("invalidVault", "More than one root data wrap");
  if (vault.mode === "strict" && nip44Count > 0) {
    return error("invalidVault", "A strict vault must not contain a nip44 wrap");
  }
  if (vault.mode === "strict" && rootCount === 0) {
    return error("invalidVault", "A strict vault needs a root data wrap");
  }
  if (vault.mode === "compatible" && nip44Count !== 1) {
    return error("invalidVault", "A compatible vault needs exactly one nip44 wrap");
  }
  if (vault.rootWraps.length > 0 && rootCount === 0) {
    return error("invalidVault", "Root wraps without a root data wrap");
  }
  if (vault.rootWraps.length > MAX_ROOT_WRAPS) return error("invalidVault", "Too many root wraps");
  const ids = vault.rootWraps.map((w) => `${w.type}:${rootWrapKeyId(w)}`);
  if (new Set(ids).size !== ids.length) return error("invalidVault", "Duplicate root wrap");
  if (vault.history.length > HISTORY_LIMIT) return error("invalidVault", "History too long");
  return ok(vault);
};

// ── Codec ───────────────────────────────────────────────────────────────────

const isString = (x: unknown): x is string => typeof x === "string";
const isRecord = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null;

const parseSealed = (x: Record<string, unknown>): Sealed | null =>
  isString(x["iv"]) && isString(x["ct"]) ? { iv: x["iv"], ct: x["ct"] } : null;

const parseRootWrap = (x: unknown): RootWrap | null => {
  if (!isRecord(x)) return null;
  const sealed = parseSealed(x);
  if (sealed === null || !isString(x["tag"])) return null;
  const tag = x["tag"];
  if (x["type"] === "signer" && isString(x["signerId"])) {
    return { type: "signer", signerId: x["signerId"], tag, ...sealed };
  }
  if (x["type"] === "passkey" && isString(x["rpId"]) && isString(x["credId"])) {
    return { type: "passkey", rpId: x["rpId"], credId: x["credId"], tag, ...sealed };
  }
  return null;
};

const parseDataWrap = (x: unknown): DataWrap | null => {
  if (!isRecord(x)) return null;
  if (x["type"] === "nip44" && isString(x["ct"])) return { type: "nip44", ct: x["ct"] };
  if (x["type"] === "root") {
    const sealed = parseSealed(x);
    return sealed === null ? null : { type: "root", ...sealed };
  }
  return null;
};

const parseHistory = (x: unknown): HistoryEntry | null =>
  isRecord(x) && isString(x["sHash"]) && typeof x["created"] === "number"
    ? { sHash: x["sHash"], created: x["created"] }
    : null;

const parseList = <T>(x: unknown, f: (item: unknown) => T | null): ReadonlyArray<T> | null => {
  if (!Array.isArray(x)) return null;
  const out: T[] = [];
  for (const item of x) {
    const parsed = f(item);
    if (parsed === null) return null;
    out.push(parsed);
  }
  return out;
};

/** Parses vault JSON (event content) and checks its rules. */
export const parseVault = (json: string): Result<Vault, EvolustrError> => {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    return error("invalidVault", "Vault content is not JSON");
  }
  if (!isRecord(data) || data["v"] !== 1) return error("invalidVault", "Unknown vault version");
  const mode = data["mode"];
  if (mode !== "compatible" && mode !== "strict") return error("invalidVault", "Unknown mode");
  const rootWraps = parseList(data["rootWraps"], parseRootWrap);
  const dataWraps = parseList(data["dataWraps"], parseDataWrap);
  const history = parseList(data["history"] ?? [], parseHistory);
  if (
    typeof data["created"] !== "number" ||
    !isString(data["sHash"]) ||
    rootWraps === null ||
    dataWraps === null ||
    history === null
  ) {
    return error("invalidVault", "Vault fields are missing or malformed");
  }
  const rotation = data["rootRotation"];
  if (rotation !== undefined && !(isRecord(rotation) && isString(rotation["proof"]))) {
    return error("invalidVault", "Malformed rootRotation");
  }
  return validateVault({
    v: 1,
    mode,
    created: data["created"],
    sHash: data["sHash"],
    history,
    rootWraps,
    dataWraps,
    ...(rotation === undefined ? {} : { rootRotation: { proof: rotation["proof"] as string } }),
  });
};

export const serializeVault = (vault: Vault): string => JSON.stringify(vault);

// ── Wrapping ────────────────────────────────────────────────────────────────

/** The vault fields the `root` data wrap authenticates (SPEC §3.1, §6.3). */
export interface VaultHeader {
  readonly mode: Mode;
  readonly created: number;
  readonly sHash: string;
  readonly history: ReadonlyArray<HistoryEntry>;
}

/**
 * Binds the header into the root data wrap's AAD: a header that was edited, or
 * replayed from an older vault with a newer history, no longer opens with R.
 */
export const headerBinding = (h: VaultHeader): string =>
  `${h.sHash}|${h.mode}|${h.created}|${sha256Hex(JSON.stringify(h.history.map((e) => [e.sHash, e.created])))}`;

const sealRootData = (ctx: VaultContext, r: Bytes, s: Bytes, header: VaultHeader): DataWrap => ({
  type: "root",
  ...seal(rootDataKey(r, ctx.appId), s, appWrapAad(ctx.pubkey, ctx.appId, "root", headerBinding(header))),
});

const headerOf = (v: VaultHeader): VaultHeader => ({ mode: v.mode, created: v.created, sHash: v.sHash, history: v.history });

/** Wraps R for a capable signer, keyed by the signer's app key (SPEC §3.1). */
export const signerRootWrap = (
  ctx: VaultContext,
  signerAppKey: Bytes,
  signerId: string,
  r: Bytes,
): RootWrap =>
  withTag(ctx, r, {
    type: "signer",
    signerId,
    ...seal(signerAppKey, r, appWrapAad(ctx.pubkey, ctx.appId, "signer", signerId)),
  });

/** Wraps R for a client passkey, keyed by its PRF-derived wrap key (SPEC §4.2). */
export const passkeyRootWrap = (
  ctx: VaultContext,
  wrapKey: Bytes,
  rpId: string,
  credId: string,
  r: Bytes,
): RootWrap =>
  withTag(ctx, r, {
    type: "passkey",
    rpId,
    credId,
    ...seal(wrapKey, r, appWrapAad(ctx.pubkey, ctx.appId, "passkey", credId)),
  });

/** HMAC tag of a root wrap under {@link wrapAuthKey} (SPEC §3.1, #37). */
export const rootWrapTag = (ctx: VaultContext, r: Bytes, wrap: UntaggedRootWrap): string => {
  const keyId = wrap.type === "signer" ? wrap.signerId : wrap.credId;
  const rpId = wrap.type === "passkey" ? wrap.rpId : "";
  const message = `${appWrapAad(ctx.pubkey, ctx.appId, wrap.type, keyId)}|${rpId}|${wrap.iv}|${wrap.ct}`;
  return toHex(hmac(nobleSha256, wrapAuthKey(r, ctx.appId), utf8(message)));
};

/** True when the wrap's tag was made with this R. */
export const verifyRootWrap = (ctx: VaultContext, r: Bytes, wrap: RootWrap): boolean => {
  const { tag, ...rest } = wrap;
  const expected = fromHex(rootWrapTag(ctx, r, rest as UntaggedRootWrap));
  const given = fromHex(tag);
  return expected !== null && given !== null && bytesEqual(expected, given);
};

const withTag = (ctx: VaultContext, r: Bytes, wrap: UntaggedRootWrap): RootWrap =>
  ({ ...wrap, tag: rootWrapTag(ctx, r, wrap) }) as RootWrap;

/** Opens one root wrap with its key, giving R. */
export const openRootWrap = (
  ctx: VaultContext,
  wrap: RootWrap,
  key: Bytes,
): Result<Bytes, EvolustrError> =>
  flatMap(open(key, wrap, appWrapAad(ctx.pubkey, ctx.appId, wrap.type, rootWrapKeyId(wrap))), (r) =>
    r.length === ROOT_KEY_LENGTH ? ok(r) : error("invalidVault", "Root key has the wrong length"),
  );

/** Opens the `root` data wrap with R and checks the result against `sHash`. */
export const openRootData = (
  ctx: VaultContext,
  vault: Vault,
  r: Bytes,
): Result<Bytes, EvolustrError> => {
  const wrap = rootDataWrap(vault);
  if (wrap === undefined) return error("noRootKey", "This vault has no root key yet");
  return flatMap(
    open(rootDataKey(r, ctx.appId), wrap, appWrapAad(ctx.pubkey, ctx.appId, "root", headerBinding(headerOf(vault)))),
    (s) =>
      s.length === DATA_SECRET_LENGTH && sHash(s) === vault.sHash
        ? ok(s)
        : error("invalidVault", "Data secret doesn't match the vault"),
  );
};

/**
 * False when R is known, the vault has a root data wrap, and R doesn't open it:
 * a vault this device must never publish or keep as its copy (#50).
 */
export const canOpenOwnVault = (ctx: VaultContext, vault: Vault, r: Bytes | undefined): boolean =>
  r === undefined || rootDataWrap(vault) === undefined || openRootData(ctx, vault, r).ok;

/** Same header and same data wraps (root: iv+ct, nip44: ct). Root wraps are not compared (#38). */
export const sameVaultCore = (a: Vault, b: Vault): boolean =>
  headerBinding(a) === headerBinding(b) &&
  JSON.stringify(a.dataWraps.map(dataWrapKey).sort()) === JSON.stringify(b.dataWraps.map(dataWrapKey).sort());

const dataWrapKey = (w: DataWrap): string => (w.type === "root" ? `root|${w.iv}|${w.ct}` : `nip44|${w.ct}`);

/** Checks a decrypted nip44 payload against the vault's `sHash`. */
export const checkDataSecret = (vault: Vault, s: Bytes): Result<Bytes, EvolustrError> =>
  s.length === DATA_SECRET_LENGTH && sHash(s) === vault.sHash
    ? ok(s)
    : error("invalidVault", "Data secret doesn't match the vault");

// ── Transitions ─────────────────────────────────────────────────────────────

export interface CreateCompatibleInput {
  readonly s: Bytes;
  /** NIP-44 self-encryption of S (base64url of S as plaintext), made by the signer. */
  readonly nip44Ct: string;
  readonly now: number;
  /** Set when a strong method or the phrase already exists at creation. */
  readonly r?: Bytes;
  readonly rootWraps?: ReadonlyArray<RootWrap>;
}

/** A new `compatible` vault (SPEC §3.2 rule 1). */
export const createCompatibleVault = (
  ctx: VaultContext,
  input: CreateCompatibleInput,
): Result<Vault, EvolustrError> => {
  const header: VaultHeader = { mode: "compatible", created: input.now, sHash: sHash(input.s), history: [] };
  return validateVault({
    v: 1,
    ...header,
    rootWraps: input.rootWraps ?? [],
    dataWraps: [
      ...(input.r === undefined ? [] : [sealRootData(ctx, input.r, input.s, header)]),
      { type: "nip44", ct: input.nip44Ct },
    ],
  });
};

export interface CreateStrictInput {
  readonly s: Bytes;
  readonly r: Bytes;
  readonly now: number;
  readonly rootWraps: ReadonlyArray<RootWrap>;
}

/** A new vault created `strict` directly, for `requireStrong` (SPEC §3.2 rule 1). */
export const createStrictVault = (
  ctx: VaultContext,
  input: CreateStrictInput,
): Result<Vault, EvolustrError> => {
  const header: VaultHeader = { mode: "strict", created: input.now, sHash: sHash(input.s), history: [] };
  return validateVault({ v: 1, ...header, rootWraps: input.rootWraps, dataWraps: [sealRootData(ctx, input.r, input.s, header)] });
};

/** Adds R to a vault that has none yet (first strong method or confirmed phrase). */
export const addRootKey = (
  ctx: VaultContext,
  vault: Vault,
  r: Bytes,
  s: Bytes,
): Result<Vault, EvolustrError> => {
  if (hasRootKey(vault)) return error("rootKeyExists", "This vault already has a root key");
  if (sHash(s) !== vault.sHash) return error("invalidVault", "Data secret doesn't match the vault");
  return validateVault({ ...vault, dataWraps: [sealRootData(ctx, r, s, headerOf(vault)), ...vault.dataWraps] });
};

/** Adds or replaces a root wrap, keyed by `signerId` / `credId` (SPEC §6.2 rule 3). */
export const addRootWrap = (vault: Vault, wrap: RootWrap): Result<Vault, EvolustrError> => {
  if (!hasRootKey(vault)) return error("noRootKey", "Add the root key before adding root wraps");
  const key = `${wrap.type}:${rootWrapKeyId(wrap)}`;
  const others = vault.rootWraps.filter((w) => `${w.type}:${rootWrapKeyId(w)}` !== key);
  return validateVault({ ...vault, rootWraps: [...others, wrap] });
};

/**
 * Removes one root wrap; only on an explicit user action (SPEC §6.2 rule 3).
 * TODO(#37): the client never calls this. With "never drop a wrap", a removal
 * would need a tombstone authenticated with R.
 */
export const removeRootWrap = (vault: Vault, type: RootWrap["type"], keyId: string): Vault => ({
  ...vault,
  rootWraps: vault.rootWraps.filter((w) => !(w.type === type && rootWrapKeyId(w) === keyId)),
});

export interface MakeStrictInput {
  readonly r: Bytes;
  readonly newS: Bytes;
  readonly now: number;
}

/**
 * Makes a vault strict with a new data secret S' (SPEC §3.2 rule 4, §3.4).
 * Root wraps and R stay; the nip44 wrap is dropped; the old S goes into history.
 */
export const makeStrict = (
  ctx: VaultContext,
  vault: Vault,
  input: MakeStrictInput,
): Result<Vault, EvolustrError> => {
  if (vault.mode === "strict") return error("alreadyStrict", "The vault is already strict");
  const current = rootDataWrap(vault);
  if (current !== undefined) {
    const check = open(
      rootDataKey(input.r, ctx.appId),
      current,
      appWrapAad(ctx.pubkey, ctx.appId, "root", headerBinding(headerOf(vault))),
    );
    if (!check.ok) return error("wrongRootKey", "The root key doesn't belong to this vault");
  }
  const history = [...vault.history, { sHash: vault.sHash, created: vault.created }].slice(
    -HISTORY_LIMIT,
  );
  const header: VaultHeader = { mode: "strict", created: input.now, sHash: sHash(input.newS), history };
  return validateVault({ v: 1, ...header, rootWraps: vault.rootWraps, dataWraps: [sealRootData(ctx, input.r, input.newS, header)] });
};

export interface MakeStrictNewRootInput {
  readonly newR: Bytes;
  readonly newS: Bytes;
  readonly now: number;
  /** At least one, each made with `newR`. */
  readonly rootWraps: ReadonlyArray<RootWrap>;
}

/**
 * Strict with a brand-new root key (#49), for a compatible vault whose root key
 * this device can't open. Every old root wrap is dropped. Safe without the old
 * R: the new S' is unrelated to the old S, so whoever knew S learns nothing.
 * A strict vault's root can only be replaced by someone who has R.
 */
export const makeStrictWithNewRoot = (
  ctx: VaultContext,
  vault: Vault,
  input: MakeStrictNewRootInput,
): Result<Vault, EvolustrError> => {
  if (vault.mode === "strict") return error("alreadyStrict", "The vault is already strict");
  if (input.rootWraps.length === 0) return error("noRootWraps", "A new root key needs at least one strong method");
  if (!input.rootWraps.every((w) => verifyRootWrap(ctx, input.newR, w))) {
    return error("invalidVault", "Every root wrap must be made with the new root key");
  }
  const history = [...vault.history, { sHash: vault.sHash, created: vault.created }].slice(-HISTORY_LIMIT);
  const header: VaultHeader = { mode: "strict", created: input.now, sHash: sHash(input.newS), history };
  return validateVault({ v: 1, ...header, rootWraps: input.rootWraps, dataWraps: [sealRootData(ctx, input.newR, input.newS, header)] });
};

export interface RotateRootInput {
  /** The current root key: it must open the vault, and it signs the rotation. */
  readonly r: Bytes;
  readonly newR: Bytes;
  readonly newS: Bytes;
  readonly now: number;
  /** At least one, each made with `newR`. */
  readonly rootWraps: ReadonlyArray<RootWrap>;
  /** NIP-44 self-encryption of `newS`; required for a compatible vault. */
  readonly nip44Ct?: string;
}

const rotationMessage = (sHashValue: string, created: number) => utf8(`${sHashValue}|${created}`);

/**
 * Replaces both R and S, keeping the mode (#52 phase C): for when R may be
 * known to someone else (a signer key exposed through the nsec, or a recovery
 * phrase that leaked). Every old root wrap is dropped, the old S goes into
 * history, and the old R signs the result (`rootRotation`).
 */
export const rotateRoot = (
  ctx: VaultContext,
  vault: Vault,
  input: RotateRootInput,
): Result<Vault, EvolustrError> => {
  if (!openRootData(ctx, vault, input.r).ok) return error("wrongRootKey", "The root key doesn't belong to this vault");
  if (input.rootWraps.length === 0) return error("noRootWraps", "A new root key needs at least one strong method");
  if (!input.rootWraps.every((w) => verifyRootWrap(ctx, input.newR, w))) {
    return error("invalidVault", "Every root wrap must be made with the new root key");
  }
  if (vault.mode === "compatible" && input.nip44Ct === undefined) {
    return error("invalidVault", "A compatible vault needs a nip44 wrap of the new secret");
  }
  const history = [...vault.history, { sHash: vault.sHash, created: vault.created }].slice(-HISTORY_LIMIT);
  const header: VaultHeader = { mode: vault.mode, created: input.now, sHash: sHash(input.newS), history };
  const proof = toHex(hmac(nobleSha256, rootRotateKey(input.r, ctx.appId), rotationMessage(header.sHash, header.created)));
  return validateVault({
    v: 1,
    ...header,
    rootWraps: input.rootWraps,
    dataWraps: [
      sealRootData(ctx, input.newR, input.newS, header),
      ...(vault.mode === "compatible" && input.nip44Ct !== undefined ? [{ type: "nip44" as const, ct: input.nip44Ct }] : []),
    ],
    rootRotation: { proof },
  });
};

/** True when `r` (an earlier root key) signed this vault's rotation (#52 phase C). */
export const verifyRootRotation = (ctx: VaultContext, vault: Vault, r: Bytes): boolean => {
  if (vault.rootRotation === undefined) return false;
  const expected = hmac(nobleSha256, rootRotateKey(r, ctx.appId), rotationMessage(vault.sHash, vault.created));
  const given = fromHex(vault.rootRotation.proof);
  return given !== null && bytesEqual(expected, given);
};

export interface DowngradeInput {
  readonly r: Bytes;
  readonly s: Bytes;
  /** NIP-44 self-encryption of the current S. */
  readonly nip44Ct: string;
}

/**
 * Turns strict off by adding a nip44 wrap of the current S (SPEC §3.2 rule 7).
 * The root data wrap is sealed again, because the mode is part of its AAD.
 */
export const downgrade = (ctx: VaultContext, vault: Vault, input: DowngradeInput): Result<Vault, EvolustrError> => {
  if (vault.mode === "compatible") return error("alreadyCompatible", "The vault is already compatible");
  const current = openRootData(ctx, vault, input.r);
  if (!current.ok) return error("wrongRootKey", "The root key doesn't belong to this vault");
  if (sHash(input.s) !== vault.sHash) return error("invalidVault", "Data secret doesn't match the vault");
  const header: VaultHeader = { ...headerOf(vault), mode: "compatible" };
  return validateVault({
    ...vault,
    mode: "compatible",
    dataWraps: [sealRootData(ctx, input.r, input.s, header), { type: "nip44", ct: input.nip44Ct }],
  });
};

/**
 * Merges two versions of the same vault (same S) after concurrent updates:
 * the union of root wraps, keyed by `signerId` / `credId` (SPEC §6.2 rule 3).
 * Never adds a nip44 wrap to a strict result (SPEC §3.2 rule 5).
 */
export const mergeVaults = (
  a: Vault,
  b: Vault,
  opts?: { readonly ctx: VaultContext; readonly r?: Bytes | undefined },
): Result<Vault, EvolustrError> => {
  if (a.sHash !== b.sHash) return error("differentSecrets", "The vaults hold different data secrets");
  // `a` is the local version and wins on the same id; with R, wraps with a bad
  // tag are dropped from both sides (#37). Without R, the union is kept, and if
  // it's too long, a's wraps come first.
  const r = opts?.r;
  const keep = (w: RootWrap) => r === undefined || opts === undefined || verifyRootWrap(opts.ctx, r, w);
  const byKey = new Map<string, RootWrap>();
  for (const w of a.rootWraps) if (keep(w)) byKey.set(`${w.type}:${rootWrapKeyId(w)}`, w);
  for (const w of b.rootWraps) {
    const k = `${w.type}:${rootWrapKeyId(w)}`;
    if (!byKey.has(k) && keep(w) && byKey.size < MAX_ROOT_WRAPS) byKey.set(k, w);
  }
  // The mode and data wraps come from one version, since the mode is part of
  // the root data wrap's AAD; strict wins, never re-adding nip44 (rule 5).
  const base = a.mode === "strict" || b.mode !== "strict" ? a : b;
  const other = base === a ? b : a;
  // A root data wrap added concurrently on the other version is valid here only
  // when both versions share the same header (same mode).
  const borrowed = rootDataWrap(base) === undefined && other.mode === base.mode ? rootDataWrap(other) : undefined;
  return validateVault({
    ...base,
    rootWraps: [...byKey.values()],
    dataWraps: borrowed === undefined ? base.dataWraps : [borrowed, ...base.dataWraps],
  });
};

// ── Migration and backup decisions ──────────────────────────────────────────

/**
 * Cut-off for copying local rows after a rotation (SPEC §3.4 step 2): the
 * `created` time of the secret that replaced the local one. `null` when the
 * local secret isn't in the history (ask the user before copying).
 */
export const migrationCutoff = (vault: Vault, localSHash: string): number | null => {
  const i = vault.history.findIndex((h) => h.sHash === localSHash);
  if (i === -1) return null;
  return vault.history[i + 1]?.created ?? vault.created;
};

export type StrongMethod =
  | { readonly kind: "passkey"; readonly synced: boolean }
  | { readonly kind: "signer"; readonly recoverable: boolean };

export type BackupRequirement = "none" | "reminder" | "required";

/**
 * Backup check before `strict` (SPEC §3.2 rule 3a): nothing when a backup
 * already exists, a skippable reminder when the only method recovers on its
 * own, otherwise a backup (or explicit acceptance) is required.
 */
export const backupRequirement = (
  methods: ReadonlyArray<StrongMethod>,
  phraseConfirmed: boolean,
): BackupRequirement => {
  if (phraseConfirmed || methods.length >= 2) return "none";
  const only = methods[0];
  if (only === undefined) return "required";
  const recoverable = only.kind === "passkey" ? only.synced : only.recoverable;
  return recoverable ? "reminder" : "required";
};

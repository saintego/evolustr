/**
 * App vault: plain data plus pure functions (SPEC §3, §6).
 *
 * Nothing here talks to relays, signers or browsers. NIP-44 ciphertext is
 * produced by the caller (it needs the user's signer) and passed in as a string.
 */
import { appWrapAad } from "./aad.ts";
import { type Bytes } from "./bytes.ts";
import { type Sealed, open, seal } from "./crypto.ts";
import { DATA_SECRET_LENGTH, ROOT_KEY_LENGTH, rootDataKey, sHash } from "./keys.ts";
import { type EvolustrError, type Result, error, flatMap, ok } from "./result.ts";

export type Mode = "compatible" | "strict";

export type RootWrap =
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
}

/** Who and which app a vault belongs to; part of every AAD. */
export interface VaultContext {
  readonly pubkey: string;
  readonly appId: string;
}

export const HISTORY_LIMIT = 10;

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
  if (sealed === null) return null;
  if (x["type"] === "signer" && isString(x["signerId"])) {
    return { type: "signer", signerId: x["signerId"], ...sealed };
  }
  if (x["type"] === "passkey" && isString(x["rpId"]) && isString(x["credId"])) {
    return { type: "passkey", rpId: x["rpId"], credId: x["credId"], ...sealed };
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
  return validateVault({
    v: 1,
    mode,
    created: data["created"],
    sHash: data["sHash"],
    history,
    rootWraps,
    dataWraps,
  });
};

export const serializeVault = (vault: Vault): string => JSON.stringify(vault);

// ── Wrapping ────────────────────────────────────────────────────────────────

const sealRootData = (ctx: VaultContext, r: Bytes, s: Bytes): DataWrap => ({
  type: "root",
  ...seal(rootDataKey(r, ctx.appId), s, appWrapAad(ctx.pubkey, ctx.appId, "root", sHash(s))),
});

/** Wraps R for a capable signer, keyed by the signer's app key (SPEC §3.1). */
export const signerRootWrap = (
  ctx: VaultContext,
  signerAppKey: Bytes,
  signerId: string,
  r: Bytes,
): RootWrap => ({
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
): RootWrap => ({
  type: "passkey",
  rpId,
  credId,
  ...seal(wrapKey, r, appWrapAad(ctx.pubkey, ctx.appId, "passkey", credId)),
});

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
    open(rootDataKey(r, ctx.appId), wrap, appWrapAad(ctx.pubkey, ctx.appId, "root", vault.sHash)),
    (s) =>
      s.length === DATA_SECRET_LENGTH && sHash(s) === vault.sHash
        ? ok(s)
        : error("invalidVault", "Data secret doesn't match the vault"),
  );
};

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
): Result<Vault, EvolustrError> =>
  validateVault({
    v: 1,
    mode: "compatible",
    created: input.now,
    sHash: sHash(input.s),
    history: [],
    rootWraps: input.rootWraps ?? [],
    dataWraps: [
      ...(input.r === undefined ? [] : [sealRootData(ctx, input.r, input.s)]),
      { type: "nip44", ct: input.nip44Ct },
    ],
  });

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
): Result<Vault, EvolustrError> =>
  validateVault({
    v: 1,
    mode: "strict",
    created: input.now,
    sHash: sHash(input.s),
    history: [],
    rootWraps: input.rootWraps,
    dataWraps: [sealRootData(ctx, input.r, input.s)],
  });

/** Adds R to a vault that has none yet (first strong method or confirmed phrase). */
export const addRootKey = (
  ctx: VaultContext,
  vault: Vault,
  r: Bytes,
  s: Bytes,
): Result<Vault, EvolustrError> => {
  if (hasRootKey(vault)) return error("rootKeyExists", "This vault already has a root key");
  if (sHash(s) !== vault.sHash) return error("invalidVault", "Data secret doesn't match the vault");
  return validateVault({ ...vault, dataWraps: [sealRootData(ctx, r, s), ...vault.dataWraps] });
};

/** Adds or replaces a root wrap, keyed by `signerId` / `credId` (SPEC §6.2 rule 3). */
export const addRootWrap = (vault: Vault, wrap: RootWrap): Result<Vault, EvolustrError> => {
  if (!hasRootKey(vault)) return error("noRootKey", "Add the root key before adding root wraps");
  const key = `${wrap.type}:${rootWrapKeyId(wrap)}`;
  const others = vault.rootWraps.filter((w) => `${w.type}:${rootWrapKeyId(w)}` !== key);
  return validateVault({ ...vault, rootWraps: [...others, wrap] });
};

/** Removes one root wrap; only on an explicit user action (SPEC §6.2 rule 3). */
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
      appWrapAad(ctx.pubkey, ctx.appId, "root", vault.sHash),
    );
    if (!check.ok) return error("wrongRootKey", "The root key doesn't belong to this vault");
  }
  const history = [...vault.history, { sHash: vault.sHash, created: vault.created }].slice(
    -HISTORY_LIMIT,
  );
  return validateVault({
    v: 1,
    mode: "strict",
    created: input.now,
    sHash: sHash(input.newS),
    history,
    rootWraps: vault.rootWraps,
    dataWraps: [sealRootData(ctx, input.r, input.newS)],
  });
};

/** Turns strict off by adding a nip44 wrap of the current S (SPEC §3.2 rule 7). */
export const downgrade = (vault: Vault, nip44Ct: string): Result<Vault, EvolustrError> =>
  vault.mode === "compatible"
    ? error("alreadyCompatible", "The vault is already compatible")
    : validateVault({
        ...vault,
        mode: "compatible",
        dataWraps: [...vault.dataWraps, { type: "nip44", ct: nip44Ct }],
      });

/**
 * Merges two versions of the same vault (same S) after concurrent updates:
 * the union of root wraps, keyed by `signerId` / `credId` (SPEC §6.2 rule 3).
 * Never adds a nip44 wrap to a strict result (SPEC §3.2 rule 5).
 */
export const mergeVaults = (a: Vault, b: Vault): Result<Vault, EvolustrError> => {
  if (a.sHash !== b.sHash) return error("differentSecrets", "The vaults hold different data secrets");
  const byKey = new Map<string, RootWrap>();
  for (const w of [...a.rootWraps, ...b.rootWraps]) byKey.set(`${w.type}:${rootWrapKeyId(w)}`, w);
  const strict = a.mode === "strict" || b.mode === "strict";
  const root = rootDataWrap(a) ?? rootDataWrap(b);
  const nip = nip44Wrap(a) ?? nip44Wrap(b);
  return validateVault({
    ...a,
    mode: strict ? "strict" : "compatible",
    rootWraps: [...byKey.values()],
    dataWraps: [
      ...(root === undefined ? [] : [root]),
      ...(strict || nip === undefined ? [] : [nip]),
    ],
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

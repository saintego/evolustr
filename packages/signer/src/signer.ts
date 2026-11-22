/**
 * `@evolustr/signer` (SPEC §5): the signer side of Evolustr, embedded by a
 * host signer (iframe signer, browser extension, NIP-46 bunker, Android signer).
 *
 * The host supplies what only it knows: who is calling, how to sign, its nsec
 * (if it holds one), and how to ask the user. Everything else lives here.
 */
import {
  type Bytes,
  type EvolustrError,
  type Passkeys,
  type Relays,
  type Result,
  type Sealed,
  type UnsignedEvent,
  MASTER_SECRET_LENGTH,
  VAULT_KIND,
  appIdFromOrigin,
  bytesEqual,
  error,
  fromHex,
  hmacSha256,
  signerWrapAuthKey,
  signerMId,
  signerPreviousKey,
  signerRotateKey,
  toHex,
  fetchReplaceable,
  isProtectedDTag,
  ok,
  open,
  publishReplaceable,
  randomBytes as defaultRandomBytes,
  seal,
  sha256,
  utf8,
  signerAppKey,
  hostSecret,
  isHostSecretLabel,
  signerId as computeSignerId,
  signerPasskeyWrapKey,
  signerPrfInput,
  signerSkWrapKey,
  signerVaultDTag,
  signerWrapAad,
  toBase64Url,
  type NostrEvent,
  type Signer,
} from "@evolustr/core";

// ── Types ───────────────────────────────────────────────────────────────────

/** Who is calling, as the host knows it (SPEC §5.2). Never taken from request params. */
export type Caller =
  | { readonly identity: "verified"; readonly origin: string }
  | { readonly identity: "verified"; readonly androidPackage: string }
  | { readonly identity: "connection"; readonly clientPubkey: string };

export type SignerWrap =
  | ({ readonly type: "sk"; readonly tag?: string } & Sealed)
  | ({
      readonly type: "passkey";
      readonly rpId: string;
      readonly credId: string;
      /** The passkey was synced (BS flag) when enrolled (#42). */
      readonly synced?: boolean;
      /**
       * HMAC under a key derived from M over the wrap's fields (#54). Wraps from
       * older versions have none.
       */
      readonly tag?: string;
    } & Sealed);

export interface SignerVault {
  readonly v: 1;
  readonly wraps: ReadonlyArray<SignerWrap>;
  /**
   * Unix seconds when an `sk` wrap was removed for this M (#52). M didn't
   * change, so anyone who can recover the nsec may still open an older copy.
   */
  readonly skDroppedAt?: number;
  /** Public id of the M this vault holds (#52 phase B); missing in older vaults. */
  readonly mId?: string;
  /** Set after {@link EvolustrSigner.rotateMaster}: the previous M authorises this one. */
  readonly rotatedFrom?: { readonly mId: string; readonly proof: string };
  /** The previous M, sealed with a key from this M, so apps can still open their old wrap. */
  readonly previous?: PreviousMaster;
  /**
   * The Ms before `previous`, newest first (#58): each sealed with a key from
   * the one before it in this chain (`older[0]` with `previous`'s M). Carried
   * over unchanged at each rotation, at most {@link MAX_PREVIOUS_MASTERS} in all.
   */
  readonly older?: ReadonlyArray<PreviousMaster>;
}

/** An earlier M, sealed with `HKDF(M_next, "evolustr/v1/signer-previous")` (#52 phase B, #58). */
export type PreviousMaster = { readonly mId: string } & Sealed;

/** How many earlier Ms a signer vault keeps (`previous` plus `older`, #58). */
export const MAX_PREVIOUS_MASTERS = 16;

export type ConfirmRequest =
  | { readonly kind: "appKey"; readonly appId: string; readonly identity: Caller["identity"] }
  | { readonly kind: "enrollPasskey" }
  | { readonly kind: "rotateMaster" };

export interface SignerHost {
  readonly relays: Relays;
  readonly relayUrls: ReadonlyArray<string>;
  /** Stable name of this signer: its origin, extension id, package name or bunker pubkey (SPEC §5.3). */
  readonly signerKey: string;
  /** Signs the signer's own vault event. */
  readonly sign: (event: UnsignedEvent) => Promise<NostrEvent>;
  readonly getPublicKey: () => Promise<string>;
  /** The nsec, for signers that hold it; omit in passthrough mode. */
  readonly getSecretKey?: () => Bytes | null;
  /**
   * False when a third party can recover the nsec (SPEC §5.7). Default true.
   * A function is read on every use, so a host can ask the user and change it
   * at runtime (e.g. OAuth signers, where the user decides).
   */
  readonly allowSkWrap?: boolean | (() => boolean);
  /** Passkeys on the signer's own origin. */
  readonly passkeys?: Passkeys;
  /** Optional device cache for the unlocked M. */
  readonly cache?: {
    readonly get: (pubkey: string) => Promise<Bytes | null>;
    readonly set: (pubkey: string, m: Bytes) => Promise<void>;
    readonly remove: (pubkey: string) => Promise<void>;
    /**
     * The last good signer vault (JSON), kept on the device (#41). Without these,
     * a replaced signer vault on the relays locks out devices that don't have M cached.
     */
    readonly getVault?: (pubkey: string) => Promise<string | null>;
    readonly setVault?: (pubkey: string, json: string) => Promise<void>;
  };
  readonly ui: {
    /** Show a prompt with the verified caller; the host may remember answers. */
    readonly confirm: (request: ConfirmRequest) => Promise<boolean>;
    /** Resolve after the user clicks inside the signer (needed before passkeys and popups). */
    readonly requestGesture: (reason: "unlock" | "enrollPasskey" | "rotateMaster") => Promise<void>;
  };
  readonly knownNsiteGateways?: ReadonlyArray<string>;
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Bytes;
  readonly timeoutMs?: number;
}

export interface Capabilities {
  readonly identity: Caller["identity"];
  readonly appId: string;
  readonly signerId: string | null;
  readonly ready: boolean;
  readonly signerPasskey: boolean;
  /** M can be recovered on another device: an `sk` wrap, or a synced signer passkey (#42). */
  readonly recoverable: boolean;
  /** M is protected by the nsec (an `sk` wrap): anyone with the nsec can derive app keys (#43). */
  readonly nsecProtected: boolean;
  /**
   * The nsec could open M now or did before (an `sk` wrap, or one removed for
   * this M): anyone who can recover the nsec may have M and every app key (#52).
   */
  readonly nsecExposed: boolean;
  /**
   * After a key rotation (#52 phase B): this app's signer id under the previous
   * M, so the client can open its old wrap and then replace its root key.
   */
  readonly previousSignerId: string | null;
  /**
   * Every earlier M's signer id for this app, newest first (#58): an app that
   * skipped rotations finds the one its wrap used and asks for that key.
   * `previousSignerIds[0]` is `previousSignerId`.
   */
  readonly previousSignerIds: ReadonlyArray<string>;
}

export const METHODS = ["evolustr_capabilities", "evolustr_get_wrap_key", "evolustr_get_previous_wrap_key", "evolustr_enroll_passkey"] as const;
export type Method = (typeof METHODS)[number];

export interface EvolustrSigner {
  /** For the host's message handler: `caller` comes from the host, never from params. */
  readonly handle: (method: string, params: ReadonlyArray<unknown>, caller: Caller) => Promise<Result<unknown>>;
  /** No prompt, and never creates or publishes anything (#29). */
  readonly capabilities: (caller: Caller) => Promise<Result<Capabilities>>;
  /** 32-byte key for the caller's app vault (SPEC §5.3). */
  readonly getWrapKey: (caller: Caller) => Promise<Result<Bytes>>;
  readonly enrollPasskey: () => Promise<Result<void>>;
  /**
   * The caller's key under an earlier M, after {@link rotateMaster} (#52 phase
   * B): the one whose signer id for this app is `signerId` (#58), else the
   * previous one.
   */
  readonly getPreviousWrapKey: (caller: Caller, signerId?: string) => Promise<Result<Bytes>>;
  /**
   * Replaces M with a new one, from a click in the signer's own UI (#52 phase
   * B). Needs a signer passkey and `allowSkWrap` false. Only the passkey used
   * here wraps the new M: other signer passkeys must be enrolled again.
   */
  readonly rotateMaster: () => Promise<Result<{ readonly droppedWraps: number }>>;
  /**
   * 32-byte secret from M for the host's own use (§5.6), e.g. its synced
   * settings. Host-only: no `handle()` method reaches it, so apps can't ask for
   * it. Unlocks M like `getWrapKey` (passkey if needed), without the app prompt.
   */
  readonly getHostSecret: (label: string) => Promise<Result<Bytes>>;
  /**
   * The same host secret under the previous M, after {@link rotateMaster}, so
   * the host can move its own data across, like apps with getPreviousWrapKey.
   */
  readonly getPreviousHostSecret: (label: string) => Promise<Result<Bytes>>;
  /** The host secret under every earlier M, newest first (#58); empty before any rotation. */
  readonly getPreviousHostSecrets: (label: string) => Promise<Result<ReadonlyArray<Bytes>>>;
  /** For the host's auto-approve list (SPEC §5.5 rule 2). */
  readonly isProtectedEvent: (event: { readonly kind: number; readonly tags: ReadonlyArray<ReadonlyArray<string>> }) => boolean;
  readonly appIdFor: (caller: Caller) => Result<string>;
  readonly lock: () => Promise<void>;
}

// ── Pure helpers ────────────────────────────────────────────────────────────

const isRecord = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null;

export const parseSignerVault = (json: string): Result<SignerVault, EvolustrError> => {
  let data: unknown;
  try {
    data = JSON.parse(json);
  } catch {
    return error("invalidSignerVault", "Not JSON");
  }
  if (!isRecord(data) || data["v"] !== 1 || !Array.isArray(data["wraps"])) {
    return error("invalidSignerVault", "Unknown format");
  }
  const wraps: SignerWrap[] = [];
  for (const w of data["wraps"]) {
    // A malformed wrap is an error, never skipped: republishing without it
    // would drop someone's way to unlock M (#28).
    if (!isRecord(w) || typeof w["iv"] !== "string" || typeof w["ct"] !== "string") {
      return error("invalidSignerVault", "Malformed wrap");
    }
    if (w["tag"] !== undefined && typeof w["tag"] !== "string") return error("invalidSignerVault", "Malformed wrap");
    const sealed = { iv: w["iv"], ct: w["ct"], ...(typeof w["tag"] === "string" ? { tag: w["tag"] } : {}) };
    if (w["type"] === "sk") wraps.push({ type: "sk", ...sealed });
    else if (w["type"] === "passkey" && typeof w["rpId"] === "string" && typeof w["credId"] === "string") {
      wraps.push({
        type: "passkey",
        rpId: w["rpId"],
        credId: w["credId"],
        ...(typeof w["synced"] === "boolean" ? { synced: w["synced"] } : {}),
        ...sealed,
      });
    } else return error("invalidSignerVault", "Unknown wrap type");
  }
  const dropped = data["skDroppedAt"];
  if (dropped !== undefined && (typeof dropped !== "number" || !Number.isFinite(dropped))) {
    return error("invalidSignerVault", "Malformed skDroppedAt");
  }
  const mId = data["mId"];
  const rotatedFrom = data["rotatedFrom"];
  const previous = data["previous"];
  const older = data["older"];
  if (mId !== undefined && typeof mId !== "string") return error("invalidSignerVault", "Malformed mId");
  if (rotatedFrom !== undefined && !(isRecord(rotatedFrom) && typeof rotatedFrom["mId"] === "string" && typeof rotatedFrom["proof"] === "string")) {
    return error("invalidSignerVault", "Malformed rotatedFrom");
  }
  if (previous !== undefined && !isPreviousMaster(previous)) return error("invalidSignerVault", "Malformed previous");
  if (older !== undefined && !(Array.isArray(older) && older.length < MAX_PREVIOUS_MASTERS && older.every(isPreviousMaster))) {
    return error("invalidSignerVault", "Malformed older");
  }
  const extra = {
    ...(typeof mId === "string" ? { mId } : {}),
    ...(isRecord(rotatedFrom) ? { rotatedFrom: { mId: rotatedFrom["mId"] as string, proof: rotatedFrom["proof"] as string } } : {}),
    ...(isPreviousMaster(previous) ? { previous: previousMaster(previous) } : {}),
    ...(isPreviousMaster(previous) && Array.isArray(older) && older.length > 0 ? { older: older.map(previousMaster) } : {}),
  };
  // A vault that exists but has no wraps isn't "first use" (#28).
  if (wraps.length === 0) return error("invalidSignerVault", "The signer vault has no wraps");
  if (wraps.length > MAX_SIGNER_WRAPS) return error("invalidSignerVault", "Too many wraps");
  return ok({ v: 1, wraps, ...(typeof dropped === "number" ? { skDroppedAt: dropped } : {}), ...extra });
};

const isPreviousMaster = (x: unknown): x is PreviousMaster =>
  isRecord(x) && typeof x["mId"] === "string" && typeof x["iv"] === "string" && typeof x["ct"] === "string";
const previousMaster = (x: PreviousMaster): PreviousMaster => ({ mId: x.mId, iv: x.iv, ct: x.ct });

const wrapId = (w: SignerWrap): string => (w.type === "sk" ? "sk" : w.credId);

export const MAX_SIGNER_WRAPS = 32;
/** Above this many wraps, untagged ones are dropped once M is unlocked (#54). */
export const UNTAGGED_SIGNER_WRAP_LIMIT = 16;

/**
 * Union of two signer vaults by wrap id; `local` wins on the same id (#41).
 * With `dropSk`, `sk` wraps are left out (#52): a relay vault without one is
 * never "healed" back to one by a device that may not use it.
 */
export const mergeSignerVaults = (
  local: SignerVault,
  fetched: SignerVault,
  opts?: { readonly dropSk?: boolean },
): SignerVault => {
  const byId = new Map<string, SignerWrap>();
  const keep = (w: SignerWrap) => opts?.dropSk !== true || w.type !== "sk";
  for (const w of local.wraps) if (keep(w)) byId.set(`${w.type}:${wrapId(w)}`, w);
  for (const w of fetched.wraps) {
    const k = `${w.type}:${wrapId(w)}`;
    if (keep(w) && !byId.has(k) && byId.size < MAX_SIGNER_WRAPS) byId.set(k, w);
  }
  const dropped = Math.max(local.skDroppedAt ?? -1, fetched.skDroppedAt ?? -1);
  const mId = local.mId ?? fetched.mId;
  const rotatedFrom = local.rotatedFrom ?? fetched.rotatedFrom;
  const previous = local.previous ?? fetched.previous;
  // The chain behind that previous M: the longer of the two sides that have it (#58).
  const olderOf = (v: SignerVault) => (v.previous?.mId === previous?.mId ? (v.older ?? []) : []);
  const [a, b] = [olderOf(local), olderOf(fetched)];
  const older = b.length > a.length ? b : a;
  return {
    v: 1,
    wraps: [...byId.values()],
    ...(dropped >= 0 ? { skDroppedAt: dropped } : {}),
    ...(mId === undefined ? {} : { mId }),
    ...(rotatedFrom === undefined ? {} : { rotatedFrom }),
    ...(previous === undefined ? {} : { previous }),
    ...(previous === undefined || older.length === 0 ? {} : { older }),
  };
};

/** Two versions of the signer vault hold different master secrets: never merge them (#52 phase B). */
export const differentMaster = (a: SignerVault, b: SignerVault): boolean =>
  (a.mId !== undefined && b.mId !== undefined && a.mId !== b.mId) ||
  (b.rotatedFrom !== undefined && a.mId !== b.mId) ||
  (a.rotatedFrom !== undefined && a.mId !== b.mId);

/** Proof that the M behind `oldMId` authorised `newMId` (#52 phase B). */
export const masterRotationProof = (oldM: Bytes, newMId: string): string => toHex(hmacSha256(signerRotateKey(oldM), utf8(newMId)));

const rotationValid = (v: SignerVault, oldM: Bytes): boolean => {
  if (v.rotatedFrom === undefined || v.mId === undefined || v.rotatedFrom.mId !== signerMId(oldM)) return false;
  const expected = fromHex(masterRotationProof(oldM, v.mId));
  const given = fromHex(v.rotatedFrom.proof);
  return expected !== null && given !== null && bytesEqual(expected, given);
};

type UntaggedSignerWrap = { readonly type: "sk"; readonly iv: string; readonly ct: string } | {
  readonly type: "passkey";
  readonly rpId: string;
  readonly credId: string;
  readonly synced?: boolean;
  readonly iv: string;
  readonly ct: string;
};

/** HMAC tag of a signer-vault wrap under a key derived from M (#54). Covers `synced` too. */
export const signerWrapTag = (pubkey: string, signerKey: string, m: Bytes, w: UntaggedSignerWrap): string => {
  const id = w.type === "sk" ? "sk" : w.credId;
  const extra = w.type === "passkey" ? `${w.rpId}|${w.synced === undefined ? "" : String(w.synced)}` : "|";
  const message = `${signerWrapAad(pubkey, signerKey, w.type, id)}|${extra}|${w.iv}|${w.ct}`;
  return toHex(hmacSha256(signerWrapAuthKey(m), utf8(message)));
};

const tagValid = (pubkey: string, signerKey: string, m: Bytes, w: SignerWrap): boolean => {
  if (w.tag === undefined) return false;
  const { tag, ...rest } = w;
  const expected = fromHex(signerWrapTag(pubkey, signerKey, m, rest as UntaggedSignerWrap));
  const given = fromHex(tag);
  return expected !== null && given !== null && bytesEqual(expected, given);
};

/**
 * Once M is known (#54): drops wraps whose tag is wrong. Untagged wraps from
 * older versions are kept, unless the vault has more than
 * {@link UNTAGGED_SIGNER_WRAP_LIMIT} wraps: then only the one just opened stays.
 */
export const pruneSignerVault = (
  vault: SignerVault,
  pubkey: string,
  signerKey: string,
  m: Bytes,
  openedId?: string,
): SignerVault => {
  const kept = vault.wraps.filter((w) => w.tag === undefined || tagValid(pubkey, signerKey, m, w));
  const wraps =
    kept.length > UNTAGGED_SIGNER_WRAP_LIMIT
      ? kept.filter((w) => w.tag !== undefined || `${w.type}:${wrapId(w)}` === openedId)
      : kept;
  return { ...vault, wraps };
};

const PACKAGE_NAME = /^[A-Za-z][\w]*(\.[A-Za-z][\w]*)+$/;
const HEX_PUBKEY = /^[0-9a-f]{64}$/;

/** App identity from the caller only (SPEC §5.2); insecure or malformed callers get none (#30). */
export const appIdForCaller = (caller: Caller, knownNsiteGateways: ReadonlyArray<string> = []): Result<string, EvolustrError> => {
  if (caller.identity === "connection") {
    return HEX_PUBKEY.test(caller.clientPubkey) ? ok(`nip46:${caller.clientPubkey}`) : error("invalidCaller", "Bad client pubkey");
  }
  if ("androidPackage" in caller) {
    return PACKAGE_NAME.test(caller.androidPackage) ? ok(`android:${caller.androidPackage}`) : error("invalidCaller", "Bad package name");
  }
  return appIdFromOrigin(caller.origin, knownNsiteGateways);
};

export const isProtectedEvent: EvolustrSigner["isProtectedEvent"] = (event) =>
  event.kind === VAULT_KIND && event.tags.some((t) => t[0] === "d" && typeof t[1] === "string" && isProtectedDTag(t[1]));

// ── Implementation ──────────────────────────────────────────────────────────

export const createEvolustrSigner = (host: SignerHost): EvolustrSigner => {
  const now = host.now ?? (() => Math.floor(Date.now() / 1000));
  const random = host.randomBytes ?? defaultRandomBytes;
  const timeoutMs = host.timeoutMs ?? 5000;
  const allowSk = (): boolean => (typeof host.allowSkWrap === "function" ? host.allowSkWrap() : host.allowSkWrap !== false);
  let m: Bytes | null = null;
  let vault: SignerVault | null = null;
  /** True once the signer vault was read from the relays this session (#40). */
  let vaultLoaded = false;
  /** The relays lack wraps the local copy has (#41); fixed after an approved key request. */
  let needsHeal = false;
  let lastEventAt = 0;
  /** A relay vault with another M than the local copy, checked once M is known (#52 phase B). */
  let candidate: SignerVault | null = null;
  /** The previous M after a rotation, for old app keys. */
  let previousM: Bytes | null = null;
  /** Every earlier M opened from the vault, newest first (#58); null until read. */
  let earlierMs: ReadonlyArray<Bytes> | null = null;

  const appIdFor = (caller: Caller) => appIdForCaller(caller, host.knownNsiteGateways);

  const fetchVault = async (pubkey: string): Promise<Result<SignerVault | null>> => {
    const f = await fetchReplaceable(
      host.relays,
      host.relayUrls,
      { author: pubkey, kind: VAULT_KIND, d: signerVaultDTag(pubkey, host.signerKey) },
      timeoutMs,
    );
    if (f.kind === "none") return ok(null);
    if (f.kind === "incomplete") return error("relaysUnavailable", "Not every relay answered");
    lastEventAt = Math.max(lastEventAt, f.event.created_at);
    return parseSignerVault(f.event.content);
  };

  /**
   * Loads the signer vault once per session; null when none exists (#40). With a
   * local copy (#41), it's merged with the relay version, or used instead of a
   * missing or invalid one; `needsHeal` marks wraps the relays lack.
   */
  const loadVault = async (pubkey: string): Promise<Result<SignerVault | null>> => {
    if (vaultLoaded) return ok(vault);
    const fetched = await fetchVault(pubkey);
    if (!fetched.ok && fetched.error.type !== "invalidSignerVault") return fetched;
    const copyText = (await host.cache?.getVault?.(pubkey)) ?? null;
    const copy = copyText === null ? null : parseSignerVault(copyText);
    const local = copy?.ok ? copy.value : null;
    if (local === null) {
      if (!fetched.ok) return fetched;
      vault = fetched.value;
    } else if (!fetched.ok || fetched.value === null) {
      vault = local;
      needsHeal = true;
    } else if (differentMaster(local, fetched.value)) {
      // Another M on the relays (a rotation, or a forgery): keep the local copy
      // until M is unlocked and can check it; never heal over it (#52 phase B).
      vault = local;
      candidate = fetched.value;
      needsHeal = false;
    } else {
      // The relay vault has no sk wrap and this device may not use one: keep it that way (#52).
      const dropSk = !allowSk() && !fetched.value.wraps.some((w) => w.type === "sk");
      vault = mergeSignerVaults(local, fetched.value, { dropSk });
      const onRelays = new Set(fetched.value.wraps.map((w) => JSON.stringify(w)));
      needsHeal = vault.wraps.some((w) => !onRelays.has(JSON.stringify(w)));
    }
    vaultLoaded = true;
    return ok(vault);
  };

  const publish = async (pubkey: string, next: SignerVault): Promise<Result<SignerVault>> => {
    // Never publish from an unknown state: it would drop wraps added elsewhere (#40).
    if (!vaultLoaded) return error("signerVaultUnknown", "Load the signer vault before changing it");
    const at = Math.max(now(), lastEventAt + 1);
    const signer: Signer = {
      getPublicKey: host.getPublicKey,
      signEvent: host.sign,
      nip44Encrypt: () => Promise.reject(new Error("unused")),
      nip44Decrypt: () => Promise.reject(new Error("unused")),
    };
    try {
      await publishReplaceable(
        host.relays,
        host.relayUrls,
        signer,
        { kind: VAULT_KIND, created_at: at, tags: [["d", signerVaultDTag(pubkey, host.signerKey)]], content: JSON.stringify(next) },
        timeoutMs,
      );
    } catch (e) {
      return error("publishFailed", e instanceof Error ? e.message : String(e));
    }
    lastEventAt = at;
    vault = next;
    needsHeal = false;
    await host.cache?.setVault?.(pubkey, JSON.stringify(next));
    return ok(next);
  };

  const sealM = (pubkey: string, key: Bytes, w: { type: "sk" } | { type: "passkey"; rpId: string; credId: string; synced?: boolean }, secret: Bytes): SignerWrap => {
    const id = w.type === "sk" ? "sk" : w.credId;
    const sealed = { ...w, ...seal(key, secret, signerWrapAad(pubkey, host.signerKey, w.type, id)) } as UntaggedSignerWrap;
    return { ...sealed, tag: signerWrapTag(pubkey, host.signerKey, secret, sealed) } as SignerWrap;
  };

  const openM = (pubkey: string, w: SignerWrap, key: Bytes): Result<Bytes> => {
    const r = open(key, w, signerWrapAad(pubkey, host.signerKey, w.type, wrapId(w)));
    return r.ok && r.value.length !== MASTER_SECRET_LENGTH ? error("invalidSignerVault", "Wrong secret length") : r;
  };

  const withWrap = (v: SignerVault | null, w: SignerWrap): SignerVault => ({
    ...(v ?? {}),
    v: 1,
    wraps: [...(v?.wraps ?? []).filter((x) => !(x.type === w.type && wrapId(x) === wrapId(w))), w],
  });

  /** With M known, drops forged wraps; a change is published on the next approved request (#54). */
  const prune = (pubkey: string, secret: Bytes, openedId?: string) => {
    // Never touch a vault that holds another M (#52 phase B).
    if (vault === null || (vault.mId !== undefined && vault.mId !== signerMId(secret))) return;
    const pruned = pruneSignerVault(vault, pubkey, host.signerKey, secret, openedId);
    if (pruned.wraps.length !== vault.wraps.length) {
      vault = pruned;
      needsHeal = true;
    }
  };

  /**
   * With M known: if the relays hold a rotation this M authorised, switch to it
   * and forget this M (it must not make new app keys). "rotated" means M must
   * now be unlocked again, from the new vault (#52 phase B).
   */
  const reconcile = async (pubkey: string): Promise<"same" | "rotated" | "foreign"> => {
    if (m === null) return "same";
    const myId = signerMId(m);
    const other = candidate ?? (vault?.mId !== undefined && vault.mId !== myId ? vault : null);
    if (other === null) return "same";
    candidate = null;
    if (!rotationValid(other, m)) return "foreign";
    previousM = m;
    earlierMs = null;
    vault = other;
    m = null;
    needsHeal = false;
    await host.cache?.remove(pubkey);
    await host.cache?.setVault?.(pubkey, JSON.stringify(other));
    return "rotated";
  };

  /** Called after a wrap opened to M, or after creating M: the vault is good (#41). */
  const remember = async (pubkey: string, secret: Bytes, openedId?: string) => {
    m = secret;
    if ((await reconcile(pubkey)) === "rotated") return;
    prune(pubkey, secret, openedId);
    // Older vaults have no mId: add it, since a wrap of this vault just opened to M.
    if (openedId !== undefined && vault !== null && vault.mId === undefined) {
      vault = { ...vault, mId: signerMId(secret) };
      needsHeal = true;
    }
    await host.cache?.set(pubkey, secret);
    if (vault !== null) await host.cache?.setVault?.(pubkey, JSON.stringify(vault));
  };

  /**
   * The earlier Ms, newest first, opened from the vault with the current one:
   * `previous` with M, each `older` entry with the one before it (#58). Stops
   * at the first entry that doesn't open.
   */
  const earlierOf = (pubkey: string): ReadonlyArray<Bytes> => {
    if (earlierMs !== null) return earlierMs;
    const first = vault?.previous;
    if (m === null || first === undefined || vault?.mId !== signerMId(m)) return previousM === null ? [] : [previousM];
    const found: Bytes[] = [];
    let key = m;
    for (const p of [first, ...(vault?.older ?? [])]) {
      const opened = open(signerPreviousKey(key), p, signerWrapAad(pubkey, host.signerKey, "previous", p.mId));
      if (!opened.ok || opened.value.length !== MASTER_SECRET_LENGTH || signerMId(opened.value) !== p.mId) break;
      found.push(opened.value);
      key = opened.value;
    }
    if (found.length === 0 && previousM !== null) found.push(previousM);
    earlierMs = found;
    return found;
  };

  /**
   * Unlocks M without a click if possible: cache, then the nsec. Creates M only
   * when `create` is set and no signer vault exists at all (#28, #29).
   */
  const unlockQuiet = async (pubkey: string, create: boolean): Promise<Result<boolean>> => {
    if (m !== null) return ok(true);
    const cached = await host.cache?.get(pubkey);
    if (cached != null && cached.length === MASTER_SECRET_LENGTH) {
      m = cached;
      // Relays down: keep using the cached M. A rotation it authorised: unlock the new one.
      const read = await loadVault(pubkey);
      if (!read.ok || (await reconcile(pubkey)) !== "rotated") return ok(true);
    }
    const loaded = await loadVault(pubkey);
    if (!loaded.ok) return loaded;
    const sk = host.getSecretKey?.() ?? null;
    if (sk !== null && allowSk()) {
      const skWrap = vault?.wraps.find((w) => w.type === "sk");
      if (skWrap !== undefined) {
        const opened = openM(pubkey, skWrap, signerSkWrapKey(sk));
        if (opened.ok) {
          await remember(pubkey, opened.value, "sk:sk");
          return ok(true);
        }
      }
      if (vault === null && create) {
        // First use: create M and protect it with the nsec.
        const fresh = random(MASTER_SECRET_LENGTH);
        const published = await publish(pubkey, { ...withWrap(vault, sealM(pubkey, signerSkWrapKey(sk), { type: "sk" }, fresh)), mId: signerMId(fresh) });
        if (!published.ok) return published;
        await remember(pubkey, fresh);
        return ok(true);
      }
    }
    return ok(false);
  };

  /** Unlocks M with a signer passkey, after a click inside the signer. */
  const unlockWithPasskey = async (pubkey: string): Promise<Result<void>> => {
    const passkeys = host.passkeys;
    const wraps = (vault?.wraps ?? []).filter(
      (w): w is Extract<SignerWrap, { type: "passkey" }> => w.type === "passkey" && passkeys !== undefined && w.rpId === passkeys.rpId,
    );
    if (passkeys === undefined || wraps.length === 0) {
      return error("signerLocked", "No way to unlock this signer's Evolustr key here; enroll a signer passkey");
    }
    await host.ui.requestGesture("unlock");
    let result;
    try {
      result = await passkeys.get({ allowCredIds: wraps.map((w) => w.credId), prfInput: signerPrfInput(pubkey) });
    } catch (e) {
      return error("passkeyFailed", e instanceof Error ? e.message : String(e));
    }
    const wrap = wraps.find((w) => w.credId === result.credId);
    if (wrap === undefined || result.prfOutput === null) return error("passkeyFailed", "The passkey gave no usable result");
    const opened = openM(pubkey, wrap, signerPasskeyWrapKey(result.prfOutput));
    if (!opened.ok) return opened;
    await remember(pubkey, opened.value, `passkey:${wrap.credId}`);
    return ok(undefined);
  };

  const ensureM = async (): Promise<Result<{ readonly pubkey: string; readonly m: Bytes }>> => {
    const pubkey = await host.getPublicKey();
    const quiet = await unlockQuiet(pubkey, true);
    if (!quiet.ok) return quiet;
    if (!quiet.value) {
      const viaPasskey = await unlockWithPasskey(pubkey);
      if (!viaPasskey.ok) return viaPasskey;
      // That opened the previous M, and the vault moved on to its successor (#52 phase B).
      if (m === null && previousM !== null) {
        const again = await unlockWithPasskey(pubkey);
        if (!again.ok) return again;
      }
    }
    return m === null ? error("signerLocked", "Locked") : ok({ pubkey, m });
  };

  const capabilities: EvolustrSigner["capabilities"] = async (caller) => {
    const appId = appIdFor(caller);
    if (!appId.ok) return appId;
    const pubkey = await host.getPublicKey();
    if (m === null) await unlockQuiet(pubkey, false);
    // M may come from the cache without the vault being read: read it, ignoring
    // failures (still never creates or publishes anything, #29).
    if (!vaultLoaded) await loadVault(pubkey);
    return ok({
      identity: caller.identity,
      appId: appId.value,
      signerId: m === null ? null : computeSignerId(m, appId.value),
      ready: m !== null,
      signerPasskey: (vault?.wraps ?? []).some((w) => w.type === "passkey"),
      recoverable: (vault?.wraps ?? []).some((w) => w.type === "sk" || (w.type === "passkey" && w.synced === true)),
      nsecProtected: (vault?.wraps ?? []).some((w) => w.type === "sk"),
      nsecExposed: (vault?.wraps ?? []).some((w) => w.type === "sk") || vault?.skDroppedAt !== undefined,
      ...(() => {
        const ids = earlierOf(pubkey).map((x) => computeSignerId(x, appId.value));
        return { previousSignerId: ids[0] ?? null, previousSignerIds: ids };
      })(),
    });
  };

  const getWrapKey: EvolustrSigner["getWrapKey"] = async (caller) => {
    const appId = appIdFor(caller);
    if (!appId.ok) return appId;
    const allowed = await host.ui.confirm({ kind: "appKey", appId: appId.value, identity: caller.identity });
    if (!allowed) return error("userRefused", "The user didn't allow this app");
    const unlocked = await ensureM();
    if (!unlocked.ok) return unlocked;
    // Self-heal (#41): the user just approved this app and M is unlocked. With M
    // from the cache the vault may not be loaded yet; a failure here doesn't block.
    if (!vaultLoaded) await loadVault(unlocked.value.pubkey);
    prune(unlocked.value.pubkey, unlocked.value.m);
    if (needsHeal && vault !== null) await publish(unlocked.value.pubkey, vault);
    return ok(signerAppKey(unlocked.value.m, appId.value));
  };

  const getHostSecret: EvolustrSigner["getHostSecret"] = async (label) => {
    if (!isHostSecretLabel(label)) return error("badRequest", "A host secret label is 1–200 characters without '|'");
    const unlocked = await ensureM();
    if (!unlocked.ok) return unlocked;
    return ok(hostSecret(unlocked.value.m, label));
  };

  const enrollPasskey: EvolustrSigner["enrollPasskey"] = async () => {
    const passkeys = host.passkeys;
    if (passkeys === undefined) return error("noPasskeys", "This signer has no passkey support");
    const pubkey = await host.getPublicKey();
    // The current wrap list must be known before adding to it (#40).
    const loaded = await loadVault(pubkey);
    if (!loaded.ok) return loaded;
    const quiet = await unlockQuiet(pubkey, false);
    if (!quiet.ok) return quiet;
    if (!(await host.ui.confirm({ kind: "enrollPasskey" }))) return error("userRefused", "Cancelled");
    // Moving from the nsec to a passkey: with the sk wrap no longer allowed, it
    // may still open M once, so the passkey wraps the same M and app keys stay.
    if (m === null && !allowSk()) {
      const sk = host.getSecretKey?.() ?? null;
      const skWrap = vault?.wraps.find((w) => w.type === "sk");
      if (sk !== null && skWrap !== undefined) {
        const opened = openM(pubkey, skWrap, signerSkWrapKey(sk));
        if (opened.ok) await remember(pubkey, opened.value, "sk:sk");
      }
    }
    // A signer vault already exists: unlock M first, never create a second one (#28).
    if (m === null && vault !== null) {
      const unlocked = await unlockWithPasskey(pubkey);
      if (!unlocked.ok) return error("signerLocked", "Unlock this signer's existing Evolustr key before adding a passkey");
    }
    await host.ui.requestGesture("enrollPasskey");
    let created;
    try {
      created = await passkeys.create({
        userId: sha256(utf8(`evolustr-signer|${pubkey}`)),
        userName: pubkey.slice(0, 16),
        excludeCredIds: (vault?.wraps ?? []).flatMap((w) => (w.type === "passkey" && w.rpId === passkeys.rpId ? [w.credId] : [])),
        prfInput: signerPrfInput(pubkey),
      });
    } catch (e) {
      return error("passkeyFailed", e instanceof Error ? e.message : String(e));
    }
    if (!created.prfEnabled) return error("prfUnsupported", "This authenticator has no PRF support");
    let prfOutput = created.prfOutput;
    if (prfOutput === null) {
      await host.ui.requestGesture("enrollPasskey");
      prfOutput = (await passkeys.get({ allowCredIds: [created.credId], prfInput: signerPrfInput(pubkey) })).prfOutput;
    }
    if (prfOutput === null) return error("prfUnsupported", "The passkey gave no PRF output");
    // Only when no signer vault exists at all: create M now.
    const secret = m ?? random(MASTER_SECRET_LENGTH);
    let next = withWrap(vault, sealM(pubkey, signerPasskeyWrapKey(prfOutput), { type: "passkey", rpId: passkeys.rpId, credId: created.credId, synced: created.synced }, secret));
    if (!allowSk() && next.wraps.some((w) => w.type === "sk")) {
      // M stays the same: whoever can recover the nsec may still have it (#52).
      next = { ...next, wraps: next.wraps.filter((w) => w.type !== "sk"), skDroppedAt: now() };
    }
    if (next.wraps.length > MAX_SIGNER_WRAPS) return error("signerVaultFull", "The signer vault has no room for another wrap");
    next = { ...next, mId: signerMId(secret) };
    const published = await publish(pubkey, next);
    if (!published.ok) return published;
    await remember(pubkey, secret);
    return ok(undefined);
  };

  const getPreviousWrapKey: EvolustrSigner["getPreviousWrapKey"] = async (caller, signerId) => {
    const appId = appIdFor(caller);
    if (!appId.ok) return appId;
    const allowed = await host.ui.confirm({ kind: "appKey", appId: appId.value, identity: caller.identity });
    if (!allowed) return error("userRefused", "The user didn't allow this app");
    const unlocked = await ensureM();
    if (!unlocked.ok) return unlocked;
    const earlier = earlierOf(unlocked.value.pubkey);
    if (earlier.length === 0) return error("noPreviousKey", "This signer hasn't replaced its key");
    const prev = signerId === undefined ? earlier[0] : earlier.find((x) => computeSignerId(x, appId.value) === signerId);
    return prev === undefined ? error("noPreviousKey", "This signer has no earlier key with that id") : ok(signerAppKey(prev, appId.value));
  };

  const getPreviousHostSecret: EvolustrSigner["getPreviousHostSecret"] = async (label) => {
    if (!isHostSecretLabel(label)) return error("badRequest", "A host secret label is 1–200 characters without '|'");
    const unlocked = await ensureM();
    if (!unlocked.ok) return unlocked;
    const prev = earlierOf(unlocked.value.pubkey)[0];
    return prev === undefined ? error("noPreviousKey", "This signer hasn't replaced its key") : ok(hostSecret(prev, label));
  };

  const getPreviousHostSecrets: EvolustrSigner["getPreviousHostSecrets"] = async (label) => {
    if (!isHostSecretLabel(label)) return error("badRequest", "A host secret label is 1–200 characters without '|'");
    const unlocked = await ensureM();
    if (!unlocked.ok) return unlocked;
    return ok(earlierOf(unlocked.value.pubkey).map((x) => hostSecret(x, label)));
  };

  const rotateMaster: EvolustrSigner["rotateMaster"] = async () => {
    const passkeys = host.passkeys;
    if (passkeys === undefined) return error("noPasskeys", "This signer has no passkey support");
    // The point is to cut off whoever can recover the nsec: an sk wrap would bring it back.
    if (allowSk()) return error("nsecAllowed", "Turn off the nsec protection (allowSkWrap) before replacing the key");
    const pubkey = await host.getPublicKey();
    const loaded = await loadVault(pubkey);
    if (!loaded.ok) return loaded;
    if (vault === null) return error("noSignerVault", "This signer has no key to replace yet");
    const wraps = vault.wraps.filter(
      (w): w is Extract<SignerWrap, { type: "passkey" }> => w.type === "passkey" && w.rpId === passkeys.rpId,
    );
    if (wraps.length === 0) return error("noSignerPasskey", "Enroll a signer passkey first");
    if (!(await host.ui.confirm({ kind: "rotateMaster" }))) return error("userRefused", "Cancelled");
    await host.ui.requestGesture("rotateMaster");
    let result;
    try {
      result = await passkeys.get({ allowCredIds: wraps.map((w) => w.credId), prfInput: signerPrfInput(pubkey) });
    } catch (e) {
      return error("passkeyFailed", e instanceof Error ? e.message : String(e));
    }
    const wrap = wraps.find((w) => w.credId === result.credId);
    if (wrap === undefined || result.prfOutput === null) return error("passkeyFailed", "The passkey gave no usable result");
    const key = signerPasskeyWrapKey(result.prfOutput);
    // The passkey in hand proves the user holds the current M.
    const oldM = openM(pubkey, wrap, key);
    if (!oldM.ok) return oldM;
    const newM = random(MASTER_SECRET_LENGTH);
    const oldMId = signerMId(oldM.value);
    const newMId = signerMId(newM);
    // The chain so far moves down one place, unchanged: each entry still opens with the one before it (#58).
    const older = vault.previous === undefined ? [] : [vault.previous, ...(vault.older ?? [])].slice(0, MAX_PREVIOUS_MASTERS - 1);
    const next: SignerVault = {
      v: 1,
      wraps: [sealM(pubkey, key, { type: "passkey", rpId: wrap.rpId, credId: wrap.credId, ...(wrap.synced === undefined ? {} : { synced: wrap.synced }) }, newM)],
      mId: newMId,
      rotatedFrom: { mId: oldMId, proof: masterRotationProof(oldM.value, newMId) },
      previous: { mId: oldMId, ...seal(signerPreviousKey(newM), oldM.value, signerWrapAad(pubkey, host.signerKey, "previous", oldMId)) },
      ...(older.length > 0 ? { older } : {}),
    };
    const droppedWraps = vault.wraps.length - 1;
    const published = await publish(pubkey, next);
    if (!published.ok) return published;
    candidate = null;
    previousM = oldM.value;
    earlierMs = null;
    m = newM;
    await host.cache?.set(pubkey, newM);
    return ok({ droppedWraps });
  };

  const handle: EvolustrSigner["handle"] = async (method, params, caller) => {
    switch (method) {
      case "evolustr_capabilities":
        return capabilities(caller);
      case "evolustr_get_wrap_key": {
        const key = await getWrapKey(caller);
        return key.ok ? ok(toBase64Url(key.value)) : key;
      }
      case "evolustr_get_previous_wrap_key": {
        // Optional: the signer id the app's wrap was made with (#58).
        const signerId = params[0];
        if (signerId !== undefined && signerId !== null && (typeof signerId !== "string" || !/^[0-9a-f]{16}$/.test(signerId))) {
          return error("badRequest", "signerId must be 16 hex characters");
        }
        const key = await getPreviousWrapKey(caller, typeof signerId === "string" ? signerId : undefined);
        return key.ok ? ok(toBase64Url(key.value)) : key;
      }
      case "evolustr_enroll_passkey":
        return enrollPasskey();
      default:
        return error("unknownMethod", `Unknown method ${method}`);
    }
  };

  const lock: EvolustrSigner["lock"] = async () => {
    const pubkey = await host.getPublicKey().catch(() => null);
    m = null;
    vault = null;
    vaultLoaded = false;
    needsHeal = false;
    candidate = null;
    previousM = null;
    earlierMs = null;
    if (pubkey !== null) await host.cache?.remove(pubkey);
  };

  return {
    handle,
    capabilities,
    getWrapKey,
    getPreviousWrapKey,
    enrollPasskey,
    rotateMaster,
    getHostSecret,
    getPreviousHostSecret,
    getPreviousHostSecrets,
    isProtectedEvent,
    appIdFor,
    lock,
  };
};

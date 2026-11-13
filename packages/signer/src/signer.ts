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
  error,
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
  | ({ readonly type: "sk" } & Sealed)
  | ({ readonly type: "passkey"; readonly rpId: string; readonly credId: string } & Sealed);

export interface SignerVault {
  readonly v: 1;
  readonly wraps: ReadonlyArray<SignerWrap>;
}

export type ConfirmRequest =
  | { readonly kind: "appKey"; readonly appId: string; readonly identity: Caller["identity"] }
  | { readonly kind: "enrollPasskey" };

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
  /** False when a third party can recover the nsec (SPEC §5.7). Default true. */
  readonly allowSkWrap?: boolean;
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
    readonly requestGesture: (reason: "unlock" | "enrollPasskey") => Promise<void>;
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
}

export const METHODS = ["evolustr_capabilities", "evolustr_get_wrap_key", "evolustr_enroll_passkey"] as const;
export type Method = (typeof METHODS)[number];

export interface EvolustrSigner {
  /** For the host's message handler: `caller` comes from the host, never from params. */
  readonly handle: (method: string, params: ReadonlyArray<unknown>, caller: Caller) => Promise<Result<unknown>>;
  /** No prompt, and never creates or publishes anything (#29). */
  readonly capabilities: (caller: Caller) => Promise<Result<Capabilities>>;
  /** 32-byte key for the caller's app vault (SPEC §5.3). */
  readonly getWrapKey: (caller: Caller) => Promise<Result<Bytes>>;
  readonly enrollPasskey: () => Promise<Result<void>>;
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
    const sealed = { iv: w["iv"], ct: w["ct"] };
    if (w["type"] === "sk") wraps.push({ type: "sk", ...sealed });
    else if (w["type"] === "passkey" && typeof w["rpId"] === "string" && typeof w["credId"] === "string") {
      wraps.push({ type: "passkey", rpId: w["rpId"], credId: w["credId"], ...sealed });
    } else return error("invalidSignerVault", "Unknown wrap type");
  }
  // A vault that exists but has no wraps isn't "first use" (#28).
  if (wraps.length === 0) return error("invalidSignerVault", "The signer vault has no wraps");
  if (wraps.length > MAX_SIGNER_WRAPS) return error("invalidSignerVault", "Too many wraps");
  return ok({ v: 1, wraps });
};

const wrapId = (w: SignerWrap): string => (w.type === "sk" ? "sk" : w.credId);

export const MAX_SIGNER_WRAPS = 32;

/** Union of two signer vaults by wrap id; `local` wins on the same id (#41). */
export const mergeSignerVaults = (local: SignerVault, fetched: SignerVault): SignerVault => {
  const byId = new Map<string, SignerWrap>();
  for (const w of local.wraps) byId.set(`${w.type}:${wrapId(w)}`, w);
  for (const w of fetched.wraps) {
    const k = `${w.type}:${wrapId(w)}`;
    if (!byId.has(k) && byId.size < MAX_SIGNER_WRAPS) byId.set(k, w);
  }
  return { v: 1, wraps: [...byId.values()] };
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
  const allowSk = host.allowSkWrap !== false;
  let m: Bytes | null = null;
  let vault: SignerVault | null = null;
  /** True once the signer vault was read from the relays this session (#40). */
  let vaultLoaded = false;
  /** The relays lack wraps the local copy has (#41); fixed after an approved key request. */
  let needsHeal = false;
  let lastEventAt = 0;

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
    } else {
      vault = mergeSignerVaults(local, fetched.value);
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

  const sealM = (pubkey: string, key: Bytes, w: { type: "sk" } | { type: "passkey"; rpId: string; credId: string }, secret: Bytes): SignerWrap => {
    const id = w.type === "sk" ? "sk" : w.credId;
    return { ...w, ...seal(key, secret, signerWrapAad(pubkey, host.signerKey, w.type, id)) } as SignerWrap;
  };

  const openM = (pubkey: string, w: SignerWrap, key: Bytes): Result<Bytes> => {
    const r = open(key, w, signerWrapAad(pubkey, host.signerKey, w.type, wrapId(w)));
    return r.ok && r.value.length !== MASTER_SECRET_LENGTH ? error("invalidSignerVault", "Wrong secret length") : r;
  };

  const withWrap = (v: SignerVault | null, w: SignerWrap): SignerVault => ({
    v: 1,
    wraps: [...(v?.wraps ?? []).filter((x) => !(x.type === w.type && wrapId(x) === wrapId(w))), w],
  });

  /** Called after a wrap opened to M, or after creating M: the vault is good (#41). */
  const remember = async (pubkey: string, secret: Bytes) => {
    m = secret;
    await host.cache?.set(pubkey, secret);
    if (vault !== null) await host.cache?.setVault?.(pubkey, JSON.stringify(vault));
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
      return ok(true);
    }
    const loaded = await loadVault(pubkey);
    if (!loaded.ok) return loaded;
    const sk = host.getSecretKey?.() ?? null;
    if (sk !== null && allowSk) {
      const skWrap = vault?.wraps.find((w) => w.type === "sk");
      if (skWrap !== undefined) {
        const opened = openM(pubkey, skWrap, signerSkWrapKey(sk));
        if (opened.ok) {
          await remember(pubkey, opened.value);
          return ok(true);
        }
      }
      if (vault === null && create) {
        // First use: create M and protect it with the nsec.
        const fresh = random(MASTER_SECRET_LENGTH);
        const published = await publish(pubkey, withWrap(vault, sealM(pubkey, signerSkWrapKey(sk), { type: "sk" }, fresh)));
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
    await remember(pubkey, opened.value);
    return ok(undefined);
  };

  const ensureM = async (): Promise<Result<{ readonly pubkey: string; readonly m: Bytes }>> => {
    const pubkey = await host.getPublicKey();
    const quiet = await unlockQuiet(pubkey, true);
    if (!quiet.ok) return quiet;
    if (!quiet.value) {
      const viaPasskey = await unlockWithPasskey(pubkey);
      if (!viaPasskey.ok) return viaPasskey;
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
    if (needsHeal && vault !== null) await publish(unlocked.value.pubkey, vault);
    return ok(signerAppKey(unlocked.value.m, appId.value));
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
    let next = withWrap(vault, sealM(pubkey, signerPasskeyWrapKey(prfOutput), { type: "passkey", rpId: passkeys.rpId, credId: created.credId }, secret));
    if (!allowSk) next = { v: 1, wraps: next.wraps.filter((w) => w.type !== "sk") };
    const published = await publish(pubkey, next);
    if (!published.ok) return published;
    await remember(pubkey, secret);
    return ok(undefined);
  };

  const handle: EvolustrSigner["handle"] = async (method, _params, caller) => {
    switch (method) {
      case "evolustr_capabilities":
        return capabilities(caller);
      case "evolustr_get_wrap_key": {
        const key = await getWrapKey(caller);
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
    if (pubkey !== null) await host.cache?.remove(pubkey);
  };

  return { handle, capabilities, getWrapKey, enrollPasskey, isProtectedEvent, appIdFor, lock };
};

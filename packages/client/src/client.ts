/**
 * `@evolustr/client` (SPEC §8): opens the app's Evolu database for the
 * signed-in Nostr user, on any device.
 *
 * All side effects come in through {@link ClientDeps}; every method returns a
 * `Result` instead of throwing. Session state lives in one immutable record
 * that each step replaces.
 */
import {
  type Bytes,
  type EvolustrError,
  type Fetched,
  type NostrEvent,
  type Relays,
  type Result,
  type Signer,
  type RootWrap,
  type Vault,
  type VaultChoice,
  type VaultContext,
  type SettingKey,
  type StrongMethod,
  type SettingsDoc,
  type SharedSettings,
  DATA_SECRET_LENGTH,
  ROOT_KEY_LENGTH,
  VAULT_KIND,
  addRootKey,
  dataSecretToEvoluMnemonic,
  addRootWrap,
  backupRequirement,
  clientPrfInput,
  createStrictVault,
  makeStrict as makeStrictVault,
  openRootWrap,
  passkeyRootWrap,
  passkeyWrapKey,
  passkeyWrapsFor,
  signerRootWrap,
  signerWrapFor,
  sha256,
  utf8,
  appVaultDTag,
  createCompatibleVault,
  decideVault,
  defaultSettings,
  emptySettings,
  mergeSettings,
  parseSettings,
  resolveSetting,
  setSetting,
  downgrade as downgradeVault,
  error,
  fetchReplaceable,
  hasRootKey,
  level,
  mergeVaults,
  migrationCutoff,
  nip44OpenSecret,
  nip44SealSecret,
  ok,
  openRootData,
  parseVault,
  phraseToRootKey,
  publishReplaceable,
  randomBytes as defaultRandomBytes,
  readVaultEvent,
  rootKeyToPhrase,
  serializeVault,
  vaultEvent,
} from "@evolustr/core";
import type { SecretCache } from "./cache.ts";
import type { CapableSigner, SignerCapabilities } from "./capable.ts";
import type { CreatedPasskey, Passkeys } from "@evolustr/core";
import { fetchSharedSettings, publishSharedSettings } from "./settings.ts";
import {
  type AppDatabase,
  type MigrationMode,
  type OpenDatabase,
  META_SHARED_SETTINGS,
  META_VAULT,
  migrateRows,
} from "./database.ts";

// ── Public types ────────────────────────────────────────────────────────────

export interface ClientDeps {
  readonly signer: Signer;
  readonly relays: Relays;
  readonly openDatabase: OpenDatabase;
  readonly cache: SecretCache;
  /** Client passkeys on this app's domain (SPEC §4); omit to disable. */
  readonly passkeys?: Passkeys | undefined;
  /** An Evolustr-capable signer (SPEC §5), e.g. from `detectCapableSigner(window.nostr)`. */
  readonly capableSigner?: CapableSigner | undefined;
  /** Unix seconds. */
  readonly now?: () => number;
  readonly randomBytes?: (length: number) => Bytes;
}

export interface ClientOptions {
  readonly appId: string;
  readonly relayUrls: ReadonlyArray<string>;
  /** Only strict databases (SPEC §3.2 rule 1). Needs passkeys or a capable signer. */
  readonly requireStrong?: boolean;
  readonly timeoutMs?: number;
  /** Margin for devices whose clocks are off, used in migrations (SPEC §3.4). */
  readonly clockMarginMs?: number;
  /** Defaults for shared settings; language and time zone usually come from the browser. */
  readonly settingsDefaults?: SharedSettings;
  /**
   * Ask before using a compatible vault on a new device when nothing stronger can
   * verify it (`needsUserAction: "confirmWeak"`). Default true; turn off only if
   * the app never offers strict mode.
   */
  readonly confirmWeakOnNewDevice?: boolean;
  /**
   * Also keep the root key R (the recovery phrase) in the device cache, so a
   * reload can follow rotations and add strong methods without a passkey or
   * signer click. Default false: R stays in memory for the session (#27).
   */
  readonly cacheRootKey?: boolean;
  /** Called as connect and unlock move through their steps; relays can be slow. */
  readonly onProgress?: (step: ProgressStep) => void;
}

export type UnlockMethod = "signer" | "passkey" | "nip44" | "recovery" | "cache" | "created";

export interface Status {
  readonly pubkey: string;
  readonly signer: "capable-verified" | "capable-connection" | "standard";
  readonly mode: "strict" | "compatible";
  readonly level: "strong" | "weak";
  readonly unlockedWith: UnlockMethod;
  /** R is unlocked on this device, so strict is possible (SPEC §8.1). */
  readonly canMakeStrict: boolean;
  /** False after a nip44-only unlock of a vault that has R (SPEC §3.1). */
  readonly canAddStrongMethod: boolean;
  readonly passkeySupported: boolean;
  readonly backupRecommended: boolean;
}

/** Steps of connect / unlock, for showing progress (`onProgress`). */
export type ProgressStep = "lookingUpVault" | "creatingVault" | "publishingVault" | "openingDatabase";

export interface UnlockInput {
  readonly recoveryPhrase?: string;
  readonly acceptDeviceLoss?: boolean;
}

export interface Ready {
  readonly pubkey: string;
  readonly db: AppDatabase;
  readonly status: Status;
}

/**
 * "confirmWeak": first use on this device of a compatible vault that can only be
 * opened through NIP-44. Someone who can sign for the user could have replaced a
 * strict vault with one like it (#26), so the user confirms before data is written.
 */
export type UserAction = "passkey" | "signerUnlock" | "recoveryPhrase" | "setupStrong" | "confirmWeak";

export type ConnectResult =
  | ({ readonly state: "ready" } & Ready)
  | { readonly state: "needsUserAction"; readonly action: UserAction }
  | {
      readonly state: "vaultChanged";
      readonly reason: "replaced" | "ambiguous" | "missing";
      readonly options: ReadonlyArray<VaultChoice>;
    };

export interface Evolustr {
  /** Never prompts for a passkey; safe on page load. */
  readonly connect: () => Promise<Result<ConnectResult>>;
  /**
   * Completes `needsUserAction`, from a click. Pass the phrase for "recoveryPhrase";
   * for "setupStrong" with a device-bound passkey, pass `acceptDeviceLoss`.
   *
   * Errors to handle: `wrongPhrase`; `vaultReplaced` when the unlock proved the
   * vault on the relays isn't the user's (#39): call
   * `resolveVaultChange("republishCopy")` to restore this device's copy.
   */
  readonly unlock: (input?: UnlockInput) => Promise<Result<Ready>>;
  readonly resolveVaultChange: (
    choice: VaultChoice,
    input?: { readonly recoveryPhrase?: string },
  ) => Promise<Result<Ready>>;
  /** Makes R available on this device while ready: phrase, or a passkey from a click (SPEC §8.1). */
  readonly unlockRoot: (input?: { readonly recoveryPhrase?: string }) => Promise<Result<Status>>;
  /** Adds a passkey on this domain, from a click. May need `finishPasskeySetup` (SPEC §4.2). */
  readonly enrollPasskey: () => Promise<Result<{ readonly done: boolean }>>;
  /** Second click when the authenticator returned no PRF output at creation. */
  readonly finishPasskeySetup: () => Promise<Result<Status>>;
  /**
   * User's choice: replaces S and drops the NIP-44 wrap (SPEC §3.2 rules 3–4, §3.4).
   * Protects what is written afterwards; data written before stays as readable
   * as it was. Tell the user before calling it (#31).
   */
  readonly makeStrict: (opts?: { readonly acceptDeviceLoss?: boolean }) => Promise<Result<Status>>;
  /**
   * This database's Evolu mnemonic (12 words), to use the data with Evolu
   * directly, without Nostr. Anyone with it can read and write all of this
   * database. It is not the recovery phrase: it changes when the database is
   * made strict, and the old one keeps opening the data from before that.
   */
  readonly exportEvoluMnemonic: () => Result<string>;
  /** R as 12 words; creates R if the vault has none yet. */
  readonly showRecoveryPhrase: () => Promise<Result<string>>;
  /** The user typed the phrase back correctly; remembered for the backup check. */
  readonly confirmRecoveryPhrase: (words: string) => Promise<Result<void>>;
  readonly restoreFromPhrase: (words: string) => Promise<Result<Ready>>;
  readonly downgrade: () => Promise<Result<Status>>;
  readonly status: () => Status | null;
  readonly settings: {
    /** `app ?? shared ?? default` (SPEC §9.2). Reads cached values; no prompt. */
    readonly get: <K extends SettingKey>(key: K) => SharedSettings[K];
    /** Fetches the shared settings from relays (may show a decrypt prompt). */
    readonly refresh: () => Promise<Result<void>>;
    /** "Use for all apps": writes to the shared event (signature + encryption). */
    readonly setShared: (key: string, value: unknown) => Promise<Result<void>>;
    /** This app only, stored in the app database. */
    readonly setApp: (key: string, value: unknown) => Promise<Result<void>>;
  };
  readonly logout: (opts?: { readonly deleteLocalData?: boolean }) => Promise<void>;
}

// ── Session state ───────────────────────────────────────────────────────────

interface Unlocked {
  readonly kind: "ready";
  readonly ctx: VaultContext;
  readonly vault: Vault;
  readonly s: Bytes;
  readonly r?: Bytes;
  readonly db: AppDatabase;
  readonly unlockedWith: UnlockMethod;
}

interface Pending {
  readonly kind: "pending";
  readonly ctx: VaultContext;
  readonly action: UserAction | "choose";
  readonly vault?: Vault;
  /** Local database and secrets, when this device already had one. */
  readonly local?: { readonly db: AppDatabase; readonly s: Bytes; readonly r?: Bytes; readonly copy?: Vault };
}

type Session = { readonly kind: "none" } | Unlocked | Pending;

export const META_PHRASE_CONFIRMED = "phraseConfirmed";
export const META_APP_SETTINGS = "appSettings";
/** Strong methods known for this database, for the backup check (SPEC §3.2 rule 3a). */
export const META_STRONG_METHODS = "strongMethods";

interface KnownMethod {
  readonly id: string;
  readonly method: StrongMethod;
}

// ── Implementation ──────────────────────────────────────────────────────────

export const createEvolustr = (deps: ClientDeps, options: ClientOptions): Evolustr => {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const random = deps.randomBytes ?? defaultRandomBytes;
  const timeoutMs = options.timeoutMs ?? 3000;
  const clockMarginMs = options.clockMarginMs ?? 5 * 60_000;
  let session: Session = { kind: "none" };
  let lastEventAt = 0;
  let settingsState: { readonly app: SettingsDoc; readonly shared: SettingsDoc } = { app: emptySettings, shared: emptySettings };
  const settingsDefaults = options.settingsDefaults ?? defaultSettings();
  const settingsIo = { signer: deps.signer, relays: deps.relays, relayUrls: options.relayUrls, timeoutMs };
  let passkeySupported = false;
  let backupState: { readonly methods: ReadonlyArray<KnownMethod>; readonly phraseConfirmed: boolean } = {
    methods: [],
    phraseConfirmed: false,
  };
  let pendingPasskey: CreatedPasskey | null = null;
  const passkeys = deps.passkeys;
  const capable = deps.capableSigner;
  let caps: SignerCapabilities | null = null;

  const refreshCaps = async (): Promise<SignerCapabilities | null> => {
    caps = capable === undefined ? null : await capable.capabilities().catch(() => null);
    return caps;
  };

  /** R through the capable signer's wrap (SPEC §8.2 step 2). May wait for a click in the signer. */
  const rootFromSigner = async (ctx: VaultContext, vault: Vault, copy?: Vault): Promise<Result<Bytes>> => {
    if (capable === undefined) return error("noCapableSigner", "No Evolustr-capable signer");
    let key: Bytes;
    try {
      key = await capable.getWrapKey();
    } catch (e) {
      return error("signerRefused", e instanceof Error ? e.message : String(e));
    }
    const c = await refreshCaps();
    if (c?.signerId == null) return error("noSignerWrap", "This signer has no wrap in the vault yet");
    // The fetched vault's wrap first, then the local copy's (#39).
    const wraps = [signerWrapFor(vault, c.signerId), copy === undefined ? undefined : signerWrapFor(copy, c.signerId)].filter(
      (w): w is RootWrap => w !== undefined,
    );
    if (wraps.length === 0) return error("noSignerWrap", "This signer has no wrap in the vault yet");
    for (const wrap of wraps) {
      const opened = openRootWrap(ctx, wrap, key);
      if (opened.ok) return opened;
    }
    return error("signerRefused", "The signer's key didn't open its wrap");
  };

  /** After an unlock: add this signer's wrap, creating R if the vault has none (SPEC §8.2 step 5). */
  const ensureSignerWrap = async (): Promise<void> => {
    if (session.kind !== "ready" || capable === undefined) return;
    const s = session;
    let c = caps;
    if (c === null) return;
    if (c.ready && c.signerId !== null && signerWrapFor(s.vault, c.signerId) !== undefined) {
      // Refresh the record: the signer may have gained an sk wrap or a synced passkey (#42).
      await rememberMethod(s.db, { id: `signer:${c.signerId}`, method: { kind: "signer", recoverable: c.recoverable === true } });
      return;
    }
    // A locked signer that needs a passkey click isn't asked here; the user adds it later.
    if (!c.ready && c.signerPasskey) return;
    if (s.r === undefined && hasRootKey(s.vault)) return; // nip44-only device: can't add (SPEC §3.1)
    let key: Bytes;
    try {
      // Asks the user to allow this app; a new signer creates its key here (#29).
      key = await capable.getWrapKey();
    } catch {
      return;
    }
    c = await refreshCaps();
    if (c === null || c.signerId === null || signerWrapFor(s.vault, c.signerId) !== undefined) return;
    const signerIdNow = c.signerId;
    let vault = s.vault;
    const r = s.r ?? random(ROOT_KEY_LENGTH);
    if (s.r === undefined) {
      const withRoot = addRootKey(s.ctx, vault, r, s.s);
      if (!withRoot.ok) return;
      vault = withRoot.value;
    }
    const added = addRootWrap(vault, signerRootWrap(s.ctx, key, signerIdNow, r));
    if (!added.ok) return;
    const published = await publishVault(s.ctx, added.value);
    if (!published.ok) return;
    await rememberMethod(s.db, { id: `signer:${signerIdNow}`, method: { kind: "signer", recoverable: c.recoverable === true } });
    // Local copy source (#38): (a) made by this device: its signer wrap added.
    await becomeReady(s.ctx, published.value, s.s, r, s.unlockedWith, s.db);
  };

  const readMethods = async (db: AppDatabase): Promise<ReadonlyArray<KnownMethod>> => {
    const text = await db.getMeta(META_STRONG_METHODS);
    if (text === null) return [];
    try {
      const list = JSON.parse(text) as unknown;
      return Array.isArray(list) ? (list as KnownMethod[]) : [];
    } catch {
      return [];
    }
  };

  const readDoc = async (db: AppDatabase, key: string): Promise<SettingsDoc> => {
    const text = await db.getMeta(key);
    const doc = text === null ? null : parseSettings(text);
    return doc?.ok ? doc.value : emptySettings;
  };

  // ── Relay helpers ──

  const fetchVault = async (ctx: VaultContext, urls: ReadonlyArray<string> = options.relayUrls): Promise<Fetched> => {
    const f = await fetchReplaceable(
      deps.relays,
      urls,
      { author: ctx.pubkey, kind: VAULT_KIND, d: appVaultDTag(ctx.pubkey, ctx.appId) },
      timeoutMs,
    );
    if (f.kind === "none") return { kind: "none" };
    if (f.kind === "incomplete") return { kind: "unreadable" };
    lastEventAt = Math.max(lastEventAt, f.event.created_at);
    lastFetched = { event: f.event, missingOn: f.missingOn };
    const v = readVaultEvent(ctx, f.event);
    return v.ok ? { kind: "found", vault: v.value } : { kind: "unreadable" };
  };

  /** A vault to publish in the background once connect is ready (self-heal, #37). */
  let healAfterConnect: Vault | null = null;

  /** Relays that accepted the last publish. */
  let lastAccepted: ReadonlyArray<string> = [];
  const progress = (step: ProgressStep) => {
    try {
      options.onProgress?.(step);
    } catch {
      /* the app's callback must not break connecting */
    }
  };

  /** The newest vault event seen, and relays that answered without it (#32). */
  let lastFetched: { readonly event: NostrEvent; readonly missingOn: ReadonlyArray<string> } | null = null;

  /** Sends the current vault event to relays that lack it; no new signature needed. */
  const rebroadcastVault = async (): Promise<void> => {
    const f = lastFetched;
    if (f === null || f.missingOn.length === 0) return;
    await deps.relays.publish(f.missingOn, f.event, timeoutMs).catch(() => undefined);
    lastFetched = { ...f, missingOn: [] };
  };

  /**
   * Publishes, merging with the relay version first when it holds the same S
   * (superset rule). With `requireAll` (rotations, #32), a relay that still
   * refuses after a retry makes it fail with `partialPublish`.
   */
  const publishVault = async (
    ctx: VaultContext,
    vault: Vault,
    requireAll = false,
    /** What the caller just fetched; skips a second lookup. */
    known?: Fetched,
    /** R, when the caller knows it and the session doesn't yet. */
    rootKey?: Bytes,
  ): Promise<Result<Vault>> => {
    let toPublish = vault;
    progress("publishingVault");
    const current = known ?? (await fetchVault(ctx));
    if (current.kind === "found" && current.vault.sHash === vault.sHash) {
      // The local version wins on the same wrap id; with R, forged wraps are dropped (#37).
      const sessionR = rootKey ?? (session.kind === "ready" && session.ctx.appId === ctx.appId ? session.r : undefined);
      const merged = mergeVaults(vault, current.vault, { ctx, r: sessionR });
      if (!merged.ok) return merged;
      // A local downgrade or upgrade decides the mode; merging only adds wraps.
      toPublish = { ...merged.value, mode: vault.mode, dataWraps: vault.dataWraps };
    }
    const at = Math.max(now(), lastEventAt + 1);
    let failed: ReadonlyArray<string>;
    try {
      const published = await publishReplaceable(deps.relays, options.relayUrls, deps.signer, vaultEvent(ctx, toPublish, at), timeoutMs);
      failed = published.failed;
      lastAccepted = published.accepted;
      lastFetched = { event: published.event, missingOn: failed };
    } catch (e) {
      return error("publishFailed", e instanceof Error ? e.message : String(e));
    }
    lastEventAt = at;
    if (requireAll && failed.length > 0) {
      return error("partialPublish", `Not every relay accepted the change (${failed.join(", ")}); it completes on the next connect`);
    }
    return ok(toPublish);
  };

  // ── Building blocks ──

  const statusOf = (s: Unlocked): Status => ({
    pubkey: s.ctx.pubkey,
    signer: caps === null ? "standard" : caps.identity === "verified" ? "capable-verified" : "capable-connection",
    mode: s.vault.mode,
    level: level(s.vault),
    unlockedWith: s.unlockedWith,
    canMakeStrict: s.r !== undefined && s.vault.mode === "compatible",
    canAddStrongMethod: s.r !== undefined || !hasRootKey(s.vault),
    passkeySupported,
    backupRecommended:
      s.vault.mode === "strict" &&
      backupRequirement(backupState.methods.map((m) => m.method), backupState.phraseConfirmed) !== "none",
  });

  /**
   * Opens the database for S, keeps the vault copy and the cache, and becomes
   * ready. The only writer of the local vault copy (META_VAULT), the trust anchor
   * of decideVault (#38): every caller passes a vault this device (a) made, (b)
   * opened with R, (c) opened through NIP-44 after the user chose or confirmed
   * it, or (d) merged from the checked copy.
   */
  const becomeReady = async (
    ctx: VaultContext,
    vaultIn: Vault,
    s: Bytes,
    r: Bytes | undefined,
    unlockedWith: UnlockMethod,
    db?: AppDatabase,
  ): Promise<Result<Ready>> => {
    progress("openingDatabase");
    let vault = vaultIn;
    const database = db ?? (await deps.openDatabase(s));
    // With R known, drop root wraps whose tag doesn't verify, and put the
    // cleaned vault back on the relays in the background (#37).
    if (r !== undefined) {
      const pruned = mergeVaults(vault, vault, { ctx, r });
      if (pruned.ok && pruned.value.rootWraps.length !== vault.rootWraps.length) {
        vault = pruned.value;
        const cleaned = vault;
        const rootKey = r;
        queueMicrotask(() => void publishVault(ctx, cleaned, false, undefined, rootKey).catch(() => undefined));
      }
    }
    await database.setMeta(META_VAULT, serializeVault(vault));
    // R is the recovery phrase: kept in memory only, unless the app opts in (#27).
    await deps.cache.set(ctx.pubkey, ctx.appId, r === undefined || options.cacheRootKey !== true ? { s } : { s, r });
    const next: Unlocked = { kind: "ready", ctx, vault, s, db: database, unlockedWith, ...(r === undefined ? {} : { r }) };
    session = next;
    settingsState = { app: await readDoc(database, META_APP_SETTINGS), shared: await readDoc(database, META_SHARED_SETTINGS) };
    backupState = {
      methods: await readMethods(database),
      phraseConfirmed: (await database.getMeta(META_PHRASE_CONFIRMED)) === "1",
    };
    return ok({ pubkey: ctx.pubkey, db: database, status: statusOf(next) });
  };

  /** Moves to a new data secret, copying local rows (SPEC §3.4). */
  const switchDatabase = async (
    from: AppDatabase | undefined,
    to: AppDatabase,
    mode: MigrationMode,
  ): Promise<void> => {
    if (from === undefined || from.sHash === to.sHash) return;
    await migrateRows(from, to, mode);
    await from.deleteLocal();
  };

  const migrationModeFor = (vault: Vault, localSHash: string): MigrationMode => {
    const cutoff = migrationCutoff(vault, localSHash);
    // Not in history: copy only rows missing in the current database (never overwrites).
    return cutoff === null
      ? { kind: "since", cutoffMs: Number.POSITIVE_INFINITY, marginMs: 0 }
      : { kind: "since", cutoffMs: cutoff * 1000, marginMs: clockMarginMs };
  };

  const createVault = async (ctx: VaultContext): Promise<Result<ConnectResult>> => {
    if (options.requireStrong === true) {
      session = { kind: "pending", ctx, action: "setupStrong" };
      return ok({ state: "needsUserAction", action: "setupStrong" });
    }
    const s = random(DATA_SECRET_LENGTH);
    let nip44Ct: string;
    try {
      nip44Ct = await nip44SealSecret(deps.signer, ctx.pubkey, s);
    } catch (e) {
      return error("signerRefused", e instanceof Error ? e.message : String(e));
    }
    const vault = createCompatibleVault(ctx, { s, nip44Ct, now: now() });
    if (!vault.ok) return vault;
    progress("creatingVault");
    const published = await publishVault(ctx, vault.value, false, { kind: "none" });
    if (!published.ok) return published;
    // Create race (SPEC §6.2 rule 2): if another device created one first, use
    // theirs. Asking the relays that just answered is enough and doesn't wait on slow ones.
    const check = await fetchVault(ctx, lastAccepted.length > 0 ? lastAccepted : options.relayUrls);
    if (check.kind === "found" && check.vault.sHash !== published.value.sHash && check.vault.created <= published.value.created) {
      return unlockFetched(ctx, check.vault, undefined);
    }
    // Local copy source (#38): (a) made by this device.
    return withReady(becomeReady(ctx, published.value, s, undefined, "created"));
  };

  const withReady = async (r: Promise<Result<Ready>>): Promise<Result<ConnectResult>> => {
    const x = await r;
    return x.ok ? ok({ state: "ready", ...x.value }) : x;
  };

  /** Unlock order without a click (SPEC §8.2 step 2), for a vault this device doesn't have yet. */
  const unlockFetched = async (
    ctx: VaultContext,
    vault: Vault,
    local: Pending["local"],
    requireWeakConfirm = false,
  ): Promise<Result<ConnectResult>> => {
    if (caps?.ready === true && caps.signerId !== null && signerWrapFor(vault, caps.signerId) !== undefined) {
      const root = await rootFromSigner(ctx, vault);
      if (root.ok) {
        const s = openRootData(ctx, vault, root.value);
        if (s.ok) {
          const db = await deps.openDatabase(s.value);
          if (local !== undefined) await switchDatabase(local.db, db, migrationModeFor(vault, local.db.sHash));
          // Local copy source (#38): (b) opened with R from the signer.
          return withReady(becomeReady(ctx, vault, s.value, root.value, "signer", db));
        }
      }
    }
    if (local?.r !== undefined) {
      const s = openRootData(ctx, vault, local.r);
      if (s.ok) {
        const db = await deps.openDatabase(s.value);
        await switchDatabase(local.db, db, migrationModeFor(vault, local.db.sHash));
        // Local copy source (#38): (b) opened with the cached R.
        return withReady(becomeReady(ctx, vault, s.value, local.r, "cache", db));
      }
    }
    if (vault.mode === "compatible" && requireWeakConfirm) {
      session = { kind: "pending", ctx, action: "confirmWeak", vault, ...(local === undefined ? {} : { local }) };
      return ok({ state: "needsUserAction", action: "confirmWeak" });
    }
    if (vault.mode === "compatible") {
      const s = await nip44OpenSecret(deps.signer, ctx.pubkey, vault);
      if (s.ok) {
        const db = await deps.openDatabase(s.value);
        if (local !== undefined) await switchDatabase(local.db, db, migrationModeFor(vault, local.db.sHash));
        // Keep a cached R only if it really opens this vault (#33).
        const r = local?.r !== undefined && openRootData(ctx, vault, local.r).ok ? local.r : undefined;
        // Local copy source (#38): (c) opened through NIP-44: a compatible vault, after confirmWeak on a new device.
        return withReady(becomeReady(ctx, vault, s.value, r, "nip44", db));
      }
      if (s.error.type === "signerRefused") return s;
    }
    return askStrongUnlock(ctx, vault, local);
  };

  /** A strong method is needed: a passkey (from a click) if one matches, else the phrase. */
  const askStrongUnlock = (ctx: VaultContext, vault: Vault, local: Pending["local"]): Result<ConnectResult> => {
    // Choose from the fetched vault's and the local copy's wraps together (#39).
    const wraps = [...vault.rootWraps, ...(local?.copy?.rootWraps ?? [])];
    const signerCanOpen = caps !== null && wraps.some((w) => w.type === "signer");
    const action: UserAction = signerCanOpen
      ? "signerUnlock"
      : passkeys !== undefined && passkeySupported && wraps.some((w) => w.type === "passkey" && w.rpId === passkeys.rpId)
        ? "passkey"
        : "recoveryPhrase";
    session = { kind: "pending", ctx, action, vault, ...(local === undefined ? {} : { local }) };
    return ok({ state: "needsUserAction", action });
  };

  /** Opens R with one of this domain's passkeys (SPEC §4.3). Call from a click. */
  /**
   * Opens R with one of this domain's passkeys (SPEC §4.3). Call from a click.
   * Wraps from the local copy are tried too, so a fetched vault with missing or
   * corrupted wraps can't lock the device out (#39).
   */
  const rootFromPasskey = async (ctx: VaultContext, vault: Vault, copy?: Vault): Promise<Result<Bytes>> => {
    if (passkeys === undefined) return error("noPasskeys", "Passkeys aren't enabled");
    const candidates = [...passkeyWrapsFor(vault, passkeys.rpId), ...(copy === undefined ? [] : passkeyWrapsFor(copy, passkeys.rpId))];
    if (candidates.length === 0) return error("noPasskeyWrap", "No passkey for this site is registered in the vault");
    let result;
    try {
      result = await passkeys.get({ allowCredIds: [...new Set(candidates.map((w) => w.credId))], prfInput: clientPrfInput(ctx.pubkey, ctx.appId) });
    } catch (e) {
      return error("passkeyFailed", e instanceof Error ? e.message : String(e));
    }
    if (result.prfOutput === null) return error("passkeyFailed", "The passkey gave no usable result");
    const key = passkeyWrapKey(result.prfOutput, ctx.appId);
    for (const wrap of candidates.filter((w) => w.credId === result.credId)) {
      const opened = openRootWrap(ctx, wrap, key);
      if (opened.ok) return opened;
    }
    return error("passkeyFailed", "The passkey didn't open any wrap of this vault");
  };

  // ── API ──

  const connect: Evolustr["connect"] = async () => {
    const result = await connectInner();
    // In the background: a slow relay must not delay opening the app.
    if (result.ok && result.value.state === "ready") {
      const heal = healAfterConnect;
      healAfterConnect = null;
      if (heal !== null && session.kind === "ready") void publishVault(session.ctx, heal).catch(() => undefined);
      else void rebroadcastVault();
    }
    if (result.ok && result.value.state === "ready" && capable !== undefined) {
      await ensureSignerWrap();
      const st = status();
      if (st !== null) return ok({ ...result.value, status: st });
    }
    return result;
  };

  const connectInner = async (): Promise<Result<ConnectResult>> => {
    let pubkey: string;
    try {
      pubkey = await deps.signer.getPublicKey();
    } catch (e) {
      return error("signerRefused", e instanceof Error ? e.message : String(e));
    }
    const ctx: VaultContext = { pubkey, appId: options.appId };
    progress("lookingUpVault");
    passkeySupported = passkeys === undefined ? false : await passkeys.supported().catch(() => false);
    await refreshCaps();
    const cached = await deps.cache.get(pubkey, options.appId);
    const fetched = await fetchVault(ctx);

    let local: Pending["local"];
    if (cached !== null) {
      const db = await deps.openDatabase(cached.s);
      const copyText = await db.getMeta(META_VAULT);
      const copy = copyText === null ? undefined : parseVault(copyText);
      local = {
        db,
        s: cached.s,
        ...(cached.r === undefined ? {} : { r: cached.r }),
        ...(copy?.ok ? { copy: copy.value } : {}),
      };
    }

    const decision = decideVault(
      ctx,
      fetched,
      local === undefined
        ? null
        : { sHash: local.db.sHash, ...(local.r === undefined ? {} : { r: local.r }), ...(local.copy === undefined ? {} : { copy: local.copy }) },
    );

    switch (decision.type) {
      case "create":
        return createVault(ctx);
      case "firstUse":
        return unlockFetched(ctx, decision.vault, undefined, decision.warnWeak && options.confirmWeakOnNewDevice !== false);
      case "same": {
        // (d) merged from the checked copy: wraps from the copy are never dropped (#37, #38).
        const fetchedVault = fetched.kind === "found" ? fetched.vault : local!.copy!;
        const merged = mergeVaults(local!.copy ?? fetchedVault, fetchedVault, { ctx, r: local!.r });
        const vault = merged.ok ? merged.value : (local!.copy ?? fetchedVault);
        // Self-heal (SPEC §6.2 rule 4): the relays lost or altered wraps this device still has.
        const onRelays = new Set(fetchedVault.rootWraps.map((w) => JSON.stringify(w)));
        if (vault.rootWraps.some((w) => !onRelays.has(JSON.stringify(w)))) healAfterConnect = vault;
        return withReady(becomeReady(ctx, vault, local!.s, local!.r, "cache", local!.db));
      }
      case "follow": {
        const db = await deps.openDatabase(decision.s);
        await switchDatabase(local?.db, db, migrationModeFor(decision.vault, local!.db.sHash));
        // Local copy source (#38): (b) opened with R (decideVault "follow").
        return withReady(becomeReady(ctx, decision.vault, decision.s, local!.r, "cache", db));
      }
      case "needsStrongUnlock":
        return askStrongUnlock(ctx, decision.vault, local);
      case "choose":
        session = {
          kind: "pending",
          ctx,
          action: "choose",
          ...(decision.vault === undefined ? {} : { vault: decision.vault }),
          ...(local === undefined ? {} : { local }),
        };
        return ok({ state: "vaultChanged", reason: decision.reason, options: decision.options });
    }
  };

  /** Opens the pending vault with a recovery phrase, migrating local rows. */
  const openWithPhrase = async (p: Pending, words: string): Promise<Result<Ready>> => {
    const r = phraseToRootKey(words);
    if (!r.ok) return r;
    return openWithRoot(p, r.value, "recovery");
  };

  /** Opens the pending vault with R, migrating local rows. */
  const openWithRoot = async (p: Pending, root: Bytes, how: UnlockMethod): Promise<Result<Ready>> => {
    const r = { value: root };
    let vault = p.vault;
    if (vault === undefined) {
      const f = await fetchVault(p.ctx);
      if (f.kind !== "found") return error("noVault", "No vault found to restore");
      vault = f.vault;
    }
    const s = openRootData(p.ctx, vault, r.value);
    if (!s.ok) {
      // R is real (it opens this device's copy), so the fetched vault is foreign (#39).
      if (p.local?.copy !== undefined && openRootData(p.ctx, p.local.copy, r.value).ok) {
        session = { kind: "pending", ctx: p.ctx, action: "choose", vault, local: { ...p.local, r: r.value } };
        return error("vaultReplaced", "The vault on the relays isn't yours; restore this device's copy with resolveVaultChange(\"republishCopy\")");
      }
      return error("wrongPhrase", "This recovery phrase doesn't open this app's data");
    }
    const db = await deps.openDatabase(s.value);
    if (p.local !== undefined) await switchDatabase(p.local.db, db, migrationModeFor(vault, p.local.db.sHash));
    // Local copy source (#38): (b) opened with R from a passkey, signer or the phrase.
    return becomeReady(p.ctx, vault, s.value, r.value, how, db);
  };

  const unlock: Evolustr["unlock"] = async (input) => {
    const result = await unlockInner(input);
    if (result.ok && capable !== undefined) {
      await ensureSignerWrap();
      const st = status();
      if (st !== null) return ok({ ...result.value, status: st });
    }
    return result;
  };

  const unlockInner = async (input: UnlockInput | undefined): Promise<Result<Ready>> => {
    if (session.kind !== "pending") return error("nothingToUnlock", "connect() didn't ask for a user action");
    const p = session;
    if (input?.recoveryPhrase !== undefined && p.action !== "setupStrong") return openWithPhrase(p, input.recoveryPhrase);
    if (p.action === "recoveryPhrase") return error("phraseRequired", "Pass the recovery phrase");
    if (p.action === "passkey") {
      if (p.vault === undefined) return error("noVault", "No vault to unlock");
      const root = await rootFromPasskey(p.ctx, p.vault, p.local?.copy);
      return root.ok ? openWithRoot(p, root.value, "passkey") : root;
    }
    if (p.action === "signerUnlock") {
      if (p.vault === undefined) return error("noVault", "No vault to unlock");
      const root = await rootFromSigner(p.ctx, p.vault, p.local?.copy);
      return root.ok ? openWithRoot(p, root.value, "signer") : root;
    }
    if (p.action === "setupStrong") return setupStrong(p.ctx, input?.acceptDeviceLoss === true);
    if (p.action === "confirmWeak") {
      if (p.vault === undefined) return error("noVault", "No vault to open");
      const r = await unlockFetched(p.ctx, p.vault, p.local, false);
      if (!r.ok) return r;
      return r.value.state === "ready"
        ? ok({ pubkey: r.value.pubkey, db: r.value.db, status: r.value.status })
        : error("needsUserAction", `Still needs: ${r.value.state === "needsUserAction" ? r.value.action : r.value.state}`);
    }
    return error("unsupported", `Unlocking with "${p.action}" isn't available in this build`);
  };

  const resolveVaultChange: Evolustr["resolveVaultChange"] = async (choice, input) => {
    if (session.kind !== "pending" || session.action !== "choose") {
      return error("nothingToResolve", "connect() didn't report a vault change");
    }
    const p = session;
    switch (choice) {
      case "republishCopy": {
        if (p.local?.copy === undefined) return error("noCopy", "This device has no copy of the vault");
        const published = await publishVault(p.ctx, p.local.copy);
        if (!published.ok) return published;
        // Local copy source (#38): (a) this device's own copy, republished.
        return becomeReady(p.ctx, published.value, p.local.s, p.local.r, "cache", p.local.db);
      }
      case "followRelay": {
        if (p.vault === undefined) return error("noVault", "No vault to follow");
        // The user chose this. Use R when it opens the vault; otherwise NIP-44
        // (only a compatible vault has a nip44 wrap; a strict one never falls back).
        const viaRoot = p.local?.r === undefined ? null : openRootData(p.ctx, p.vault, p.local.r);
        // A database protected by a root key never follows a vault only NIP-44 opens (#38).
        if (!viaRoot?.ok && p.local?.copy !== undefined && hasRootKey(p.local.copy)) {
          return error("unsafeFollow", "This device's data is protected by a root key; restore with a strong method instead");
        }
        const s = viaRoot?.ok ? viaRoot : p.vault.mode === "compatible" ? await nip44OpenSecret(deps.signer, p.ctx.pubkey, p.vault) : viaRoot ?? error("rootLocked", "A strong unlock is needed");
        if (!s.ok) return s;
        const db = await deps.openDatabase(s.value);
        // Not verifiable: copy only rows missing there, never overwrite, and keep
        // the previous local database (it isn't deleted).
        if (p.local !== undefined && p.local.db.sHash !== db.sHash) {
          await migrateRows(p.local.db, db, { kind: "since", cutoffMs: Number.POSITIVE_INFINITY, marginMs: 0 });
        }
        // Local copy source (#38): (b) opened with R, or (c) through NIP-44 after the user chose to follow.
        return becomeReady(p.ctx, p.vault, s.value, viaRoot?.ok ? p.local?.r : undefined, viaRoot?.ok ? "cache" : "nip44", db);
      }
      case "restorePhrase":
        if (input?.recoveryPhrase === undefined) return error("phraseRequired", "Pass the recovery phrase");
        return openWithPhrase(p, input.recoveryPhrase);
      case "startNew": {
        session = { kind: "none" };
        const created = await createVault(p.ctx);
        if (!created.ok) return created;
        return created.value.state === "ready"
          ? ok({ pubkey: created.value.pubkey, db: created.value.db, status: created.value.status })
          : error("needsUserAction", "Creating a new database needs a user action first");
      }
    }
  };

  const requireReady = (): Result<Unlocked> =>
    session.kind === "ready" ? ok(session) : error("notReady", "Connect first");

  const unlockRoot: Evolustr["unlockRoot"] = async (input) => {
    const s = requireReady();
    if (!s.ok) return s;
    const r = input?.recoveryPhrase === undefined ? await rootFromPasskey(s.value.ctx, s.value.vault) : phraseToRootKey(input.recoveryPhrase);
    if (!r.ok) return r;
    const check = openRootData(s.value.ctx, s.value.vault, r.value);
    if (!check.ok) return error("wrongPhrase", "This recovery phrase doesn't belong to this app's data");
    if (options.cacheRootKey === true) await deps.cache.set(s.value.ctx.pubkey, s.value.ctx.appId, { s: s.value.s, r: r.value });
    // Now that R is known, drop root wraps with a bad tag and publish the result (#37).
    const pruned = mergeVaults(s.value.vault, s.value.vault, { ctx: s.value.ctx, r: r.value });
    let vault = s.value.vault;
    if (pruned.ok && pruned.value.rootWraps.length !== vault.rootWraps.length) {
      const published = await publishVault(s.value.ctx, pruned.value, false, undefined, r.value);
      vault = published.ok ? published.value : pruned.value;
      await s.value.db.setMeta(META_VAULT, serializeVault(vault));
    }
    const next: Unlocked = { ...s.value, vault, r: r.value };
    session = next;
    return ok(statusOf(next));
  };

  const showRecoveryPhrase: Evolustr["showRecoveryPhrase"] = async () => {
    const s = requireReady();
    if (!s.ok) return s;
    if (s.value.r !== undefined) return ok(rootKeyToPhrase(s.value.r));
    if (hasRootKey(s.value.vault)) {
      return error("rootLocked", "Unlock the root key on this device first (unlockRoot)");
    }
    const r = random(ROOT_KEY_LENGTH);
    const withRoot = addRootKey(s.value.ctx, s.value.vault, r, s.value.s);
    if (!withRoot.ok) return withRoot;
    const published = await publishVault(s.value.ctx, withRoot.value);
    if (!published.ok) return published;
    // Local copy source (#38): (a) made by this device.
    const ready = await becomeReady(s.value.ctx, published.value, s.value.s, r, s.value.unlockedWith, s.value.db);
    return ready.ok ? ok(rootKeyToPhrase(r)) : ready;
  };

  const confirmRecoveryPhrase: Evolustr["confirmRecoveryPhrase"] = async (words) => {
    const s = requireReady();
    if (!s.ok) return s;
    const r = phraseToRootKey(words);
    if (!r.ok || s.value.r === undefined || rootKeyToPhrase(r.value) !== rootKeyToPhrase(s.value.r)) {
      return error("wrongPhrase", "The words don't match the recovery phrase");
    }
    await s.value.db.setMeta(META_PHRASE_CONFIRMED, "1");
    backupState = { ...backupState, phraseConfirmed: true };
    return ok(undefined);
  };

  const restoreFromPhrase: Evolustr["restoreFromPhrase"] = async (words) => {
    if (session.kind === "pending") return openWithPhrase(session, words);
    let pubkey: string;
    try {
      pubkey = await deps.signer.getPublicKey();
    } catch (e) {
      return error("signerRefused", e instanceof Error ? e.message : String(e));
    }
    return openWithPhrase({ kind: "pending", ctx: { pubkey, appId: options.appId }, action: "recoveryPhrase" }, words);
  };

  const downgrade: Evolustr["downgrade"] = async () => {
    const s = requireReady();
    if (!s.ok) return s;
    if (s.value.r === undefined) return error("rootLocked", "Unlock the root key on this device first (unlockRoot)");
    let ct: string;
    try {
      ct = await nip44SealSecret(deps.signer, s.value.ctx.pubkey, s.value.s);
    } catch (e) {
      return error("signerRefused", e instanceof Error ? e.message : String(e));
    }
    const next = downgradeVault(s.value.ctx, s.value.vault, { r: s.value.r, s: s.value.s, nip44Ct: ct });
    if (!next.ok) return next;
    const published = await publishVault(s.value.ctx, next.value, true);
    if (!published.ok && published.error.type !== "partialPublish") return published;
    // Local copy source (#38): (a) made by this device (downgrade).
    const ready = await becomeReady(s.value.ctx, published.ok ? published.value : next.value, s.value.s, s.value.r, s.value.unlockedWith, s.value.db);
    if (!ready.ok) return ready;
    return published.ok ? ok(ready.value.status) : published;
  };

  const createPasskey = async (ctx: VaultContext, vault: Vault | undefined): Promise<Result<CreatedPasskey>> => {
    if (passkeys === undefined) return error("noPasskeys", "Passkeys aren't enabled");
    try {
      const created = await passkeys.create({
        userId: sha256(utf8(ctx.pubkey)),
        userName: ctx.pubkey.slice(0, 16),
        excludeCredIds: vault === undefined ? [] : passkeyWrapsFor(vault, passkeys.rpId).map((w) => w.credId),
        prfInput: clientPrfInput(ctx.pubkey, ctx.appId),
      });
      return created.prfEnabled ? ok(created) : error("prfUnsupported", "This authenticator can't be used: no PRF support");
    } catch (e) {
      return error("passkeyFailed", e instanceof Error ? e.message : String(e));
    }
  };

  const rememberMethod = async (db: AppDatabase, known: KnownMethod) => {
    const methods = [...backupState.methods.filter((m) => m.id !== known.id), known];
    await db.setMeta(META_STRONG_METHODS, JSON.stringify(methods));
    backupState = { ...backupState, methods };
  };

  /** Adds a passkey wrap of R once the PRF output is known. */
  const completeEnrollment = async (s: Unlocked, created: CreatedPasskey, prfOutput: Bytes): Promise<Result<Status>> => {
    if (passkeys === undefined) return error("noPasskeys", "Passkeys aren't enabled");
    let vault = s.vault;
    let r = s.r;
    if (r === undefined) {
      if (hasRootKey(vault)) return error("rootLocked", "Unlock the root key on this device first (unlockRoot)");
      r = random(ROOT_KEY_LENGTH);
      const withRoot = addRootKey(s.ctx, vault, r, s.s);
      if (!withRoot.ok) return withRoot;
      vault = withRoot.value;
    }
    const wrap = passkeyRootWrap(s.ctx, passkeyWrapKey(prfOutput, s.ctx.appId), passkeys.rpId, created.credId, r);
    const added = addRootWrap(vault, wrap);
    if (!added.ok) return added;
    const published = await publishVault(s.ctx, added.value);
    if (!published.ok) return published;
    await rememberMethod(s.db, { id: `passkey:${created.credId}`, method: { kind: "passkey", synced: created.synced } });
    // Local copy source (#38): (a) made by this device (passkey added).
    const ready = await becomeReady(s.ctx, published.value, s.s, r, s.unlockedWith, s.db);
    return ready.ok ? ok(ready.value.status) : ready;
  };

  const enrollPasskey: Evolustr["enrollPasskey"] = async () => {
    const s = requireReady();
    if (!s.ok) return s;
    if (s.value.r === undefined && hasRootKey(s.value.vault)) {
      return error("rootLocked", "Unlock the root key on this device first (unlockRoot)");
    }
    const created = await createPasskey(s.value.ctx, s.value.vault);
    if (!created.ok) return created;
    if (created.value.prfOutput === null) {
      pendingPasskey = created.value;
      return ok({ done: false });
    }
    const done = await completeEnrollment(s.value, created.value, created.value.prfOutput);
    return done.ok ? ok({ done: true }) : done;
  };

  const finishPasskeySetup: Evolustr["finishPasskeySetup"] = async () => {
    const s = requireReady();
    if (!s.ok) return s;
    const created = pendingPasskey;
    if (created === null || passkeys === undefined) return error("nothingToFinish", "No passkey setup is waiting");
    let result;
    try {
      result = await passkeys.get({ allowCredIds: [created.credId], prfInput: clientPrfInput(s.value.ctx.pubkey, s.value.ctx.appId) });
    } catch (e) {
      return error("passkeyFailed", e instanceof Error ? e.message : String(e));
    }
    if (result.prfOutput === null) return error("prfUnsupported", "The passkey gave no PRF output");
    pendingPasskey = null;
    return completeEnrollment(s.value, created, result.prfOutput);
  };

  const makeStrict: Evolustr["makeStrict"] = async (opts) => {
    const s = requireReady();
    if (!s.ok) return s;
    if (s.value.r === undefined) return error("rootLocked", "Unlock the root key on this device first");
    const need = backupRequirement(backupState.methods.map((m) => m.method), backupState.phraseConfirmed);
    if (need === "required" && opts?.acceptDeviceLoss !== true) {
      return error("backupRequired", "Save the recovery phrase or add a second passkey first, or accept losing the data with this device");
    }
    const newS = random(DATA_SECRET_LENGTH);
    const next = makeStrictVault(s.value.ctx, s.value.vault, { r: s.value.r, newS, now: now() });
    if (!next.ok) return next;
    const db = await deps.openDatabase(newS);
    await migrateRows(s.value.db, db, { kind: "all" });
    for (const key of [META_APP_SETTINGS, META_SHARED_SETTINGS, META_STRONG_METHODS, META_PHRASE_CONFIRMED]) {
      const v = await s.value.db.getMeta(key);
      if (v !== null) await db.setMeta(key, v);
    }
    const published = await publishVault(s.value.ctx, next.value, true);
    if (!published.ok && published.error.type !== "partialPublish") {
      await db.deleteLocal();
      return published;
    }
    if (!published.ok) {
      // Some relays have the strict vault: continue on S', but keep the old
      // local database until every relay agrees (#32). connect() re-sends it.
      // Local copy source (#38): (a) made by this device (makeStrict).
      const ready = await becomeReady(s.value.ctx, next.value, newS, s.value.r, s.value.unlockedWith, db);
      return ready.ok ? published : ready;
    }
    await s.value.db.deleteLocal();
    // Local copy source (#38): (a) made by this device (makeStrict).
    const ready = await becomeReady(s.value.ctx, published.value, newS, s.value.r, s.value.unlockedWith, db);
    return ready.ok ? ok(ready.value.status) : ready;
  };

  /** First vault created strict for `requireStrong` (SPEC §8.2 step 4). */
  const setupStrong = async (ctx: VaultContext, acceptDeviceLoss: boolean): Promise<Result<Ready>> => {
    if (capable !== undefined) {
      let key: Bytes;
      try {
        key = await capable.getWrapKey();
      } catch (e) {
        return error("signerRefused", e instanceof Error ? e.message : String(e));
      }
      const c = await refreshCaps();
      if (c?.signerId != null) {
        // The same backup check as for passkeys (SPEC §3.2 rule 3a, #42).
        const method: StrongMethod = { kind: "signer", recoverable: c.recoverable === true };
        if (backupRequirement([method], false) === "required" && !acceptDeviceLoss) {
          return error("backupRequired", "This signer's key can't be recovered on another device: accept losing the data with this device, or set up a backup first");
        }
        const r = random(ROOT_KEY_LENGTH);
        const s = random(DATA_SECRET_LENGTH);
        const vault = createStrictVault(ctx, { s, r, now: now(), rootWraps: [signerRootWrap(ctx, key, c.signerId, r)] });
        if (!vault.ok) return vault;
        const published = await publishVault(ctx, vault.value);
        if (!published.ok) return published;
        const db = await deps.openDatabase(s);
        await db.setMeta(META_STRONG_METHODS, JSON.stringify([{ id: `signer:${c.signerId}`, method }]));
        // Local copy source (#38): (a) made by this device (requireStrong).
        return becomeReady(ctx, published.value, s, r, "signer", db);
      }
    }
    const created = await createPasskey(ctx, undefined);
    if (!created.ok) return created;
    let prfOutput = created.value.prfOutput;
    if (prfOutput === null && passkeys !== undefined) {
      try {
        prfOutput = (await passkeys.get({ allowCredIds: [created.value.credId], prfInput: clientPrfInput(ctx.pubkey, ctx.appId) })).prfOutput;
      } catch (e) {
        return error("passkeyFailed", e instanceof Error ? e.message : String(e));
      }
    }
    if (prfOutput === null || passkeys === undefined) return error("prfUnsupported", "The passkey gave no PRF output");
    const method: StrongMethod = { kind: "passkey", synced: created.value.synced };
    if (backupRequirement([method], false) === "required" && !acceptDeviceLoss) {
      return error("backupRequired", "This passkey isn't synced: accept losing the data with this device, or use a synced passkey");
    }
    const r = random(ROOT_KEY_LENGTH);
    const s = random(DATA_SECRET_LENGTH);
    const wrap = passkeyRootWrap(ctx, passkeyWrapKey(prfOutput, ctx.appId), passkeys.rpId, created.value.credId, r);
    const vault = createStrictVault(ctx, { s, r, now: now(), rootWraps: [wrap] });
    if (!vault.ok) return vault;
    const published = await publishVault(ctx, vault.value);
    if (!published.ok) return published;
    const db = await deps.openDatabase(s);
    await db.setMeta(META_STRONG_METHODS, JSON.stringify([{ id: `passkey:${created.value.credId}`, method }]));
    // Local copy source (#38): (a) made by this device (requireStrong).
    return becomeReady(ctx, published.value, s, r, "passkey", db);
  };

  const exportEvoluMnemonic: Evolustr["exportEvoluMnemonic"] = () => {
    const s = requireReady();
    return s.ok ? ok(dataSecretToEvoluMnemonic(s.value.s)) : s;
  };

  const status: Evolustr["status"] = () => (session.kind === "ready" ? statusOf(session) : null);

  const settings: Evolustr["settings"] = {
    get: (key) => resolveSetting(key, settingsState.app, settingsState.shared, settingsDefaults),
    refresh: async () => {
      const s = requireReady();
      if (!s.ok) return s;
      const fetched = await fetchSharedSettings(settingsIo, s.value.ctx.pubkey);
      if (!fetched.ok) return fetched;
      const shared = mergeSettings(settingsState.shared, fetched.value);
      await s.value.db.setMeta(META_SHARED_SETTINGS, JSON.stringify(shared));
      settingsState = { ...settingsState, shared };
      return ok(undefined);
    },
    setShared: async (key, value) => {
      const s = requireReady();
      if (!s.ok) return s;
      const fetched = await fetchSharedSettings(settingsIo, s.value.ctx.pubkey);
      if (!fetched.ok) return fetched;
      const at = Math.max(now(), lastEventAt + 1);
      const next = setSetting(mergeSettings(settingsState.shared, fetched.value), key, value, at);
      if (!next.ok) return next;
      const published = await publishSharedSettings(settingsIo, s.value.ctx.pubkey, next.value, at);
      if (!published.ok) return published;
      lastEventAt = at;
      await s.value.db.setMeta(META_SHARED_SETTINGS, JSON.stringify(next.value));
      settingsState = { ...settingsState, shared: next.value };
      return ok(undefined);
    },
    setApp: async (key, value) => {
      const s = requireReady();
      if (!s.ok) return s;
      const next = setSetting(settingsState.app, key, value, now());
      if (!next.ok) return next;
      await s.value.db.setMeta(META_APP_SETTINGS, JSON.stringify(next.value));
      settingsState = { ...settingsState, app: next.value };
      return ok(undefined);
    },
  };

  const logout: Evolustr["logout"] = async (opts) => {
    const s = session;
    session = { kind: "none" };
    if (s.kind === "none") return;
    await deps.cache.remove(s.ctx.pubkey, s.ctx.appId);
    const db = s.kind === "ready" ? s.db : s.local?.db;
    if (db === undefined) return;
    if (opts?.deleteLocalData === true) await db.deleteLocal();
    else await db.close();
  };

  return {
    connect,
    unlock,
    resolveVaultChange,
    unlockRoot,
    enrollPasskey,
    finishPasskeySetup,
    makeStrict,
    showRecoveryPhrase,
    exportEvoluMnemonic,
    confirmRecoveryPhrase,
    restoreFromPhrase,
    downgrade,
    status,
    settings,
    logout,
  };
};

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
  type Relays,
  type Result,
  type Signer,
  type Vault,
  type VaultChoice,
  type VaultContext,
  DATA_SECRET_LENGTH,
  ROOT_KEY_LENGTH,
  VAULT_KIND,
  addRootKey,
  appVaultDTag,
  createCompatibleVault,
  decideVault,
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
import {
  type AppDatabase,
  type MigrationMode,
  type OpenDatabase,
  META_VAULT,
  migrateRows,
} from "./database.ts";

// ── Public types ────────────────────────────────────────────────────────────

export interface ClientDeps {
  readonly signer: Signer;
  readonly relays: Relays;
  readonly openDatabase: OpenDatabase;
  readonly cache: SecretCache;
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

export interface Ready {
  readonly pubkey: string;
  readonly db: AppDatabase;
  readonly status: Status;
}

export type UserAction = "passkey" | "signerUnlock" | "recoveryPhrase" | "setupStrong";

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
  /** Completes `needsUserAction`, from a click. Pass the phrase for "recoveryPhrase". */
  readonly unlock: (input?: { readonly recoveryPhrase?: string }) => Promise<Result<Ready>>;
  readonly resolveVaultChange: (
    choice: VaultChoice,
    input?: { readonly recoveryPhrase?: string },
  ) => Promise<Result<Ready>>;
  /** Makes R available on this device while ready (SPEC §8.1). */
  readonly unlockRoot: (input: { readonly recoveryPhrase: string }) => Promise<Result<Status>>;
  /** R as 12 words; creates R if the vault has none yet. */
  readonly showRecoveryPhrase: () => Promise<Result<string>>;
  /** The user typed the phrase back correctly; remembered for the backup check. */
  readonly confirmRecoveryPhrase: (words: string) => Promise<Result<void>>;
  readonly restoreFromPhrase: (words: string) => Promise<Result<Ready>>;
  readonly downgrade: () => Promise<Result<Status>>;
  readonly status: () => Status | null;
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

// ── Implementation ──────────────────────────────────────────────────────────

export const createEvolustr = (deps: ClientDeps, options: ClientOptions): Evolustr => {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const random = deps.randomBytes ?? defaultRandomBytes;
  const timeoutMs = options.timeoutMs ?? 5000;
  const clockMarginMs = options.clockMarginMs ?? 5 * 60_000;
  let session: Session = { kind: "none" };
  let lastEventAt = 0;

  // ── Relay helpers ──

  const fetchVault = async (ctx: VaultContext): Promise<Fetched> => {
    const f = await fetchReplaceable(
      deps.relays,
      options.relayUrls,
      { author: ctx.pubkey, kind: VAULT_KIND, d: appVaultDTag(ctx.pubkey, ctx.appId) },
      timeoutMs,
    );
    if (f.kind === "none") return { kind: "none" };
    if (f.kind === "incomplete") return { kind: "unreadable" };
    lastEventAt = Math.max(lastEventAt, f.event.created_at);
    const v = readVaultEvent(ctx, f.event);
    return v.ok ? { kind: "found", vault: v.value } : { kind: "unreadable" };
  };

  /** Publishes, merging with the relay version first when it holds the same S (superset rule). */
  const publishVault = async (ctx: VaultContext, vault: Vault): Promise<Result<Vault>> => {
    let toPublish = vault;
    const current = await fetchVault(ctx);
    if (current.kind === "found" && current.vault.sHash === vault.sHash) {
      const merged = mergeVaults(vault, current.vault);
      if (!merged.ok) return merged;
      // A local downgrade or upgrade decides the mode; merging only adds wraps.
      toPublish = { ...merged.value, mode: vault.mode, dataWraps: vault.dataWraps };
    }
    const at = Math.max(now(), lastEventAt + 1);
    try {
      await publishReplaceable(deps.relays, options.relayUrls, deps.signer, vaultEvent(ctx, toPublish, at), timeoutMs);
    } catch (e) {
      return error("publishFailed", e instanceof Error ? e.message : String(e));
    }
    lastEventAt = at;
    return ok(toPublish);
  };

  // ── Building blocks ──

  const statusOf = (s: Unlocked): Status => ({
    pubkey: s.ctx.pubkey,
    signer: "standard",
    mode: s.vault.mode,
    level: level(s.vault),
    unlockedWith: s.unlockedWith,
    canMakeStrict: s.r !== undefined,
    canAddStrongMethod: s.r !== undefined || !hasRootKey(s.vault),
    passkeySupported: false,
    backupRecommended: false,
  });

  /** Opens the database for S, keeps the vault copy and the cache, and becomes ready. */
  const becomeReady = async (
    ctx: VaultContext,
    vault: Vault,
    s: Bytes,
    r: Bytes | undefined,
    unlockedWith: UnlockMethod,
    db?: AppDatabase,
  ): Promise<Result<Ready>> => {
    const database = db ?? (await deps.openDatabase(s));
    await database.setMeta(META_VAULT, serializeVault(vault));
    await deps.cache.set(ctx.pubkey, ctx.appId, r === undefined ? { s } : { s, r });
    const next: Unlocked = { kind: "ready", ctx, vault, s, db: database, unlockedWith, ...(r === undefined ? {} : { r }) };
    session = next;
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
    const published = await publishVault(ctx, vault.value);
    if (!published.ok) return published;
    // Create race (SPEC §6.2 rule 2): if another device created one first, use theirs.
    const check = await fetchVault(ctx);
    if (check.kind === "found" && check.vault.sHash !== published.value.sHash && check.vault.created <= published.value.created) {
      return unlockFetched(ctx, check.vault, undefined);
    }
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
  ): Promise<Result<ConnectResult>> => {
    if (local?.r !== undefined) {
      const s = openRootData(ctx, vault, local.r);
      if (s.ok) {
        const db = await deps.openDatabase(s.value);
        await switchDatabase(local.db, db, migrationModeFor(vault, local.db.sHash));
        return withReady(becomeReady(ctx, vault, s.value, local.r, "cache", db));
      }
    }
    if (vault.mode === "compatible") {
      const s = await nip44OpenSecret(deps.signer, ctx.pubkey, vault);
      if (s.ok) {
        const db = await deps.openDatabase(s.value);
        if (local !== undefined) await switchDatabase(local.db, db, migrationModeFor(vault, local.db.sHash));
        return withReady(becomeReady(ctx, vault, s.value, local?.r, "nip44", db));
      }
      if (s.error.type === "signerRefused") return s;
    }
    session = { kind: "pending", ctx, action: "recoveryPhrase", vault, ...(local === undefined ? {} : { local }) };
    return ok({ state: "needsUserAction", action: "recoveryPhrase" });
  };

  // ── API ──

  const connect: Evolustr["connect"] = async () => {
    let pubkey: string;
    try {
      pubkey = await deps.signer.getPublicKey();
    } catch (e) {
      return error("signerRefused", e instanceof Error ? e.message : String(e));
    }
    const ctx: VaultContext = { pubkey, appId: options.appId };
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
        return unlockFetched(ctx, decision.vault, undefined);
      case "same": {
        const vault = fetched.kind === "found" ? fetched.vault : local!.copy!;
        return withReady(becomeReady(ctx, vault, local!.s, local!.r, "cache", local!.db));
      }
      case "follow": {
        const db = await deps.openDatabase(decision.s);
        await switchDatabase(local?.db, db, migrationModeFor(decision.vault, local!.db.sHash));
        return withReady(becomeReady(ctx, decision.vault, decision.s, local!.r, "cache", db));
      }
      case "needsStrongUnlock":
        session = { kind: "pending", ctx, action: "recoveryPhrase", vault: decision.vault, ...(local === undefined ? {} : { local }) };
        return ok({ state: "needsUserAction", action: "recoveryPhrase" });
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
    let vault = p.vault;
    if (vault === undefined) {
      const f = await fetchVault(p.ctx);
      if (f.kind !== "found") return error("noVault", "No vault found to restore");
      vault = f.vault;
    }
    const s = openRootData(p.ctx, vault, r.value);
    if (!s.ok) return error("wrongPhrase", "This recovery phrase doesn't open this app's data");
    const db = await deps.openDatabase(s.value);
    if (p.local !== undefined) await switchDatabase(p.local.db, db, migrationModeFor(vault, p.local.db.sHash));
    return becomeReady(p.ctx, vault, s.value, r.value, "recovery", db);
  };

  const unlock: Evolustr["unlock"] = async (input) => {
    if (session.kind !== "pending") return error("nothingToUnlock", "connect() didn't ask for a user action");
    const p = session;
    if (p.action === "recoveryPhrase") {
      if (input?.recoveryPhrase === undefined) return error("phraseRequired", "Pass the recovery phrase");
      return openWithPhrase(p, input.recoveryPhrase);
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
        return becomeReady(p.ctx, published.value, p.local.s, p.local.r, "cache", p.local.db);
      }
      case "followRelay": {
        if (p.vault === undefined) return error("noVault", "No vault to follow");
        const s = await nip44OpenSecret(deps.signer, p.ctx.pubkey, p.vault);
        if (!s.ok) return s;
        const db = await deps.openDatabase(s.value);
        // Not verifiable: copy only rows missing there, never overwrite.
        if (p.local !== undefined) {
          await switchDatabase(p.local.db, db, { kind: "since", cutoffMs: Number.POSITIVE_INFINITY, marginMs: 0 });
        }
        return becomeReady(p.ctx, p.vault, s.value, undefined, "nip44", db);
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

  const unlockRoot: Evolustr["unlockRoot"] = async ({ recoveryPhrase }) => {
    const s = requireReady();
    if (!s.ok) return s;
    const r = phraseToRootKey(recoveryPhrase);
    if (!r.ok) return r;
    const check = openRootData(s.value.ctx, s.value.vault, r.value);
    if (!check.ok) return error("wrongPhrase", "This recovery phrase doesn't belong to this app's data");
    await deps.cache.set(s.value.ctx.pubkey, s.value.ctx.appId, { s: s.value.s, r: r.value });
    const next: Unlocked = { ...s.value, r: r.value };
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
    let ct: string;
    try {
      ct = await nip44SealSecret(deps.signer, s.value.ctx.pubkey, s.value.s);
    } catch (e) {
      return error("signerRefused", e instanceof Error ? e.message : String(e));
    }
    const next = downgradeVault(s.value.vault, ct);
    if (!next.ok) return next;
    const published = await publishVault(s.value.ctx, next.value);
    if (!published.ok) return published;
    const ready = await becomeReady(s.value.ctx, published.value, s.value.s, s.value.r, s.value.unlockedWith, s.value.db);
    return ready.ok ? ok(ready.value.status) : ready;
  };

  const status: Evolustr["status"] = () => (session.kind === "ready" ? statusOf(session) : null);

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
    showRecoveryPhrase,
    confirmRecoveryPhrase,
    restoreFromPhrase,
    downgrade,
    status,
    logout,
  };
};

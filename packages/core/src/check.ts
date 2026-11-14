/**
 * Decides what a device does with the vault it fetched (SPEC §6.3).
 * Pure: the caller supplies what it fetched and what it already knows.
 */
import type { Bytes } from "./bytes.ts";
import { type Vault, type VaultContext, hasRootKey, headerBinding, migrationCutoff, nip44Wrap, openRootData, sameVaultCore, verifyRootRotation } from "./vault.ts";

export type Fetched =
  | { readonly kind: "found"; readonly vault: Vault }
  /** Every relay answered and none has a vault. */
  | { readonly kind: "none" }
  /** A vault event exists but can't be parsed, or relays didn't all answer. */
  | { readonly kind: "unreadable" };

export interface LocalState {
  /** `sHash` of the local database for this (pubkey, appId). */
  readonly sHash: string;
  /** R, if this device knows it (cached or just unlocked). */
  readonly r?: Bytes;
  /** The last good vault, as kept in the app database (SPEC §6.2 rule 5). */
  readonly copy?: Vault;
  /** Data secrets this device has moved past, kept locally beyond the vault's history limit (#44). */
  readonly seen?: ReadonlyArray<string>;
}

/** True when this device has already moved past the vault's secret: a rollback. */
const movedPast = (local: LocalState, sHash: string): boolean =>
  local.copy?.history.some((h) => h.sHash === sHash) === true || local.seen?.includes(sHash) === true;

export type VaultChoice = "republishCopy" | "followRelay" | "restorePhrase" | "startNew";

export type VaultDecision =
  /** No local database: unlock normally; warn about the weak level before first use. */
  | { readonly type: "firstUse"; readonly vault: Vault; readonly warnWeak: boolean }
  /** No vault anywhere and no local database: create one. */
  | { readonly type: "create" }
  | { readonly type: "same" }
  /** A rotation this device can verify (its secret is in the vault's history): follow and migrate. */
  | { readonly type: "follow"; readonly vault: Vault; readonly s: Bytes; readonly cutoff: number | null }
  /** The device can't verify a strict vault: needs a strong method or the phrase. */
  | { readonly type: "needsStrongUnlock"; readonly vault: Vault }
  /** The user must choose; `options` lists what is safe to offer. */
  | {
      readonly type: "choose";
      readonly reason: "replaced" | "ambiguous" | "missing";
      readonly vault?: Vault;
      readonly options: ReadonlyArray<VaultChoice>;
    };

/**
 * Same secret as the local database (#38). The local copy is the trust anchor,
 * so a fetched vault is only accepted when R verifies it or it matches the copy.
 */
const decideSameSecret = (
  ctx: VaultContext,
  vault: Vault,
  local: LocalState,
  replaced: VaultDecision,
  canRepublish: boolean,
): VaultDecision => {
  const copy = local.copy;
  if (local.r !== undefined) {
    if (hasRootKey(vault)) return openRootData(ctx, vault, local.r).ok ? { type: "same" } : replaced;
    // The relay version lost the root key the copy has: forged.
    return copy !== undefined && hasRootKey(copy) ? replaced : { type: "same" };
  }
  // No copy and no R: nothing to check a root key or strict header against (#54).
  if (copy === undefined) return vault.mode === "strict" || hasRootKey(vault) ? { type: "needsStrongUnlock", vault } : { type: "same" };
  if (sameVaultCore(copy, vault)) return { type: "same" };
  if (!hasRootKey(copy)) {
    // Another device added R: the header and the nip44 wrap are unchanged.
    const sameHeader = headerBinding(copy) === headerBinding(vault);
    const sameNip44 = nip44Wrap(copy)?.ct === nip44Wrap(vault)?.ct;
    if (hasRootKey(vault) && sameHeader && sameNip44) return { type: "same" };
    return { type: "choose", reason: "ambiguous", vault, options: canRepublish ? ["followRelay", "republishCopy"] : ["followRelay"] };
  }
  // The copy has a root key and the relay version differs: a legitimate
  // downgrade elsewhere looks like this, and only R can tell.
  return { type: "needsStrongUnlock", vault };
};

export const decideVault = (
  ctx: VaultContext,
  fetched: Fetched,
  local: LocalState | null,
): VaultDecision => {
  const canRepublish = local?.copy !== undefined;

  if (fetched.kind !== "found") {
    if (local === null) {
      return fetched.kind === "none"
        ? { type: "create" }
        : { type: "choose", reason: "missing", options: ["restorePhrase", "startNew"] };
    }
    return {
      type: "choose",
      reason: "missing",
      options: canRepublish ? ["republishCopy", "restorePhrase", "startNew"] : ["restorePhrase", "startNew"],
    };
  }

  const vault = fetched.vault;
  if (local === null) return { type: "firstUse", vault, warnWeak: vault.mode === "compatible" };
  const replaced: VaultDecision = {
    type: "choose",
    reason: "replaced",
    vault,
    options: canRepublish ? ["republishCopy", "restorePhrase", "startNew"] : ["restorePhrase", "startNew"],
  };

  if (vault.sHash === local.sHash) return decideSameSecret(ctx, vault, local, replaced, canRepublish);

  // A root rotation moving forward from this device's secret (#52 phase C).
  const forward = vault.history.some((h) => h.sHash === local.sHash);
  if (local.r !== undefined) {
    const s = openRootData(ctx, vault, local.r);
    // Signed by this device's R: the user replaced the root key elsewhere. The
    // new R comes from a strong method; never offer to republish the old copy.
    if (!s.ok) return forward && verifyRootRotation(ctx, vault, local.r) ? { type: "needsStrongUnlock", vault } : replaced;
    // Follow on its own only when moving forward: the vault's authenticated
    // history names the local secret (#25). An older vault replayed by someone
    // who can sign for the user opens with R too, so it must never be followed.
    if (vault.history.some((h) => h.sHash === local.sHash)) {
      return { type: "follow", vault, s: s.value, cutoff: migrationCutoff(vault, local.sHash) };
    }
    if (movedPast(local, vault.sHash)) return replaced;
    return {
      type: "choose",
      reason: "ambiguous",
      vault,
      options: canRepublish ? ["republishCopy", "followRelay", "restorePhrase"] : ["followRelay", "restorePhrase"],
    };
  }

  // Without R the header can't be verified, but the local copy still tells a
  // rollback (an older secret this device has moved past) or a swap from strict
  // to a different, weak vault: both are replaced, never followed (#25, #27).
  if (movedPast(local, vault.sHash)) return replaced;
  if (local.copy?.mode === "strict" && vault.mode === "compatible") return replaced;

  if (vault.mode === "strict") {
    // Never republish here: it could undo a legitimate makeStrict().
    return { type: "needsStrongUnlock", vault };
  }

  // Claims a root rotation from this device's secret: only R can check it, so
  // ask for a strong unlock rather than offering to undo it (#52 phase C).
  if (forward && vault.rootRotation !== undefined) return { type: "needsStrongUnlock", vault };

  // This device's database is protected by a root key: never offer to follow a
  // vault that only NIP-44 can open (#38).
  if (local.copy !== undefined && hasRootKey(local.copy)) return replaced;

  return {
    type: "choose",
    reason: "ambiguous",
    vault,
    options: canRepublish ? ["followRelay", "republishCopy"] : ["followRelay"],
  };
};

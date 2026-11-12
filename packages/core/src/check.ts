/**
 * Decides what a device does with the vault it fetched (SPEC §6.3).
 * Pure: the caller supplies what it fetched and what it already knows.
 */
import type { Bytes } from "./bytes.ts";
import { type Vault, type VaultContext, hasRootKey, migrationCutoff, openRootData } from "./vault.ts";

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
}

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

  if (vault.sHash === local.sHash) {
    // Same secret, but an edited header (e.g. strict flipped to compatible)
    // no longer opens with R: nobody without R can make a valid one.
    if (local.r !== undefined && hasRootKey(vault) && !openRootData(ctx, vault, local.r).ok) return replaced;
    return { type: "same" };
  }

  if (local.r !== undefined) {
    const s = openRootData(ctx, vault, local.r);
    if (!s.ok) return replaced;
    // Follow on its own only when moving forward: the vault's authenticated
    // history names the local secret (#25). An older vault replayed by someone
    // who can sign for the user opens with R too, so it must never be followed.
    if (vault.history.some((h) => h.sHash === local.sHash)) {
      return { type: "follow", vault, s: s.value, cutoff: migrationCutoff(vault, local.sHash) };
    }
    if (local.copy?.history.some((h) => h.sHash === vault.sHash) === true) return replaced;
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
  if (local.copy?.history.some((h) => h.sHash === vault.sHash) === true) return replaced;
  if (local.copy?.mode === "strict" && vault.mode === "compatible") return replaced;

  if (vault.mode === "strict") {
    // Never republish here: it could undo a legitimate makeStrict().
    return { type: "needsStrongUnlock", vault };
  }

  return {
    type: "choose",
    reason: "ambiguous",
    vault,
    options: canRepublish ? ["followRelay", "republishCopy"] : ["followRelay"],
  };
};

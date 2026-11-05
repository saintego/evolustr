import { fromBase64Url, toBase64Url } from "../bytes.ts";
import { type EvolustrError, type Result, error, flatMap, ok } from "../result.ts";
import { VAULT_KIND, appVaultDTag } from "../tags.ts";
import { type Vault, type VaultContext, checkDataSecret, nip44Wrap, parseVault, serializeVault } from "../vault.ts";
import type { NostrEvent, Signer, UnsignedEvent } from "./types.ts";
import type { Bytes } from "../bytes.ts";

/** The unsigned kind-30078 event for an app vault (SPEC §6.1). */
export const vaultEvent = (ctx: VaultContext, vault: Vault, now: number): UnsignedEvent => ({
  kind: VAULT_KIND,
  created_at: now,
  tags: [["d", appVaultDTag(ctx.pubkey, ctx.appId)]],
  content: serializeVault(vault),
});

/** Parses a fetched vault event, checking author and `d`-tag. */
export const readVaultEvent = (ctx: VaultContext, event: NostrEvent): Result<Vault, EvolustrError> => {
  const d = appVaultDTag(ctx.pubkey, ctx.appId);
  if (event.pubkey !== ctx.pubkey || event.kind !== VAULT_KIND || !event.tags.some((t) => t[0] === "d" && t[1] === d)) {
    return error("invalidVault", "The event isn't this user's vault for this app");
  }
  return parseVault(event.content);
};

/** NIP-44 self-encryption of S (the `nip44` data wrap). */
export const nip44SealSecret = (signer: Signer, pubkey: string, s: Bytes): Promise<string> =>
  signer.nip44Encrypt(pubkey, toBase64Url(s));

/** Opens the `nip44` data wrap through the signer and checks it against `sHash`. */
export const nip44OpenSecret = async (
  signer: Signer,
  pubkey: string,
  vault: Vault,
): Promise<Result<Bytes, EvolustrError>> => {
  const wrap = nip44Wrap(vault);
  if (wrap === undefined) return error("noNip44Wrap", "This vault has no nip44 wrap");
  let plaintext: string;
  try {
    plaintext = await signer.nip44Decrypt(pubkey, wrap.ct);
  } catch (e) {
    return error("signerRefused", e instanceof Error ? e.message : String(e));
  }
  const s = fromBase64Url(plaintext);
  return s === null ? error("invalidVault", "The nip44 wrap doesn't hold a data secret") : flatMap(ok(s), (x) => checkDataSecret(vault, x));
};


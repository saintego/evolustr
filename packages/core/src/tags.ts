import { sha256Hex } from "./crypto.ts";

/** Kind for all Evolustr events (NIP-78 application data). */
export const VAULT_KIND = 30078;

/** Prefix that lets signers recognise Evolustr events (SPEC §5.5 rule 2). */
export const PROTECTED_DTAG_PREFIX = "evolustr:";

/** `d`-tag of an app vault; includes the pubkey so tags differ per user (SPEC §6.1). */
export const appVaultDTag = (pubkey: string, appId: string): string =>
  `evolustr:v1:${sha256Hex(`evolustr/v1/vault|${pubkey}|${appId}`)}`;

/** `d`-tag of a signer's own vault, found before M is known (SPEC §5.3). */
export const signerVaultDTag = (pubkey: string, signerKey: string): string =>
  `evolustr:v1:signer:${sha256Hex(`evolustr/v1/signer-vault|${pubkey}|${signerKey}`)}`;

/** `d`-tag of the shared settings event (SPEC §9.1). */
export const SETTINGS_DTAG = "evolustr:settings:v1";

export const isProtectedDTag = (d: string): boolean => d.startsWith(PROTECTED_DTAG_PREFIX);

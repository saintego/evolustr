import { type Bytes, toHex, utf8 } from "./bytes.ts";
import { hkdf, sha256 } from "./crypto.ts";

/** Root key R and data secret S are 16 bytes (12 BIP-39 words). Signer master M is 32 bytes. */
export const ROOT_KEY_LENGTH = 16;
export const DATA_SECRET_LENGTH = 16;
export const MASTER_SECRET_LENGTH = 32;

const short = (bytes: Bytes): string => toHex(bytes.slice(0, 8));

/** First 8 bytes of SHA-256(S), hex (SPEC §6.1). */
export const sHash = (s: Bytes): string => short(sha256(s));

/** Key for the `root` data wrap: HKDF(R, "evolustr/v1/data|" + appId) (SPEC §3.1). */
export const rootDataKey = (r: Bytes, appId: string): Bytes =>
  hkdf(r, `evolustr/v1/data|${appId}`);

/** Key for root-wrap tags (SPEC §3.1, #37): only holders of R can make a valid tag. */
export const wrapAuthKey = (r: Bytes, appId: string): Bytes => hkdf(r, `evolustr/v1/wrap-auth|${appId}`);

/** PRF input shared by all client passkeys of one vault (SPEC §4.1). */
export const clientPrfInput = (pubkey: string, appId: string): Bytes =>
  sha256(utf8(`evolustr/v1/prf|${pubkey}|${appId}`));

/** Wrap key from a client passkey's PRF output (SPEC §4.1). */
export const passkeyWrapKey = (prfOutput: Bytes, appId: string): Bytes =>
  hkdf(prfOutput, `evolustr/v1/wrap|${appId}`);

/** PRF input for a signer passkey (SPEC §5.3). */
export const signerPrfInput = (pubkey: string): Bytes =>
  sha256(utf8(`evolustr/v1/signer-prf|${pubkey}`));

/** Wrap key for M from a signer passkey's PRF output. */
export const signerPasskeyWrapKey = (prfOutput: Bytes): Bytes =>
  hkdf(prfOutput, "evolustr/v1/signer-passkey-wrap");

/** Wrap key for M from the nsec (`sk` wrap, SPEC §5.3). */
export const signerSkWrapKey = (secretKey: Bytes): Bytes =>
  hkdf(secretKey, "evolustr/v1/signer-wrap");

/** HMAC key for signer-vault wrap tags (#54): only a holder of M can tag a wrap. */
export const signerWrapAuthKey = (m: Bytes): Bytes => hkdf(m, "evolustr/v1/signer-wrap-auth");

/** Per-app key a capable signer gives the caller (SPEC §5.3). */
export const signerAppKey = (m: Bytes, appId: string): Bytes =>
  hkdf(m, `evolustr/v1|app|${appId}`);

/**
 * Label of a signer's wrap inside one app's vault (SPEC §5.3). Derived per app,
 * so apps can't use it to link the same user across apps (#29).
 */
export const signerId = (m: Bytes, appId: string): string =>
  toHex(hkdf(m, `evolustr/v1/signer-id|${appId}`, 8));

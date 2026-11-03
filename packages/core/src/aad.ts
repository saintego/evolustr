/** Wrap types inside app vaults (SPEC §3.1). */
export type AppWrapType = "signer" | "passkey" | "root";

/** AAD for app-vault wraps: binds the wrap to user, app, type and its key id. */
export const appWrapAad = (
  pubkey: string,
  appId: string,
  wrapType: AppWrapType,
  keyId: string,
): string => `evolustr/v1|${pubkey}|${appId}|${wrapType}|${keyId}`;

/** Wrap types inside a signer's own vault (SPEC §5.3). */
export type SignerWrapType = "sk" | "passkey";

/** AAD for signer-vault wraps; `keyId` is the credId, or "sk". */
export const signerWrapAad = (
  pubkey: string,
  signerKey: string,
  wrapType: SignerWrapType,
  keyId: string,
): string => `evolustr/v1|signer|${pubkey}|${signerKey}|${wrapType}|${keyId}`;

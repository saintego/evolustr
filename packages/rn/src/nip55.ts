/**
 * NIP-55 Android signers (e.g. Amber). React Native has no standard NIP-55
 * module, so the app passes a small bridge over its native module (intents or
 * the content provider). Android tells the signer which app is calling, so a
 * capable NIP-55 signer can give strong per-app keys (SPEC §5.2).
 */
import { type NostrEvent, type Signer, fromBase64Url } from "@evolustr/core";
import type { CapableSigner, SignerCapabilities } from "@evolustr/client";

/** What the app's native module must provide; one call per NIP-55 request type. */
export interface Nip55Bridge {
  readonly getPublicKey: () => Promise<string>;
  /** `sign_event`: takes the unsigned event JSON, returns the signed event JSON. */
  readonly signEvent: (eventJson: string) => Promise<string>;
  readonly nip44Encrypt: (plaintext: string, pubkey: string) => Promise<string>;
  readonly nip44Decrypt: (ciphertext: string, pubkey: string) => Promise<string>;
  /** Any other request type, for `evolustr_*` methods of a capable signer. */
  readonly request?: (type: string, params: ReadonlyArray<string>) => Promise<string>;
}

export const nip55Signer = (bridge: Nip55Bridge): Signer => ({
  getPublicKey: () => bridge.getPublicKey(),
  signEvent: async (event) => JSON.parse(await bridge.signEvent(JSON.stringify(event))) as NostrEvent,
  nip44Encrypt: (peer, plaintext) => bridge.nip44Encrypt(plaintext, peer),
  nip44Decrypt: (peer, ciphertext) => bridge.nip44Decrypt(ciphertext, peer),
});

/** A capable NIP-55 signer, if the bridge supports custom requests and the signer answers. */
export const nip55CapableSigner = async (bridge: Nip55Bridge): Promise<CapableSigner | undefined> => {
  const request = bridge.request;
  if (request === undefined) return undefined;
  const capabilities = async () => JSON.parse(await request("evolustr_capabilities", [])) as SignerCapabilities;
  try {
    await capabilities();
  } catch {
    return undefined; // a standard signer: compatible mode and client passkeys still work
  }
  return {
    capabilities,
    getWrapKey: async () => {
      const key = fromBase64Url(await request("evolustr_get_wrap_key", []));
      if (key === null || key.length !== 32) throw new Error("The signer returned an invalid key");
      return key;
    },
    getPreviousWrapKey: async () => {
      const key = fromBase64Url(await request("evolustr_get_previous_wrap_key", []));
      if (key === null || key.length !== 32) throw new Error("The signer returned an invalid key");
      return key;
    },
    enrollPasskey: async () => void (await request("evolustr_enroll_passkey", [])),
  };
};

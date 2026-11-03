import * as nip44 from "nostr-tools/nip44";
import { finalizeEvent, getPublicKey } from "nostr-tools/pure";
import type { NostrEvent, Signer, UnsignedEvent } from "./types.ts";

/** The NIP-07 `window.nostr` shape (with NIP-44). */
export interface Nip07 {
  readonly getPublicKey: () => Promise<string>;
  readonly signEvent: (event: UnsignedEvent) => Promise<NostrEvent>;
  readonly nip44?: {
    readonly encrypt: (pubkey: string, plaintext: string) => Promise<string>;
    readonly decrypt: (pubkey: string, ciphertext: string) => Promise<string>;
  };
}

/** Wraps a NIP-07 provider; fails clearly when it has no NIP-44. */
export const nip07Signer = (nostr: Nip07): Signer => ({
  getPublicKey: () => nostr.getPublicKey(),
  signEvent: (event) => nostr.signEvent({ ...event, tags: event.tags.map((t) => [...t]) }),
  nip44Encrypt: (peer, plaintext) => {
    if (nostr.nip44 === undefined) return Promise.reject(new Error("The signer doesn't support NIP-44"));
    return nostr.nip44.encrypt(peer, plaintext);
  },
  nip44Decrypt: (peer, ciphertext) => {
    if (nostr.nip44 === undefined) return Promise.reject(new Error("The signer doesn't support NIP-44"));
    return nostr.nip44.decrypt(peer, ciphertext);
  },
});

/** A signer holding the secret key in memory (tests, and signers that hold the nsec). */
export const secretKeySigner = (secretKey: Uint8Array): Signer => {
  const pubkey = getPublicKey(secretKey);
  return {
    getPublicKey: () => Promise.resolve(pubkey),
    signEvent: (event) =>
      Promise.resolve(
        finalizeEvent(
          { kind: event.kind, created_at: event.created_at, content: event.content, tags: event.tags.map((t) => [...t]) },
          secretKey,
        ) as NostrEvent,
      ),
    nip44Encrypt: (peer, plaintext) =>
      Promise.resolve(nip44.v2.encrypt(plaintext, nip44.v2.utils.getConversationKey(secretKey, peer))),
    nip44Decrypt: (peer, ciphertext) =>
      Promise.resolve(nip44.v2.decrypt(ciphertext, nip44.v2.utils.getConversationKey(secretKey, peer))),
  };
};

/**
 * Client passkeys behind an interface (SPEC §4). `webauthnPasskeys` uses the
 * browser; `memoryPasskeys` simulates an authenticator for tests.
 */
import { hmac } from "@noble/hashes/hmac.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { type Bytes, fromBase64Url, randomBytes, toBase64Url } from "./bytes.ts";

export interface PasskeyResult {
  readonly credId: string;
  /** PRF output, or null when the authenticator didn't return one. */
  readonly prfOutput: Bytes | null;
  /** WebAuthn backup-state flag (BS): the passkey is synced (SPEC §3.2 rule 3a). */
  readonly synced: boolean;
}

export interface CreatedPasskey extends PasskeyResult {
  /** PRF is supported, even if no output came with `create()` (SPEC §4.2 step 4). */
  readonly prfEnabled: boolean;
}

export interface Passkeys {
  readonly rpId: string;
  readonly supported: () => Promise<boolean>;
  readonly create: (args: {
    readonly userId: Bytes;
    readonly userName: string;
    readonly excludeCredIds: ReadonlyArray<string>;
    readonly prfInput: Bytes;
  }) => Promise<CreatedPasskey>;
  readonly get: (args: {
    readonly allowCredIds: ReadonlyArray<string>;
    readonly prfInput: Bytes;
  }) => Promise<PasskeyResult>;
}

/** A copy backed by a plain ArrayBuffer, as the WebAuthn types require. */
const buf = (b: Bytes): Uint8Array<ArrayBuffer> => new Uint8Array(b);

/** Flags byte of authenticator data: BS = 0x10 (SPEC §3.2 rule 3a). */
const isSynced = (authData: ArrayBuffer): boolean => ((new Uint8Array(authData)[32] ?? 0) & 0x10) !== 0;

const asBytes = (b: ArrayBuffer | Uint8Array | undefined): Bytes | null =>
  b === undefined ? null : new Uint8Array(b instanceof Uint8Array ? b : new Uint8Array(b));

interface PrfResults {
  readonly prf?: { readonly enabled?: boolean; readonly results?: { readonly first?: ArrayBuffer } };
}

/** WebAuthn in the browser. Call `create` and `get` only from a user gesture. */
export const webauthnPasskeys = (opts: { readonly rpId?: string; readonly rpName: string }): Passkeys => {
  const rpId = opts.rpId ?? globalThis.location.hostname;
  return {
    rpId,
    supported: async () => {
      if (typeof PublicKeyCredential === "undefined") return false;
      const caps = (PublicKeyCredential as unknown as { getClientCapabilities?: () => Promise<Record<string, boolean>> })
        .getClientCapabilities;
      if (caps === undefined) return true; // unknown: try, and report PRF at setup
      return (await caps())["extension:prf"] !== false;
    },
    create: async ({ userId, userName, excludeCredIds, prfInput }) => {
      const cred = (await navigator.credentials.create({
        publicKey: {
          challenge: buf(randomBytes(32)),
          rp: { id: rpId, name: opts.rpName },
          user: { id: buf(userId), name: userName, displayName: userName },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 },
          ],
          authenticatorSelection: { residentKey: "required", userVerification: "required" },
          excludeCredentials: excludeCredIds.flatMap((id) => {
            const raw = fromBase64Url(id);
            return raw === null ? [] : [{ type: "public-key" as const, id: buf(raw) }];
          }),
          extensions: { prf: { eval: { first: buf(prfInput) } } } as AuthenticationExtensionsClientInputs,
        },
      })) as PublicKeyCredential | null;
      if (cred === null) throw new Error("Passkey creation was cancelled");
      const ext = cred.getClientExtensionResults() as PrfResults;
      const response = cred.response as AuthenticatorAttestationResponse;
      return {
        credId: toBase64Url(new Uint8Array(cred.rawId)),
        prfEnabled: ext.prf?.enabled === true || ext.prf?.results?.first !== undefined,
        prfOutput: asBytes(ext.prf?.results?.first),
        synced: typeof response.getAuthenticatorData === "function" ? isSynced(response.getAuthenticatorData()) : false,
      };
    },
    get: async ({ allowCredIds, prfInput }) => {
      const cred = (await navigator.credentials.get({
        publicKey: {
          challenge: buf(randomBytes(32)),
          rpId,
          userVerification: "required",
          allowCredentials: allowCredIds.flatMap((id) => {
            const raw = fromBase64Url(id);
            return raw === null ? [] : [{ type: "public-key" as const, id: buf(raw) }];
          }),
          extensions: { prf: { eval: { first: buf(prfInput) } } } as AuthenticationExtensionsClientInputs,
        },
      })) as PublicKeyCredential | null;
      if (cred === null) throw new Error("Passkey use was cancelled");
      const ext = cred.getClientExtensionResults() as PrfResults;
      return {
        credId: toBase64Url(new Uint8Array(cred.rawId)),
        prfOutput: asBytes(ext.prf?.results?.first),
        synced: isSynced((cred.response as AuthenticatorAssertionResponse).authenticatorData),
      };
    },
  };
};

/**
 * A simulated authenticator for tests. Credentials live in `store`; pass the
 * same store to two devices to simulate a synced passkey provider.
 */
export const memoryPasskeys = (opts: {
  readonly rpId: string;
  readonly store?: Map<string, Bytes>;
  readonly synced?: boolean;
  readonly prfAtCreate?: boolean;
  readonly prf?: boolean;
  /** The credential the "user" picks in `get`; defaults to the first allowed one present. */
  readonly pick?: (allowed: ReadonlyArray<string>) => string | undefined;
}): Passkeys & { readonly store: Map<string, Bytes> } => {
  const store = opts.store ?? new Map<string, Bytes>();
  const prf = (credId: string, input: Bytes): Bytes => hmac(sha256, store.get(credId)!, input);
  return {
    rpId: opts.rpId,
    store,
    supported: async () => opts.prf !== false,
    create: async ({ excludeCredIds, prfInput }) => {
      if (excludeCredIds.some((id) => store.has(id))) throw new Error("InvalidStateError: already registered here");
      const credId = toBase64Url(randomBytes(16));
      store.set(credId, randomBytes(32));
      const enabled = opts.prf !== false;
      return {
        credId,
        prfEnabled: enabled,
        prfOutput: enabled && opts.prfAtCreate !== false ? prf(credId, prfInput) : null,
        synced: opts.synced ?? true,
      };
    },
    get: async ({ allowCredIds, prfInput }) => {
      const credId = opts.pick?.(allowCredIds) ?? allowCredIds.find((id) => store.has(id));
      if (credId === undefined || !store.has(credId)) throw new Error("NotAllowedError: no matching passkey");
      return { credId, prfOutput: opts.prf === false ? null : prf(credId, prfInput), synced: opts.synced ?? true };
    },
  };
};

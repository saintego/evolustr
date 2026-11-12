/**
 * Native passkeys through `react-native-passkey` (SPEC §4). Pass the module's
 * `Passkey` class; the app needs an associated domain for `rpId`
 * (apple-app-site-association on iOS, assetlinks.json on Android).
 */
import { type Bytes, type Passkeys, fromBase64Url, randomBytes, toBase64Url } from "@evolustr/core";

type Binary = Uint8Array | ArrayBuffer | number[] | string;

interface PrfOut {
  readonly enabled?: boolean;
  readonly results?: { readonly first: Binary };
}

/** The subset of react-native-passkey's `Passkey` class used here. */
export interface NativePasskeyModule {
  readonly isSupported: () => boolean;
  readonly create: (request: {
    challenge: string;
    rp: { id: string; name: string };
    user: { id: string; name: string; displayName: string };
    pubKeyCredParams: Array<{ type: "public-key"; alg: number }>;
    excludeCredentials?: Array<{ type: "public-key"; id: string }>;
    authenticatorSelection?: { residentKey?: "required"; userVerification?: "required" };
    extensions?: { prf?: { eval?: { first: Binary } } };
  }) => Promise<{
    rawId: string;
    response: { authenticatorData?: string };
    clientExtensionResults?: { prf?: PrfOut };
  }>;
  readonly get: (request: {
    challenge: string;
    rpId: string;
    allowCredentials?: Array<{ type: "public-key"; id: string }>;
    userVerification?: "required";
    extensions?: { prf?: { eval?: { first: Binary } } };
  }) => Promise<{
    id: string;
    rawId?: string;
    response: { authenticatorData: string };
    clientExtensionResults?: { prf?: PrfOut };
  }>;
}

/** PRF output in any of the shapes the native module may return. */
export const toBytes = (b: Binary | undefined): Bytes | null => {
  if (b === undefined) return null;
  if (typeof b === "string") return fromBase64Url(b.replace(/=+$/, ""));
  if (Array.isArray(b)) return Uint8Array.from(b);
  return b instanceof Uint8Array ? b : new Uint8Array(b);
};

/** Backup-state flag (BS, 0x10) from base64url authenticator data. */
export const syncedFromAuthData = (authData: string | undefined): boolean => {
  const bytes = authData === undefined ? null : fromBase64Url(authData.replace(/=+$/, ""));
  return bytes !== null && ((bytes[32] ?? 0) & 0x10) !== 0;
};

export const nativePasskeys = (Passkey: NativePasskeyModule, opts: { readonly rpId: string; readonly rpName: string }): Passkeys => ({
  rpId: opts.rpId,
  supported: async () => Passkey.isSupported(),
  create: async ({ userId, userName, excludeCredIds, prfInput }) => {
    const r = await Passkey.create({
      challenge: toBase64Url(randomBytes(32)),
      rp: { id: opts.rpId, name: opts.rpName },
      user: { id: toBase64Url(userId), name: userName, displayName: userName },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      excludeCredentials: excludeCredIds.map((id) => ({ type: "public-key" as const, id })),
      authenticatorSelection: { residentKey: "required", userVerification: "required" },
      extensions: { prf: { eval: { first: toBase64Url(prfInput) } } },
    });
    const prf = r.clientExtensionResults?.prf;
    const output = toBytes(prf?.results?.first);
    return {
      credId: r.rawId.replace(/=+$/, ""),
      prfEnabled: prf?.enabled === true || output !== null,
      prfOutput: output,
      synced: syncedFromAuthData(r.response.authenticatorData),
    };
  },
  get: async ({ allowCredIds, prfInput }) => {
    const r = await Passkey.get({
      challenge: toBase64Url(randomBytes(32)),
      rpId: opts.rpId,
      allowCredentials: allowCredIds.map((id) => ({ type: "public-key" as const, id })),
      userVerification: "required",
      extensions: { prf: { eval: { first: toBase64Url(prfInput) } } },
    });
    return {
      credId: (r.rawId ?? r.id).replace(/=+$/, ""),
      prfOutput: toBytes(r.clientExtensionResults?.prf?.results?.first),
      synced: syncedFromAuthData(r.response.authenticatorData),
    };
  },
});

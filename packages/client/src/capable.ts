/**
 * Talking to an Evolustr-capable signer from the app (SPEC §5.1, §5.4).
 */
import { type Bytes, fromBase64Url, randomBytes, toHex } from "@evolustr/core";

export interface SignerCapabilities {
  readonly identity: "verified" | "connection";
  readonly appId: string;
  readonly signerId: string | null;
  readonly ready: boolean;
  readonly signerPasskey: boolean;
  /** M can be recovered on another device (#42). Older signers don't send it: counts as false. */
  readonly recoverable?: boolean;
}

export interface CapableSigner {
  readonly capabilities: () => Promise<SignerCapabilities>;
  /** May wait for the user to click inside the signer; don't use short timeouts. */
  readonly getWrapKey: () => Promise<Bytes>;
  readonly enrollPasskey?: () => Promise<void>;
}

const toKey = (v: unknown): Bytes => {
  if (v instanceof Uint8Array) return v;
  if (typeof v === "string") {
    const b = fromBase64Url(v);
    if (b !== null && b.length === 32) return b;
  }
  throw new Error("The signer returned an invalid key");
};

/** The NIP-07 namespace `window.nostr.evolustr`, if present. */
export interface Nip07Evolustr {
  readonly capabilities: () => Promise<SignerCapabilities>;
  readonly getWrapKey: () => Promise<string | Uint8Array>;
  readonly enrollPasskey?: () => Promise<void>;
}

export const nip07CapableSigner = (ns: Nip07Evolustr): CapableSigner => ({
  capabilities: () => ns.capabilities(),
  getWrapKey: async () => toKey(await ns.getWrapKey()),
  ...(ns.enrollPasskey === undefined ? {} : { enrollPasskey: () => ns.enrollPasskey!() }),
});

/** Detects `window.nostr.evolustr`; undefined for standard signers. */
export const detectCapableSigner = (nostr: unknown): CapableSigner | undefined => {
  const ns = (nostr as { evolustr?: Partial<Nip07Evolustr> } | undefined)?.evolustr;
  return typeof ns?.capabilities === "function" && typeof ns.getWrapKey === "function"
    ? nip07CapableSigner(ns as Nip07Evolustr)
    : undefined;
};

/**
 * Forwards calls to an iframe signer with postMessage. Used by bridge scripts
 * to implement `window.nostr.evolustr` (see {@link exposeOnWindowNostr}).
 */
export const iframeCapableSigner = (args: {
  readonly target: { postMessage: (message: unknown, targetOrigin: string) => void };
  readonly signerOrigin: string;
  readonly self: Pick<Window, "addEventListener" | "removeEventListener">;
}): CapableSigner => {
  const call = (method: string, params: ReadonlyArray<unknown> = []): Promise<unknown> =>
    new Promise((resolve, reject) => {
      const id = toHex(randomBytes(8));
      const listener = (e: Event) => {
        const m = e as MessageEvent;
        const data = m.data as { type?: unknown; id?: unknown; result?: unknown; error?: { message?: string } };
        if (m.origin !== args.signerOrigin || data?.type !== "evolustr" || data.id !== id) return;
        args.self.removeEventListener("message", listener);
        if (data.error !== undefined) reject(new Error(data.error.message ?? "Signer error"));
        else resolve(data.result);
      };
      args.self.addEventListener("message", listener);
      args.target.postMessage({ type: "evolustr", id, method, params }, args.signerOrigin);
    });
  return {
    capabilities: async () => (await call("evolustr_capabilities")) as SignerCapabilities,
    getWrapKey: async () => toKey(await call("evolustr_get_wrap_key")),
    enrollPasskey: async () => void (await call("evolustr_enroll_passkey")),
  };
};

/** Adds `evolustr` to a `window.nostr` object, for bridge scripts of iframe signers. */
export const exposeOnWindowNostr = (nostr: Record<string, unknown>, signer: CapableSigner): void => {
  nostr["evolustr"] = {
    capabilities: () => signer.capabilities(),
    getWrapKey: async () => signer.getWrapKey(),
    ...(signer.enrollPasskey === undefined ? {} : { enrollPasskey: () => signer.enrollPasskey!() }),
  };
};

/** A NIP-46 client that can send custom requests (nostr-tools `BunkerSigner.sendRequest`). */
export interface Nip46RequestClient {
  readonly sendRequest: (method: string, params: string[]) => Promise<string>;
}

/**
 * An Evolustr-capable NIP-46 bunker (SPEC §5.1). The bunker identifies the app
 * only by its connection (SPEC §5.2). Check `capabilities()` first: a bunker
 * without the API returns an error, and the client falls back.
 */
export const nip46CapableSigner = (bunker: Nip46RequestClient): CapableSigner => ({
  capabilities: async () => JSON.parse(await bunker.sendRequest("evolustr_capabilities", [])) as SignerCapabilities,
  getWrapKey: async () => toKey(await bunker.sendRequest("evolustr_get_wrap_key", [])),
  enrollPasskey: async () => void (await bunker.sendRequest("evolustr_enroll_passkey", [])),
});

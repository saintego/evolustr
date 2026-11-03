/**
 * Device cache for the unlocked secrets of one (pubkey, appId) (SPEC §6.2 rule 6).
 * Evolu needs S on every start; R is optional.
 */
import { type Bytes, fromBase64Url, sha256Hex, toBase64Url } from "@evolustr/core";

export interface CachedSecrets {
  readonly s: Bytes;
  readonly r?: Bytes;
}

export interface SecretCache {
  readonly get: (pubkey: string, appId: string) => Promise<CachedSecrets | null>;
  readonly set: (pubkey: string, appId: string, secrets: CachedSecrets) => Promise<void>;
  readonly remove: (pubkey: string, appId: string) => Promise<void>;
}

const cacheKey = (pubkey: string, appId: string) => `evolustr:secrets:${sha256Hex(`${pubkey}|${appId}`)}`;

interface KeyValue {
  readonly getItem: (k: string) => string | null;
  readonly setItem: (k: string, v: string) => void;
  readonly removeItem: (k: string) => void;
}

const encode = (c: CachedSecrets) =>
  JSON.stringify({ s: toBase64Url(c.s), ...(c.r === undefined ? {} : { r: toBase64Url(c.r) }) });

const decode = (text: string | null): CachedSecrets | null => {
  if (text === null) return null;
  try {
    const data = JSON.parse(text) as { s?: unknown; r?: unknown };
    const s = typeof data.s === "string" ? fromBase64Url(data.s) : null;
    const r = typeof data.r === "string" ? fromBase64Url(data.r) : null;
    if (s === null) return null;
    return r === null ? { s } : { s, r };
  } catch {
    return null;
  }
};

/** A cache over any `localStorage`-like store. Failing storage acts as empty. */
export const keyValueCache = (store: KeyValue): SecretCache => ({
  get: async (pubkey, appId) => {
    try {
      return decode(store.getItem(cacheKey(pubkey, appId)));
    } catch {
      return null;
    }
  },
  set: async (pubkey, appId, secrets) => {
    try {
      store.setItem(cacheKey(pubkey, appId), encode(secrets));
    } catch {
      /* storage unavailable: the user unlocks again next time */
    }
  },
  remove: async (pubkey, appId) => {
    try {
      store.removeItem(cacheKey(pubkey, appId));
    } catch {
      /* ignore */
    }
  },
});

export const memoryCache = (): SecretCache => {
  const map = new Map<string, string>();
  return keyValueCache({
    getItem: (k) => map.get(k) ?? null,
    setItem: (k, v) => void map.set(k, v),
    removeItem: (k) => void map.delete(k),
  });
};

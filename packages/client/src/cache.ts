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

/** An async key-value store, e.g. `expo-secure-store` (getItemAsync / setItemAsync / deleteItemAsync). */
export interface AsyncKeyValue {
  readonly getItemAsync: (key: string) => Promise<string | null>;
  readonly setItemAsync: (key: string, value: string) => Promise<void>;
  readonly deleteItemAsync: (key: string) => Promise<void>;
}

/**
 * A cache over an async store. Keys use only letters, digits, "." "-" "_",
 * which secure stores such as `expo-secure-store` require.
 */
export const asyncKeyValueCache = (store: AsyncKeyValue): SecretCache => {
  const key = (pubkey: string, appId: string) => `evolustr_secrets_${sha256Hex(`${pubkey}|${appId}`)}`;
  return {
    get: async (pubkey, appId) => {
      try {
        return decode(await store.getItemAsync(key(pubkey, appId)));
      } catch {
        return null;
      }
    },
    set: async (pubkey, appId, secrets) => {
      try {
        await store.setItemAsync(key(pubkey, appId), encode(secrets));
      } catch {
        /* unavailable: unlock again next time */
      }
    },
    remove: async (pubkey, appId) => {
      try {
        await store.deleteItemAsync(key(pubkey, appId));
      } catch {
        /* ignore */
      }
    },
  };
};

/** Where an encrypted cache keeps its key: a non-extractable WebCrypto key. */
export interface CryptoKeyStore {
  readonly get: () => Promise<CryptoKey | null>;
  readonly set: (key: CryptoKey) => Promise<void>;
}

/** Keeps the key in IndexedDB, which can store a CryptoKey without exposing its bytes. */
export const indexedDbKeyStore = (dbName = "evolustr-keys"): CryptoKeyStore => {
  const open = () =>
    new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open(dbName, 1);
      req.onupgradeneeded = () => req.result.createObjectStore("keys");
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error("IndexedDB unavailable"));
    });
  const tx = async <T>(mode: IDBTransactionMode, f: (s: IDBObjectStore) => IDBRequest<T>) => {
    const db = await open();
    return new Promise<T>((resolve, reject) => {
      const req = f(db.transaction("keys", mode).objectStore("keys"));
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error("IndexedDB error"));
    }).finally(() => db.close());
  };
  return {
    get: async () => ((await tx("readonly", (s) => s.get("cache"))) as CryptoKey | undefined) ?? null,
    set: async (key) => void (await tx("readwrite", (s) => s.put(key, "cache"))),
  };
};

export const memoryKeyStore = (): CryptoKeyStore => {
  let key: CryptoKey | null = null;
  return { get: async () => key, set: async (k) => void (key = k) };
};

/**
 * A cache whose entries are encrypted with a non-extractable AES-GCM key (#27).
 * It doesn't stop script running on the app's origin (an XSS can still ask for
 * decryption), but plain reads of storage, backups or the browser profile only
 * get ciphertext. Failures act as an empty cache.
 */
export const encryptedCache = (
  store: KeyValue,
  keyStore: CryptoKeyStore,
  subtle: SubtleCrypto = globalThis.crypto.subtle,
): SecretCache => {
  let keyPromise: Promise<CryptoKey> | null = null;
  const key = (): Promise<CryptoKey> =>
    (keyPromise ??= (async () => {
      const existing = await keyStore.get();
      if (existing !== null) return existing;
      const fresh = await subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
      await keyStore.set(fresh);
      return fresh;
    })());
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  return {
    get: async (pubkey, appId) => {
      try {
        const raw = store.getItem(cacheKey(pubkey, appId));
        if (raw === null) return null;
        const { iv, ct } = JSON.parse(raw) as { iv: string; ct: string };
        const ivBytes = fromBase64Url(iv);
        const ctBytes = fromBase64Url(ct);
        if (ivBytes === null || ctBytes === null) return null;
        // The slot name is the AAD: an entry copied to another slot doesn't decrypt (#44).
        const plain = await subtle.decrypt(
          { name: "AES-GCM", iv: new Uint8Array(ivBytes), additionalData: enc.encode(cacheKey(pubkey, appId)) },
          await key(),
          new Uint8Array(ctBytes),
        );
        return decode(dec.decode(plain));
      } catch {
        return null;
      }
    },
    set: async (pubkey, appId, secrets) => {
      try {
        const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
        const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(cacheKey(pubkey, appId)) }, await key(), enc.encode(encode(secrets)));
        store.setItem(cacheKey(pubkey, appId), JSON.stringify({ iv: toBase64Url(iv), ct: toBase64Url(new Uint8Array(ct)) }));
      } catch {
        /* unavailable: unlock again next time */
      }
    },
    remove: async (pubkey, appId) => {
      try {
        store.removeItem(cacheKey(pubkey, appId));
      } catch {
        /* ignore */
      }
    },
  };
};

/** The recommended web cache: localStorage entries encrypted with a key kept in IndexedDB. */
export const webSecretCache = (): SecretCache => encryptedCache(globalThis.localStorage, indexedDbKeyStore());

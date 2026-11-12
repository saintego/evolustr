import { SimplePool } from "nostr-tools/pool";
import { matchFilter, type Filter as NtFilter } from "nostr-tools/filter";
import { isValidEvent } from "./verify.ts";
import type { Filter, NostrEvent, PublishResult, QueryResult, Relays } from "./types.ts";

const toNtFilter = (f: Filter): NtFilter => JSON.parse(JSON.stringify(f)) as NtFilter;

const withTimeout = <T>(p: Promise<T>, ms: number): Promise<T> =>
  new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timeout")), ms);
    p.then(
      (v) => (clearTimeout(t), resolve(v)),
      (e: unknown) => (clearTimeout(t), reject(e instanceof Error ? e : new Error(String(e)))),
    );
  });

/** Relays over nostr-tools, tracking EOSE per relay (SPEC §6.2 rule 1). */
export const poolRelays = (pool: SimplePool = new SimplePool()): Relays => ({
  query: async (urls, filter, timeoutMs) => {
    const events = new Map<string, NostrEvent>();
    const idsByRelay = new Map<string, Set<string>>();
    const one = async (url: string): Promise<boolean> => {
      const ids = new Set<string>();
      idsByRelay.set(url, ids);
      try {
        const relay = await withTimeout(pool.ensureRelay(url, { connectionTimeout: timeoutMs }), timeoutMs);
        return await new Promise<boolean>((resolve) => {
          // Settle once: closing the subscription fires onclose, which must not
          // turn an answered relay into a failed one.
          let settled = false;
          let timer: ReturnType<typeof setTimeout> | undefined;
          const settle = (answered: boolean) => {
            if (settled) return;
            settled = true;
            if (timer !== undefined) clearTimeout(timer);
            resolve(answered);
          };
          const sub = relay.subscribe([toNtFilter(filter)], {
            onevent: (e) => {
              if (isValidEvent(e as NostrEvent)) {
                events.set(e.id, e as NostrEvent);
                ids.add(e.id);
              }
            },
            oneose: () => {
              settle(true);
              sub.close();
            },
            onclose: () => settle(false),
          });
          timer = setTimeout(() => {
            settle(false);
            sub.close();
          }, timeoutMs);
        });
      } catch {
        return false;
      }
    };
    const results = await Promise.all(urls.map(async (url) => [url, await one(url)] as const));
    return {
      events: [...events.values()],
      answered: results.filter(([, ok]) => ok).map(([u]) => u),
      failed: results.filter(([, ok]) => !ok).map(([u]) => u),
      idsByRelay,
    };
  },
  publish: async (urls, event, timeoutMs) => {
    const results = await Promise.all(
      urls.map(async (url) => {
        try {
          const relay = await withTimeout(pool.ensureRelay(url, { connectionTimeout: timeoutMs }), timeoutMs);
          await withTimeout(relay.publish(event as Parameters<typeof relay.publish>[0]), timeoutMs);
          return [url, true] as const;
        } catch {
          return [url, false] as const;
        }
      }),
    );
    return {
      accepted: results.filter(([, ok]) => ok).map(([u]) => u),
      failed: results.filter(([, ok]) => !ok).map(([u]) => u),
    };
  },
});

/**
 * In-memory relays for tests. Each URL is a separate store; URLs in `down`
 * fail every request. Replaceable events (kind 30000–39999) keep only the newest.
 */
export const memoryRelays = (opts: { readonly down?: Set<string> } = {}) => {
  const stores = new Map<string, NostrEvent[]>();
  const store = (url: string): NostrEvent[] => {
    let s = stores.get(url);
    if (s === undefined) stores.set(url, (s = []));
    return s;
  };
  const dTag = (e: NostrEvent) => e.tags.find((t) => t[0] === "d")?.[1] ?? "";
  const put = (url: string, event: NostrEvent) => {
    const s = store(url);
    if (event.kind >= 30000 && event.kind < 40000) {
      const i = s.findIndex((e) => e.kind === event.kind && e.pubkey === event.pubkey && dTag(e) === dTag(event));
      if (i !== -1) {
        if (s[i]!.created_at > event.created_at) return;
        s.splice(i, 1);
      }
    }
    s.push(event);
  };
  const down = opts.down ?? new Set<string>();
  const relays: Relays = {
    query: (urls, filter) => {
      const answered = urls.filter((u) => !down.has(u));
      const per = new Map(answered.map((u) => [u, store(u).filter((e) => matchFilter(toNtFilter(filter), e as Parameters<typeof matchFilter>[1]))] as const));
      return Promise.resolve({
        events: [...per.values()].flat(),
        answered,
        failed: urls.filter((u) => down.has(u)),
        idsByRelay: new Map([...per].map(([u, es]) => [u, new Set(es.map((e) => e.id))])),
      });
    },
    publish: (urls, event) => {
      const accepted = urls.filter((u) => !down.has(u) && isValidEvent(event));
      for (const u of accepted) put(u, event);
      return Promise.resolve({ accepted, failed: urls.filter((u) => !accepted.includes(u)) });
    },
  };
  return { relays, down, put, store };
};

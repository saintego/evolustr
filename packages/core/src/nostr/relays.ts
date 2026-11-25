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
  query: async (urls, filter, timeoutMs, opts) => {
    const events = new Map<string, NostrEvent>();
    const idsByRelay = new Map<string, Set<string>>();
    /** "answered", "hard" (refused or closed: it won't answer), or "timeout". */
    const one = async (url: string): Promise<"answered" | "hard" | "timeout"> => {
      const ids = new Set<string>();
      idsByRelay.set(url, ids);
      try {
        const relay = await withTimeout(pool.ensureRelay(url, { connectionTimeout: timeoutMs }), timeoutMs);
        return await new Promise<"answered" | "hard" | "timeout">((resolve) => {
          // Settle once: closing the subscription fires onclose, which must not
          // turn an answered relay into a failed one.
          let settled = false;
          let timer: ReturnType<typeof setTimeout> | undefined;
          const settle = (outcome: "answered" | "hard" | "timeout") => {
            if (settled) return;
            settled = true;
            if (timer !== undefined) clearTimeout(timer);
            resolve(outcome);
          };
          const sub = relay.subscribe([toNtFilter(filter)], {
            onevent: (e) => {
              if (isValidEvent(e as NostrEvent)) {
                events.set(e.id, e as NostrEvent);
                ids.add(e.id);
              }
            },
            oneose: () => {
              settle("answered");
              sub.close();
            },
            onclose: () => settle("hard"),
          });
          timer = setTimeout(() => {
            settle("timeout");
            sub.close();
          }, timeoutMs);
        });
      } catch (e) {
        // Our own timeout may still have an answer later; a refused connection won't.
        return e instanceof Error && /time(d)?\s?out/i.test(e.message) ? "timeout" : "hard";
      }
    };
    // With a quorum, return as soon as that many relays answered; the rest count
    // as failed and pending, and `rest` resolves once every relay finished (#62).
    const quorum = Math.min(opts?.quorum ?? urls.length, urls.length);
    const answered: string[] = [];
    const hard = new Set<string>();
    const snapshot = (): QueryResult => {
      const done = new Set(answered);
      const failed = urls.filter((u) => !done.has(u));
      return {
        // Events from a relay still waiting are kept: the newest version wins either way.
        events: [...events.values()],
        answered: [...answered],
        failed,
        pending: failed.filter((u) => !hard.has(u)),
        idsByRelay: new Map([...idsByRelay].filter(([u]) => done.has(u))),
      };
    };
    let early: ((r: QueryResult) => void) | undefined;
    const first = new Promise<QueryResult>((resolve) => (early = resolve));
    const all = new Promise<QueryResult>((resolve) => {
      let finished = 0;
      if (urls.length === 0) return resolve(snapshot());
      for (const url of urls) {
        void one(url).then((outcome) => {
          finished++;
          if (outcome === "answered") answered.push(url);
          if (outcome === "hard") hard.add(url);
          if (finished === urls.length) resolve(snapshot());
          else if (answered.length >= quorum) early?.(snapshot());
        });
      }
    });
    const result = await Promise.race([first.then((r) => ({ ...r, rest: all })), all]);
    return result;
  },
  publish: async (urls, event, timeoutMs) => {
    const results = await Promise.all(
      urls.map(async (url) => {
        try {
          const relay = await withTimeout(pool.ensureRelay(url, { connectionTimeout: timeoutMs }), timeoutMs);
          await withTimeout(relay.publish(event as Parameters<typeof relay.publish>[0]), timeoutMs);
          return [url, "ok"] as const;
        } catch (e) {
          // Ours ("timeout") or nostr-tools' own ("publish timed out", "connection timed out").
          return [url, /time(d)?\s?out/i.test(e instanceof Error ? e.message : String(e)) ? "timeout" : "error"] as const;
        }
      }),
    );
    return {
      accepted: results.filter(([, r]) => r === "ok").map(([u]) => u),
      failed: results.filter(([, r]) => r !== "ok").map(([u]) => u),
      timedOut: results.filter(([, r]) => r === "timeout").map(([u]) => u),
    };
  },
});

/**
 * In-memory relays for tests. Each URL is a separate store; URLs in `down`
 * fail every request as unreachable (they might still hold events), URLs in
 * `refused` refuse the connection (#62). Replaceable events (kind 30000–39999)
 * keep only the newest.
 */
export const memoryRelays = (opts: { readonly down?: Set<string>; readonly refused?: Set<string> } = {}) => {
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
  const refused = opts.refused ?? new Set<string>();
  const out = (u: string) => down.has(u) || refused.has(u);
  const relays: Relays = {
    query: (urls, filter) => {
      const answered = urls.filter((u) => !out(u));
      const per = new Map(answered.map((u) => [u, store(u).filter((e) => matchFilter(toNtFilter(filter), e as Parameters<typeof matchFilter>[1]))] as const));
      return Promise.resolve({
        events: [...per.values()].flat(),
        answered,
        failed: urls.filter(out),
        pending: urls.filter((u) => down.has(u)),
        idsByRelay: new Map([...per].map(([u, es]) => [u, new Set(es.map((e) => e.id))])),
      });
    },
    publish: (urls, event) => {
      const accepted = urls.filter((u) => !out(u) && isValidEvent(event));
      for (const u of accepted) put(u, event);
      return Promise.resolve({ accepted, failed: urls.filter((u) => !accepted.includes(u)) });
    },
  };
  return { relays, down, refused, put, store };
};

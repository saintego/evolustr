import { isValidEvent } from "./verify.ts";
import type { NostrEvent, QueryResult, Relays, Signer, UnsignedEvent } from "./types.ts";

export type FetchedEvent =
  | {
      readonly kind: "found";
      readonly event: NostrEvent;
      readonly complete: boolean;
      /** Relays that answered without this newest version; send it to them (#32). */
      readonly missingOn: ReadonlyArray<string>;
    }
  /**
   * No relay has the event, and every relay answered or failed hard (refused
   * the connection): none may still hold it (#62). A quorum never decides this.
   */
  | { readonly kind: "none" }
  /** No event found, but not enough relays answered: don't treat it as missing. */
  | { readonly kind: "incomplete" };

export interface Address {
  readonly author: string;
  readonly kind: number;
  readonly d: string;
}

const matches = (e: NostrEvent, a: Address): boolean =>
  e.pubkey === a.author &&
  e.kind === a.kind &&
  e.tags.some((t) => t[0] === "d" && t[1] === a.d) &&
  isValidEvent(e);

/** Newest wins; on equal `created_at`, the lowest id (NIP-01). */
export const newest = (events: ReadonlyArray<NostrEvent>): NostrEvent | undefined =>
  [...events].sort((x, y) => y.created_at - x.created_at || (x.id < y.id ? -1 : 1))[0];

/**
 * Fetches the newest replaceable event at an address. Waits for every relay,
 * or with `quorum` until that many answered (#60), which is for reads that
 * only unlock: "found" may come from the quorum, "none" never does (#62). With
 * nothing found at the quorum, it waits for the other relays.
 *
 * Before publishing a new version, read without `quorum`: a version found at
 * the quorum may be stale, and a write based on it would replace a newer one.
 */
export const fetchReplaceable = async (
  relays: Relays,
  urls: ReadonlyArray<string>,
  address: Address,
  timeoutMs = 5000,
  quorum?: number,
): Promise<FetchedEvent> => {
  const first = await relays.query(
    urls,
    { kinds: [address.kind], authors: [address.author], "#d": [address.d] },
    timeoutMs,
    quorum === undefined ? undefined : { quorum },
  );
  const found = (r: QueryResult) => newest(r.events.filter((e) => matches(e, address)));
  // Nothing at the quorum: the fastest relays may be the ones that lack it, so wait for the others.
  const result = found(first) === undefined && first.rest !== undefined ? await first.rest : first;
  const event = found(result);
  if (event !== undefined) {
    const complete = result.failed.length === 0 || (quorum !== undefined && result.answered.length >= Math.min(quorum, urls.length));
    const missingOn = result.idsByRelay === undefined ? [] : result.answered.filter((u) => !result.idsByRelay!.get(u)?.has(event.id));
    return { kind: "found", event, complete, missingOn };
  }
  // "None" only when no relay may still have it: answered, or failed hard.
  const pending = result.pending ?? result.failed;
  return pending.length === 0 && result.answered.length > 0 ? { kind: "none" } : { kind: "incomplete" };
};

/**
 * Signs and publishes a replaceable event; succeeds if at least one relay
 * accepts it. Relays that refused get one more try with the same signed event;
 * `failed` lists those that still refused.
 */
export const publishReplaceable = async (
  relays: Relays,
  urls: ReadonlyArray<string>,
  signer: Signer,
  event: UnsignedEvent,
  timeoutMs = 5000,
): Promise<{ readonly event: NostrEvent; readonly accepted: ReadonlyArray<string>; readonly failed: ReadonlyArray<string> }> => {
  const signed = await signer.signEvent(event);
  const first = await relays.publish(urls, signed, timeoutMs);
  // Retry relays that refused quickly; one that timed out would just time out again.
  const timedOut = new Set(first.timedOut ?? []);
  const toRetry = first.failed.filter((u) => !timedOut.has(u));
  const retry = toRetry.length === 0 ? { accepted: [], failed: [] } : await relays.publish(toRetry, signed, timeoutMs);
  const accepted = [...first.accepted, ...retry.accepted];
  if (accepted.length === 0) throw new Error("No relay accepted the event");
  return { event: signed, accepted, failed: [...first.failed.filter((u) => timedOut.has(u)), ...retry.failed] };
};

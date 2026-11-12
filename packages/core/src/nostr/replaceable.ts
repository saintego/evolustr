import { isValidEvent } from "./verify.ts";
import type { NostrEvent, Relays, Signer, UnsignedEvent } from "./types.ts";

export type FetchedEvent =
  | {
      readonly kind: "found";
      readonly event: NostrEvent;
      readonly complete: boolean;
      /** Relays that answered without this newest version; send it to them (#32). */
      readonly missingOn: ReadonlyArray<string>;
    }
  /** Every relay answered and none has the event. */
  | { readonly kind: "none" }
  /** No event found, but not every relay answered: don't treat it as missing. */
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

/** Fetches the newest replaceable event at an address from all relays. */
export const fetchReplaceable = async (
  relays: Relays,
  urls: ReadonlyArray<string>,
  address: Address,
  timeoutMs = 5000,
): Promise<FetchedEvent> => {
  const result = await relays.query(
    urls,
    { kinds: [address.kind], authors: [address.author], "#d": [address.d] },
    timeoutMs,
  );
  const event = newest(result.events.filter((e) => matches(e, address)));
  const complete = result.failed.length === 0;
  if (event !== undefined) {
    const missingOn = result.idsByRelay === undefined ? [] : result.answered.filter((u) => !result.idsByRelay!.get(u)?.has(event.id));
    return { kind: "found", event, complete, missingOn };
  }
  return complete ? { kind: "none" } : { kind: "incomplete" };
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
  const retry = first.failed.length === 0 ? { accepted: [], failed: [] } : await relays.publish(first.failed, signed, timeoutMs);
  const accepted = [...first.accepted, ...retry.accepted];
  if (accepted.length === 0) throw new Error("No relay accepted the event");
  return { event: signed, accepted, failed: retry.failed };
};

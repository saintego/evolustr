import { verifyEvent } from "nostr-tools/pure";
import type { NostrEvent } from "./types.ts";

/**
 * Checks id and signature on a clean copy. nostr-tools caches a successful
 * check on the event object itself, and a copied object would keep that flag.
 */
export const isValidEvent = (event: NostrEvent): boolean => {
  const clean = JSON.parse(JSON.stringify(event)) as Parameters<typeof verifyEvent>[0];
  return verifyEvent(clean);
};

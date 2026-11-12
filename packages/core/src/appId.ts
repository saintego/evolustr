import { decode } from "nostr-tools/nip19";
import { type EvolustrError, type Result, error, ok } from "./result.ts";

const isLocalhost = (host: string): boolean =>
  host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host.endsWith(".localhost");

/**
 * App identity from a page origin (SPEC §3.3). On a known nsite gateway,
 * `<npub>.<gateway>` maps to `nsite:<npub>` so every known gateway shares one vault.
 *
 * Only `https:` origins, and `http:` on localhost for development, are accepted:
 * a network attacker could otherwise serve a page on `http://app.example` and get
 * that app's keys (#30). Anything that isn't a valid origin is an error, never
 * passed through, because app ids end up in AADs and d-tags.
 */
export const appIdFromOrigin = (
  origin: string,
  knownNsiteGateways: ReadonlyArray<string> = [],
): Result<string, EvolustrError> => {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return error("invalidOrigin", "Not a valid origin");
  }
  const host = url.hostname.toLowerCase();
  if (url.protocol !== "https:" && !(url.protocol === "http:" && isLocalhost(host))) {
    return error("insecureOrigin", "Only https: origins (or http: on localhost) can have app data");
  }
  for (const gateway of knownNsiteGateways) {
    const g = gateway.toLowerCase().replace(/^\.+/, "");
    if (!host.endsWith(`.${g}`)) continue;
    const label = host.slice(0, -(g.length + 1));
    if (label.includes(".") || !label.startsWith("npub1")) continue;
    if (isValidNpub(label)) return ok(`nsite:${label}`);
  }
  return ok(url.origin);
};

const isValidNpub = (value: string): boolean => {
  try {
    return decode(value).type === "npub";
  } catch {
    return false;
  }
};

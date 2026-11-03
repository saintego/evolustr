import { decode } from "nostr-tools/nip19";

/**
 * App identity from a page origin (SPEC §3.3). On a known nsite gateway,
 * `<npub>.<gateway>` maps to `nsite:<npub>` so every known gateway shares one vault.
 */
export const appIdFromOrigin = (
  origin: string,
  knownNsiteGateways: ReadonlyArray<string> = [],
): string => {
  let url: URL;
  try {
    url = new URL(origin);
  } catch {
    return origin;
  }
  const host = url.hostname.toLowerCase();
  for (const gateway of knownNsiteGateways) {
    const g = gateway.toLowerCase().replace(/^\.+/, "");
    if (!host.endsWith(`.${g}`)) continue;
    const label = host.slice(0, -(g.length + 1));
    if (label.includes(".") || !label.startsWith("npub1")) continue;
    if (isValidNpub(label)) return `nsite:${label}`;
  }
  return url.origin;
};

const isValidNpub = (value: string): boolean => {
  try {
    return decode(value).type === "npub";
  } catch {
    return false;
  }
};

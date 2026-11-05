/**
 * React Native adapters for Evolustr.
 *
 * Setup notes:
 * - Import `react-native-get-random-values` before anything else: the crypto
 *   libraries need `crypto.getRandomValues`.
 * - Use Evolu's React Native package for the database and pass its
 *   `createEvolu` to `evoluDatabases` from `@evolustr/client`, with
 *   `onDatabaseDeleted: () => {}`.
 * - `appId` is `nativeAppId("android", packageName)` or `nativeAppId("ios", bundleId)`.
 */
export * from "./passkeys.ts";
export * from "./nip55.ts";
export { asyncKeyValueCache as secureStoreCache } from "@evolustr/client";
export { nip46Signer } from "@evolustr/core";
export { nip46CapableSigner } from "@evolustr/client";

/** App identity for native apps (SPEC §3.3). Android's is verified by NIP-55 signers; iOS's is self-asserted. */
export const nativeAppId = (platform: "android" | "ios", id: string): string => `${platform}:${id}`;

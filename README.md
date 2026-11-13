# Evolustr

Log in with Nostr, and your app's private data is on every device you use.

> [!WARNING]
> **EARLY ALPHA: DON'T USE IT FOR DATA YOU CAN'T AFFORD TO LOSE**
> Evolustr has not had a security audit. Its vault format and APIs may still change without a migration path. It has been tested mainly with simulated signers, relays and passkeys; testing on real devices and public relays has only started (see the open issues).
>
> - Keep your own backup of anything important, and save your recovery phrase.
> - Don't use it to protect high-value secrets (keys to funds, bank credentials).
> - Security reviews, test reports and pull requests are very welcome.
>
> The design is in [SPEC.md](SPEC.md).

## In plain words

- **Nostr** gives a user one identity (a key pair) that works across many apps. A *signer* (a browser extension like Alby, a phone app like Amber, or a remote "bunker") keeps the private key, and apps ask it to sign or encrypt things.
- **[Evolu](https://www.evolu.dev)** is a database that lives on the user's own devices. It works offline, and syncs between those devices through a relay that only ever sees encrypted data.
- **The gap:** an Evolu database is opened by a secret, which Evolu shows as 12 words. Without help, users would have to write those words down and type them on every new device.
- **Evolustr** stores that secret, encrypted, as a Nostr event. When the user logs in with Nostr on another device, Evolustr finds the event, has it decrypted, and opens the same database. There is no server of yours involved.

## How it works

For what each secret is, where it's stored and how it's locked, without assuming a cryptography background, read **[docs/how-it-works.md](docs/how-it-works.md)**.

1. The user logs in with their Nostr signer.
2. Evolustr looks for this app's *vault* event on Nostr relays. The vault holds the database secret, encrypted.
3. **First time anywhere:** Evolustr creates a new random secret, encrypts it, and publishes the vault.
4. **On another device:** Evolustr fetches the vault, the signer decrypts it (the user may see a prompt), and Evolu opens the database. Evolu then syncs the data from its relay.
5. The device remembers the secret, so the next start opens without prompts. "Log out" forgets it.

Each app gets its own database. Apps can also share a few harmless preferences, such as dark mode or language, through one shared settings event.

## Who can read the data?

The user chooses one of two levels for each app's database:

| Level | Who can read it | What the user needs on a new device |
|---|---|---|
| **Compatible** (default) | The user, and any app the user has allowed to *decrypt* with their signer. That's the same protection as Nostr direct messages. | Just their Nostr signer. |
| **Strict** | Only the user, for everything written **after** the switch. Other apps can't read it, even with signer permissions. | A passkey (synced by Apple, Google or a password manager), a signer that supports Evolustr, or the 12-word recovery phrase. |

**Strict protects against apps that only have signer *permissions*, not against anyone who has your nsec.** If the signer protects its Evolustr key with the nsec (the default for signers that hold it), anyone you ever gave your nsec to, for example by pasting it into another client, can open strict data too. For protection that doesn't depend on the nsec, use a passkey: on the app's domain, or as the signer's own passkey with its nsec protection turned off. Apps can show this with `status.dependsOnNsec`.

Switching to strict is one action (`makeStrict()`). It protects what the user writes from then on. **Data written before the switch stays as readable as it was:** an app that had decrypt permission could have kept the old secret, and Evolu's relay keeps the old copy (Evolu can't delete it yet). So choose strict before storing anything sensitive. With a synced passkey it needs no extra step. With a passkey that lives on one device only, the user first saves the recovery phrase or adds a second passkey, because losing that one device would otherwise lose the data.

## Why use it (for Nostr developers)

- **Private app data next to a public identity.** Settings, drafts, notes, bookmarks, app state: things that shouldn't be public events, available on every device the user logs in from.
- **A real database instead of encrypted events.** You could store everything in NIP-44-encrypted events (kind 30078). That works for a little data. Evolu gives you SQL queries, offline use, conflict-free merging when two devices edit at once, and efficient sync of many small changes.
- **No backend to run.** Vaults live on Nostr relays, data on Evolu's relay (theirs or one you host). It works on static hosting and nsites.
- **Any signer works.** Signers that implement the Evolustr Signer API, and passkeys, make strict mode smoother; see [docs/signer-integration.md](docs/signer-integration.md).

## What it doesn't do

- **It isn't a backup.** The data lives on the user's devices and on the Evolu relay. A relay can go away. Keep backups of anything important.
- **It doesn't hide which apps a user uses.** Vault events are public. Their names are hashed, which stops anyone from listing all users of an app at once, but not from checking one user against a list of known apps.
- **Compatible mode trusts every app the user lets decrypt.** If that isn't acceptable for your data, require strict mode (`requireStrong`).
- **Strict mode can lock users out.** If they lose every passkey, the signer that holds their key and the recovery phrase, the data is gone. Nobody can recover it, including you.
- **It isn't audited**, and the format may still change (see the warning above).

## Packages

| Package | What it is |
|---|---|
| [`@evolustr/client`](packages/client) | For apps: connect, unlock, passkeys, strict mode, recovery phrase, shared settings. |
| [`@evolustr/react`](packages/react) | `<EvolustrProvider>`, `useEvolustr()`, `useSetting()`. |
| [`@evolustr/signer`](packages/signer) | For signer developers: adds the Evolustr Signer API to a signer (per-app keys, one passkey for all apps). |
| [`@evolustr/rn`](packages/rn) | React Native: native passkeys, NIP-55 (Amber) and NIP-46 signers, secure storage. |
| [`@evolustr/core`](packages/core) | Shared crypto, vault format, Nostr I/O. |

## Quick start (app)

```ts
import { AppName, NonEmptyTrimmedString1000, createEvolu, id } from "@evolu/common";
import { createEvoluDeps, createRun } from "@evolu/web";
import { createEvolustr, detectCapableSigner, evoluDatabases, webSecretCache } from "@evolustr/client";
import { appIdFromOrigin, nip07Signer, poolRelays, webauthnPasskeys } from "@evolustr/core";

const Schema = { note: { id: id("Note"), text: NonEmptyTrimmedString1000 } };
const appId = appIdFromOrigin(location.origin, ["nsite.lol"]); // a Result: https: (or http: on localhost) only
if (!appId.ok) throw new Error(appId.error.message);
const run = createRun(createEvoluDeps());

const databases = evoluDatabases({
  appId: appId.value,
  schema: Schema,
  createEvolu: ({ schema, appOwner, appName }) =>
    run.ok(createEvolu(schema, {
      appName: AppName.orThrow(appName),
      appOwner,
      onDatabaseDeleted: () => {}, // Evolustr deletes old databases after a migration
    })),
});

const evolustr = createEvolustr(
  {
    signer: nip07Signer(window.nostr),
    relays: poolRelays(),
    openDatabase: databases.open,
    cache: webSecretCache(),                            // encrypted with a non-extractable key
    passkeys: webauthnPasskeys({ rpName: "My App" }),
    capableSigner: detectCapableSigner(window.nostr), // optional
  },
  { appId: appId.value, relayUrls: ["wss://relay.damus.io", "wss://nos.lol"] },
);

const result = await evolustr.connect(); // never prompts for a passkey
if (result.ok && result.value.state === "ready") {
  const evolu = databases.current()!;     // your typed Evolu instance
  evolu.insert("note", { text: NonEmptyTrimmedString1000.orThrow("Hello") });
}
// result.value.state === "needsUserAction" → show a button that calls evolustr.unlock()
```

Every method returns a `Result` (`{ ok: true, value }` or `{ ok: false, error }`) instead of throwing. See the [demo](examples/notes/src/main.ts) for a complete app.

### Things to know

- **Same app, new device:** compatible databases open after one confirmation (`needsUserAction: "confirmWeak"`, so the user notices if a strict database was swapped for a weak one) and a decrypt prompt; strict ones with a synced passkey, a capable signer, or the recovery phrase.
- **Leaving Evolustr:** `exportEvoluMnemonic()` gives the database's own Evolu phrase, which opens the data in any Evolu app without Nostr. Anyone with it can read and change the data.
- **nsite:** pass the gateways you trust to `appIdFromOrigin`, so `<npub>.gateway` maps to one app on every gateway. A passkey on one gateway doesn't work on another (WebAuthn binds passkeys to the domain); a capable signer does.
- **Migration resets `createdAt`:** when a database becomes strict, rows are copied to a new Evolu owner and get new `createdAt` / `updatedAt` values. Keep your own `created` column if you show creation dates.
- **Evolu reloads the page** when a local database is deleted unless you pass `onDatabaseDeleted`.
- **The device cache holds the database secret.** Evolu needs it on every start. `webSecretCache()` encrypts it with a non-extractable key, which protects it from plain storage reads but not from script running on your page. Use a strict Content-Security-Policy (no inline scripts, no third-party scripts you don't trust): an XSS on your origin can read the user's data, as in any web app. The recovery phrase key is kept in memory only, unless you set `cacheRootKey: true`.

## Mobile (React Native)

There is no iframe signer on mobile; the app talks to the user's signer directly:

| Signer | Adapter | Level |
|---|---|---|
| Android signer app, NIP-55 (Amber) | `nip55Signer(bridge)`; `nip55CapableSigner(bridge)` if it supports the Evolustr API. Android tells the signer the calling package, so app separation is verified. | Compatible; strict with a capable signer. |
| Remote bunker, NIP-46 | `nip46Signer(bunkerSigner)`; `nip46CapableSigner` if supported (connection-scoped). | Compatible; strict with a capable bunker. |
| Any signer + native passkeys | `nativePasskeys(Passkey, { rpId, rpName })` over `react-native-passkey`; needs an associated domain. | Strict. |

```ts
import "react-native-get-random-values"; // first: crypto needs getRandomValues
import * as SecureStore from "expo-secure-store";
import { Passkey } from "react-native-passkey";
import { nativeAppId, nativePasskeys, nip46Signer, secureStoreCache } from "@evolustr/rn";

const evolustr = createEvolustr(
  {
    signer: nip46Signer(bunker),                        // or nip55Signer(bridge)
    relays: poolRelays(),
    openDatabase: databases.open,                       // evoluDatabases with Evolu's React Native package
    cache: secureStoreCache(SecureStore),
    passkeys: nativePasskeys(Passkey, { rpId: "notes.example", rpName: "Notes" }),
  },
  { appId: nativeAppId("android", "com.example.notes"), relayUrls },
);
```

`nip55Signer` needs a small bridge over your native module (NIP-55 has no standard React Native package); see `Nip55Bridge`. The adapters are tested with simulated native modules; testing on real phones is tracked in the issues.

## Demo

Live: https://saintego.github.io/evolustr/ (deployed from `main` by the Pages workflow).

```sh
npm install
cd examples/notes
npm run dev        # http://localhost:5173
npm run e2e        # builds, then runs the end-to-end test in Chromium
```

Query parameters: `?relays=wss://a,wss://b` and `?sync=off` (keep Evolu data on the device).

## Development

```sh
npm install
npm run typecheck
npm test
```

TypeScript (strict), Vitest, functional style: plain data, pure functions, side effects behind injected interfaces (`Signer`, `Relays`, `Passkeys`, `AppDatabase`, `SecretCache`), so everything except the browser layer is tested in Node.

Tools: [`tools/passkey-prf-test.html`](tools/passkey-prf-test.html) ([live](https://saintego.github.io/evolustr/tools/passkey-prf-test.html)) checks whether a browser's passkeys support what strict mode needs.

## License

MIT

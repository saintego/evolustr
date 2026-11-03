# Evolustr

Log in with Nostr, get your app's private [Evolu](https://www.evolu.dev) database on every device.

Evolustr connects a Nostr identity (any NIP-07 extension, NIP-46 bunker or NIP-55 signer) to a local-first, end-to-end encrypted Evolu database. The secret that opens the database is kept in an encrypted Nostr event, so a user who logs in on a new device gets their data without copying 12 words around. There is no backend.

> **Status: alpha.** The design is in [SPEC.md](SPEC.md). Not audited.

## How private is it?

Each app database has a level, and the **user** chooses it:

| Level | What protects the data | Works with |
|---|---|---|
| **Compatible** (default) | Your Nostr signer (NIP-44 encryption). **As private as your Nostr DMs:** an app you let decrypt with your signer could read it. | Every signer, every device, nothing to set up. |
| **Strict** | A passkey on the app's domain, or an Evolustr-capable signer, plus a 12-word recovery phrase. Other apps can't read it, even with signer permissions. | Browsers with passkey PRF (Chrome, Android, …), or a capable signer. |

Making a database strict is a single action (`makeStrict()`); the data moves to a new secret. Synced passkeys (iCloud Keychain, Google Password Manager) need no extra backup step; device-bound ones ask for the recovery phrase first.

## Packages

| Package | What it is |
|---|---|
| [`@evolustr/client`](packages/client) | For apps: connect, unlock, passkeys, strict mode, recovery phrase, shared settings. |
| [`@evolustr/react`](packages/react) | `<EvolustrProvider>`, `useEvolustr()`, `useSetting()`. |
| [`@evolustr/signer`](packages/signer) | For signer developers: adds the Evolustr Signer API to a signer (per-app keys, one passkey for all apps). |
| [`@evolustr/core`](packages/core) | Shared crypto, vault format, Nostr I/O. |

## Quick start (app)

```ts
import { AppName, NonEmptyTrimmedString1000, createEvolu, id } from "@evolu/common";
import { createEvoluDeps, createRun } from "@evolu/web";
import { createEvolustr, detectCapableSigner, evoluDatabases, keyValueCache } from "@evolustr/client";
import { appIdFromOrigin, nip07Signer, poolRelays, webauthnPasskeys } from "@evolustr/core";

const Schema = { note: { id: id("Note"), text: NonEmptyTrimmedString1000 } };
const appId = appIdFromOrigin(location.origin, ["nsite.lol"]);
const run = createRun(createEvoluDeps());

const databases = evoluDatabases({
  appId,
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
    cache: keyValueCache(localStorage),
    passkeys: webauthnPasskeys({ rpName: "My App" }),
    capableSigner: detectCapableSigner(window.nostr), // optional
  },
  { appId, relayUrls: ["wss://relay.damus.io", "wss://nos.lol"] },
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

- **Same app, new device:** compatible databases open with one decrypt prompt; strict ones with a synced passkey, a capable signer, or the recovery phrase.
- **nsite:** pass the gateways you trust to `appIdFromOrigin`, so `<npub>.gateway` maps to one app on every gateway. A passkey on one gateway doesn't work on another (WebAuthn binds passkeys to the domain); a capable signer does.
- **Migration resets `createdAt`:** when a database becomes strict, rows are copied to a new Evolu owner and get new `createdAt` / `updatedAt` values. Keep your own `created` column if you show creation dates.
- **Evolu reloads the page** when a local database is deleted unless you pass `onDatabaseDeleted`.

## Demo

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

# @evolustr/client

Opens an app's [Evolu](https://www.evolu.dev) database for the signed-in Nostr user, on any device. See the [main README](../../README.md) for the quick start and [SPEC.md](../../SPEC.md) for the design.

Every method returns a `Result`: `{ ok: true, value }` or `{ ok: false, error: { type, message } }`.

## Errors worth handling

| `error.type` | From | What to do |
|---|---|---|
| `signerRefused` | any | The user declined in their signer, or it failed. Let them retry. |
| `wrongPhrase` | `unlock`, `unlockRoot`, `restoreFromPhrase` | The phrase doesn't open this app's data. |
| `vaultReplaced` | `unlock` | The unlock proved the vault on the relays isn't the user's. Call `resolveVaultChange("republishCopy")` to restore this device's copy. |
| `unsafeFollow` | `resolveVaultChange("followRelay")` | This device's data is protected by a root key and the vault on the relays only opens through NIP-44. Restore with a strong method instead. |
| `backupRequired` | `makeStrict`, `unlock` (setupStrong) | Ask the user to save the recovery phrase or add a second passkey, or pass `acceptDeviceLoss: true` after they agree. |
| `partialPublish` | `makeStrict`, `downgrade` | Not every relay took the change; it completes on the next `connect()`. |
| `rootLocked` | `enrollPasskey`, `showRecoveryPhrase`, `downgrade`, `makeStrict` | Call `unlockRoot()` first. If `status.canReplaceRoot` is true (this device can't open the root key of a compatible database), offer `makeStrict({ replaceRoot: true })` instead. |
| `rootRotated` | `unlock` | The root key was replaced on another device (`rotateRoot()`); the old phrase or passkey no longer works. Unlock with the new method. |
| `rootKnown` | `makeStrict({ replaceRoot: true })` | The root key is unlocked here; call `makeStrict()` without `replaceRoot`. |

## Going strict with a new recovery phrase

`status.canReplaceRoot` is true when the database is compatible and this device can't open its root key: the user lost every passkey, signer and the phrase, or another app that can decrypt added a root key of its own. `makeStrict({ replaceRoot: true })`, from a click, then creates a new root key and a new strong method (the capable signer, else a new passkey), and moves the data to strict. Tell the user first: "Your earlier recovery phrase and passkeys for this app will stop working." Other devices then ask for a strong unlock and get in with the new passkey, the signer or the new phrase; a device that still has the old root key cached reports the vault as replaced.

## Optional dependencies

- `hints`: a small non-secret store that survives logout (for example `localStorage`). It keeps the last mode and secret hash per user and app, so after a logout the device still notices a strict database swapped for a weak one. It also holds the facts for the backup check before strict: which of the user's passkeys and signers recover on their own, and whether the recovery phrase was confirmed. They're kept on the device because other apps with decrypt permission can write to a compatible database. Without `hints`, they last for the session only, and the user may be asked to confirm the phrase again after a reload. The mode hint is removed by `logout({ deleteLocalData: true })`.
- `cache`: `webSecretCache()` on the web. Its entries are bound to their slot; entries written by earlier versions don't decrypt anymore and act as an empty cache (the user unlocks once).

## Replacing the root key

`rotateRoot()`, from a click, replaces the root key and the data secret, keeping the mode. Offer it when `status.rootExposed` is true (the user's signer replaced its key because the old one was exposed), or when the user thinks their recovery phrase leaked. One new strong method seals the new key (the capable signer, else a new passkey). Tell the user first: their earlier recovery phrase, and other passkeys and signers for this app, stop working, and data written before stays as readable as it was.

## After a switch to strict elsewhere

When a device follows a database that was made strict elsewhere, it copies only the rows the strict database doesn't have yet. Rows it already has are never overwritten, because any app that could decrypt the old secret could have written to the old database. `ready.migration` says what happened: `{ copied, skippedChanged }`. When `skippedChanged > 0`, edits made on this device while it was away were left in the old database, which is kept: tell the user, then call `discardOldDatabase()`. Set `migrateChangedRows: true` to carry those edits over instead, accepting that such an app could then change strict data.

## States from `connect()`

- `ready`: use the database.
- `needsUserAction`: show a button that calls `unlock()`. The action is `passkey`, `signerUnlock`, `recoveryPhrase`, `setupStrong` or `confirmWeak` (first use of a weak vault on this device).
- `vaultChanged`: show the offered `options` and call `resolveVaultChange(choice)`. When it also has `advice: "useAnotherDevice"`, nothing on this device can restore the real vault (it was logged out, and the vault on the relays was swapped for a weak one). Tell the user to open the app on a device that is still signed in, which restores the vault (`republishCopy`), and then to sign in here again. `restoreFromPhrase()` works once the real vault is back.

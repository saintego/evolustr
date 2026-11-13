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
| `rootLocked` | `enrollPasskey`, `showRecoveryPhrase`, `downgrade` | Call `unlockRoot()` first. |

## Optional dependencies

- `hints`: a small non-secret store that survives logout (for example `localStorage`). It keeps the last mode and secret hash per user and app, so after a logout the device still notices a strict database swapped for a weak one. Removed by `logout({ deleteLocalData: true })`.
- `cache`: `webSecretCache()` on the web. Its entries are bound to their slot; entries written by earlier versions don't decrypt anymore and act as an empty cache (the user unlocks once).

## States from `connect()`

- `ready`: use the database.
- `needsUserAction`: show a button that calls `unlock()`. The action is `passkey`, `signerUnlock`, `recoveryPhrase`, `setupStrong` or `confirmWeak` (first use of a weak vault on this device).
- `vaultChanged`: show the offered `options` and call `resolveVaultChange(choice)`.

# @evolustr/signer

The signer side of Evolustr: lets a Nostr signer (iframe signer, browser extension, NIP-46 bunker, NIP-55 Android signer) give each app its own strong key. Read the [integration guide](../../docs/signer-integration.md) first; the design is in [SPEC.md](../../SPEC.md) §5.

## Host interface

`createEvolustrSigner(host)` needs:

| Field | Purpose |
|---|---|
| `relays`, `relayUrls` | Where the signer vault (its encrypted master key) lives. |
| `signerKey` | A stable name for the signer: origin, extension id, package name or bunker pubkey. |
| `getPublicKey`, `sign` | The user's pubkey, and signing for the signer vault event. |
| `getSecretKey` (optional) | The nsec, if the signer holds it. With `allowSkWrap` (default true) it protects the master key, so new devices unlock silently. `allowSkWrap` can be a function, read on every use, for signers where the user decides (e.g. OAuth). Enrolling a passkey while it's false drops the `sk` wrap, keeping the same master key. That stops new devices from unlocking with the nsec, but doesn't take access away from someone who can recover the nsec: the master key stays the same. Removing that access needs a new master key and new app keys (not implemented yet). `capabilities()` reports `nsecExposed`. |
| `passkeys` (optional) | Signer passkeys on the signer's own origin. |
| `cache` (optional) | `get` / `set` / `remove` for the unlocked master key on this device, and `getVault` / `setVault` for a local copy of the signer vault. **Provide `getVault` / `setVault`**: without them, a replaced signer vault on the relays locks out devices that don't have the key cached. |
| `ui.confirm`, `ui.requestGesture` | Prompts with the verified caller, and a click inside the signer before passkey calls. |

## Methods

`handle(method, params, caller)` routes `evolustr_capabilities`, `evolustr_get_wrap_key` and `evolustr_enroll_passkey`. The caller always comes from the transport (`event.origin`, extension sender, Android package, NIP-46 client pubkey), never from params. `isProtectedEvent(event)` tells auto-approve rules which events need a prompt.

# Adding the Evolustr Signer API to a signer

This guide is for developers of Nostr signers: browser extensions, iframe signers, NIP-46 bunkers and NIP-55 Android signers. Section numbers refer to [SPEC.md](../SPEC.md).

## What it gives your users

Apps can already use Evolustr with any signer that supports NIP-44. That "compatible" level is as private as the user's Nostr DMs: any app the user lets decrypt could read the data.

If your signer implements the Evolustr Signer API (§5), apps get a **separate key per app** from you, derived from a secret only your signer holds. The user can then make an app's data **strict**: other apps can't read it, even with signing and decrypt permission, and the user needs no passkey per app or per domain. One signer passkey covers every app and every nsite gateway.

## What your signer must provide

`@evolustr/signer` does the work: the signer's master secret `M`, its vault on relays, key derivation, request handling, and the auto-approve filter. Your signer supplies five things:

| Your signer provides | Why |
|---|---|
| **Who is calling**, from the platform, never from the request | Each app's key is derived from it (§5.2). |
| A way to **sign** the signer's own vault event (kind 30078) | `M` is stored on relays, encrypted. |
| The **nsec**, if your signer holds it, or nothing | `M` can then be unlocked silently (`sk` wrap). Without it, a signer passkey unlocks `M`. |
| A **confirmation prompt** showing the verified caller | The user approves which apps get keys. |
| A **click inside your signer UI** before passkey calls | Browsers only allow passkeys and popups from a user gesture in the same frame (§5.4). |

Where "who is calling" comes from:

| Signer kind | Caller identity | Adapter |
|---|---|---|
| Iframe signer | `postMessage` `event.origin` | `handleIframeMessage` / `listenForIframeRequests` |
| Browser extension | The sender origin from the extension runtime | `handleExtensionRequest` |
| NIP-55 Android signer | The calling package, from Android | `handle(method, params, { identity: "verified", androidPackage })` |
| NIP-46 bunker | The client's connection pubkey (not verified by any platform) | `handleNip46Request` (connection-scoped, §5.2) |

## 1. Create the Evolustr signer

```ts
import { createEvolustrSigner } from "@evolustr/signer";
import { poolRelays, webauthnPasskeys } from "@evolustr/core";

const evolustr = createEvolustrSigner({
  relays: poolRelays(),
  relayUrls: ["wss://relay.damus.io", "wss://nos.lol"],
  signerKey: "https://signer.example",        // a stable name for your signer: origin, extension id, package name or bunker pubkey (§5.3)
  getPublicKey: async () => userPubkey,
  sign: (event) => signWithUserKey(event),     // your existing signing path
  getSecretKey: () => nsecBytesOrNull,         // omit if your signer never holds the nsec
  allowSkWrap: true,                           // false if someone else can recover the nsec (see "Custody" below)
  passkeys: webauthnPasskeys({ rpName: "My Signer" }), // optional: signer passkeys on your origin
  ui: {
    confirm: (request) => askUser(request),    // show request.appId; you may remember answers per app
    requestGesture: (reason) => showUnlockButton(reason), // resolve on a click inside your UI
  },
  knownNsiteGateways: ["nsite.lol"],           // same key for an nsite on every gateway you trust
});
```

### Keep a local copy of the signer vault

Give `cache` the optional `getVault` / `setVault` methods (any device-local storage). The signer then keeps the last good list of its wraps and merges it with the relay version. Without them, anyone who can sign for the user can replace the signer vault on the relays and lock out every device that doesn't have `M` cached.

```ts
cache: {
  get, set, remove,                         // the unlocked M, device-local
  getVault: (pubkey) => store.get(`signer-vault:${pubkey}`),
  setVault: (pubkey, json) => store.set(`signer-vault:${pubkey}`, json),
},
```

## 2. Route `evolustr_*` requests

Pass requests to `evolustr.handle()` with the caller **your platform** reports:

```ts
// Iframe signer, inside your existing message handler:
if (event.data?.type === "evolustr") {
  const response = await handleIframeMessage(evolustr, { origin: event.origin, data: event.data });
  if (response) event.source.postMessage(response, event.origin);
}

// NIP-46 bunker, for methods starting with "evolustr_":
const reply = await handleNip46Request(evolustr, clientPubkey, { id, method, params });

// NIP-55 Android signer, for custom request types:
const result = await evolustr.handle(type, params, { identity: "verified", androidPackage: callingPackage });
```

Never read an app id from the request: anything in it can be forged.

## 3. Protect Evolustr events in your auto-approve rules

If your signer signs some kind 30078 events without asking, exclude Evolustr's:

```ts
if (evolustr.isProtectedEvent(event)) requireConfirmation(); // §5.5 rule 2
```

The prompt should say "<app> wants to change your Evolustr data keys".

## 4. Expose the API to apps

- **Extension or injected `window.nostr`:** add `window.nostr.evolustr` with `capabilities()`, `getWrapKey()` and `enrollPasskey()`. An iframe signer's bridge script can use `exposeOnWindowNostr(window.nostr, iframeCapableSigner({ ... }))` from `@evolustr/client`.
- **NIP-46 and NIP-55:** answer the `evolustr_*` methods. Apps detect support with `evolustr_capabilities`; a signer without it returns an error and apps fall back.

`getWrapKey` may wait for the user to click in your UI. Don't apply short request timeouts to `evolustr_*` calls.

## Custody

`capabilities()` reports `recoverable`: true when the signer vault has an `sk` wrap or a passkey that was synced when enrolled. Apps use it for the backup check before strict (SPEC §3.2 rule 3a); a signer that doesn't report it counts as not recoverable.

How your signer stores `M` decides who besides the user could derive app keys:

| Your signer | `allowSkWrap` | Result |
|---|---|---|
| Holds the nsec, and only the user can recover it | `true` | Keys without any passkey; a new device with the same nsec gets them silently. **But anyone who has the nsec can then open strict data too**: many users have pasted their nsec into several clients. Tell the user when they turn Evolustr on, and offer the passkey option below. `capabilities()` reports `nsecProtected`. |
| Holds the nsec, but a third party can recover it (OAuth/MPC login, custodial bunker) | Offer the user a choice | With the `sk` wrap, that third party could derive the app keys. Offer a signer passkey and `allowSkWrap: false` instead. |
| Passes requests to another signer (no nsec) | n/a | The API works after the user enrolls a signer passkey. |

## Passkeys in an iframe signer

- The app page must create your iframe with `allow="publickey-credentials-get; publickey-credentials-create"`.
- A click in the app page doesn't count as a click in your iframe; `requestGesture` must show your own button.
- If the browser refuses passkeys in a cross-origin iframe, open a popup on your origin from that click (to be measured per browser, see issue #3).

## Test checklist

- Two apps on different origins get different keys; a request claiming another app id changes nothing.
- A second device with the same nsec (or synced signer passkey) unlocks a strict app database.
- Auto-approve never signs an `evolustr:` event silently.
- Requests that wait for a click don't time out.

## Example: nostr-shard-signer

[nostr-shard-signer](https://github.com/saintego/nostr-shard-signer) is an iframe signer with an OAuth (Web3Auth) mode that holds the nsec, and a passthrough mode for extensions and bunkers. Integration plan, tracked in issue #15:

- **Iframe (`bunker/src/App.tsx`):** create the Evolustr signer once signed in, with `signerKey: location.origin`, `getSecretKey: () => privateKeyRef.current`, and `confirm` / `requestGesture` built on the existing `ConfirmView`. Route `type: "evolustr"` messages to `handleIframeMessage(evolustr, event, parentOrigin)` after the existing origin checks.
- **Auto-approve list (PR #46 there):** skip events where `isProtectedEvent()` is true.
- **`nostr-bridge.js`:** add `window.nostr.evolustr` forwarding to the iframe, and stop the 30 s RPC timeout for `evolustr_*` calls (the existing `CONFIRM_PENDING` message can be reused). `nostr-bridge.js` is a plain script, so either bundle `@evolustr/client` into it or inline the small iframe-client code.
- **Custody:** in OAuth mode the Web3Auth `clientId` owner can recover the nsec, so the `sk` wrap needs the user's consent; offer a signer passkey instead. In passthrough mode a signer passkey is required.
- **Testing:** issue #22.

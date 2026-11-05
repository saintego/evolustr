# Integrating @evolustr/signer into nostr-shard-signer

Step 12 (#15). This is a plan for the change in [saintego/nostr-shard-signer](https://github.com/saintego/nostr-shard-signer); it can't be made from this repository. Section numbers refer to [SPEC.md](../SPEC.md).

## 1. Inside the signer iframe (`bunker/src`)

Create the Evolustr signer once the user is signed in:

```ts
import { createEvolustrSigner, handleIframeMessage } from "@evolustr/signer";
import { poolRelays, webauthnPasskeys } from "@evolustr/core";

const evolustr = createEvolustrSigner({
  relays: poolRelays(),
  relayUrls: publishRelays,
  signerKey: location.origin,                       // stable name of this signer (§5.3)
  getPublicKey: async () => keyInfo.publicKeyHex,
  sign: async (event) => finalizeEvent({ ...event, tags: event.tags.map((t) => [...t]) }, privateKeyRef.current!),
  getSecretKey: () => privateKeyRef.current,        // OAuth mode; null in window.nostr.js mode
  allowSkWrap: userAcceptedOwnerAccess,             // see "OAuth mode" below
  passkeys: webauthnPasskeys({ rpName: "Nostr Shard Signer" }),
  ui: {
    confirm: (req) => showConfirmation(req),        // existing ConfirmView; remember per origin
    requestGesture: (reason) => showUnlockButton(reason), // resolves on a click inside the iframe
  },
  knownNsiteGateways: ["nsite.lol"],
});
```

In the existing `postMessage` handler (`App.tsx`, after the `event.origin === parentOrigin` check):

```ts
if (event.data?.type === "evolustr") {
  const response = await handleIframeMessage(evolustr, { origin: event.origin, data: event.data }, parentOrigin);
  if (response) window.parent.postMessage(response, parentOrigin);
  return;
}
```

The caller identity is `event.origin`, set by the browser; never read an app id from the message.

## 2. Auto-approve list (PR #46)

Before auto-approving a kind 30078 event:

```ts
if (evolustr.isProtectedEvent(event)) return requiresConfirmation; // §5.5 rule 2
```

The prompt should say "<origin> wants to change your Evolustr data keys".

## 3. `nostr-bridge.js` (the app page)

Expose `window.nostr.evolustr`, forwarding to the iframe:

```js
import { exposeOnWindowNostr, iframeCapableSigner } from "@evolustr/client";

exposeOnWindowNostr(window.nostr, iframeCapableSigner({
  target: iframe.contentWindow,
  signerOrigin: config._bunkerMessageOrigin,
  self: window,
}));
```

Apps then pick it up with `detectCapableSigner(window.nostr)`. Calls may wait for a click inside the signer, so the bridge must not apply its 30 s RPC timeout to `evolustr_*` calls (the existing `CONFIRM_PENDING` message can be reused).

## 4. Passkeys in the iframe

- Create the iframe with `allow="publickey-credentials-get; publickey-credentials-create"`.
- `requestGesture` shows a button inside the iframe; the passkey call runs in that click handler. A click in the app page doesn't count (§5.4).
- If the browser refuses WebAuthn in the cross-origin iframe (to be measured, issue #3), open a popup on the signer origin from that click.

## 5. Modes

| Mode | `getSecretKey` | `allowSkWrap` | Result |
|---|---|---|---|
| OAuth (Web3Auth) | the key | user's choice | With the `sk` wrap, apps get strong keys without a passkey, but the Web3Auth `clientId` owner can recover them. Offer a signer passkey and `allowSkWrap: false` to users who don't accept that (§5.7). |
| window.nostr.js / extension passthrough | `null` | — | Evolustr is available after the user enrolls a signer passkey (`evolustr_enroll_passkey`). |

## 6. Test plan

- Two apps on different origins get different keys; a message claiming another app id changes nothing.
- A second browser with the same OAuth login opens a strict app vault without prompts.
- Passthrough mode: enroll a signer passkey, then a second device with the synced passkey unlocks after one click in the signer.
- Auto-approve never signs an `evolustr:` event silently.

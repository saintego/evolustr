# Evolustr Specification

**Status:** Draft v0.12
**Scope:** Nostr identity → one Evolu (local-first, E2E-encrypted SQLite) database per app, synced across devices, with **no backend and no storage other than Nostr relays and Evolu**.

---

## 1. Overview

A user signs in to an app with any Nostr signer. Evolustr then opens **that app's Evolu database** for the user, on any device.

Evolustr has three parts:

| Part | What it is |
|---|---|
| **App database** | One Evolu database per user per app: the app's private data and its secrets. This is the core of Evolustr. |
| **Shared settings** | One small Nostr event with harmless preferences (theme, language, …) that every app can read. **Not** an Evolu database (§9). |
| **Evolustr Signer API** | An optional protocol any signer can implement, to give each app a strong key without a passkey (§5). This repo ships it as `@evolustr/signer`, a package signers embed (§5.6). |

Settings resolve as `app ?? shared ?? default`.

A user's cross-app secrets (API keys, nsec, bank details) are a separate, optional signer feature, specified in [`SECRETS.md`](SECRETS.md). An app that only needs its own secrets keeps them in its app database.

Evolustr works with **any** Nostr signer. Signers that implement the Signer API, or a **passkey on the app's own domain** (§4), let the user make the app database strong. §7 lists every combination.

### 1.1 Terms

| Term | Meaning |
|---|---|
| **Standard signer** | Any NIP-07, NIP-46 or NIP-55 signer without the Evolustr Signer API (Alby, nos2x, nsec.app, Amber today). |
| **Evolustr-capable signer** | A signer that implements the Evolustr Signer API (§5). |
| **Data secret `S`** | The random secret behind one app database (its Evolu owner mnemonic). It changes when the user makes the database strict (§3.4). |
| **Root key `R`** | A random 16-byte key per vault that protects `S` for every strong unlock method. It never changes, and it is never encrypted with NIP-44. Its 12-word form is the **recovery phrase**. |
| **Vault event** | A Kind 30078 event on Nostr relays that stores `R` and `S` in encrypted form (§6). |
| **Wrap** | One encrypted copy of `R` or `S` inside a vault event (§3). |
| **Client passkey** | A WebAuthn passkey the **app** registers on **its own domain**. Needs no special signer. |
| **Signer passkey** | A passkey a **capable signer** registers on **its own origin**, used for every app. |
| **Level** | `strong` or `weak` (§3.2). |

### 1.2 Design principles

1. **No backend, no third-party storage.** Data lives only on Nostr relays (vault events, settings) and in Evolu (the app database and its sync). Signers and clients keep nothing elsewhere except their normal device-local caches.
2. **Any signer works.** Capable signers and passkeys add strength and convenience. Without them the library still works, at a lower level.
3. **The user chooses the level.** Every database starts `compatible`, which works everywhere, unless the app requires strict (§3.2). The user can make it `strict` and can turn that back. Nothing changes the level on its own.
4. **Honest security levels.** The database reports its level, and the docs never claim more.
5. **Only browser- or OS-enforced identities separate apps:** web origin (`event.origin`, extension sender origin, WebAuthn `rpId`) or the Android calling package. Self-asserted app names and URLs never do.
6. **One Evolu instance per page.**

---

## 2. The app database

- One per user per app, keyed by `appId` (§3.3). It is the app's private storage and can hold the app's own secrets.
- Its data secret `S` and root key `R` live in a vault event (§6).
- Its level is set by the **vault**, not by the app's code (§3.2). The app can only require a minimum: `requireStrong: true` means the app only opens strict databases.
- On the device, each `(pubkey, appId)` has its **own** local Evolu database. Evolu (8.x) identifies a local database by its `appName` plus the AppOwner made from `S`, so a different account (different `S`) automatically gets a different database. Evolustr sets `appName` to `evolustr-` + the first 16 hex characters of `SHA-256(appId)`. Two Nostr accounts on one browser never share local data or cached vault copies.
- Evolu 8.x does **not** keep the owner secret itself: the app passes `appOwner` (made from `S` with `createAppOwner`) every time it creates the Evolu instance. Evolustr supplies it after unlocking.

---

## 3. Keys and wraps

### 3.1 Two levels of keys

```
 strong unlock methods            root key            data secret
 ─────────────────────            ────────            ───────────
 signer wrap   ─┐
 passkey wrap  ─┼──►  R  ──(root data wrap)──►  S  ──►  Evolu database
 recovery      ─┘                                ▲
 phrase (= R)                                    │
                              nip44 data wrap ───┘   (compatible only)
```

| Wrap | Encrypts | Key | Identified by | Level | Needs |
|---|---|---|---|---|---|
| `signer` | `R` | Key from a capable signer, derived for the caller's verified `appId` (§5.3) | `signerId` | strong | Evolustr-capable signer |
| `passkey` | `R` | PRF output of a client passkey, `rpId` = the app's host (§4) | `credId` | strong | WebAuthn PRF on the user's platform |
| recovery phrase | — | It **is** `R`, as 12 BIP-39 words, written down by the user. Never stored. | — | strong (offline) | The user keeping it safe |
| `root` | `S` | `HKDF-SHA256(R, "", "evolustr/v1/data|" + appId)` | — | — | Exactly one per vault that has `R` |
| `nip44` | `S` | NIP-44 self-encryption, user → user, through the user's signer | — | weak | Any signer with NIP-44 |

Why two levels: the strong methods protect `R`, and `R` protects `S`. When `S` is replaced (§3.4), only the one `root` wrap is rewritten. Every passkey, signer and recovery phrase keeps working without being touched, including passkeys on other gateways and signers on other devices.

`R` is created with the vault's **first strong method**: the first passkey, signer wrap or confirmed recovery phrase. A `compatible` vault used only through NIP-44 may have no `R` yet.

**`R` is never reachable through NIP-44, even in `compatible` mode.** If it were, anyone who read the `nip44` wrap while the vault was weak would still know `R` after `makeStrict()`. The cost: a device that opened a `compatible` vault through `nip44` has `S` but not `R`. Once `R` exists, that device can read and write the data, but it **can't add a strong method** (passkey or signer wrap) until the user unlocks `R` there once, with a synced passkey, a capable signer that already has a wrap, or the recovery phrase. The client says so plainly instead of failing (`status.canAddStrongMethod`).

`signer`, `passkey` and `root` wraps use **AES-256-GCM** with a random 12-byte IV and
`AAD = "evolustr/v1|" + pubkey + "|" + appId + "|" + wrapType + "|" + (signerId | credId | sHash)`.
Binding each wrap to its own key identifier (and the `root` wrap to the `sHash` of the `S` it holds) means concurrent additions never collide and a wrap can't be moved to another vault or swapped for an older one.

A vault may hold several `signer` wraps (one per capable signer, each with its own `M`, §5.3) and several `passkey` wraps.

`@noble/ciphers` and `@noble/hashes` are used everywhere, so web, workers and React Native give the same results.

### 3.2 Levels: the user's choice

**A database's level is the level of its weakest way to `S`.** If a vault holds a `nip44` wrap, any app with decrypt permission uses it and ignores everything else. So a vault is in one of two states, recorded in its `mode` field (§6.1), which is the **only** source of truth:

| `mode` | Ways to `S` | Level |
|---|---|---|
| `compatible` | `nip44` wrap, plus `root` wrap if `R` exists | weak |
| `strict` | `root` wrap only | strong |

Rules:

1. **A new vault starts `compatible`**, unless the app sets `requireStrong`. Then the first vault is created `strict` directly (§8.2 step 4), so no throwaway weak vault is ever published.
2. **Strong methods don't change the level.** A user may add a passkey or use a capable signer just for convenience (unlocking without a decrypt prompt). The vault stays `compatible`.
3. **`strict` is the user's choice.** The client may *offer* it when the user has a strong method (`status.canMakeStrict`), but only `makeStrict()`, called after the user confirms, changes the mode. A user who refuses passkeys and capable signers simply stays `compatible`. How much backup is asked for first depends on whether the user's strong method can be recovered on its own (rule 3a).
3a. **Backup check before `strict`, scaled to the risk:**

| The user's only strong method | Recoverable on its own? | Before `makeStrict()` |
|---|---|---|
| Synced passkey: the WebAuthn authenticator data has the **backup state** flag (BS) set, e.g. iCloud Keychain, Google Password Manager, a password manager | Yes, through the provider account | Nothing required. Show a skippable reminder: "Your data is protected by your passkey. Save your recovery phrase or add a second passkey in case you lose access to your passkey provider." |
| Capable signer whose `M` can be recovered from the nsec (`sk` wrap), or by a synced signer passkey | Yes, through the signer | Nothing required. Same skippable reminder. |
| Device-bound passkey (BS flag not set: a hardware key, a local-only platform authenticator) or a signer passkey that isn't synced | **No**: losing that one device loses the data | Confirm the recovery phrase, add a second strong method, **or** explicitly accept "I will lose this data if I lose this device". |

The BS flag is what the authenticator reports at that moment; a user can still lose the provider account or turn sync off later. So the reminder stays visible (`status.backupRecommended`) until the user has a second strong method or has confirmed the phrase. The recovery phrase can be shown at any time later (`showRecoveryPhrase()`).
4. **Making a vault strict replaces `S`.** Dropping the `nip44` wrap doesn't make the old `S` secret again, because relays and other apps may have kept copies. The client creates a new `S'` (§3.4). `R` and all strong wraps stay as they are, so the recovery phrase doesn't change either.
5. **Clients never add a `nip44` wrap to a `strict` vault**, whatever the app's code or configuration says.
6. **A `strict` vault ignores `nip44`.** A client reading a `strict` vault never tries a `nip44` wrap, even if one appears on a relay.
7. **Turning strict off is also the user's choice, on a device that can unlock.** `downgrade()` adds a `nip44` wrap of the current `S` and sets `mode: "compatible"`, after an explicit confirmation that names the risk.
8. **A device that can't unlock a strict vault has no access.** For example a new device with a standard signer and no synced passkey. The user then uses the recovery phrase, a capable signer, or downgrades from a device that can unlock.

### 3.3 App identity (`appId`)

`appId` names which vault to use. Security comes from the passkey `rpId` or the signer's verified caller identity, never from `appId` itself.

| Environment | `appId` |
|---|---|
| Web app on its own domain | The page origin, `https://app.example.com` |
| nsite on a known gateway | `nsite:<site-npub>`, taken from `<npub>.gateway.tld`, so the same vault is used on every gateway |
| nsite on an unknown gateway | The page origin |
| Android | `android:<package name>` (verified for NIP-55 signers) |
| iOS / other native | `ios:<bundle id>` (self-asserted) |

### 3.4 Replacing `S` (making a vault strict)

Evolu stores CRDT messages tied to the owner, so a database can't be copied as a SQLite file. Evolu 8.x can open two local databases at once (same `appName`, different AppOwner), which the migration uses.

**On the device that runs `makeStrict()`:**

1. Unlock `R` (any strong method or the recovery phrase).
2. Create `S'`. If the database has no rows in any app table, skip to step 4.
3. For every table in the app's schema (not Evolu's internal tables), read the rows from `S` and write them into `S'` with Evolu's **`upsert`, keeping each row's `id`**, so references between rows stay valid. Copy `isDeleted` too.

**Known limit:** Evolu sets the system columns `createdAt` and `updatedAt` itself and they can't be written, so in `S'` every copied row gets the migration time. An app that shows when something was created must keep that in its own column (for example `created`). Evolustr's docs say so up front.
4. Publish the vault with `mode: "strict"`, a new `root` wrap for `S'`, no `nip44` wrap, `sHash` of `S'`, `created` = now, and the old `{ sHash, created }` appended to **`history`** (the last 10 data secrets, oldest first).

**On other devices** (online or back from offline), when the fetched vault's `sHash` differs from the local database's and its `root` wrap opens with `R` (§6.3):

1. Unlock `R`, then the current secret from the `root` wrap. If the device can't (it only used `nip44`, or has no strong method here), it has no access yet (§3.2 rule 8). Its local database stays untouched until the user unlocks `R` on this device; the migration then runs.
2. Find the local `sHash` in the vault's `history`. The **cut-off** is the `created` time of the secret that replaced it: the next entry in `history`, or the vault's own `created` if the local one is the last entry. This also works after several rotations while the device was offline.
3. Copy into the current database only the local rows that are **missing** there or were **changed after the cut-off** (Evolu's `updatedAt ?? createdAt`, which comes from the change's hybrid logical clock; allow a few minutes of margin for devices whose clocks are off). Copying every row would overwrite newer edits with older local values. If the local `sHash` isn't in `history` (more than 10 rotations ago, or a restore), ask the user before copying anything.
4. Switch to the current database and delete the local old one (`deleteDatabase()` on the old instance).

Evolu doesn't delete an owner's data on its relays yet, so the old `S` data stays on Evolu relays after a rotation. That data was already readable by anyone who had the `nip44` wrap; everything written after the rotation is under `S'`.

The relay vault carries all the information, so no device waits for Evolu sync to learn about a rotation.

---

## 4. Client passkeys (no capable signer needed)

This is how a user can make an app database strong with **any** signer, including standard ones.

### 4.1 Rules for every passkey operation

- **Only from a user gesture.** Passkey calls, and any popup, need a user click. `connect()` never prompts for a passkey on page load. If a passkey is needed, it reports `needsUserAction: "passkey"` and the app shows an **Unlock** button that calls `unlock()`.
- **Check PRF.** If the platform or authenticator returns no PRF output, client passkeys are unavailable on that device.
- **One PRF input per vault:** `prfInput = SHA-256("evolustr/v1/prf|" + pubkey + "|" + appId)`. Every passkey gets the same input; each passkey still returns a different secret, because each holds its own key. With one input, `extensions.prf.eval` works for any number of passkeys, without the less widely supported `evalByCredential`.
- Wrap key = `HKDF-SHA256(prfOutput, "", "evolustr/v1/wrap|" + appId)`.

### 4.2 Enroll

1. Unlock `R` by any strong method or the recovery phrase. If the vault has no `R` yet, create it now (§3.1). A device that unlocked only through `nip44` can't add a passkey to a vault that already has `R` until the user unlocks `R` there once (§3.1).
2. From a click, call `navigator.credentials.create()` with:
   - `rp.id` = the page's host. For an nsite, the exact gateway subdomain.
   - `user.id` = `SHA-256(pubkey)`, `user.name` = the npub.
   - `residentKey: "required"`, `userVerification: "required"`.
   - `excludeCredentials` = the `credId`s of every `passkey` wrap in the vault with this `rpId`. Without it, a second enrollment on the same provider can replace the first passkey instead of adding one.
   - `extensions: { prf: { eval: { first: prfInput } } }`.
3. If `getClientExtensionResults().prf` has `results.first`, use it. One prompt, done.
4. If it only reports `prf.enabled: true` without results, show **"Finish passkey setup"** and, **from that new click**, call `navigator.credentials.get()` for the new credential with the same `prfInput`. A second call chained right after `create()` can fail, because the first one used up the click.
5. If PRF is not enabled, stop and tell the user this authenticator can't be used.
6. Add a `passkey` wrap of `R` with `rpId` and `credId` (§6.2). The level doesn't change (§3.2 rule 2).

### 4.3 Unlock on a device

1. `getPublicKey()` from the signer (no decrypt prompt).
2. Fetch the vault. Collect `passkey` wraps whose `rpId` equals the current host.
3. From a click, call `navigator.credentials.get()` with `allowCredentials` = their `credId`s and `prf: { eval: { first: prfInput } }`.
4. The user picks one passkey. Use the returned credential's `rawId` to find its wrap, unwrap `R`, then `S`.
5. This works with **synced** passkeys (iCloud Keychain, Google Password Manager, password managers) and, where the platform supports PRF over it, with a **phone passkey via QR** (hybrid).

### 4.4 Where client passkeys work

| Environment | Notes |
|---|---|
| Own domain | ✅ The normal case. |
| nsite | ⚠️ **Locked to one gateway.** The `rpId` is the gateway subdomain, and a page on gateway B can't use gateway A's passkey. To add a passkey on gateway B, `R` must first be unlocked there by a capable signer or the recovery phrase. WebAuthn Related Origin Requests don't help, because the developer doesn't control the gateway domains. |
| React Native | ✅ Through a native passkey module. The app needs an associated domain (`apple-app-site-association`, `assetlinks.json`), so a web domain but no backend. |

### 4.5 Limits

- Bound to one host. That's the point, but it means no sharing between apps or gateways.
- Depends on a passkey provider. Recommend at least two passkeys (for example two ecosystems, or a hardware key) and the recovery phrase.
- PRF support differs between browsers, operating systems and authenticators, and must be measured (§11).

---

## 5. Evolustr Signer API

An optional protocol any signer can implement. It gives each app a strong `signer` wrap key with **no passkey on the app's side**, and lets one **signer passkey** serve every app and every domain, including every nsite gateway.

### 5.1 Transports

| Transport | How methods are exposed |
|---|---|
| NIP-07 (browser extensions, iframe signers that inject `window.nostr`) | `window.nostr.evolustr.<method>(...)`, an optional namespace like `window.nostr.nip44` |
| NIP-46 (remote bunkers) | Request methods `evolustr_capabilities`, `evolustr_get_wrap_key`, … with JSON params |
| NIP-55 (Android signers) | Intent / content-provider types with the same names |

Clients detect support with `capabilities()`. A signer that doesn't know a method returns an error, and the client falls back.

### 5.2 Caller identity: what a signer may trust

The `appId` a signer uses must come from the signer's own view of the caller, **never** from request params.

| Signer kind | Caller identity | Strength |
|---|---|---|
| Browser extension | Origin of the calling tab or frame, from the browser | verified |
| Iframe signer (e.g. nostr-shard-signer) | `postMessage` `event.origin` | verified |
| Android signer (NIP-55) | Calling package, from the OS (Binder caller UID) | verified |
| NIP-46 remote bunker | Not verifiable: the client's pubkey and name are self-asserted | **connection-scoped**: `appId = "nip46:" + client pubkey`, labelled by the user when approving the connection |

A connection-scoped key stops other connections from reading the database, but a malicious app can still ask the user to approve a connection that **claims** to be App A. `capabilities()` reports which applies.

For nsites, a signer with verified identity maps known gateways to `nsite:<npub>` (§3.3) itself, so the **same key** works on every known gateway without enrolling anything per gateway.

### 5.3 Signer master secret and derived keys

- Each signer keeps its own random 32-byte **master secret** `M`.
- **`signerKey`**: a stable name the signer picks for itself and never changes: its origin for web and iframe signers, its extension id, its package name on Android, or its own pubkey for a NIP-46 bunker. Every installation of the same signer uses the same `signerKey`.
- **The signer's own vault event** has `d = "evolustr:v1:signer:" + hex(SHA-256("evolustr/v1/signer-vault|" + pubkey + "|" + signerKey))`. A signer on a new device knows its `signerKey` and the user's pubkey, so it finds its vault **before** it has `M`.
- That vault holds `M` with strong wraps only:
  - `sk`: AES-GCM keyed with `HKDF(nsec, "evolustr/v1/signer-wrap")`. Only for signers that hold the nsec.
  - **Signer passkey**: PRF output of a passkey whose `rpId` is the signer's own origin, with `prfInput = SHA-256("evolustr/v1/signer-prf|" + pubkey)`. Needed by signers that don't hold the nsec (passthrough signers).
  - **Never `nip44`.** That would give `M`, and so every app's key, to any app with decrypt permission. A signer that can't use either option above doesn't offer the API.
- Signer vault format and AAD (AES-256-GCM, random 12-byte IV, like §3.1):

  ```jsonc
  {
    "v": 1,
    "wraps": [
      { "type": "sk", "iv": "…", "ct": "…" },
      { "type": "passkey", "rpId": "signer.example.com", "credId": "<base64url>", "iv": "…", "ct": "…" }
    ]
  }
  ```

  `AAD = "evolustr/v1|signer|" + pubkey + "|" + signerKey + "|" + wrapType + "|" + (credId | "sk")`.
  The `signer` marker keeps signer-vault wraps and app-vault wraps (§3.1) from ever being valid in each other's place.
- `signerId = hex(SHA-256("evolustr/v1/signer-id|" + M))`, first 8 bytes. It is computed **after** unlocking `M`, and only labels this signer's wraps inside **app** vaults, so clients know which `signer` wrap the current signer can open. Two capable signers have different `M` and different `signerId`.
- Wrap key for a caller: `K = HKDF-SHA256(M, "evolustr/v1|app|" + appId)`. HKDF is one-way, so one app's key reveals nothing about another's or about `M`.
- A signer may cache the unlocked `M` on the device, as it caches its keys. It stores nothing else for Evolustr.

### 5.4 Methods

```ts
interface EvolustrSignerApi {
  version: 1;
  capabilities(): Promise<{
    identity: "verified" | "connection";
    appId: string;                 // as the signer sees the caller
    signerId: string | null;       // null until M is unlocked
    ready: boolean;                // M is unlocked
    signerPasskey: boolean;        // M can be unlocked by a signer passkey
  }>;
  /** Wrap key for the caller's app vault. The signer computes appId itself.
   *  If M is locked (ready === false), the signer first shows its own Unlock UI
   *  and resolves after the user clicks there; it may take a while. */
  getWrapKey(): Promise<Uint8Array>;            // 32 bytes
  /** Register a signer passkey. The signer always shows its own UI for the click. */
  enrollPasskey(): Promise<void>;
}
```

A click in the app's page does **not** count as a click inside a cross-origin signer: browsers don't pass user activation through `postMessage`, so the signer can't start a passkey ceremony or a popup on the app's behalf. Whenever a method needs a passkey or a popup, the signer asks for its own click through its `requestGesture` UI (§5.6) and only then resolves. Apps must not apply short timeouts to these calls.

### 5.5 Behaviour required of a capable signer

1. Derive `appId` only from the caller identity in §5.2.
2. **Never auto-approve** signing Kind 30078 events whose `d`-tag starts with `evolustr:`. Show "App X wants to change your Evolustr data keys" (§6.3).
3. Show the verified caller identity, not app-supplied names, in every Evolustr prompt.
4. Let the user see apps with keys, revoke them, and manage signer passkeys.
5. Passkey operations and popups only on a user gesture. An iframe signer that can't create or use a passkey inside the iframe opens a popup on its own origin **from a click inside the iframe** (e.g. its own **Unlock** button), because a popup opened without a click is blocked. It needs `allow="publickey-credentials-get; publickey-credentials-create"` on the iframe.

### 5.6 `@evolustr/signer`: the signer side as a package

The signer side of Evolustr is a package in this repo, so a signer adds the API by embedding it instead of reimplementing §5. It contains everything that doesn't depend on a particular signer:

- the master secret `M`: creating it, its vault event, `sk` and signer-passkey wraps, unlocking
- `signerId` and key derivation (§5.3)
- request handling for `window.nostr.evolustr`, `evolustr_*` (NIP-46) and NIP-55
- the auto-approve filter for vault events (§5.5 rule 2)
- optionally, cross-app secrets ([SECRETS.md](SECRETS.md))

The host signer supplies what only it knows: who is calling, how to sign, and how to ask the user.

```ts
import { createEvolustrSigner } from "@evolustr/signer";

const evolustr = createEvolustrSigner({
  relays: ["wss://…"],
  signerKey: "https://signer.example.com", // stable name of this signer (§5.3)
  // Host-provided signing for the signer's own vault event (kind 30078).
  sign: (event) => hostSignEvent(event),
  getPublicKey: () => hostPubkey(),
  // Only signers that hold the nsec. Omit in passthrough mode.
  getSecretKey: () => hostSecretKeyOrNull(),
  allowSkWrap: true,           // false when a third party can recover the nsec (§5.7)
  passkey: { rpId: location.hostname, rpName: "My Signer" },
  cache: deviceLocalStore,     // optional: keeps the unlocked M on this device only
  ui: {
    // Show a prompt with the verified caller; resolve true/false.
    confirm: (req) => hostConfirm(req),
    // Ask the user to click (needed before passkey calls and popups).
    requestGesture: (reason) => hostShowUnlockButton(reason),
  },
  knownNsiteGateways: ["nsite.lol"],
  secrets: true,               // enable SECRETS.md
});

// In the host's message handler. `caller` comes from the host, never from params:
// iframe → event.origin, extension → sender origin, NIP-55 → calling package,
// NIP-46 → client pubkey (identity: "connection").
const result = await evolustr.handle(method, params, { identity: "verified", origin: event.origin });

// In the host's auto-approve logic:
if (evolustr.isProtectedEvent(event)) requireConfirmation();
```

Thin adapters cover the common hosts: `adapters/iframe` (postMessage signers), `adapters/nip46` (bunkers), `adapters/extension` (browser extensions). A client-side helper exposes `window.nostr.evolustr` by forwarding calls to the host (for iframe signers, inside the bridge script).

### 5.7 Reference host: nostr-shard-signer

**nostr-shard-signer** (iframe signer, verified origin) embeds `@evolustr/signer` as the first host:

- **Integration:** the iframe's message handler passes `evolustr_*` requests to `evolustr.handle()` with `origin: event.origin`. `nostr-bridge.js` adds `window.nostr.evolustr` and forwards its calls to the iframe, the same way it forwards `signEvent`. The auto-approve list calls `isProtectedEvent()`. `signerKey` is the signer's own origin.
- **OAuth mode** holds the nsec, so `M` can use the `sk` wrap. The Web3Auth `clientId` owner can recover the nsec, and so `M` and every app key derived from it. For users who don't accept that, the signer offers a signer passkey and drops the `sk` wrap. If a looser version of the signer uses a shared `clientId`, that owner is whoever controls the shared project.
- **Passthrough mode** (extension or bunker through the bridge) has no nsec, so the API is available only after the user enrolls a signer passkey. The signer's own vault event is then signed by the extension or bunker, through the bridge. The parent page sees only the AES-encrypted vault: it could block the publish, but not read or forge `M`.
- Per-app separation relies on `event.origin`, not on the `clientId` allowlist, so it holds in the looser version too.

---

## 6. Vault events

### 6.1 Format

Kind **30078** (NIP-78), replaceable.

```jsonc
{
  "kind": 30078,
  "tags": [["d", "evolustr:v1:<hex(SHA-256('evolustr/v1/vault|' + pubkey + '|' + appId))>"]],
  "content": "<JSON below>"
}
```

The pubkey is part of the hash, so two users of the same app have **different** `d`-tags and nobody can list an app's users by querying one `d`-tag. This only stops **bulk** listing: anyone who targets one npub can hash a list of known app ids and test which vaults that npub has. Which apps a user uses is therefore **not secret**. The `evolustr:` prefix lets signers recognise vault events.

```jsonc
{
  "v": 1,
  "mode": "strict",               // "strict" | "compatible": the source of truth (§3.2)
  "created": 1730000000,          // when the current S was created
  "sHash": "<hex SHA-256(S), first 8 bytes>",
  "history": [                    // earlier data secrets, oldest first, last 10 (§3.4)
    { "sHash": "<hex 8B>", "created": 1720000000 }
  ],
  "rootWraps": [                  // wraps of R
    { "type": "signer", "signerId": "<hex 8B>", "iv": "…", "ct": "…" },
    { "type": "signer", "signerId": "<another signer>", "iv": "…", "ct": "…" },
    { "type": "passkey", "rpId": "app.example.com", "credId": "<base64url>", "iv": "…", "ct": "…" }
  ],
  "dataWraps": [                  // wraps of S
    { "type": "root", "iv": "…", "ct": "…" }
    // a "compatible" vault also has: { "type": "nip44", "ct": "…" }
  ]
}
```

A `compatible` vault that has no `R` yet has empty `rootWraps` and only the `nip44` data wrap. The recovery phrase is never stored.

### 6.2 Client rules

1. **Lookup:** query all configured relays and wait for EOSE from each, or a timeout. Never decide "no vault exists" from a single relay.
2. **Create** only when every relay answered and none has the vault. After publishing, fetch again. If a vault with a different `sHash` and an earlier `created` appears, keep the earlier one (moving any rows already written is open question §11.3).
3. **Adding a wrap:** fetch, add the wrap (wraps are keyed by `signerId` / `credId`, so concurrent additions merge), publish, fetch again to check. Never drop a wrap without an explicit user action. `makeStrict()` and `downgrade()` are such actions.
4. **Self-healing:** after unlocking, re-add your own wrap if a concurrent update dropped it. Never re-add `nip44` to a `strict` vault (§3.2 rule 5).
5. **Keep a copy in Evolu:** after a successful unlock, store the vault event in the app database itself (table `evolustr_meta`, key `vault`). It lives in that `(pubkey, appId)` database only (§2), and Evolu syncs it, so every device that has the database also has the last good vault (§6.3).
6. **Device cache:** Evolu needs `S` every time the app starts (§2), so a device caches the unlocked `S`, and may cache `R`, for its `(pubkey, appId)`: in device-local storage on the web, in secure storage on mobile. `logout()` removes both; `logout({ deleteLocalData: true })` also deletes the local database.

### 6.3 Checking a fetched vault

Any app the user lets sign can publish a replacement vault event. Capable signers refuse to auto-approve it (§5.5 rule 2), but standard signers may sign it without asking. A device compares the fetched vault with what it already knows, in this order:

| Situation | What the client does |
|---|---|
| No local database for this `(pubkey, appId)` | First use on this device: unlock normally. If the vault is `compatible`, show its weak level before first use. |
| Same `sHash` as the local database | Normal. |
| Different `sHash`, and its `root` wrap opens with the `R` this device has | A legitimate change made by the user: a rotation (local `sHash` in `history`), a restore or a resolved create race. Follow it and migrate local rows as in §3.4. |
| Different `sHash`, the device has `R`, but the vault has no `root` wrap that opens with it | **Replaced.** Nobody without `R` can make a valid `root` wrap. Offer to republish the copy from Evolu (§6.2 rule 5). |
| Different `sHash`, the device has no `R` (it only used `nip44`), fetched vault is `strict` | Can't verify and can't unlock (§3.2 rule 8). Ask for a strong method or the recovery phrase. **Never** republish the local copy: it could undo a legitimate `makeStrict()`. Keep the local database; once the user unlocks `R` here, migrate its rows into the current one (§3.4) before deleting it. |
| Different `sHash`, the device has no `R`, fetched vault is `compatible` | Can't tell a user change from an attack. Keep the local database, show both options to the user, and republish only on the user's choice. An attacker who can do this can already read the `nip44` wrap, so this is about availability, not secrecy. |
| Vault missing or unreadable | Offer to republish the copy from Evolu, if this device has one. |

Attacks against the strong path all fail: `signer`, `passkey` and `root` wraps can't be forged without the key, and AAD stops wraps being moved between vaults. A downgrade attack on a **new** device (replacing a `strict` vault with a `compatible` one) can make that device open an attacker's empty database, never the user's data; the client warns about the weak level before first use (first row above).

When a vault fails these checks, the client never silently creates a new database. It shows the user what happened and offers what the table allows: republish the copy from Evolu, restore from the recovery phrase, or start a new database.

---

## 7. Support matrix

**App database level:** ✅ strong · 🔶 connection-scoped (§5.2) · ⚠️ weak ("as private as your Nostr DMs").
Shared settings are always ⚠️ by design (§9). The level shown is the **highest the user can choose** with that setup. Every vault starts ⚠️ (unless the app requires strict) and becomes ✅ only when the user makes it strict (§3.2).

### 7.1 By signer and hosting

| Signer ↓ / Hosting → | Own domain (web) | nsite (gateway subdomain) | Mobile app |
|---|---|---|---|
| **Capable signer, verified identity** (extension, iframe signer, NIP-55) | ✅ | ✅ same data on every known gateway | ✅ (Android, NIP-55) |
| **Capable signer, NIP-46 bunker** | 🔶 | 🔶 | 🔶 |
| **Standard signer + client passkey** | ✅ | ✅ on one gateway; other gateways via the recovery phrase | ✅ (associated domain) |
| **Standard signer, no passkey (or no PRF)** | ⚠️ (✅ with the recovery phrase typed on each new device) | ⚠️ (same) | ⚠️ (same) |

### 7.2 New device

| Vault | Setup on the new device | Opens with |
|---|---|---|
| `strict` | A capable signer with a `signer` wrap in the vault | The signer (signer passkey synced, or nsec in the signer) |
| `strict` | A different capable signer | The recovery phrase once, then that signer adds its own wrap |
| `strict` | Standard signer + synced passkey | The passkey |
| `strict` | Standard signer, no passkey | ❌ No access, by design (§3.2 rule 8): recovery phrase, a capable signer, or a downgrade from another device |
| `compatible` | Any signer | The signer alone (that is why it's weak) |
| `strict` | Everything lost, no phrase | ❌ Data is lost. The backup check and reminder (§3.2 rule 3a) exist to prevent this. |

### 7.3 Who can read what

| Party | Shared settings | App DB, strong | App DB, weak | Cross-app secrets ([SECRETS.md](SECRETS.md)) |
|---|---|---|---|---|
| Relays, network, Evolu relay | ❌ | ❌ | ❌ | ❌ |
| Other app, no signer permission | ❌ | ❌ | ❌ | ❌ |
| Other app with sign + decrypt permission | ✅ | ❌ | ✅ | ❌ (needs user approval per item) |
| OAuth/MPC project owner (e.g. Web3Auth `clientId` owner) | ✅ | ✅ if `M` has an `sk` wrap · ❌ with signer passkey only | ✅ | ❌ (passkey required) |
| Compromised signer code or host | ✅ | ✅ | ✅ | ✅ (out of scope) |

---

## 8. Client library

### 8.1 API

```ts
interface EvolustrOptions<S> {
  schema: S;                          // the app's Evolu schema
  relays: string[];
  requireStrong?: boolean;            // only strict databases (§2, §3.2 rule 1); default false
  appId?: string;                     // native apps; web uses §3.3
  passkey?: { rpName: string };       // enables client passkeys
  knownNsiteGateways?: string[];      // for appId = nsite:<npub>
}

interface Evolustr<S> {
  /** Never prompts for a passkey. Safe to call on page load. */
  connect(): Promise<
    | { state: "ready"; pubkey: string; db: EvoluInstance<S>; status: Status }
    | { state: "needsUserAction";
        action: "passkey" | "signerUnlock" | "recoveryPhrase" | "setupStrong" }
    | { state: "vaultChanged"; options: VaultChoice[] }
  >;
  /** Call from a click. Completes whatever connect() asked for.
   *  For action "recoveryPhrase", pass the words. */
  unlock(input?: { recoveryPhrase?: string }): Promise<Ready<S>>;
  /** Completes a "vaultChanged" state with one of the offered options. */
  resolveVaultChange(choice: VaultChoice, input?: { recoveryPhrase?: string }): Promise<Ready<S>>;
  /** Unlock R on this device while already "ready" (e.g. after a nip44-only unlock),
   *  so strong methods can be added. With no input: tries a synced passkey (from a
   *  click) or a capable signer's wrap. With the phrase: checks it against the vault. */
  unlockRoot(input?: { recoveryPhrase?: string }): Promise<Status>;
  enrollPasskey(): Promise<void>;     // from a click; doesn't change the level. Needs R:
                                      // call unlockRoot() first if canAddStrongMethod is false
  makeStrict(opts?: { acceptDeviceLoss?: boolean }): Promise<void>; // user's choice; backup check (§3.2 rule 3a), replaces S (§3.4)
  downgrade(): Promise<void>;         // user's choice (§3.2 rule 7)
  showRecoveryPhrase(): Promise<string>; // R as 12 words; creates R if the vault has none
  restoreFromPhrase(words: string): Promise<Ready<S>>; // same as unlock({ recoveryPhrase })
  settings: {
    get<K extends keyof SharedSettings>(key: K): SharedSettings[K]; // app ?? shared ?? default
    setShared<K extends keyof SharedSettings>(key: K, value: SharedSettings[K]): Promise<void>;
  };
  logout(opts?: { deleteLocalData?: boolean }): Promise<void>; // removes cached S and R (§6.2 rule 6)
}

type Ready<S> = { pubkey: string; db: EvoluInstance<S>; status: Status };
type VaultChoice = "republishCopy" | "followRelay" | "restorePhrase" | "startNew";

interface Status {
  signer: "capable-verified" | "capable-connection" | "standard";
  mode: "strict" | "compatible";      // from the vault
  level: "strong" | "connection" | "weak";
  canMakeStrict: boolean;             // R is unlocked here, so strict is possible
  backupRecommended: boolean;         // strict (or about to be) with one strong method and no confirmed phrase
  canAddStrongMethod: boolean;        // false after a nip44-only unlock of a vault that has R (§3.1)
  unlockedWith: "signer" | "passkey" | "nip44" | "recovery";
  passkeySupported: boolean;          // PRF available on this device
}
```

### 8.2 Unlock order

1. Fetch the vault (§6.2) and check it against the local database for this `(pubkey, appId)` (§6.3).
2. Try methods that need no click: the `signer` wrap whose `signerId` matches `capabilities().signerId` (if the signer is ready), a cached `R`, then `nip44` (**only** if the vault is `compatible`).
3. If only a `passkey` wrap matches, or the signer needs unlocking, return `needsUserAction`. `unlock()` does the rest from a click. If nothing matches, ask for the recovery phrase.
4. If no vault exists:
   - without `requireStrong`: create it `compatible`, with any strong wraps this device can also make;
   - with `requireStrong`: return `needsUserAction: "setupStrong"`. `unlock()` then creates `R`, adds a strong method (passkey or signer), runs the backup check (§3.2 rule 3a), and publishes the **first** vault already `strict`.
5. After unlocking, add any missing strong wrap this device can make (the level stays as it is). This needs `R`: it runs after an unlock through a strong method or the phrase, or when this device creates `R`. After a `nip44`-only unlock of a vault that already has `R`, nothing is added and `status.canAddStrongMethod` is false (§3.1). The app can then offer **"Use this device for passkeys"**, which calls `unlockRoot()` (passkey or signer) or `unlockRoot({ recoveryPhrase })`. The database stays open throughout; afterwards `canAddStrongMethod` is true and `enrollPasskey()` works.
6. If `requireStrong` is set and an existing vault is `compatible`, the app tells the user it needs a strict database and offers `makeStrict()`. A user who declines can't use that app.

### 8.3 Packages

| Package | Purpose |
|---|---|
| `@evolustr/client` | Client logic. Framework-agnostic. Web and workers. |
| `@evolustr/react` | `<EvolustrProvider>`, `useEvolustr()`, `useSetting()`. |
| `@evolustr/rn` | React Native: NIP-46 and NIP-55, native passkeys, secure-store cache of `S` and `R`. |
| `@evolustr/signer` | The signer side (§5.6): `M`, `signerKey`, `signerId`, key derivation, request handling, vault-event filter, optional cross-app secrets. Adapters for iframe, NIP-46 and extension hosts. Embedded by nostr-shard-signer. |

---

## 9. Shared settings

Shared settings are **not** an Evolu database: one small event is enough, and a second database would mean a second SQLite worker and sync connection on every page.

### 9.1 Storage

One Kind 30078 event per user, `d = "evolustr:settings:v1"`, content NIP-44 self-encrypted. It's `weak` by design: any app with decrypt permission can read it, which is the point. Never put secrets or personal data in it.

```jsonc
{
  "v": 1,
  "values": {
    "theme":    { "value": "dark", "at": 1730000000 },
    "language": { "value": "cs",   "at": 1729990000 }
  }
}
```

- **Merge per field, last write wins:** before publishing, fetch the current event and keep, for each key, the entry with the newer `at`. Two devices changing different settings don't overwrite each other.
- Every write needs a signature and a NIP-44 encryption, so apps write shared settings only on an explicit user action ("Use for all apps"). On standard signers that may show a prompt.
- Apps keep a copy of the decoded settings in their own Evolu database, so later page loads don't need a decrypt prompt.

### 9.2 Schema v1

```ts
interface SharedSettings {
  theme: "light" | "dark" | "system";       // default "system"
  language: string;                          // BCP 47, default from navigator
  locale: string;                            // number and date formatting
  timeZone: string;                          // IANA
  reducedMotion: boolean;
  fontScale: number;                         // 0.75 – 2.0
  density: "compact" | "comfortable";
}
```

- App-specific overrides live in the app's Evolu database, table `evolustr_setting(key TEXT PRIMARY KEY, value JSON)`.
- `settings.get(key)` reads the app value, then shared, then the default.
- New keys use namespaces (`x-<vendor>-<name>`) until a new schema version standardises them. Unknown keys are kept, never deleted.

---

## 10. Rejected designs (for the record)

| Design | Why rejected |
|---|---|
| Seed derived from `signEvent(...).sig` | Signatures aren't deterministic (random nonce, `created_at`), and any app can request the same signature. |
| `userSign(appSign(npub))` | Any app can fake or replay `appSign` and ask the signer to sign it. |
| Inner AES layer keyed by `HMAC(server_secret, pubkey)`, released with NIP-98 | NIP-98 doesn't bind a request to the app that asked for the signature. App B gets a valid header from the user's signer and calls the server from its own backend. |
| Shared nsite key broker checking the `Origin` header | Any non-browser client can forge `Origin`. |
| Custom NIP-46 method as the only path | Works only with one signer. Generalised into the Evolustr Signer API with fallbacks. |
| Evolu syncing over Nostr relays | Evolu has its own sync protocol and relay. Nostr is used for identity and vaults only. |
| Shared settings as a second Evolu database (v0.2–v0.3) | A second SQLite worker and sync connection per page for a few harmless values. Replaced by one event (§9). |
| Passkey and `nip44` wraps in the same vault (v0.2) | The database is only as strong as its weakest way to `S` (§3.2). |
| `d`-tag hashed without the pubkey (v0.2–v0.3) | Same tag for every user of an app, so one query listed all its users (§6.1). |
| Personal vault inside Evolustr (v0.2–v0.3) | A signer feature unrelated to app databases. Moved to [SECRETS.md](SECRETS.md). |
| Always requiring a second strong method or the phrase before `strict` (v0.6–v0.10) | Too much friction when the passkey is already synced by the user's provider. Now scaled to the risk (§3.2 rule 3a). |
| Automatic upgrade to the strongest level (v0.6) | Took the choice from the user. Strict is opt-in (§3.2). |
| App-chosen `mode` option (v0.4–v0.5) | Let an app's configuration downgrade a vault the user had made strict. The vault records its own mode; apps can only require strong. |
| Signer-held vault pins (v0.4–v0.5) | Needed storage outside Nostr and Evolu, and tied to one signer. |
| Optional server with a write-once vault commitment (v0.2–v0.5) | Only protected `compatible` vaults, where an attacker gains nothing by replacing the vault. Not worth a backend. |
| Wrap ids (`w1`, `w2`) in the AAD (v0.3–v0.5) | Concurrent additions collided. Wraps are identified by `signerId` / `credId`. |
| Strong methods wrapping `S` directly (v0.2–v0.7) | Replacing `S` meant re-creating every wrap, which needs every passkey and every signer present at once. Strong methods now wrap `R` (§3.1). |
| Recovery phrase = Evolu mnemonic of `S` (v0.3–v0.7) | Changed with every rotation. The phrase is now `R`, which never changes. |
| `rotatedTo` marker synced through Evolu (v0.6–v0.7) | Devices had to wait for Evolu sync to learn about a rotation. Replaced by the vault's `history` (§3.4). |
| A single `previousSHash` (v0.8) | After two rotations while a device was offline, the migration cut-off was wrong and could drop edits. Replaced by `history` (§3.4). |
| `R` reachable through `nip44` in `compatible` mode (considered for v0.9) | Would let any app that read the weak vault keep `R` after `makeStrict()`. Instead, nip44-only devices unlock `R` once before adding strong methods (§3.1). |
| Signer vault `d`-tag based on `signerId` (v0.6–v0.7) | `signerId` comes from `M`, so a new device couldn't find the vault that holds `M`. Now based on `signerKey` (§5.3). |
| A random PRF salt per passkey wrap (v0.3–v0.7) | Several salts need `evalByCredential`, which fewer browsers support. One `prfInput` per vault (§4.1). |
| One local Evolu database name per app (v0.2–v0.7) | Two Nostr accounts on one browser mixed their data and vault copies. Now one per `(pubkey, appId)` (§2). |
| Our own hashed database name with the pubkey (v0.8–v0.11) | Not needed: Evolu already separates local databases by AppOwner (§2). |

---

## 11. Open questions

1. ~~**Evolu API**~~ **Checked against Evolu 8.26 (`@evolu/common`):** owner from a 16-byte secret (12 words) with `createAppOwner`, mnemonic round trip, `upsert` with a fixed `id`, system columns `createdAt` / `updatedAt` / `isDeleted`, two databases open at once: all present. Corrections taken into the spec: the app must supply the owner on every start (§2, §6.2 rule 6), and copied rows lose their original `createdAt` (§3.4).
2. **PRF support:** measure which browsers, operating systems, authenticators and hybrid (QR) flows return PRF output, which return it already at `create()`, and where passkey creation and use work inside a cross-origin iframe (for iframe signers).
3. **Create race:** how to move rows written to the losing data secret (§6.2 rule 2) into the winner.
4. **Compatible vault replaced, new device:** the new device may write into an attacker's empty database until another device restores the real vault. Define how those rows are moved back.
5. **Known nsite gateways:** who maintains the list, and how it is distributed (config or a Nostr list event).
6. **NIP-46 method names:** agree on them with bunker developers, ideally as a NIP.
7. **Adding a device without the phrase:** a way for a device that has `R` to hand it to a new device the user is holding (for example a QR code shown on one and scanned by the other), so users in `compatible` mode don't need the recovery phrase to add a strong method on a second device.
8. **Rotating `M`:** a signer that replaces `M` gets a new `signerId`. Define how it re-adds its wraps to every app vault it knows, or whether old wraps are left to the recovery phrase.

---

## 12. Implementation phases

1. `@evolustr/client` with `compatible` vaults: §6.2 relay rules, §6.3 checks, copy in Evolu, recovery phrase (`R`), shared settings event.
2. Client passkeys (§4), opt-in `strict` vaults and rotation (§3.2, §3.4), `requireStrong` first setup, for web, then nsite.
3. `@evolustr/signer` (§5.6), embedded in nostr-shard-signer as the first host.
4. `@evolustr/rn` (NIP-55, native passkeys).
5. Propose the Signer API as a NIP.
6. Cross-app secrets ([SECRETS.md](SECRETS.md)) as an optional module of `@evolustr/signer`.

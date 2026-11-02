# Evolustr Specification

**Status:** Draft v0.6
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

Evolustr works with **any** Nostr signer. Signers that implement the Signer API, or a **passkey on the app's own domain** (§4), make the app database strong. §7 lists every combination.

### 1.1 Terms

| Term | Meaning |
|---|---|
| **Standard signer** | Any NIP-07, NIP-46 or NIP-55 signer without the Evolustr Signer API (Alby, nos2x, nsec.app, Amber today). |
| **Evolustr-capable signer** | A signer that implements the Evolustr Signer API (§5). |
| **Owner secret `S`** | The random secret behind one app database (its 12-word Evolu mnemonic). |
| **Vault event** | A Kind 30078 event on Nostr relays that stores `S` in encrypted form (§6). |
| **Wrap** | One encrypted copy of `S` inside a vault event, made with one unlock method (§3). |
| **Client passkey** | A WebAuthn passkey the **app** registers on **its own domain**. Needs no special signer. |
| **Signer passkey** | A passkey a **capable signer** registers on **its own origin**, used for every app. |
| **Level** | `strong` or `weak` (§3.2). |

### 1.2 Design principles

1. **No backend, no third-party storage.** Data lives only on Nostr relays (vault events, settings) and in Evolu (the app database and its sync). Signers and clients keep nothing elsewhere except their normal device-local caches.
2. **Any signer works.** Capable signers and passkeys add strength. Without them the library still works, at a lower level.
3. **Maximum available security.** A database is as strong as the user's setup allows. It only becomes weaker when the user explicitly chooses so (§3.2).
4. **Honest security levels.** The database reports its level, and the docs never claim more.
5. **Only browser- or OS-enforced identities separate apps:** web origin (`event.origin`, extension sender origin, WebAuthn `rpId`) or the Android calling package. Self-asserted app names and URLs never do.
6. **One Evolu instance per page.**

---

## 2. The app database

- One per user per app, keyed by `appId` (§3.3). It is the app's private storage and can hold the app's own secrets.
- Its owner secret `S` lives in a vault event (§6) with one or more wraps (§3).
- Its level is set by the **vault**, not by the app's code (§3.2). The app can only require a minimum: `requireStrong: true` means the app refuses to open a weak database and asks the user to set up a strong unlock first.

---

## 3. Unlock methods (wraps)

### 3.1 Wrap types

| Wrap | Wrap key | Identified by | Level | Needs |
|---|---|---|---|---|
| `signer` | Key from a capable signer, derived for the caller's verified `appId` (§5.3) | `signerId` | strong | Evolustr-capable signer |
| `passkey` | PRF output of a client passkey, `rpId` = the app's host (§4) | `credId` | strong | WebAuthn PRF on the user's platform |
| `nip44` | NIP-44 self-encryption, user → user, through the user's signer | (one per vault) | weak | Any signer with NIP-44 |
| `recovery` | None. The 12-word mnemonic of `S`, written down by the user | — | strong (offline) | The user keeping it safe |

`signer` and `passkey` wraps use **AES-256-GCM** with a random 12-byte IV and
`AAD = "evolustr/v1|" + pubkey + "|" + appId + "|" + wrapType + "|" + (signerId | credId)`.
Binding the key's own identifier (rather than a position or counter) means two devices that add wraps at the same time never collide, and wraps can be merged freely.

A vault may hold **several** wraps of the same type: one `signer` wrap per capable signer the user uses (each signer has its own `M`, §5.3), and one `passkey` wrap per passkey.

`@noble/ciphers` and `@noble/hashes` are used everywhere, so web, workers and React Native give the same results.

### 3.2 Levels: maximum by default, lower only by choice

**A database's level is the level of its weakest wrap.** If a vault holds both a `passkey` wrap and a `nip44` wrap, any app with decrypt permission ignores the passkey and uses `nip44`. So a vault is in one of two states, recorded in its `mode` field (§6.1), which is the **only** source of truth:

| `mode` | Wraps | Level |
|---|---|---|
| `compatible` | `nip44` plus any others | weak |
| `strict` | strong wraps only | strong |

Rules:

1. **A new vault starts at the strongest state the device can create.** With a strong wrap available and a safety net confirmed (rule 3), it's created `strict`. Otherwise `compatible`.
2. **Upgrade is automatic.** As soon as a device that opened a `compatible` vault can create a strong wrap (the user has a capable signer, or enrolls a passkey), the client upgrades to `strict` after the safety net is in place.
3. **Safety net first.** Before a vault becomes `strict`, the user confirms the recovery phrase **or** has a second strong unlock method. This is the only user step in an upgrade. Without it, losing one passkey would lose the data.
4. **Upgrading rotates `S`.** Dropping the `nip44` wrap doesn't make the old `S` secret again, because relays and other apps may have kept copies. The client creates a new `S'`, moves the data (§3.4) and publishes a `strict` vault for `S'`.
5. **Clients never add a `nip44` wrap to a `strict` vault**, whatever the app's code or configuration says.
6. **A `strict` vault ignores `nip44`.** A client reading a `strict` vault never tries a `nip44` wrap, even if one appears on a relay. A vault with no strong wrap the client can use is treated as **attacked or unavailable** (§6.3), never as a fallback.
7. **Downgrade only by the user, on a device that can unlock.** `downgrade()` adds a `nip44` wrap and sets `mode: "compatible"`, after an explicit confirmation that names the risk.
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

### 3.4 Moving data to a new owner (rotation)

Evolu stores CRDT messages tied to the owner, so a database can't be copied as a SQLite file.

1. Open the old database (`S`) and the new one (`S'`).
2. For every table in the app's schema (not Evolu's internal tables), read the rows and insert them into `S'` **through Evolu's mutation API**, so `S'` gets valid timestamps of its own.
3. Write a row `evolustr_meta(key = "rotatedTo", value = sHash(S'))` into the **old** database. Evolu syncs it to devices that are offline at the time.
4. A device that later opens the old database and finds `rotatedTo` unlocks `S'` (it has to be able to: rotation only happens to `strict`, see rule 8 above), moves its own **unsynced** changes into `S'` the same way, and stops using `S`.

---

## 4. Client passkeys (no capable signer needed)

This is how an app gets a strong database with **any** signer, including standard ones.

### 4.1 Rules for every passkey operation

- **Only from a user gesture.** Passkey calls, and any popup, need a user click. `connect()` never prompts for a passkey on page load. If a passkey is needed, it reports `needsUserAction: "passkey"` and the app shows an **Unlock** button that calls `unlock()`.
- **Check PRF.** If the platform or authenticator returns no PRF output, client passkeys are unavailable on that device.

### 4.2 Enroll

1. Unlock the database once by any method, or create it (§6.2).
2. Pick a random 32-byte `salt`. Let `prfInput = SHA-256("evolustr/v1/prf|" + salt)`.
3. From a click, call `navigator.credentials.create()` with:
   - `rp.id` = the page's host. For an nsite, the exact gateway subdomain.
   - `user.id` = `SHA-256(pubkey)`, `user.name` = the npub.
   - `residentKey: "required"`, `userVerification: "required"`.
   - `excludeCredentials` = the `credId`s of every `passkey` wrap in the vault with this `rpId`. Without it, a second enrollment on the same provider can replace the first passkey instead of adding one.
   - `extensions: { prf: { eval: { first: prfInput } } }`.
4. If `getClientExtensionResults().prf` has `results.first`, use it. One prompt, done.
5. If it only reports `prf.enabled: true` without results, show **"Finish passkey setup"** and, **from that new click**, call `navigator.credentials.get()` for the new credential with the same `prfInput`. A second call chained right after `create()` can fail, because the first one used up the click.
6. If PRF is not enabled, stop and tell the user this authenticator can't be used.
7. Wrap key = `HKDF-SHA256(prfOutput, salt, "evolustr/v1/wrap|" + appId)`. Add a `passkey` wrap with `rpId`, `credId` and `salt` (§6.2). If the vault is `compatible`, this starts the upgrade (§3.2 rules 2–4).

### 4.3 Unlock on a device

1. `getPublicKey()` from the signer (no decrypt prompt).
2. Fetch the vault. Collect `passkey` wraps whose `rpId` equals the current host.
3. From a click, call `navigator.credentials.get()` with `allowCredentials` = their `credId`s and each wrap's PRF input.
4. This works with **synced** passkeys (iCloud Keychain, Google Password Manager, password managers) and, where the platform supports PRF over it, with a **phone passkey via QR** (hybrid).

### 4.4 Where client passkeys work

| Environment | Notes |
|---|---|
| Own domain | ✅ The normal case. |
| nsite | ⚠️ **Locked to one gateway.** The `rpId` is the gateway subdomain, and a page on gateway B can't use gateway A's passkey. To add a passkey on gateway B, the database must first be unlocked there by another method: a capable signer or the recovery phrase (or `nip44` while the vault is still `compatible`). WebAuthn Related Origin Requests don't help, because the developer doesn't control the gateway domains. |
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
- `signerId = hex(SHA-256("evolustr/v1/signer-id|" + M))`, first 8 bytes. It tells clients which `signer` wrap belongs to the current signer. Two capable signers (say an iframe signer on desktop and a NIP-55 signer on Android) have different `M` and different `signerId`, and each adds its own wrap to the vault.
- Wrap key for a caller: `K = HKDF-SHA256(M, "evolustr/v1|app|" + appId)`. HKDF is one-way, so one app's key reveals nothing about another's or about `M`.
- `M` is stored **only on Nostr relays**, in the signer's own vault event (`d = "evolustr:v1:signer:<signerId>"`), with strong wraps only:
  - `sk`: AES-GCM keyed with `HKDF(nsec, "evolustr/v1/signer-wrap")`. Only for signers that hold the nsec.
  - **Signer passkey**: PRF output of a passkey whose `rpId` is the signer's own origin. Needed by signers that don't hold the nsec (passthrough signers).
  - **Never `nip44`.** That would give `M`, and so every app's key, to any app with decrypt permission. A signer that can't use either option above doesn't offer the API.
- A signer may cache the unlocked `M` on the device, as it caches its keys. It stores nothing else for Evolustr.

### 5.4 Methods

```ts
interface EvolustrSignerApi {
  version: 1;
  capabilities(): Promise<{
    identity: "verified" | "connection";
    appId: string;                 // as the signer sees the caller
    signerId: string;              // which signer wraps this signer can open
    ready: boolean;                // M is unlocked
    signerPasskey: boolean;        // M can be unlocked by a signer passkey
  }>;
  /** Wrap key for the caller's app database. The signer computes appId itself. */
  getWrapKey(): Promise<Uint8Array>;            // 32 bytes
  /** Register a signer passkey. Must be called from a user gesture. */
  enrollPasskey(): Promise<void>;
}
```

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

- **Integration:** the iframe's message handler passes `evolustr_*` requests to `evolustr.handle()` with `origin: event.origin`. `nostr-bridge.js` adds `window.nostr.evolustr` and forwards its calls to the iframe, the same way it forwards `signEvent`. The auto-approve list calls `isProtectedEvent()`.
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
  "mode": "strict",             // "strict" | "compatible": the source of truth (§3.2)
  "created": 1730000000,        // creation time of S, never changes
  "sHash": "<hex SHA-256(S), first 8 bytes>",
  "wraps": [
    { "type": "signer", "signerId": "<hex 8B>", "iv": "…", "ct": "…" },
    { "type": "signer", "signerId": "<another signer>", "iv": "…", "ct": "…" },
    { "type": "passkey", "rpId": "app.example.com",
      "credId": "<base64url>", "salt": "<base64url 32B>", "iv": "…", "ct": "…" }
    // a "compatible" vault also has exactly one: { "type": "nip44", "ct": "…" }
  ]
}
```

`recovery` is never stored. The user writes it down.

### 6.2 Client rules

1. **Lookup:** query all configured relays and wait for EOSE from each, or a timeout. Never decide "no vault exists" from a single relay.
2. **Create** only when every relay answered and none has the vault. After publishing, fetch again. If a vault with a different `sHash` and an earlier `created` appears, keep the earlier one (moving any rows already written is open question §11.3).
3. **Adding a wrap:** fetch, add the wrap (wraps are keyed by `signerId` / `credId`, so concurrent additions merge), publish, fetch again to check. Never drop a wrap without an explicit user action, except the `nip44` wrap during an upgrade (§3.2 rule 4).
4. **Self-healing:** after unlocking, re-add your own wrap if a concurrent update dropped it. Never re-add `nip44` to a `strict` vault (§3.2 rule 5).
5. **Keep a copy in Evolu:** after a successful unlock, store the vault event in the app database itself (`evolustr_meta`, key `vault`). Evolu syncs it, so every device that has the database also has the last good vault (§6.3).

### 6.3 Hostile overwrites

Any app the user lets sign can publish a replacement vault event. Capable signers refuse to auto-approve it (§5.5 rule 2), but standard signers may sign it without asking. Nothing extra needs storing to handle this:

| Attack | `strict` vault | `compatible` vault |
|---|---|---|
| Replace with a vault whose `nip44` wrap holds a secret the attacker knows | ❌ The user's data stays safe: it is under the real `S`, which the attacker can't reach. Devices that have the database see the change against the copy in Evolu and restore it. A **new** device sees a `compatible` vault, would open the attacker's empty database, and is warned first (below). | The attacker gains nothing: anyone who can do this can already decrypt the real `nip44` wrap and read the data. A new device may open the attacker's empty database (open question §11.4). |
| Replace with forged `signer` or `passkey` wraps | ❌ Fails: AES-GCM with AAD can't be forged without the key. | ❌ Fails. |
| Replace with garbage, or delete | DoS only. Any device that has the database republishes the copy kept in Evolu (§6.2 rule 5), after telling the user. | Same. |

A downgrade attack on a new device (replacing a `strict` vault with a `compatible` one) is the reason for rule 6: a client that has never seen the vault can't know it used to be strict. It therefore treats a vault whose `created` and `sHash` differ from the copy in an already-open database as replaced. On a device with no copy at all, the client shows the vault's level before first use, so a weak vault is never silently trusted with data the user expects to be strong.

When a vault fails these checks, the client never silently creates a new database. It shows the user what happened and offers: republish the copy from Evolu (if this device has it), restore from the recovery phrase, or start a new database.

---

## 7. Support matrix

**App database level:** ✅ strong · 🔶 connection-scoped (§5.2) · ⚠️ weak ("as private as your Nostr DMs").
Shared settings are always ⚠️ by design (§9). The level shown is the **maximum** for that setup; the vault reaches it automatically once the safety net is confirmed (§3.2).

### 7.1 By signer and hosting

| Signer ↓ / Hosting → | Own domain (web) | nsite (gateway subdomain) | Mobile app |
|---|---|---|---|
| **Capable signer, verified identity** (extension, iframe signer, NIP-55) | ✅ | ✅ same data on every known gateway | ✅ (Android, NIP-55) |
| **Capable signer, NIP-46 bunker** | 🔶 | 🔶 | 🔶 |
| **Standard signer + client passkey** | ✅ | ✅ on one gateway; other gateways only via the recovery phrase | ✅ (associated domain) |
| **Standard signer, no passkey (or no PRF)** | ⚠️ | ⚠️ | ⚠️ |

### 7.2 New device

| Vault | Setup on the new device | Opens with |
|---|---|---|
| `strict` | A capable signer with a `signer` wrap in the vault | The signer (signer passkey synced, or nsec in the signer) |
| `strict` | A different capable signer | The recovery phrase once, then that signer adds its own wrap |
| `strict` | Standard signer + synced passkey | The passkey |
| `strict` | Standard signer, no passkey | ❌ No access, by design (§3.2 rule 8): recovery phrase, a capable signer, or a downgrade from another device |
| `compatible` | Any signer | The signer alone (that is why it's weak) |
| `strict` | Everything lost, no phrase | ❌ Data is lost. The safety net (§3.2 rule 3) exists to prevent this. |

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
  requireStrong?: boolean;            // refuse weak databases (§2); default false
  appId?: string;                     // native apps; web uses §3.3
  passkey?: { rpName: string };       // enables client passkeys
  knownNsiteGateways?: string[];      // for appId = nsite:<npub>
}

interface Evolustr<S> {
  /** Never prompts for a passkey. Safe to call on page load. */
  connect(): Promise<
    | { state: "ready"; pubkey: string; db: EvoluInstance<S>; status: Status }
    | { state: "needsUserAction";
        action: "passkey" | "signerUnlock" | "recoveryPhrase" | "confirmSafetyNet" }
    | { state: "vaultReplaced"; options: ("republishCopy" | "restorePhrase" | "startNew")[] }
  >;
  /** Call from a click. Completes whatever connect() asked for, including an upgrade. */
  unlock(): Promise<{ pubkey: string; db: EvoluInstance<S>; status: Status }>;
  enrollPasskey(): Promise<void>;     // from a click; may start an upgrade (§3.2)
  downgrade(): Promise<void>;         // explicit user choice (§3.2 rule 7)
  showRecoveryPhrase(): Promise<string>;
  restoreFromPhrase(words: string): Promise<void>;
  settings: {
    get<K extends keyof SharedSettings>(key: K): SharedSettings[K]; // app ?? shared ?? default
    setShared<K extends keyof SharedSettings>(key: K, value: SharedSettings[K]): Promise<void>;
  };
  logout(): Promise<void>;            // wipes cached secrets
}

interface Status {
  signer: "capable-verified" | "capable-connection" | "standard";
  mode: "strict" | "compatible";      // from the vault
  level: "strong" | "connection" | "weak";
  canUpgrade: boolean;                // a strong wrap could be added on this device
  unlockedWith: "signer" | "passkey" | "nip44" | "recovery";
  passkeySupported: boolean;          // PRF available on this device
}
```

### 8.2 Unlock order

1. Fetch the vault (§6.2) and compare it with the copy in Evolu, if this device has the database (§6.3).
2. Try wraps that need no click: the `signer` wrap whose `signerId` matches `capabilities().signerId` (if the signer is ready), then `nip44` (**only** if the vault is `compatible`).
3. If only a `passkey` wrap matches, or the signer needs unlocking, return `needsUserAction`. `unlock()` does the rest from a click. If nothing matches, ask for the recovery phrase.
4. If no vault exists, create it at the strongest state available (§3.2 rule 1).
5. After unlocking, add any missing strong wrap this device can make. If the vault is `compatible` and a strong wrap now exists, start the upgrade (§3.2 rules 2–4), asking for the safety net if it isn't confirmed yet.
6. If `requireStrong` is set and the result is weak, return `needsUserAction` with the steps to make it strong.

### 8.3 Packages

| Package | Purpose |
|---|---|
| `@evolustr/client` | Client logic. Framework-agnostic. Web and workers. |
| `@evolustr/react` | `<EvolustrProvider>`, `useEvolustr()`, `useSetting()`. |
| `@evolustr/rn` | React Native: NIP-46 and NIP-55, native passkeys, secure-store cache of the unlocked `S`. |
| `@evolustr/signer` | The signer side (§5.6): `M`, `signerId`, key derivation, request handling, vault-event filter, optional cross-app secrets. Adapters for iframe, NIP-46 and extension hosts. Embedded by nostr-shard-signer. |

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
| Passkey and `nip44` wraps in the same vault (v0.2) | The database is only as strong as its weakest wrap (§3.2). |
| `d`-tag hashed without the pubkey (v0.2–v0.3) | Same tag for every user of an app, so one query listed all its users (§6.1). |
| Personal vault inside Evolustr (v0.2–v0.3) | A signer feature unrelated to app databases. Moved to [SECRETS.md](SECRETS.md). |
| App-chosen `mode` option (v0.4–v0.5) | Let an app's configuration downgrade a vault the user had made strict. The vault now records its own mode; apps can only require strong (§3.2). |
| Signer-held vault pins (v0.4–v0.5) | Needed storage outside Nostr and Evolu, and tied to one signer. Strict vaults can't be forged anyway, and the copy in Evolu covers deletion (§6.3). |
| Optional server with a write-once vault commitment (v0.2–v0.5) | Only protected `compatible` vaults, where an attacker gains nothing by replacing the vault. Not worth a backend. |
| Wrap ids (`w1`, `w2`) in the AAD (v0.3–v0.5) | Concurrent additions collided. Wraps are now identified by `signerId` / `credId`. |

---

## 11. Open questions

1. **Evolu API:** confirm the current release's API for restoring an owner from a mnemonic, and for reading every app table during rotation (§3.4).
2. **PRF support:** measure which browsers, operating systems, authenticators and hybrid (QR) flows return PRF output, which return it already at `create()`, and where passkey creation and use work inside a cross-origin iframe (for iframe signers).
3. **Create race:** how to move rows written to the losing owner (§6.2 rule 2) into the winner.
4. **Compatible vault replaced, new device:** the new device may write into an attacker's empty database until another device restores the real vault. Define how those rows are moved back.
5. **Known nsite gateways:** who maintains the list, and how it is distributed (config or a Nostr list event).
6. **NIP-46 method names:** agree on them with bunker developers, ideally as a NIP.
7. **Rotating `M`:** a signer that replaces `M` gets a new `signerId`. Define how it re-adds its wraps to every vault it knows, or whether old wraps are left to the recovery phrase.

---

## 12. Implementation phases

1. `@evolustr/client` with `compatible` vaults: §6.2 relay rules, copy in Evolu, recovery phrase, shared settings event.
2. Client passkeys (§4), `strict` vaults and the automatic upgrade with rotation (§3.2, §3.4), for web, then nsite.
3. `@evolustr/signer` (§5.6), embedded in nostr-shard-signer as the first host.
4. `@evolustr/rn` (NIP-55, native passkeys).
5. Propose the Signer API as a NIP.
6. Cross-app secrets ([SECRETS.md](SECRETS.md)) as an optional module of `@evolustr/signer`.

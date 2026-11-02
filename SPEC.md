# Evolustr Specification

**Status:** Draft v0.4
**Scope:** Nostr identity → one Evolu (local-first, E2E-encrypted SQLite) database per app, synced across devices, with **no mandatory backend**.

---

## 1. Overview

A user signs in to an app with any Nostr signer. Evolustr then opens **that app's Evolu database** for the user, on any device.

Evolustr has three parts:

| Part | What it is |
|---|---|
| **App database** | One Evolu database per user per app: the app's private data and its secrets. This is the core of Evolustr. |
| **Shared settings** | One small Nostr event with harmless preferences (theme, language, …) that every app can read. **Not** an Evolu database (§9). |
| **Evolustr Signer API** | An optional protocol any signer can implement, to give each app a strong key without a passkey (§5). |

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

1. **No backend is required.** Everything works from static hosting, including nsites (NIP-5A). An optional server (§10) adds hardening only.
2. **Any signer works.** Capable signers and passkeys add strength. Without them the library still works, at a lower level.
3. **Honest security levels.** The app database reports its level, and the docs never claim more.
4. **One secret, several ways to unlock it**, but a strong database never also has a weak way in (§3.2).
5. **Only browser- or OS-enforced identities separate apps:** web origin (`event.origin`, extension sender origin, WebAuthn `rpId`) or the Android calling package. Self-asserted app names and URLs never do.
6. **One Evolu instance per page.** Nothing else Evolustr stores needs a second database.

---

## 2. The app database

- One per user per app, keyed by `appId` (§3.3). It is the app's private storage and can hold the app's own secrets.
- Its owner secret `S` lives in a vault event (§6) with one or more wraps (§3).
- Its level is `strong` or `weak` (§3.2). The app chooses which it requires with `mode` (§8):
  - **`compatible`** (default): a `nip44` wrap is allowed. Works with every signer, on every device, with nothing to set up. Level `weak`.
  - **`strict`**: only strong wraps. The client **never** reads or writes a `nip44` wrap. Level `strong`. Users need a capable signer, a client passkey, or the recovery phrase.

---

## 3. Unlock methods (wraps)

### 3.1 Wrap types

| Wrap | Wrap key | Who can create and open it | Level | Needs |
|---|---|---|---|---|
| `signer` | Key from a capable signer, derived for the caller's verified `appId` (§5.3) | Only that app, through that signer | strong | Evolustr-capable signer |
| `passkey` | PRF output of a client passkey, `rpId` = the app's host (§4) | Only pages on that host | strong | WebAuthn PRF on the user's platform |
| `nip44` | NIP-44 self-encryption, user → user, through the user's signer | **Any app** the user lets decrypt | weak | Any signer with NIP-44 |
| `recovery` | None. The 12-word mnemonic of `S`, written down by the user | Whoever has the words | strong (offline) | The user keeping it safe |

`signer` and `passkey` wraps use **AES-256-GCM** with a random 12-byte IV and
`AAD = "evolustr/v1|" + pubkey + "|" + appId + "|" + wrapType + "|" + wrapId`.
`@noble/ciphers` and `@noble/hashes` are used everywhere, so web, workers and React Native give the same results.

### 3.2 Levels and the strict rules

**A database's level is the level of its weakest wrap.** If a vault holds both a `passkey` wrap and a `nip44` wrap, any app with decrypt permission ignores the passkey and uses `nip44`. So:

1. **Never mix.** A vault has either strong wraps only (`strict`), or a `nip44` wrap plus any others (`compatible`, level `weak`).
2. **In `strict` mode the client ignores `nip44` wraps entirely**, even when one appears on a relay. A vault that has no strong wrap the client can use is treated as **missing or attacked**, never as a fallback (§6.3).
3. **Moving from `compatible` to `strict` rotates `S`.** Removing the `nip44` wrap doesn't make the old `S` secret again: relays and other apps may have kept copies of that wrap. The client creates a new `S'`, copies the data from the old database into the new one, publishes a strict vault for `S'` and stops using `S`.
4. **Moving from `strict` to `compatible`** (adding `nip44`) is allowed only on an explicit user action, and the level becomes `weak`.

### 3.3 App identity (`appId`)

`appId` names which vault to use. Security comes from the passkey `rpId` or the signer's verified caller identity, never from `appId` itself.

| Environment | `appId` |
|---|---|
| Web app on its own domain | The page origin, `https://app.example.com` |
| nsite on a known gateway | `nsite:<site-npub>`, taken from `<npub>.gateway.tld`, so the same vault is used on every gateway |
| nsite on an unknown gateway | The page origin |
| Android | `android:<package name>` (verified for NIP-55 signers) |
| iOS / other native | `ios:<bundle id>` (self-asserted) |

---

## 4. Client passkeys (no capable signer needed)

This is how an app gets a strong database with **any** signer, including standard ones.

### 4.1 Rules for every passkey operation

- **Only from a user gesture.** Passkey calls, and any popup, need a user click. `connect()` never prompts for a passkey on page load. If a passkey is needed, it reports `needsUserAction: "passkey"` and the app shows an **Unlock** button that calls `unlock()`.
- **Check PRF.** If the platform or authenticator returns no PRF output, client passkeys are unavailable on that device. In `strict` mode the user then needs a capable signer or the recovery phrase.

### 4.2 Enroll

1. Unlock the database once by any method, or create it (§6.2).
2. Call `navigator.credentials.create()` with:
   - `rp.id` = the page's host. For an nsite, the exact gateway subdomain.
   - `user.id` = `SHA-256(pubkey)`, `user.name` = the npub.
   - `residentKey: "required"`, `userVerification: "required"`.
   - `extensions: { prf: {} }`.
3. If `getClientExtensionResults().prf.enabled` is not true, stop and tell the user this authenticator can't be used.
4. Pick a random 32-byte `salt`. Call `navigator.credentials.get()` for that credential with `prf: { eval: { first: SHA-256("evolustr/v1/prf|" + salt) } }`.
5. Wrap key = `HKDF-SHA256(prfOutput, salt, "evolustr/v1/wrap|" + appId)`.
6. Add a `passkey` wrap with `rpId`, `credId` and `salt` to the vault (§6.2).
7. To switch to `strict`: rotate `S` (§3.2 rule 3). Before that, require **either** a second passkey **or** a confirmed recovery phrase, because losing the only passkey would lose the data.

### 4.3 Unlock on a device

1. `getPublicKey()` from the signer (no decrypt prompt).
2. Fetch the vault. Collect `passkey` wraps whose `rpId` equals the current host.
3. On a user gesture, call `navigator.credentials.get()` with `allowCredentials` = their `credId`s and the PRF input from each wrap's salt.
4. This works with **synced** passkeys (iCloud Keychain, Google Password Manager, password managers) and, where the platform supports PRF over it, with a **phone passkey via QR** (hybrid). If none works: other strong wraps, then `nip44` (compatible mode only), then the recovery phrase.

### 4.4 Where client passkeys work

| Environment | Notes |
|---|---|
| Own domain | ✅ The normal case. |
| nsite | ⚠️ **Locked to one gateway.** The `rpId` is the gateway subdomain, and a page on gateway B can't use gateway A's passkey. To add a passkey on gateway B, the database must first be unlocked there by another method: a capable signer, `nip44` (compatible mode only), or the recovery phrase. In `strict` mode without a capable signer, the **recovery phrase is the only way** to use the app on a second gateway. WebAuthn Related Origin Requests don't help, because the developer doesn't control the gateway domains. |
| React Native | ✅ Through a native passkey module. The app needs an associated domain (`apple-app-site-association`, `assetlinks.json`), so a web domain but no backend. |

### 4.5 Limits

- Bound to one host. That's the point, but it means no sharing between apps or gateways.
- Depends on a passkey provider. Recommend at least two passkeys (for example two ecosystems, or a hardware key) and the recovery phrase.
- PRF support differs between browsers, operating systems and authenticators, and must be measured (§12).

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

- The signer keeps a random 32-byte **master secret** `M`.
- Wrap key for a caller: `K = HKDF-SHA256(M, "evolustr/v1|app|" + appId)`. HKDF is one-way, so one app's key reveals nothing about another's or about `M`.
- How the signer stores `M` is its own choice. Recommended: its own vault event with strong wraps only:
  - `sk`: AES-GCM keyed with `HKDF(nsec, "evolustr/v1/signer-wrap")`. Only for signers that hold the nsec.
  - **Signer passkey**: PRF output of a passkey whose `rpId` is the signer's own origin. Needed by signers that don't hold the nsec (passthrough signers).
  - **Never `nip44`.** That would give `M`, and so every app's key, to any app with decrypt permission. A signer that can't use either option above doesn't offer the API.

### 5.4 Methods

```ts
interface EvolustrSignerApi {
  version: 1;
  capabilities(): Promise<{
    identity: "verified" | "connection";
    appId: string;                 // as the signer sees the caller
    ready: boolean;                // M is unlocked
    signerPasskey: boolean;        // M can be unlocked by a signer passkey
  }>;
  /** Wrap key for the caller's app database. The signer computes appId itself. */
  getWrapKey(): Promise<Uint8Array>;            // 32 bytes
  /** Last known vault fingerprint for the caller's app, for downgrade detection (§6.3). */
  getPin(): Promise<string | null>;             // sHash
  setPin(sHash: string): Promise<void>;
  /** Register a signer passkey. Must be called from a user gesture. */
  enrollPasskey(): Promise<void>;
}
```

Pins are stored in the signer's own synced storage, so a **new device** also sees the pin. This is what lets a capable signer detect a replaced vault on a device that has never seen it.

### 5.5 Behaviour required of a capable signer

1. Derive `appId` only from the caller identity in §5.2.
2. **Never auto-approve** signing Kind 30078 events whose `d`-tag starts with `evolustr:`. Show "App X wants to change your Evolustr data keys" (§6.3).
3. Show the verified caller identity, not app-supplied names, in every Evolustr prompt.
4. Let the user see apps with keys, revoke them, and manage signer passkeys.
5. Passkey operations and popups only on a user gesture. An iframe signer that can't create or use a passkey inside the iframe opens a popup on its own origin **from a click inside the iframe** (e.g. its own **Unlock** button), because a popup opened without a click is blocked. It needs `allow="publickey-credentials-get; publickey-credentials-create"` on the iframe.

### 5.6 Reference implementation

**nostr-shard-signer** (iframe signer, verified origin) is the first target:

- **OAuth mode** holds the nsec, so `M` can use the `sk` wrap. The Web3Auth `clientId` owner can recover the nsec, and so `M` and every app key derived from it. For users who don't accept that, the signer offers a signer passkey and drops the `sk` wrap. If a looser version of the signer uses a shared `clientId`, that owner is whoever controls the shared project.
- **Passthrough mode** (extension or bunker through the bridge) has no nsec, so the API is available only after the user enrolls a signer passkey.
- Per-app separation relies on `event.origin`, not on the `clientId` allowlist, so it holds in the looser version too.
- Its auto-approve list for Kind 30078 must exclude `evolustr:` `d`-tags (§5.5 rule 2).

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
  "mode": "strict",             // "strict" | "compatible"
  "created": 1730000000,        // creation time of S, never changes
  "sHash": "<hex SHA-256(S), first 8 bytes>",
  "wraps": [
    { "id": "w1", "type": "signer", "kid": "v1", "iv": "…", "ct": "…" },
    { "id": "w2", "type": "passkey", "rpId": "app.example.com",
      "credId": "<base64url>", "salt": "<base64url 32B>", "iv": "…", "ct": "…" }
    // compatible mode also has: { "id": "w3", "type": "nip44", "ct": "…" }
  ]
}
```

`recovery` is never stored. The user writes it down.

### 6.2 Client rules

1. **Lookup:** query all configured relays and wait for EOSE from each, or a timeout. Never decide "no vault exists" from a single relay.
2. **Create** only when every relay answered and none has the vault. After publishing, fetch again. If a vault with a different `sHash` and an earlier `created` appears, keep the earlier one (data migration is open question §12.3).
3. **Adding a wrap:** fetch, add the wrap, publish, fetch again to check. Never drop a wrap of the same strength without an explicit user action. The only automatic removal is the `nip44` wrap during rotation to `strict` (§3.2 rule 3).
4. **Self-healing:** after unlocking, re-add your own wrap if a concurrent update dropped it.
5. **Pin:** remember the last good `sHash` locally, and with a capable signer also through `setPin()`.

### 6.3 Hostile overwrites

Any app the user lets sign can publish a replacement vault event. Capable signers refuse to auto-approve it (§5.5), but standard signers may sign it without asking.

| Attack | `strict` mode | `compatible` mode |
|---|---|---|
| Replace with a vault whose `nip44` wrap holds a secret the attacker knows | ❌ Fails. The client ignores `nip44` and reports the vault as attacked. | ⚠️ **Works on a new device with a standard signer.** Existing devices and capable-signer users see the changed `sHash` (local pin / `getPin()`). The optional server (§10) closes it for everyone. |
| Replace with forged `signer` or `passkey` wraps | ❌ Fails: AES-GCM with AAD can't be forged without the key. | ❌ Fails. |
| Replace with garbage, or delete | DoS: new devices can't open the data. Devices that pinned the vault republish the last good one, after telling the user. | Same. |

When a vault fails these checks, the client never silently creates a new database. It shows the user what happened and offers: republish the last good vault (if this device has it), restore from the recovery phrase, or start a new database.

---

## 7. Support matrix

**App database level:** ✅ strong · 🔶 connection-scoped (§5.2) · ⚠️ weak ("as private as your Nostr DMs").
Shared settings are always ⚠️ by design (§9).

### 7.1 By signer and hosting

| Signer ↓ / Hosting → | Own domain (web) | nsite (gateway subdomain) | Mobile app |
|---|---|---|---|
| **Capable signer, verified identity** (extension, iframe signer, NIP-55) | ✅ | ✅ same data on every known gateway | ✅ (Android, NIP-55) |
| **Capable signer, NIP-46 bunker** | 🔶 | 🔶 | 🔶 |
| **Standard signer + client passkey, `strict`** | ✅ | ✅ on one gateway; other gateways only via the recovery phrase | ✅ (associated domain) |
| **Standard signer, `compatible`** (with or without passkey) | ⚠️ | ⚠️ | ⚠️ |
| **+ optional server (§10)** | Blocks hostile `nip44` replacement for everyone; revocation | ❌ nsites have no backend (§11) | as web |

### 7.2 New device

| Setup | Opens the app database with |
|---|---|
| Capable signer | The same signer on the new device (signer passkey synced, or nsec in the signer) |
| Client passkey | A synced passkey, a phone via QR, or the recovery phrase |
| `compatible` mode | The signer alone (that is why it's weak) |
| `strict`, all passkeys lost, no phrase, no capable signer | ❌ Data is lost. The client warns about this before switching to `strict`. |

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
  mode?: "compatible" | "strict";     // default "compatible" (§2)
  appId?: string;                     // native apps; web uses §3.3
  passkey?: { rpName: string };       // enables client passkeys
  knownNsiteGateways?: string[];      // for appId = nsite:<npub>
}

interface Evolustr<S> {
  /** Never prompts for a passkey. Safe to call on page load. */
  connect(): Promise<
    | { state: "ready"; pubkey: string; db: EvoluInstance<S>; status: Status }
    | { state: "needsUserAction"; action: "passkey" | "recoveryPhrase" | "signerUnlock" }
    | { state: "vaultAttacked"; options: ("republishPinned" | "restorePhrase" | "startNew")[] }
  >;
  /** Call from a click. Completes whatever connect() asked for. */
  unlock(): Promise<{ pubkey: string; db: EvoluInstance<S>; status: Status }>;
  enrollPasskey(): Promise<void>;     // from a click
  switchToStrict(): Promise<void>;    // rotates S (§3.2 rule 3), from a click
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
  level: "strong" | "connection" | "weak";
  unlockedWith: "signer" | "passkey" | "nip44" | "recovery";
  passkeySupported: boolean;          // PRF available on this device
}
```

### 8.2 Unlock order

1. Fetch the vault (§6.2) and check the pins (§6.3).
2. Try the wraps without a gesture: `signer` (if the signer is capable and ready), then `nip44` (`compatible` mode only).
3. If only a `passkey` wrap matches, or the signer needs unlocking, return `needsUserAction`. `unlock()` does the rest from a click. If nothing matches, ask for the recovery phrase.
4. If no vault exists, create it (§6.2) with the wraps available now. In `compatible` mode include `nip44`; in `strict` mode create one only with a strong wrap, otherwise ask the user to enroll a passkey first.
5. After unlocking, add any missing strong wrap the current setup can make.

### 8.3 Packages

| Package | Purpose |
|---|---|
| `@evolustr/client` | Client logic. Framework-agnostic. Web and workers. |
| `@evolustr/react` | `<EvolustrProvider>`, `useEvolustr()`, `useSetting()`. |
| `@evolustr/rn` | React Native: NIP-46 and NIP-55, native passkeys, secure-store cache of the unlocked `S`. |
| `@evolustr/signer-kit` | Helpers for signer developers implementing §5: `M` storage, key derivation, pins. |
| `@evolustr/server` (optional) | §10. |

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
- Apps cache the decoded settings locally, so later page loads don't need a decrypt prompt.

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

## 10. Optional server: `@evolustr/server`

This is not required, and not possible for nsites. It is useful for apps on their own domain whose users have standard signers:

- **Write-once vault commitment:** stores `(pubkey, appId) → sHash` on first create. Clients check fetched vaults against it, which protects new devices against a hostile `nip44` replacement in `compatible` mode. Changing the commitment (for example after rotation to `strict`) needs a delay and a notification.
- **Revocation and rate limiting**, authenticated with NIP-98: check the signature, `kind 27235`, `created_at` within ±60 s, `method`, the `payload` hash, `u` against a **configured** canonical URL, and keep a replay cache.

The server never receives a wrap key or owner secret.

---

## 11. Rejected designs (for the record)

| Design | Why rejected |
|---|---|
| Seed derived from `signEvent(...).sig` | Signatures aren't deterministic (random nonce, `created_at`), and any app can request the same signature. |
| `userSign(appSign(npub))` | Any app can fake or replay `appSign` and ask the signer to sign it. |
| Inner AES layer keyed by `HMAC(server_secret, pubkey)`, released with NIP-98 | NIP-98 doesn't bind a request to the app that asked for the signature. App B gets a valid header from the user's signer and calls the server from its own backend. |
| Shared nsite key broker checking the `Origin` header | Any non-browser client can forge `Origin`. |
| Custom NIP-46 method as the only path | Works only with one signer. Generalised into the Evolustr Signer API with fallbacks. |
| Evolu syncing over Nostr relays | Evolu has its own sync protocol and relay. Nostr is used for identity and vaults only. |
| Shared settings as a second Evolu database (v0.2–v0.3) | A second SQLite worker and sync connection per page for a few harmless values. Replaced by one event (§9). |
| Passkey and `nip44` wraps in the same vault (v0.2) | The layer is only as strong as its weakest wrap (§3.2). |
| `d`-tag hashed without the pubkey (v0.2–v0.3) | Same tag for every user of an app, so one query listed all its users (§6.1). |
| Personal vault inside Evolustr (v0.2–v0.3) | A signer feature unrelated to app databases. Moved to [SECRETS.md](SECRETS.md). |

---

## 12. Open questions

1. **Evolu instance per app:** confirm the current Evolu release's API for restoring an owner from a mnemonic, and for copying data into a new owner (needed for rotation, §3.2 rule 3).
2. **PRF support:** measure which browsers, operating systems, authenticators and hybrid (QR) flows return PRF output, and where passkey creation and use work inside a cross-origin iframe (for iframe signers). Until then, assume the popup fallback is often needed.
3. **Create race:** how to move rows written to the losing owner (§6.2 rule 2) into the winner.
4. **Known nsite gateways:** who maintains the list, and how it is distributed (config or a Nostr list event).
5. **NIP-46 method names:** agree on them with bunker developers, ideally as a NIP.
6. **Key rotation of `M`:** the `kid` field allows a new `M`. Define the re-wrap procedure.

---

## 13. Implementation phases

1. `@evolustr/client` in `compatible` mode: `nip44` vaults, §6.2 relay rules, pins, recovery phrase, shared settings event.
2. Client passkeys (§4) and `strict` mode with rotation, for web, then nsite.
3. Evolustr Signer API (§5) in nostr-shard-signer as the reference, plus `@evolustr/signer-kit`.
4. `@evolustr/rn` (NIP-55, native passkeys).
5. Propose the Signer API as a NIP. Optional `@evolustr/server`.
6. Cross-app secrets ([SECRETS.md](SECRETS.md)), independently of the above.

# Evolustr Specification

**Status:** Draft v0.3
**Scope:** Nostr identity → Evolu (local-first, E2E-encrypted SQLite) data, synced across devices and apps, with **no mandatory backend**.

---

## 1. Overview

A user signs in to an app with any Nostr signer. Evolustr then opens that user's Evolu databases for the app, on any device:

| Layer | What it holds | Who can read it |
|---|---|---|
| **shared** | Harmless preferences used by every app: theme, language, locale, time zone, reduced motion, font scale, density. | Every app the user signs in to. |
| **app** | The app's own data and settings overrides. It is the app's private storage and can hold that app's secrets. | Only that app. |
| **personal vault** | The user's own items that span apps: API keys, nsec, bank details, personal data. | Nobody as a whole. An app asks for one item and the user approves it. |

Settings resolve as `app ?? shared ?? default`.

Evolustr is two things:

1. **`@evolustr/client`**, a library apps use. It works with **any** Nostr signer.
2. **The Evolustr Signer API** (§5), an optional protocol that **any signer can implement**: browser extensions, iframe signers, Android signers, NIP-46 bunkers. A signer that implements it is an **Evolustr-capable signer**. It gives stronger separation between apps and enables the personal vault. Apps don't depend on any particular signer.

Where no capable signer is available, the client can protect the app layer with **its own passkey** on the app's domain (§4). How strong each layer is depends on the signer and on where the app runs. §7 lists every combination.

### 1.1 Terms

| Term | Meaning |
|---|---|
| **Standard signer** | Any NIP-07, NIP-46 or NIP-55 signer without the Evolustr Signer API (Alby, nos2x, nsec.app, Amber today). |
| **Evolustr-capable signer** | A signer that implements the Evolustr Signer API (§5). |
| **Owner secret `S`** | The random secret behind one Evolu database (becomes its 12-word mnemonic). One per layer instance. |
| **Vault event** | A Kind 30078 event on Nostr relays that stores `S` in encrypted form (§6). |
| **Wrap** | One encrypted copy of `S` inside a vault event, made with one unlock method (§3). |
| **Client passkey** | A WebAuthn passkey the **app** registers on **its own domain**. Needs no special signer. |
| **Signer passkey** | A passkey a **capable signer** registers on **its own origin**. Used for every app. |
| **Level** | `strong` or `weak`, see §3.2. |

### 1.2 Design principles

1. **No backend is required.** Everything works from static hosting, including nsites (NIP-5A). An optional server (§10) adds hardening only.
2. **Any signer works.** Capable signers and passkeys add strength. Without them the library still works, at a lower level.
3. **Honest security levels.** Each layer reports its level, and the docs never claim more.
4. **One secret per layer, many ways to unlock it.** Changing signer, device or unlock method never loses data.
5. **Only browser- or OS-enforced identities separate apps:** web origin (`event.origin`, extension sender origin, WebAuthn `rpId`) or the Android calling package. Self-asserted app names and URLs never do.

---

## 2. Layers

### 2.1 shared

- One per user. It is meant to be readable by every app, so it always keeps a `nip44` wrap (§3).
- Only harmless preferences go here, never secrets or personal data.
- Every app can **write** it. Apps should write a shared value only on an explicit user action ("Use for all apps").
- Schema: §9.

### 2.2 app

- One per user per app, keyed by `appId` (§3.3).
- It is the app's private storage, and its level depends on its wraps (§3.2):
  - with a capable signer or a client passkey and **no** `nip44` wrap → `strong`
  - with a `nip44` wrap → `weak`

### 2.3 personal vault

- One per user, kept **inside a capable signer**. Apps never get its owner secret.
- An app calls `vault.get(name)`. The signer shows a prompt naming the app (verified identity, §5.2) and the item. Approvals can be remembered per app and item, and revoked in the signer UI.
- Requires a capable signer whose personal-vault key no third party can recover (§5.4).
- There is no personal vault without a capable signer. Instead, an app can keep its own secrets in its **app** layer, protected by a client passkey.

---

## 3. Unlock methods (wraps)

### 3.1 The four wrap types

| Wrap | Wrap key | Who can create and open it | Level | Needs |
|---|---|---|---|---|
| `signer` | Key from a capable signer, derived for the caller's verified `appId` (§5.3) | Only that app, through that signer | strong | Evolustr-capable signer |
| `passkey` (client) | PRF output of a client passkey, `rpId` = app's domain (§4) | Only pages on that domain | strong | WebAuthn PRF on the user's platform |
| `nip44` | NIP-44 self-encryption, user → user, through the user's signer | **Any app** the user lets decrypt | weak | Any signer with NIP-44 |
| `recovery` | None. The 12-word mnemonic of `S`, written down by the user | Whoever has the words | strong (offline) | The user keeping it safe |

`signer` and `passkey` wraps use **AES-256-GCM** with a random 12-byte IV and
`AAD = "evolustr/v1|" + pubkey + "|" + layer + "|" + appId + "|" + wrapType + "|" + wrapId`.
`@noble/ciphers` and `@noble/hashes` are used everywhere, so web, workers and React Native give the same results.

### 3.2 Level of a layer

**A layer's level is the level of its weakest wrap.** One `nip44` wrap makes the layer `weak` however the current device unlocked it, because any app with decrypt permission can use that wrap.

Consequences:

- An app that wants a `strong` app layer must **not** keep a `nip44` wrap. Its users then need a capable signer, a client passkey, or the recovery phrase on each new device.
- The shared layer always keeps `nip44`, so it is always `weak` by design.
- Apps choose with `minLevel` (§8). The default is `weak`, which always works.

### 3.3 App identity (`appId`)

`appId` names which vault to use. For `passkey` and `signer` wraps, security comes from the `rpId` or from the signer's verified caller identity, not from `appId`.

| Environment | `appId` |
|---|---|
| Web app on its own domain | The page origin, `https://app.example.com` |
| nsite on a known gateway | `nsite:<site-npub>`, taken from `<npub>.gateway.tld`. The same vault is then used on every gateway. |
| nsite on an unknown gateway | The page origin |
| Android | `android:<package name>` (verified for NIP-55 signers) |
| iOS / other native | `ios:<bundle id>` (self-asserted) |

---

## 4. Client passkeys (no capable signer needed)

This is how an app gets a `strong` app layer with **any** signer, including standard ones.

### 4.1 Enroll

1. Unlock the app layer once by any method (or create it, §6.2).
2. Call `navigator.credentials.create()` with:
   - `rp.id` = the app's host. For an nsite, the exact gateway subdomain.
   - `user.id` = `SHA-256(pubkey)`, `user.name` = the npub.
   - `residentKey: "required"`, `userVerification: "required"`.
   - `extensions: { prf: {} }`.
3. If `getClientExtensionResults().prf.enabled` is not true, stop. This authenticator can't be used, so tell the user.
4. Pick a random 32-byte `salt`. Call `navigator.credentials.get()` for that credential with `prf: { eval: { first: SHA-256("evolustr/v1/prf|" + salt) } }`.
5. Wrap key = `HKDF-SHA256(prfOutput, salt, "evolustr/v1/wrap|" + layer + "|" + appId)`.
6. Add a `passkey` wrap with `rpId`, `credId` and `salt` to the vault (superset rule, §6.2).
7. Optionally, remove the `nip44` wrap to reach `strong` (§3.2). Before that, require **either** a second passkey **or** a confirmed recovery phrase.

### 4.2 Unlock on a device

1. `getPublicKey()` from the signer (no decrypt prompt).
2. Fetch the vault. Collect the `passkey` wraps whose `rpId` equals the current host.
3. Call `navigator.credentials.get()` with `allowCredentials` = their `credId`s and the PRF input from each wrap's salt.
4. This works with **synced** passkeys (iCloud Keychain, Google Password Manager, password managers) and, where the platform supports PRF over it, with a **phone passkey via QR** (hybrid). If none works, try the other wraps, then the recovery phrase.

### 4.3 Where client passkeys work

| Environment | Notes |
|---|---|
| Own domain | ✅ The normal case. |
| nsite | ✅ The `rpId` is the gateway subdomain. Each gateway needs its **own** enrollment, unlocked first by another method (another wrap or the recovery phrase). WebAuthn Related Origin Requests don't help, because the developer doesn't control the gateway domain. |
| React Native | ✅ Through a native passkey module. The app needs an associated domain (`apple-app-site-association`, `assetlinks.json`), so a web domain but no backend. |
| Cross-origin iframe | Not used by the client. |

### 4.4 Limits

- Bound to one domain: other apps can't use it. That is the point for the app layer, but it means no cross-app personal vault.
- Depends on a passkey provider. Recommend at least two passkeys (for example two ecosystems, or a hardware key) and the recovery phrase.
- PRF support differs between browsers and authenticators. The client must check and fall back (§8.2).

---

## 5. Evolustr Signer API

An optional protocol for signers. A signer that implements it can:

- give each app a strong `signer` wrap key, with **no passkey on the app's side**
- link apps through one **signer passkey**, so the user enrolls once for all apps and all domains
- hold the **personal vault**

### 5.1 Transports

The same methods are offered over each signer transport:

| Transport | How methods are exposed |
|---|---|
| NIP-07 (browser extensions, iframe signers that inject `window.nostr`) | `window.nostr.evolustr.<method>(...)`, an optional namespace like `window.nostr.nip44` |
| NIP-46 (remote bunkers) | Request methods `evolustr_capabilities`, `evolustr_get_wrap_key`, `evolustr_vault_get`, … with JSON params |
| NIP-55 (Android signers) | Intent / content-provider types with the same names |

Clients detect support with `capabilities()`. A NIP-46 or NIP-55 signer that doesn't know a method returns an error, and the client falls back.

### 5.2 Caller identity: what a signer may trust

The `appId` a signer uses for keys must come from the signer's own view of the caller, **never** from request params.

| Signer kind | Caller identity | Strength |
|---|---|---|
| Browser extension | Origin of the calling tab or frame, from the browser | verified |
| Iframe signer (e.g. nostr-shard-signer) | `postMessage` `event.origin` | verified |
| Android signer (NIP-55) | Calling package, from the OS (Binder caller UID) | verified |
| NIP-46 remote bunker | Not verifiable: the client's pubkey and name are self-asserted | **connection-scoped**: `appId = "nip46:" + client pubkey`. The user labels the connection when approving it. Stronger than `nip44`, because each connection gets its own key, but a malicious app can still ask the user to approve a connection that claims to be App A. |

`capabilities()` reports which applies (`identity: "verified" | "connection"`).

### 5.3 Signer master secret and derived keys

- The signer keeps a random 32-byte **master secret** `M`.
- Wrap key for a caller: `K = HKDF-SHA256(M, "evolustr/v1|" + layer + "|" + appId)`. HKDF is one-way, so one app's key reveals nothing about another's or about `M`.
- How the signer stores `M` is its own choice. Recommended: its own vault event (`layer = "signer"`) with wraps from:
  - `sk`: AES-GCM keyed with `HKDF(nsec, "evolustr/v1/signer-wrap")`. Only for signers that hold the nsec.
  - **Signer passkey**: PRF output of a passkey whose `rpId` is the signer's own origin. Needed by signers that don't hold the nsec (passthrough signers) and by signers where someone else can recover the nsec (§5.4).
  - Never `nip44` for `M`, because that would hand `M` to any app with decrypt permission. A signer that can't use either option above doesn't offer the API.

### 5.4 Personal vault requirements

- The signer runs the personal vault's Evolu database itself.
- Its key must come from a secret **only the signer controls**:
  - a signer passkey, or
  - the nsec, **only if** the signer is its sole custodian.
- If a third party can recover the nsec (for example an OAuth/MPC login where the project owner can obtain keys), the personal vault **must** use a signer passkey.

### 5.5 Methods

```ts
interface EvolustrSignerApi {
  version: 1;
  capabilities(): Promise<{
    identity: "verified" | "connection";
    appId: string;                 // as the signer sees the caller
    personalVault: boolean;
    signerPasskey: boolean;        // M is unlockable by a signer passkey
  }>;
  /** Wrap key for the caller's own layer. The signer computes appId itself. */
  getWrapKey(layer: "shared" | "app"): Promise<Uint8Array>; // 32 bytes
  /** Register a signer passkey (a signer may open a popup on its own origin). */
  enrollPasskey(): Promise<void>;
  vault: {
    get(name: string): Promise<string | null>;        // prompts per app and item
    set(name: string, value: string): Promise<void>;  // prompts
    list(): Promise<string[]>;                        // names this app may see
  };
}
```

### 5.6 Behaviour required of a capable signer

1. Derive `appId` only from the caller identity in §5.2.
2. **Never auto-approve** signing Kind 30078 events whose `d`-tag starts with `evolustr:`. Show "App X wants to change your Evolustr data keys" (§6.3).
3. Show the verified caller identity, not app-supplied names, in every Evolustr prompt.
4. Let the user see and revoke apps with vault access, and manage signer passkeys.
5. An iframe signer needs `allow="publickey-credentials-get; publickey-credentials-create"` on its iframe, with a popup on the signer origin as the fallback.

### 5.7 Reference implementation

**nostr-shard-signer** (iframe signer, verified origin) is the first target. Notes specific to it:

- **OAuth mode** holds the nsec, so `M` can use the `sk` wrap. The Web3Auth `clientId` owner can recover the nsec, so the shared and app layers are readable by that owner. The personal vault therefore requires a signer passkey (§5.4). If a looser version of the signer uses a shared `clientId`, that owner is whoever controls the shared project.
- **Passthrough mode** (extension or bunker through the bridge) has no nsec, so the API is available only after the user enrolls a signer passkey.
- Per-app separation relies on `event.origin`, not on the `clientId` allowlist, so it holds in the looser version too.
- Its auto-approve list for Kind 30078 must exclude `evolustr:` `d`-tags (§5.6 rule 2).

---

## 6. Vault events

### 6.1 Format

Kind **30078** (NIP-78), replaceable.

```jsonc
{
  "kind": 30078,
  "tags": [["d", "evolustr:v1:<hex(SHA-256('evolustr/v1/vault|' + layer + '|' + appId))>"]],
  "content": "<JSON below>"
}
```

The hashed `d`-tag hides which apps a user uses. The `evolustr:` prefix lets signers recognise vault events.

```jsonc
{
  "v": 1,
  "layer": "app",               // "shared" | "app" | "signer"
  "created": 1730000000,        // creation time of S, never changes
  "sHash": "<hex SHA-256(S), first 8 bytes>",
  "wraps": [
    { "id": "w1", "type": "signer", "kid": "v1", "iv": "…", "ct": "…" },
    { "id": "w2", "type": "passkey", "rpId": "app.example.com",
      "credId": "<base64url>", "salt": "<base64url 32B>", "iv": "…", "ct": "…" },
    { "id": "w3", "type": "nip44", "ct": "…" }
  ]
}
```

`recovery` is never stored. The user writes it down.

### 6.2 Client rules

1. **Lookup:** query all configured relays and wait for EOSE from each, or a timeout. Never decide "no vault exists" from a single relay.
2. **Create** only when every relay answered and none has the vault. After publishing, fetch again. If a vault with a different `sHash` and an earlier `created` appears, keep the earlier one (data migration is open question §12.3).
3. **Superset rule:** fetch, add a wrap, publish, fetch again to check. Never publish a vault with fewer wraps, unless the user explicitly removes an unlock method.
4. **Self-healing:** after unlocking, re-add your own wrap if a concurrent update dropped it.
5. **Pin locally:** keep the last good vault and its `sHash` on each device.

### 6.3 Hostile overwrites

Any app the user lets sign can publish a replacement vault event, through **any** signer. Capable signers refuse to auto-approve it (§5.6), but standard signers may sign it without asking. Clients must handle it:

| Attack | Result | Mitigation |
|---|---|---|
| Replace with a vault holding a secret the attacker knows | ❌ Fails for `signer` and `passkey` wraps: AES-GCM with AAD can't be forged without the key. ⚠️ **Works for `nip44` wraps**: the attacker can NIP-44-encrypt any secret through the signer. | Existing devices notice the changed `sHash`. A device that never saw the vault cannot tell. This is part of `weak`. The optional server (§10) closes it. |
| Replace with garbage, or delete | New devices can't open the data (DoS). | Devices keep the last good vault and republish it if the newest one fails or has another `sHash`, after telling the user. |

---

## 7. Support matrix

**S** = shared · **A** = app · **P** = personal vault.
✅ strong · 🔶 connection-scoped (§5.2) · ⚠️ weak ("as private as your Nostr DMs") · ❌ not available

### 7.1 By signer and hosting

| Signer ↓ / Hosting → | Own domain (web) | nsite (gateway subdomain) | Mobile app |
|---|---|---|---|
| **Capable signer, verified identity** (extension, iframe signer, NIP-55) | S ⚠️ · A ✅ · P ✅ | S ⚠️ · A ✅¹ · P ✅ | NIP-55: S ⚠️ · A ✅ · P ✅ (Android) |
| **Capable signer, NIP-46 bunker** | S ⚠️ · A 🔶 · P 🔶² | S ⚠️ · A 🔶 · P 🔶² | S ⚠️ · A 🔶 · P 🔶² |
| **Standard signer + client passkey** | S ⚠️ · A ✅ · P ❌ | S ⚠️ · A ✅³ · P ❌ | S ⚠️ · A ✅⁴ · P ❌ |
| **Standard signer, no passkey** | S ⚠️ · A ⚠️ · P ❌ | S ⚠️ · A ⚠️ · P ❌ | S ⚠️ · A ⚠️ · P ❌ |
| **+ optional server (§10)** | Blocks hostile `nip44` replacement for new devices; revocation | ❌ (nsites have no backend; see §11) | as web |

1. On a known gateway, the same app data on every gateway (`nsite:<npub>`), with no extra enrollment.
2. The personal vault is available, but each connection's prompt shows a self-asserted name. The user approves per item, so the risk is a misleading prompt, not silent access.
3. One enrollment per gateway (§4.3).
4. Needs an associated domain (§4.3).

"A ✅" assumes the app layer has **no** `nip44` wrap (§3.2). An app that keeps `nip44` for convenience is A ⚠️ in every row.

### 7.2 Recovery per setup

| Setup | New device opens the app layer with |
|---|---|
| Capable signer | The same signer on the new device (signer passkey synced, or nsec in the signer) |
| Client passkey | A synced passkey, a phone via QR, or the recovery phrase |
| Standard signer, `nip44` kept | The signer alone (that is why it's weak) |
| All passkeys lost, no phrase | ❌ Data is lost. The client must warn before it removes the `nip44` wrap. |

### 7.3 Who can read what

| Party | shared | app (strong) | app (weak) | personal vault |
|---|---|---|---|---|
| Relays, network, Evolu relay | ❌ | ❌ | ❌ | ❌ |
| Other app, no signer permission | ❌ | ❌ | ❌ | ❌ |
| Other app with sign + decrypt permission | ✅ | ❌ | ✅ | ❌ (needs user approval per item) |
| OAuth/MPC project owner (e.g. Web3Auth `clientId` owner) | ✅ if the signer derives `M` from the nsec | same | ✅ | ❌ (passkey required) |
| Compromised signer code or host | ✅ | ✅ | ✅ | ✅ (out of scope) |

---

## 8. Client library

### 8.1 API

```ts
interface EvolustrOptions<S> {
  schema: S;                          // the app's Evolu schema
  relays: string[];
  appId?: string;                     // native apps; web uses §3.3
  passkey?: { rpName: string };       // enables client passkeys
  minLevel?: { app?: "weak" | "strong" }; // default "weak"
  knownNsiteGateways?: string[];      // for appId = nsite:<npub>
}

interface Evolustr<S> {
  connect(): Promise<{
    pubkey: string;
    shared: EvoluInstance<SharedSchema>;
    app: EvoluInstance<S>;
    status: {
      signer: "capable-verified" | "capable-connection" | "standard";
      levels: { shared: "weak"; app: "strong" | "connection" | "weak" };
      unlockedWith: "signer" | "passkey" | "nip44" | "recovery";
      personalVault: boolean;
      passkeySupported: boolean;      // PRF available here
    };
  }>;
  enrollPasskey(): Promise<void>;     // client passkey on this domain
  makeAppStrong(): Promise<void>;     // remove the nip44 wrap (§4.1 step 7)
  showRecoveryPhrase(): Promise<string>; // after a user confirmation
  restoreFromPhrase(words: string): Promise<void>;
  setting<K extends keyof SharedSettings>(key: K): SharedSettings[K];
  vault?: EvolustrSignerApi["vault"]; // only with a capable signer
  logout(): Promise<void>;            // wipes cached secrets
}
```

### 8.2 Unlock order

For each layer:

1. Fetch the vault (§6.2).
2. Try wraps in this order:
   1. `signer`, if the signer is capable
   2. `passkey`, if a wrap matches this `rpId` and PRF is supported
   3. `nip44`
   4. otherwise ask for the recovery phrase
3. If no vault exists, create it (§6.2) with every wrap available now. Include `nip44` unless `minLevel.app` is `strong`.
4. After unlocking, add any missing strong wrap the current setup can make (superset rule).
5. If the layer's level (§3.2) is below `minLevel`, show how to upgrade: enroll a passkey, or use a capable signer.

### 8.3 Packages

| Package | Purpose |
|---|---|
| `@evolustr/client` | The client logic. Framework-agnostic. Web and workers. |
| `@evolustr/react` | `<EvolustrProvider>`, `useEvolustr()`, `useSetting()`. |
| `@evolustr/rn` | React Native: NIP-46 and NIP-55, native passkeys, secure-store cache of unlocked secrets. |
| `@evolustr/signer-kit` | Helpers for signer developers implementing §5: `M` storage, key derivation, vault rules, personal vault. |
| `@evolustr/server` (optional) | §10. |

---

## 9. Shared settings schema v1

Each setting is one Evolu row, so devices merge per field.

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

- Evolu table `evolustr_setting(key TEXT PRIMARY KEY, value JSON)`, in both the shared and the app databases.
- `setting(key)` reads the app value, then shared, then the default.
- New keys use namespaces (`x-<vendor>-<name>`) until a new schema version standardises them. Unknown keys are kept, never deleted.

---

## 10. Optional server: `@evolustr/server`

This is not required, and not possible for nsites. It is useful for apps on their own domain whose users have standard signers:

- **Write-once vault commitment:** stores `(pubkey, layer, appId) → sHash` on first create. Clients check fetched vaults against it, which also protects new devices against a hostile `nip44` replacement. Changing the commitment needs a delay and a notification.
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

---

## 12. Open questions

1. **Evolu with several owners:** can one Evolu instance mount the shared and app owners together, or do we run one instance per layer? Check against the current Evolu release.
2. **PRF support:** measure which browsers, authenticators and hybrid (QR) flows return PRF output, including inside cross-origin iframes for iframe signers.
3. **Create race:** how to move rows written to the losing owner (§6.2 rule 2) into the winner.
4. **Known nsite gateways:** who maintains the list, and how it is distributed (config or a Nostr list event).
5. **NIP-46 method names:** agree on them with bunker developers, ideally as a NIP.
6. **Key rotation:** the `kid` field allows a new `M`. Define the re-wrap procedure.

---

## 13. Implementation phases

1. `@evolustr/client`: `nip44` vaults, §6.2 relay rules, recovery phrase, shared settings.
2. Client passkeys (§4) for web, then nsite.
3. Evolustr Signer API (§5) in nostr-shard-signer as the reference, plus `@evolustr/signer-kit`.
4. Personal vault and consent UI.
5. `@evolustr/rn` (NIP-55, native passkeys).
6. Propose the Signer API as a NIP. Optional `@evolustr/server`.

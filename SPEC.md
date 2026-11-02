# Evolustr Specification

**Status:** Draft v0.2
**Scope:** Nostr identity → Evolu (local-first, E2E-encrypted SQLite) data, synced across devices and apps, with **no mandatory backend**.

---

## 1. Summary

A user signs in with any Nostr signer. Evolustr then opens the right Evolu databases for that user on every device:

| Layer | What it holds | Who can read it |
|---|---|---|
| **shared** | Harmless preferences used by every app: theme, language, locale, time zone, reduced motion, font scale, density. | Every app the user signs in to. |
| **app** | The app's own data and settings overrides. It is the app's private storage and can hold that app's secrets. | Only that app. |
| **personal vault** | The user's own items that span apps: API keys, nsec, bank details, personal data. | Nobody as a whole. An app asks for one item and the user approves it. |

Settings resolve as `app ?? shared ?? default`.

How strong each layer is depends on **which signer** the user has and **where the app runs** (own domain, nsite, mobile). Not every combination supports every layer. §6 lists them all.

### 1.1 Design principles

1. **No backend is required.** Everything works from static hosting, including nsites (NIP-5A). An optional server (§10) adds hardening only.
2. **Honest security levels.** Each layer reports how it was unlocked (`strong` / `weak`). The docs never claim more than the level gives.
3. **Each layer has its own random owner secret.** It is stored in a vault event with several *wraps*. Any one unlock method opens the same data, so changing signer or device never loses data.
4. **Origin is the app identity.** Only browser-enforced origins (`postMessage` `event.origin`, WebAuthn `rpId`) separate apps. Self-asserted names and URLs do not.

---

## 2. Threat model

### 2.1 What we protect against

| Attacker | Protected? |
|---|---|
| Relays, network observers | ✅ Everything on relays is encrypted. |
| Evolu sync relay operator | ✅ Evolu is E2E-encrypted. |
| Another app's **page code** (XSS, malicious dependency) on a different origin | ✅ for the **app** layer and **personal vault** when unlocked `strong`. ❌ for `weak` layers. |
| **Malicious App B** that the user has given signing and decrypt permission in a **standard** signer | ✅ only for layers unlocked by a **passkey** or by **our signer**. ❌ for NIP-44-only (`weak`) layers. |
| App B overwriting vault events (any signer can publish kind 30078) | ⚠️ It **cannot plant** a fake secret (AES-GCM wraps). It **can delete** (DoS). §5.4 lists the mitigations. |
| Web3Auth `clientId` owner (our signer, OAuth mode) | ❌ for shared and app layers derived from the nsec. ✅ for the personal vault, which **requires a passkey** (§4.3). |
| Compromised signer host or CDN (supply chain) | ❌ Out of scope. The signer is trusted code. |
| The user's own device fully compromised | ❌ Out of scope. |

### 2.2 Accepted baseline

Any app the user lets **decrypt** through a standard signer can already read the user's NIP-04/NIP-17 DMs. A `weak` layer is therefore **"as private as your Nostr DMs"**, and the docs say exactly that.

---

## 3. Building blocks

### 3.1 Owner secrets and wraps

Each layer instance has a random 16-byte **owner secret** `S`, which becomes the Evolu mnemonic (BIP-39, 12 words):

- `S_shared`: one per user
- `S_app(appId)`: one per user per app
- `S_personal`: one per user, **never leaves our signer**

`S` is stored on Nostr relays in a **vault event** (§5). It is encrypted several times, once per unlock method. Each encrypted copy is a **wrap**:

| Wrap type | Wrap key | Strength | Available with |
|---|---|---|---|
| `signer` | `HKDF(M_signer, "evolustr/v1/<layer>/" + appId)`, from our signer | strong | our signer |
| `passkey` | PRF output of a WebAuthn passkey (`rpId` = signer origin **or** app domain) | strong | browsers and platforms with WebAuthn PRF |
| `nip44` | NIP-44 self-encryption (`user → user`) through the user's signer | weak | any signer with NIP-44 |

Wraps of type `signer` and `passkey` use **AES-256-GCM** with a random 12-byte IV and
`AAD = "evolustr/v1|" + pubkey + "|" + layer + "|" + appId + "|" + wrapType + "|" + wrapId`.
All crypto uses `@noble/ciphers` and `@noble/hashes`, so web, workers and React Native give the same results.

### 3.2 App identity (`appId`)

| Environment | `appId` |
|---|---|
| Web app | Browser origin: `https://app.example.com` |
| nsite on an **allowlisted** gateway | `nsite:<site-npub>`, mapped from `<npub>.gateway.tld`. The same app data then works on every allowlisted gateway. |
| nsite on an unknown gateway | Its origin (data is not shared with other gateways). |
| React Native | `rn:<bundle-id>`. It is self-asserted, see §6.5. |

Gateway mapping is only safe for gateways on an allowlist. A malicious gateway can serve its own code under any `<npub>` hostname.

### 3.3 Signer master secret `M_signer` (our signer only)

`M_signer` is a random 32-byte secret kept by our signer, in its own vault event (`layer = "signer"`). Its wraps:

- `sk`: AES-GCM keyed with `HKDF(nsec, "evolustr/v1/signer-wrap")`. Only our signer can create or open it, in OAuth mode.
- `passkey`: AES-GCM keyed with the PRF output of a passkey whose `rpId` is the **signer's origin**. One passkey therefore serves every app on every domain.
- `nip44` (optional, weak): for passthrough mode without a passkey.

Our signer derives a **different** wrap key for each app: `K = HKDF(M_signer, "evolustr/v1/app/" + appId)`. HKDF is one-way, so App A's key reveals nothing about App B's key or `M_signer`.

---

## 4. Layers in detail

### 4.1 shared

- Every app gets `S_shared` without a prompt. Keep it to preferences only, never secrets or personal data.
- Every app can **write** it. Apps should write a shared value only on an explicit user action ("Use for all apps").
- Schema: §8.

### 4.2 app

- One vault per `(pubkey, appId)`.
- Only the app whose `appId` matches can obtain a strong wrap key. The browser enforces this through our signer (`event.origin`) or the app's own passkey (`rpId`).
- If the app's only wrap is `nip44`, the layer is `weak`.

### 4.3 personal vault

- `S_personal` is created **only inside our signer**, and only after the user registers a **signer-origin passkey**. It is **never** wrapped with `sk`, because the Web3Auth `clientId` owner could recover `sk`. It is never wrapped with `nip44` either.
- The signer runs its own Evolu instance for this layer, inside the iframe.
- Apps never get `S_personal`. They call `vault.get(name)`, and the signer shows a confirmation naming the app (verified origin) and the item. Approvals can be remembered per app and item, and revoked from the signer UI.
- Not available without our signer (§6).

---

## 5. Vault events

### 5.1 Format

Kind **30078** (NIP-78), replaceable.

```jsonc
{
  "kind": 30078,
  "tags": [["d", "evolustr:v1:<hex(SHA-256('evolustr/v1/vault|' + layer + '|' + appId))>"]],
  "content": "<JSON, see below>"
}
```

The hashed `d`-tag hides which apps a user uses. The `evolustr:` prefix lets signers recognise vault events (§5.3).

```jsonc
{
  "v": 1,
  "layer": "app",               // "shared" | "app" | "signer"
  "created": 1730000000,        // creation time of S, never changes
  "sHash": "<hex SHA-256(S) truncated to 8 bytes>", // lets a client detect a different S
  "wraps": [
    { "id": "w1", "type": "signer",  "kid": "v1", "iv": "…", "ct": "…" },
    { "id": "w2", "type": "passkey", "rpId": "app.example.com",
      "credId": "<base64url>", "salt": "<base64url 32B>", "iv": "…", "ct": "…" },
    { "id": "w3", "type": "nip44", "ct": "…" }
  ]
}
```

`sHash` leaks nothing useful: `S` has 128 bits of entropy and the hash is truncated.

### 5.2 Rules for clients

1. **Lookup:** query all configured relays and wait for EOSE from each, or a timeout. Never decide "no vault exists" from a single relay.
2. **Create** only when every relay answered and none has the vault. After publishing, fetch again. If a vault with a different `sHash` and an earlier `created` appears, keep the earlier one and discard the local one. If the losing device has already written data, migrate it (open question §12).
3. **Update only as a superset.** Adding a wrap means fetch, add, publish, then fetch again to check. A client never publishes a vault with fewer wraps, unless the user explicitly removes an unlock method.
4. **Self-healing:** after a successful unlock, a client re-adds its own wrap if a concurrent update dropped it.
5. **Pin locally:** keep the last good vault and `sHash` in local storage on each device.

### 5.3 Signer requirement: never auto-approve vault events

A signer that auto-approves kind 30078 (for example nostr-shard-signer PR #46) **must exclude** events whose `d`-tag starts with `evolustr:`. Signing them always needs explicit user confirmation, worded as "App X wants to change your Evolustr data keys".

**Our signer implements this. We cannot require it of other signers**, so clients must also handle hostile overwrites (§5.4).

### 5.4 Hostile overwrite (any signer)

An app with signing permission can publish a replacement vault event.

| Attack | Result | Mitigation |
|---|---|---|
| Replace the vault with a vault holding a secret the attacker knows | ❌ Fails against `signer` and `passkey` wraps: AES-GCM with AAD cannot be forged without the key. ⚠️ **Works against a vault whose only wrap is `nip44`**: the attacker can NIP-44-encrypt any secret through the signer. | The `sHash` pin on existing devices detects it. New devices with only `nip44` cannot detect it. Document this as part of `weak`. |
| Replace with garbage or delete it | Data is unreachable on new devices (DoS). | Clients keep the last good vault and republish it if the newest one fails to decrypt or has a different `sHash`, after telling the user. Optionally, the server's write-once commitment (§10). |

---

## 6. Support matrix

Rows are **signer setups**, columns are **hosting environments**. Each cell shows the best level available for each layer: **S** = shared, **A** = app, **P** = personal vault.
Legend: ✅ strong · ⚠️ weak (NIP-44, "as private as your DMs") · ❌ not available

### 6.1 Overview

| Signer ↓ / Hosting → | Own domain (web) | nsite (gateway subdomain) | React Native |
|---|---|---|---|
| **① Our signer, OAuth mode** (key inside the iframe) | S ✅ · A ✅ · P ✅¹ | S ✅ · A ✅² · P ✅¹ | ❌ no iframe (§6.5) |
| **② Our signer, passthrough mode** (extension or bunker via the bridge) | S ✅³ · A ✅³ · P ✅¹ | S ✅³ · A ✅²³ · P ✅¹ | ❌ |
| **③ Standard signer + app-domain passkey** | S ⚠️ · A ✅ · P ❌ | S ⚠️ · A ✅⁴ · P ❌ | S ⚠️ · A ✅⁵ · P ❌ |
| **④ Standard signer, no passkey** (NIP-07 / NIP-46 / NIP-55) | S ⚠️ · A ⚠️ · P ❌ | S ⚠️ · A ⚠️ · P ❌ | S ⚠️ · A ⚠️ · P ❌ |
| **⑤ Optional server (§10)** added to ③/④ | Adds overwrite protection and revocation, not confidentiality | ❌ nsites have no backend (a shared broker cannot verify origins; see §11) | Same as web |

1. P needs a **signer-origin passkey** in every mode, including OAuth, because of the `clientId` owner.
2. With an allowlisted gateway, the same app data appears on every allowlisted gateway (`appId = nsite:<npub>`). Otherwise each gateway origin is a separate app.
3. In passthrough mode the signer has no nsec, so `M_signer` must be unlocked by a **signer-origin passkey**. Without one the signer falls back to a `nip44` wrap of `M_signer`, and S and A become ⚠️.
4. The passkey's `rpId` is the gateway subdomain. The user enrolls a passkey separately on each gateway they use. WebAuthn Related Origin Requests can't help, because the developer doesn't control the gateway domain.
5. Needs an associated domain (iOS `apple-app-site-association`, Android `assetlinks.json`), so a React Native app with passkeys still needs a web domain, but not a backend.

### 6.2 ① Our signer, OAuth mode

- `M_signer` is unlocked silently via the `sk` wrap, then wrap keys are derived per app.
- The nsec-derived layers (S, A) are readable by the **Web3Auth `clientId` owner**. This is documented in the signer README. If the signer uses a shared, loosely checked `clientId`, that owner is whoever controls the shared project.
- The per-app separation does **not** depend on the `clientId` allowlist. It relies only on `event.origin`, so it also holds in a version of the signer with lighter checks.
- P requires a passkey.

### 6.3 ② Our signer, passthrough mode

- The signer forwards signing to the extension or bunker, so it has no nsec.
- With a signer-origin passkey: same strength as ①, and not exposed to any `clientId` owner.
- Without a passkey: the signer still separates apps by origin, but `M_signer` is only `nip44`-wrapped, so App B can unwrap it through the extension → ⚠️.

### 6.4 ③ / ④ Standard signers

- No shared signer links apps together, so there is **no personal vault**.
- The app layer is strong only with the app's **own-domain passkey**.
- The shared layer is always ⚠️ (NIP-44).
- Vault overwrites cannot be blocked at the signer (§5.4).

### 6.5 React Native

- There is no browser origin and no iframe signer. Signers: NIP-46, NIP-55 (Amber).
- `appId = rn:<bundle-id>` is self-asserted, so a strong app layer relies **only** on the passkey (`rpId` bound to the app's associated domain).
- The decrypted owner secrets are cached in `expo-secure-store` / Keychain for fast offline start.

### 6.6 Passkey options compared

| | Signer-origin passkey | App-domain passkey |
|---|---|---|
| Needs our signer | yes | no |
| One passkey for all apps | ✅ | ❌ (one per domain, and one per nsite gateway) |
| Unlocks | `M_signer` → S, A for every app, plus P | that app's `S_app` only |
| Personal vault | ✅ | ❌ |
| Provider lock-in | Apple / Google / password manager. Register several passkeys for safety. | Same |

---

## 7. APIs

### 7.1 Signer extension: `window.nostr.evolustr` (our signer only)

The NIP-07 methods are unchanged. This extra namespace is optional, like `window.nostr.nip44`.

```ts
interface NostrEvolustr {
  version: 1;
  /** What this signer can do in the current session. */
  capabilities(): Promise<{
    mode: "oauth" | "passthrough";
    signerPasskey: boolean;        // M_signer unlockable by passkey
    level: "strong" | "weak";      // strength of M_signer unlock
    personalVault: boolean;
    appId: string;                 // as the signer sees the caller
  }>;
  /** Wrap key for the caller's layer, derived from the verified origin. */
  getWrapKey(layer: "shared" | "app"): Promise<Uint8Array>; // 32 bytes
  /** Register a signer-origin passkey (popup fallback if iframe WebAuthn is unsupported). */
  enrollPasskey(): Promise<void>;
  vault: {
    get(name: string): Promise<string | null>;  // asks the user, per app and item
    set(name: string, value: string): Promise<void>; // asks the user
    list(): Promise<string[]>;                  // item names the app was granted
  };
}
```

The signer derives `appId` itself (§3.2) and **ignores** any `appId` the caller sends.

### 7.2 Client: `@evolustr/client`

```ts
interface EvolustrOptions<S> {
  schema: S;                       // the app's Evolu schema
  relays: string[];
  appId?: string;                  // RN only; web uses the origin
  passkey?: { rpName: string };    // enables app-domain passkey fallback
  minLevel?: { shared?: Level; app?: Level }; // refuse to open below this level
}
type Level = "strong" | "weak";

interface Evolustr<S> {
  connect(): Promise<{
    pubkey: string;
    shared: EvoluInstance<SharedSchema>;
    app: EvoluInstance<S>;
    levels: { shared: Level; app: Level; personalVault: boolean };
  }>;
  enrollPasskey(): Promise<void>;          // our signer if present, else app-domain
  setting<K extends keyof SharedSettings>(key: K): SharedSettings[K]; // app ?? shared ?? default
  vault?: NostrEvolustr["vault"];          // only with our signer
  logout(): Promise<void>;                 // wipes cached secrets
}
```

The order for opening a layer (shared or app):

1. Fetch the vault (§5.2).
2. Try to unwrap: `signer` wrap (if `window.nostr.evolustr`) → `passkey` wrap (if the platform supports PRF) → `nip44` wrap.
3. If the vault doesn't exist, create it (§5.2) with every wrap available now.
4. After a strong unlock, add any missing strong wraps (superset rule).
5. If the resulting level is below `minLevel`, return an error that tells the user how to upgrade (enroll a passkey, or use our signer).

### 7.3 Packages

| Package | Purpose |
|---|---|
| `@evolustr/client` | The client logic above. Framework-agnostic. Web and workers. |
| `@evolustr/react` | `<EvolustrProvider>`, `useEvolustr()`, `useSetting()`. |
| `@evolustr/rn` | React Native: NIP-46/NIP-55, native passkeys, secure-store cache. |
| nostr-shard-signer module | `M_signer`, signer-origin passkeys, `window.nostr.evolustr`, personal vault, consent UI, the §5.3 rule. |
| `@evolustr/server` (optional) | §10. |

---

## 8. Shared settings schema v1

Each setting is one Evolu row, so devices merge per field.

```ts
interface SharedSettings {
  theme: "light" | "dark" | "system";       // default "system"
  language: string;                          // BCP 47, default from navigator
  locale: string;                            // number/date formatting
  timeZone: string;                          // IANA
  reducedMotion: boolean;
  fontScale: number;                         // 0.75 – 2.0
  density: "compact" | "comfortable";
}
```

- Evolu table `evolustr_setting(key TEXT PRIMARY KEY, value JSON)`, in both the shared and the app databases.
- `setting(key)` reads the app value first, then shared, then the default.
- New keys use namespaces (`x-<vendor>-<name>`) until they are standardised in a new schema version. Unknown keys are kept, not deleted.

---

## 9. Signer requirements (nostr-shard-signer)

1. Derive `appId` only from `event.origin`, plus the gateway allowlist (§3.2).
2. Never auto-approve kind 30078 events with `d` starting `evolustr:` (§5.3).
3. Never wrap `S_personal` with `sk` or `nip44`.
4. Create the iframe with `allow="publickey-credentials-get; publickey-credentials-create"`. If WebAuthn create or get fails in the iframe, open a popup on the signer origin.
5. Show the verified origin, not app-supplied names, in every Evolustr prompt.
6. Provide a UI that lists apps with access to vault items, and lets the user revoke access and remove passkeys.

---

## 10. Optional server: `@evolustr/server`

This is not required, and not possible for nsites. It is useful for apps on their own domain that support standard signers (③/④):

- **Write-once vault commitment:** stores `(pubkey, layer, appId) → sHash` on the first create. Clients check fetched vaults against it, which also protects new devices against a hostile `nip44`-only replacement. Changing the commitment needs a delay and a notification.
- **Revocation and rate limiting**, authenticated with NIP-98 (check the signature, `kind 27235`, `created_at` within ±60 s, `method`, `payload` hash, `u` against a **configured** canonical URL, and keep a replay cache).

The server never receives any wrap key or owner secret.

---

## 11. Rejected designs (for the record)

| Design | Why rejected |
|---|---|
| Seed derived from `signEvent(...).sig` | Signatures aren't deterministic (random nonce, `created_at`), and any app can request the same signature. |
| `userSign(appSign(npub))` | Any app can fake or replay `appSign` and ask the signer to sign it. |
| Inner AES layer keyed by `HMAC(server_secret, pubkey)` released with NIP-98 | NIP-98 doesn't bind a request to the app that asked for the signature. App B gets a valid header from the user's signer and calls the server from its own backend. It only adds a second prompt. |
| Shared nsite key broker that checks the `Origin` header | `Origin` can be forged by any non-browser client. |
| Custom NIP-46 method (`sync_evolu_mnemonic`) as the only path | Only works with our own signer. Kept as a concept in `window.nostr.evolustr`, with fallbacks for other signers. |
| Evolu syncing over Nostr relays | Evolu has its own sync protocol and relay. Nostr is used only for identity and vaults. |

---

## 12. Open questions

1. **Evolu with several owners:** can one Evolu instance mount the shared and app owners together, or do we run one instance per layer? Check against the current Evolu release.
2. **WebAuthn PRF in a cross-origin iframe:** browser support for `create` and `get` with PRF varies. Measure it and define when to use the popup fallback.
3. **Merging after a create race (§5.2 rule 2):** how to move rows written to the losing owner into the winner.
4. **Gateway allowlist:** who maintains it, and how it is distributed (signer config or a Nostr list event).
5. **Shared `clientId` in the looser signer version:** document who the `clientId` owner is and what they can read (S and A in OAuth mode only).
6. **Key rotation:** the `kid` field on `signer` wraps allows a new `M_signer` version. Define the re-wrap procedure.

---

## 13. Implementation phases

1. `@evolustr/client` with **④** (NIP-44 vaults) and §5.2 relay rules, plus the shared settings schema.
2. App-domain passkeys (**③**) for web, then nsite.
3. Signer module: `M_signer`, `window.nostr.evolustr`, signer-origin passkeys, the §5.3 rule (**①/②**).
4. Personal vault and consent UI.
5. `@evolustr/rn`.
6. Optional `@evolustr/server`.

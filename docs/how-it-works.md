# How Evolustr works, without the crypto background

This page is for developers who know the basics of Nostr (keys, signers, events, relays) and of Evolu (a local-first database that syncs encrypted data), but not the cryptography in between. It explains what each secret is, where it's kept, and how it's locked. The exact rules are in [SPEC.md](../SPEC.md).

## The problem in one picture

An Evolu database is opened by **one secret**. Evolu shows it as 12 words. Whoever has those 12 words can read and write the whole database, on any device.

A user who logs in with Nostr on a new phone needs those 12 words, without ever typing them. Evolustr's job is to get them there safely:

```
user's Nostr login  ──►  find the app's vault on Nostr relays  ──►  unlock it  ──►  the 12 words  ──►  Evolu opens
```

## The building blocks (crypto in plain words)

You only need six ideas.

| Term | What it does | Everyday comparison |
|---|---|---|
| **Random secret** | 16 or 32 bytes from the system's secure random generator. Nobody can guess it. | A long key cut at random. |
| **Hash** (SHA-256) | Turns any input into a fixed 32-byte fingerprint. Same input, same fingerprint; you can't go back from the fingerprint to the input. | A fingerprint of a document. |
| **Key derivation** (HKDF) | Turns one secret plus a label into a new, independent key. Different labels give unrelated keys, and none of them reveals the original secret. | One master key that cuts a different, unrelated key for each door. |
| **Sealing** (AES-256-GCM) | Locks data with a key, so only that key opens it. It also detects any change: one altered byte, and opening fails. | A sealed envelope with tamper-proof tape. |
| **Label on the seal** (AAD) | Extra text that is *checked*, not hidden, when opening. If someone copies a sealed envelope into another vault, or onto another app, the label no longer matches and opening fails. | "For Alice, Notes app" printed on the tape. |
| **Tag** (HMAC) | A checksum only the holder of a key can produce. Anyone can see it; nobody without the key can make a valid one. | A wax seal with a private signet ring. |

Two more come from the platforms you already use:

- **NIP-44** is how a Nostr signer encrypts. Evolustr asks the signer to encrypt something "to the user themselves", so only that user's signer can decrypt it.
- **Passkey PRF** is a feature of passkeys (WebAuthn). Besides logging in, a passkey can give the app a secret that is always the same for that passkey and that site, and that no other site can get. Evolustr uses that secret as a key.

## The three secrets

| Secret | Size | What it is | Who ever sees it |
|---|---|---|---|
| **S**, the data secret | 16 bytes | The Evolu database's own secret: the "12 words" Evolu uses. Evolu derives the database's encryption key and owner id from it. | Your app (it needs it to open Evolu) and devices that unlock the vault. |
| **R**, the root key | 16 bytes | The key that protects S for every strong method (passkeys, signers). Its 12-word form is the **recovery phrase** the user writes down. | The user (as the phrase), and devices while unlocked. Not stored by default. |
| **M**, a signer's master key | 32 bytes | Only in Evolustr-capable signers. From it the signer derives a separate key for each app. | Only the signer. Apps never see it. |

Why two secrets, S and R, instead of one? Because **S sometimes has to change**, and R must not:

- In compatible mode, S is also encrypted with NIP-44, so any app the user allowed to decrypt could have read it. When the user makes the database strict, a **new** S is created and the data is copied into it.
- If every passkey and signer locked S directly, they would all have to be redone on every device at that moment. Instead they lock R, and R locks S. Changing S rewrites one envelope; every passkey, every signer and the recovery phrase keep working.

```
passkey ─┐
signer  ─┼──► R ───► S ───► Evolu database
phrase  ─┘     (recovery phrase = R)
                      ▲
     NIP-44 copy ─────┘   (only in compatible mode)
```

## Where everything lives

| Thing | Where | Who can read it |
|---|---|---|
| The app's data | Evolu: on each device, and on Evolu's sync relay | Only holders of S (the relay sees only encrypted data) |
| The **vault**: S and R, sealed | A Nostr event (kind 30078) on the user's relays | Everyone can download it; nobody can open it without a key |
| A copy of the vault | Inside the app's own Evolu database | Holders of S |
| S on this device | The device cache: encrypted on the web (key kept by the browser, can't be exported), secure storage on mobile | This app on this device |
| R on this device | **Only in memory** while the app runs (unless the app opts in to caching it) | This app, this session |
| The recovery phrase (R) | Written down by the user | The user |
| A signer's M | The signer's own vault event on the relays, sealed; cached inside the signer | The signer |
| Shared settings (theme, language) | One Nostr event, NIP-44 encrypted | Apps the user lets decrypt |

### Why is the vault on public relays?

So any device can find it with nothing but the user's Nostr login, and there's no server to run or trust. Being public is fine because everything inside is sealed. What *is* visible: that this user has a vault for some app. The event's name is a hash of the user and the app, so nobody can list "all users of app X" in one query, but someone who already suspects a specific user and app can check.

### Why cache anything on the device?

Evolu needs S every time the app starts. Without a cache the user would unlock (decrypt prompt, passkey or phrase) on every page load. So S is cached, encrypted with a key the browser keeps and won't hand out. That protects it from someone reading the storage files, but **not** from malicious script running in your app's page; that's why the README asks for a strict Content-Security-Policy.

R is the recovery phrase, which never changes, so it's deliberately **not** cached by default: a stolen cache then gives today's data at most, never a permanent key.

## What's inside the vault

```jsonc
{
  "v": 1,
  "mode": "compatible",           // or "strict"
  "created": 1730000000,          // when this S was made
  "sHash": "3f9a…",               // fingerprint of S, to check the right S came out
  "history": [ … ],               // fingerprints of earlier S values (after making it strict)
  "rootWraps": [                  // R, sealed once per strong method
    { "type": "passkey", "rpId": "notes.example", "credId": "…", "iv": "…", "ct": "…", "tag": "…" },
    { "type": "signer", "signerId": "…", "iv": "…", "ct": "…", "tag": "…" }
  ],
  "dataWraps": [                  // S, sealed
    { "type": "root", "iv": "…", "ct": "…" },  // sealed with a key derived from R
    { "type": "nip44", "ct": "…" }             // NIP-44 to the user (compatible mode only)
  ]
}
```

- A **wrap** is one sealed copy of a secret. `ct` is the sealed bytes; `iv` is a random number that makes every sealing different, even of the same secret.
- **`rootWraps`**: R sealed with each strong method's key. The `tag` proves the entry was made by someone who had R, so nobody without R can add a fake one. Devices also merge the wraps they've seen and never drop one, so deleting a passkey's entry from the event doesn't stick: the next device that connects puts it back.
- **`dataWraps`**: S sealed with a key derived from R, and in compatible mode also with NIP-44.
- The `root` data wrap's label covers `mode`, `created`, `sHash` and `history`. So nobody without R can, for example, flip `"strict"` to `"compatible"` or fake the history: the envelope would no longer open.

## How each lock works

### Compatible mode (the default): NIP-44

1. On first use the app creates a random S.
2. It asks the signer: "encrypt S to me" (NIP-44). The signer returns ciphertext only it can decrypt.
3. That goes into the vault as the `nip44` data wrap and is published.
4. On another device, the app asks the signer to decrypt it (the user may see a prompt) and gets S.

Weakness, stated honestly: any app the user lets *decrypt* with their signer can do step 4 too. It's the same protection as Nostr direct messages.

### A passkey on the app's domain

1. R exists (created the first time a strong method or the phrase is added).
2. The browser asks the passkey for its PRF secret for this site. It's only available on this domain.
3. Key derivation turns that secret into a sealing key (labelled with the app).
4. R is sealed with that key and added as a `passkey` root wrap.
5. On another device with the same synced passkey: get the PRF secret again → same key → open R → open S.

Another app's site can't ask your passkey for this secret. That's what makes strict mode strong.

### An Evolustr-capable signer

1. The signer has its own master key M, sealed in its own vault event (with the nsec, or with the signer's own passkey).
2. When your app asks, the signer checks which app is really calling (the browser or Android tells it) and derives a key just for that app: `key = derive(M, "app" + appId)`.
3. Your app seals R with that key as a `signer` root wrap.
4. Another app gets a different key from the same signer and can't open your wrap.

If the signer protects M with the nsec, anyone holding the nsec can rebuild M and every app key. `status.dependsOnNsec` tells you when that's the case.

**More than one signer.** Each signer product has its own M, kept in its own signer vault: a browser extension, Amber and nostr-shard-signer don't share one, and can't read each other's. You don't depend on one of them, because the app's vault holds **one root wrap per signer**, next to the passkeys. Each wrap opens the same R, so any one of them unlocks the database. The catch: each signer has to be added once, on a device where R is already unlocked (by another signer, a passkey or the phrase). The client does this by itself: when the database is unlocked and a capable signer without a wrap is connected, it asks that signer for its app key and adds the wrap. The exception is a signer that needs a passkey click first, which is added later. A signer that was never added can't open the database. Different installations of the *same* signer (say, the extension on two computers) share one M through its signer vault, so they count as one.

### The recovery phrase

The phrase **is** R, written as 12 words (the same word list Bitcoin wallets use). Typing it gives R directly, which opens S through the `root` data wrap. It needs no device, no passkey and no signer, which is why users should keep it safe.

## Making a database strict, step by step

1. The device needs R (any strong method or the phrase).
2. Create a new random S'. Copy every row from the old database into a new Evolu database opened with S'.
3. Write a new vault: `mode: "strict"`, S' sealed with R, **no** NIP-44 wrap, the old S's fingerprint added to `history`. Root wraps (R's envelopes) stay as they were.
4. Publish it to every relay. The old local database is deleted.
5. Other devices see a vault whose history names their current S: they know it's a forward step, open S' with R and move their unsynced rows over.

Data written before the switch stays as readable as it was: anyone who already got the old S through NIP-44 can still read the old data on Evolu's relay. Strict protects what's written from then on.

## How a device spots a forged vault

Anyone who can sign events for the user (any app with signing permission) can publish a fake vault. A device compares what it fetched with what it knows:

- **Its local copy of the vault** (kept in Evolu). It's only ever updated from vaults the device could check, so a fake can't overwrite it.
- **R**, if the device has it: a fake can't contain envelopes that open with R, and can't carry valid tags.
- **The history** and a local list of secrets it has moved past: an old, genuine vault re-published later is recognised as a step backwards.

When something doesn't add up, the client never silently follows. It returns `vaultChanged` or `vaultReplaced`, and the app lets the user restore the device's copy or use the recovery phrase.

## Common questions

**Why not compute S instead of storing it, e.g. from the nsec or a signature?** Most signers never reveal the nsec, and Nostr signatures differ every time you sign the same thing, so they can't produce a stable secret. Any app the user lets sign could also ask for the same signature.

**Why not S = NIP-44 encryption of "1" (or "2", "3" after a rotation)?** NIP-44 also picks a random nonce on every call, so encrypting "1" twice gives two different results: there's nothing stable to use as S. Standard signers offer no operation that gives the same secret output twice.

**A capable signer can derive a stable key from M and the app. Why not use that as S directly, with no vault?** For one user with one signer it would work, but:

- **S would belong to that signer.** Another signer (extension vs. Amber) has a different M and would produce a different S, so the user could never switch signers or use two. A passkey couldn't open the database either; its PRF output is a different number again.
- **Compatible mode would be impossible**: standard signers can't derive anything stable, so they'd have no way in.
- **Rotation needs a counter.** Making a database strict means a new S ("path 2"). Every device must learn that "2" is current, so the counter has to be stored somewhere, which is a vault again.
- **No recovery phrase independent of the signer.** Losing the signer, or its M, would lose the data.

The vault is what lets several independent keys (passkeys, signers, the phrase, the NIP-44 copy) all open the same S. Deriving keys from M and the app is still used, just one step earlier: it produces the key that opens that signer's root wrap.

**Can the Evolu relay or the Nostr relays read my data?** No. Evolu's relay stores data encrypted with S; Nostr relays store sealed envelopes.

**What if the user loses everything?** With the recovery phrase they get everything back. Without it, and without any passkey or signer that still works, a strict database is gone: nobody, including the app developer, can open it. Compatible databases only need the Nostr login, and can start over strict with a new recovery phrase (`makeStrict({ replaceRoot: true })`); the old phrase and passkeys stop working.

**Can a user leave Evolustr?** Yes: `exportEvoluMnemonic()` gives S as Evolu's 12 words, which open the data in any Evolu app. Anyone holding them can read and change the data.

**Where do I read the exact formulas?** SPEC.md §3 (keys and wraps), §4 (passkeys), §5 (signers), §6 (vault events and checks).

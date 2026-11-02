# Cross-App Secrets (signer extension)

**Status:** Draft v0.1, companion to [SPEC.md](SPEC.md)
**Scope:** A signer-held store for the user's secrets that several apps may need: API keys, nsec, bank details, personal data.

This is **not** part of Evolustr's app databases. An app that only needs its **own** secrets keeps them in its app database (SPEC §2). This store is for secrets the **user** owns and lends to apps one at a time.

It only exists in signers that implement it. There is no fallback for standard signers. It ships as an optional module of `@evolustr/signer` (SPEC §5.6), enabled with `secrets: true`.

---

## 1. Model

- The signer keeps the secrets in its own store (for example its own Evolu database). Apps never get the store's key or a list of all items.
- An app asks for one named item. The signer shows a prompt with the app's **verified** identity (SPEC §5.2) and the item name. The user can approve once, remember the approval for that app and item, or refuse.
- The signer UI lists every approval and lets the user revoke it.
- **NIP-46 bunkers:** the caller's identity is only connection-scoped (SPEC §5.2), so the prompt shows a self-asserted name. The user still approves each item, so the risk is a misleading prompt, not silent access. Signers must say this in the prompt.

## 2. Key requirements

The store's key must come from a secret **only the signer controls**:

- a **signer passkey** (WebAuthn PRF, `rpId` = the signer's origin), or
- the nsec, **only if** the signer is its sole custodian.

If a third party can recover the nsec (for example an OAuth/MPC login where the project owner can obtain keys, such as nostr-shard-signer's Web3Auth mode), the store **must** use a signer passkey. It is never protected with NIP-44, because any app with decrypt permission could then read it.

## 3. API

NIP-07: `window.nostr.secrets`. NIP-46: `secrets_get`, `secrets_set`, `secrets_list`. NIP-55: the same names.

```ts
interface NostrSecrets {
  /** Prompts per app and item unless the user remembered an approval. */
  get(name: string): Promise<string | null>;
  /** Prompts. Creates or replaces the item. */
  set(name: string, value: string): Promise<void>;
  /** Names of items this app may see (approved or created by it). */
  list(): Promise<string[]>;
}
```

Item names should use a common vocabulary so apps find the same item, for example `openai_api_key`, `nostr_nsec`, `iban`. A registry of names is an open question.

## 4. Rules for signers

1. Derive the caller's identity as in SPEC §5.2, never from request params.
2. Passkey operations and popups only on a user gesture.
3. Never auto-approve `get`.
4. Show the item name and the verified caller in every prompt.
5. Let the user export the store (for example as an encrypted file) so it doesn't depend on one signer.

## 5. Open questions

1. A shared vocabulary of item names.
2. Typed items (card, address, login) versus plain strings.
3. Moving the store between signers.

/** Shared settings event I/O (SPEC §9.1). */
import {
  type EvolustrError,
  type Relays,
  type Result,
  type SettingsDoc,
  type Signer,
  SETTINGS_DTAG,
  VAULT_KIND,
  emptySettings,
  error,
  fetchReplaceable,
  ok,
  parseSettings,
  publishReplaceable,
} from "@evolustr/core";

export interface SettingsIo {
  readonly signer: Signer;
  readonly relays: Relays;
  readonly relayUrls: ReadonlyArray<string>;
  readonly timeoutMs: number;
}

/** Fetches and decrypts the shared settings; an absent event is an empty document. */
export const fetchSharedSettings = async (io: SettingsIo, pubkey: string): Promise<Result<SettingsDoc, EvolustrError>> => {
  const f = await fetchReplaceable(io.relays, io.relayUrls, { author: pubkey, kind: VAULT_KIND, d: SETTINGS_DTAG }, io.timeoutMs);
  if (f.kind === "none") return ok(emptySettings);
  if (f.kind === "incomplete") return error("relaysUnavailable", "Not every relay answered");
  try {
    return parseSettings(await io.signer.nip44Decrypt(pubkey, f.event.content));
  } catch (e) {
    return error("signerRefused", e instanceof Error ? e.message : String(e));
  }
};

export const publishSharedSettings = async (
  io: SettingsIo,
  pubkey: string,
  doc: SettingsDoc,
  at: number,
): Promise<Result<SettingsDoc, EvolustrError>> => {
  try {
    const content = await io.signer.nip44Encrypt(pubkey, JSON.stringify(doc));
    await publishReplaceable(io.relays, io.relayUrls, io.signer, { kind: VAULT_KIND, created_at: at, tags: [["d", SETTINGS_DTAG]], content }, io.timeoutMs);
    return ok(doc);
  } catch (e) {
    return error("publishFailed", e instanceof Error ? e.message : String(e));
  }
};

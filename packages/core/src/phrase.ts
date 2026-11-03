import { entropyToMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import type { Bytes } from "./bytes.ts";
import { ROOT_KEY_LENGTH } from "./keys.ts";
import { type EvolustrError, type Result, error, ok } from "./result.ts";

/** The recovery phrase is R as 12 BIP-39 English words (SPEC §3.1). */
export const rootKeyToPhrase = (r: Bytes): string => entropyToMnemonic(r, wordlist);

/** Parses a recovery phrase, tolerating extra spaces and capitals. */
export const phraseToRootKey = (phrase: string): Result<Bytes, EvolustrError> => {
  const normalized = phrase.trim().toLowerCase().split(/\s+/).join(" ");
  if (!validateMnemonic(normalized, wordlist)) {
    return error("invalidPhrase", "Not a valid 12-word recovery phrase");
  }
  const r = mnemonicToEntropy(normalized, wordlist);
  return r.length === ROOT_KEY_LENGTH
    ? ok(r)
    : error("invalidPhrase", "The recovery phrase must have 12 words");
};

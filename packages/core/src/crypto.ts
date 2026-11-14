import { gcm } from "@noble/ciphers/aes.js";
import { hkdf as nobleHkdf } from "@noble/hashes/hkdf.js";
import { hmac as nobleHmac } from "@noble/hashes/hmac.js";
import { sha256 as nobleSha256 } from "@noble/hashes/sha2.js";
import {
  type Bytes,
  fromBase64Url,
  randomBytes,
  toBase64Url,
  toHex,
  utf8,
} from "./bytes.ts";
import { type EvolustrError, type Result, attempt, error, ok } from "./result.ts";

export const sha256 = (data: Bytes): Bytes => nobleSha256(data);

export const sha256Hex = (data: Bytes | string): string =>
  toHex(sha256(typeof data === "string" ? utf8(data) : data));

/** HMAC-SHA256. */
export const hmacSha256 = (key: Bytes, message: Bytes): Bytes => nobleHmac(nobleSha256, key, message);

/** HKDF-SHA256 with an empty salt unless one is given. */
export const hkdf = (ikm: Bytes, info: string, length = 32, salt?: Bytes): Bytes =>
  nobleHkdf(nobleSha256, ikm, salt, utf8(info), length);

/** AES-256-GCM ciphertext as stored in vault JSON. */
export interface Sealed {
  readonly iv: string;
  readonly ct: string;
}

/** Encrypts with AES-256-GCM, a random 12-byte IV and the given AAD. */
export const seal = (key: Bytes, plaintext: Bytes, aad: string): Sealed => {
  const iv = randomBytes(12);
  const ct = gcm(key, iv, utf8(aad)).encrypt(plaintext);
  return { iv: toBase64Url(iv), ct: toBase64Url(ct) };
};

/** Decrypts {@link seal} output; fails on a wrong key, wrong AAD or tampering. */
export const open = (key: Bytes, sealed: Sealed, aad: string): Result<Bytes, EvolustrError> => {
  const iv = fromBase64Url(sealed.iv);
  const ct = fromBase64Url(sealed.ct);
  if (iv === null || iv.length !== 12 || ct === null) {
    return error("malformedCiphertext", "IV or ciphertext is not valid base64url");
  }
  const r = attempt("decryptFailed", () => gcm(key, iv, utf8(aad)).decrypt(ct));
  return r.ok ? ok(r.value) : error("decryptFailed", "Wrong key, wrong AAD, or tampered data");
};

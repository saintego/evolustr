import { randomBytes as nobleRandomBytes } from "@noble/hashes/utils.js";

export type Bytes = Uint8Array;

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const utf8 = (text: string): Bytes => encoder.encode(text);
export const fromUtf8 = (bytes: Bytes): string => decoder.decode(bytes);

export const randomBytes = (length: number): Bytes => nobleRandomBytes(length);

export const toHex = (bytes: Bytes): string =>
  Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

export const fromHex = (hex: string): Bytes | null => {
  if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
};

export const toBase64Url = (bytes: Bytes): string => {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export const fromBase64Url = (text: string): Bytes | null => {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  try {
    const binary = atob(text.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
};

export const concat = (...parts: ReadonlyArray<Bytes>): Bytes => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
};

/** Constant-time comparison for equal-length secrets. */
export const bytesEqual = (a: Bytes, b: Bytes): boolean => {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
};

// Byte/string encoding helpers shared by the PWA modules. Works in browsers and Node >= 20.

const te = new TextEncoder();
const td = new TextDecoder("utf-8", { fatal: true });

export const utf8 = (s) => te.encode(s);
export const fromUtf8 = (b) => td.decode(b);

export function concat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function b64encode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function b64decode(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export const b64urlEncode = (bytes) =>
  b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export function b64urlDecode(str) {
  if (!/^[A-Za-z0-9_-]*$/.test(str)) throw new Error("invalid base64url");
  const s = str.replace(/-/g, "+").replace(/_/g, "/");
  return b64decode(s + "=".repeat((4 - (s.length % 4)) % 4));
}

const B32 = "abcdefghijklmnopqrstuvwxyz234567";

// RFC 4648 base32, lowercase, no padding.
export function base32(bytes) {
  let out = "";
  let bits = 0;
  let acc = 0;
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += B32[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += B32[(acc << (5 - bits)) & 31];
  return out;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

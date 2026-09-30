// yessh wire protocol (PWA side): PSK derivation, AES-GCM envelope, pairing string,
// request evaluation against policy, and approve/deny response construction.

import {
  b64urlDecode,
  b64urlEncode,
  base32,
  fromUtf8,
  randomBytes,
  utf8,
} from "./encoding.js";
import { buildUserCert, fingerprint, parsePublicKey } from "./sshcert.js";

export const VERSION = 1;
export const AAD_REQ = "yessh1|req";
export const AAD_RESP = "yessh1|resp";
export const PAIRING_PREFIX = "yessh1:";
export const MAX_SKEW = 120; // seconds
export const BACKDATE = 60; // seconds
export const SEEN_TTL = 24 * 3600; // seconds

export const DEFAULT_POLICY = Object.freeze({
  allowedPrincipals: [],
  maxTtl: 8 * 3600,
  defaultTtl: 3600,
  extensions: ["permit-pty"],
  sourceAddress: "",
});

const LABEL_RE = /^[A-Za-z0-9._-]{1,64}$/;
const ID_RE = /^[A-Za-z0-9_-]{22}$/;

// ---- key derivation ----

export async function hkdf(psk, info, length) {
  const base = await crypto.subtle.importKey("raw", psk, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: utf8(info) },
    base,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** Derive { encKey: CryptoKey, reqTopic, respTopic } from the 32-byte PSK. */
export async function derive(psk) {
  if (!(psk instanceof Uint8Array) || psk.length !== 32) throw new Error("psk must be 32 bytes");
  const raw = await hkdf(psk, "yessh1 enc", 32);
  const encKey = await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  raw.fill(0);
  return {
    encKey,
    reqTopic: "yessh-r-" + base32(await hkdf(psk, "yessh1 req topic", 20)),
    respTopic: "yessh-r-" + base32(await hkdf(psk, "yessh1 resp topic", 20)),
  };
}

// ---- envelope ----

/** Encrypt a message (object -> JSON, or string) into an envelope JSON string. */
export async function seal(encKey, aad, message, nonce = randomBytes(12)) {
  const pt = utf8(typeof message === "string" ? message : JSON.stringify(message));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: utf8(aad) }, encKey, pt);
  return JSON.stringify({ v: VERSION, n: b64urlEncode(nonce), c: b64urlEncode(new Uint8Array(ct)) });
}

/** Decrypt an envelope to its plaintext string, or null for anything invalid (drop silently). */
export async function openRaw(encKey, aad, body) {
  try {
    const env = typeof body === "string" ? JSON.parse(body) : body;
    if (!env || env.v !== VERSION || typeof env.n !== "string" || typeof env.c !== "string") return null;
    const nonce = b64urlDecode(env.n);
    if (nonce.length !== 12) return null;
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: utf8(aad) },
      encKey,
      b64urlDecode(env.c),
    );
    return fromUtf8(new Uint8Array(pt));
  } catch {
    return null;
  }
}

/** Decrypt and JSON-parse an envelope; null for anything invalid. */
export async function open(encKey, aad, body) {
  const s = await openRaw(encKey, aad, body);
  if (s === null) return null;
  try {
    const v = JSON.parse(s);
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

// ---- pairing ----

export function makePairing({ ntfy, pwa, psk, ca, token }) {
  const obj = { v: VERSION, ntfy, pwa, psk: b64urlEncode(psk), ca };
  if (token) obj.token = token;
  return PAIRING_PREFIX + b64urlEncode(utf8(JSON.stringify(obj)));
}

export function parsePairing(s) {
  s = String(s).trim();
  if (!s.startsWith(PAIRING_PREFIX)) throw new Error("pairing string must start with " + PAIRING_PREFIX);
  const obj = JSON.parse(fromUtf8(b64urlDecode(s.slice(PAIRING_PREFIX.length).replace(/=+$/, ""))));
  if (obj.v !== VERSION) throw new Error("unsupported pairing version");
  const psk = b64urlDecode(obj.psk.replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_"));
  if (psk.length !== 32) throw new Error("psk must be 32 bytes");
  return { ...obj, psk };
}

// ---- requests ----

const isText = (s, max) => typeof s === "string" && s.length > 0 && s.length <= max && !/[\x00-\x1f\x7f]/.test(s);
const isPrincipal = (s) => typeof s === "string" && /^[A-Za-z0-9._@+-]{1,64}$/.test(s);

/**
 * Check a decrypted request against freshness, replay and policy.
 *
 * @param {object} req      decrypted request
 * @param {object} policy   see DEFAULT_POLICY
 * @param {{now:number, seen:(id:string)=>boolean}} ctx   now in unix seconds
 * @returns {{ok:true, principals:string[], maxTtl:number, ttl:number}
 *          | {ok:false, reason:string, detail?:any}}
 *   On success, principals is the clamped set, maxTtl the most the user may grant and ttl the
 *   pre-selected value (low by default).
 */
export function evaluateRequest(req, policy, { now, seen }) {
  const bad = (reason, detail) => ({ ok: false, reason, detail });
  if (!req || typeof req !== "object") return bad("malformed");
  if (typeof req.id !== "string" || !ID_RE.test(req.id)) return bad("malformed", "id");
  if (!Number.isSafeInteger(req.ts)) return bad("malformed", "ts");
  if (typeof req.label !== "string" || !LABEL_RE.test(req.label)) return bad("malformed", "label");
  if (!isText(req.who, 128)) return bad("malformed", "who");
  if (!Array.isArray(req.principals) || req.principals.length === 0 || req.principals.length > 32 ||
      !req.principals.every(isPrincipal)) return bad("malformed", "principals");
  if (!Number.isSafeInteger(req.ttl) || req.ttl <= 0) return bad("malformed", "ttl");
  try {
    parsePublicKey(req.pubkey);
  } catch (e) {
    return bad("malformed", "pubkey: " + e.message);
  }

  if (Math.abs(now - req.ts) > MAX_SKEW) return bad("stale", now - req.ts);
  if (seen(req.id)) return bad("replay");

  const allowed = new Set(policy.allowedPrincipals ?? []);
  const principals = [...new Set(req.principals)].filter((p) => allowed.has(p));
  if (principals.length === 0) return bad("principals-not-allowed", [...new Set(req.principals)]);

  const maxTtl = Math.min(req.ttl, policy.maxTtl);
  const ttl = Math.min(maxTtl, policy.defaultTtl ?? maxTtl);
  return { ok: true, principals, maxTtl, ttl };
}

/**
 * Issue a certificate for an evaluated request. `choice` is what the user picked in the approval
 * dialog; it is clamped again here so the phone never grants more than requested and allowed.
 * Returns { response, audit }.
 */
export async function approve({ ca, req, policy, evaluation, choice = {}, now }) {
  if (!evaluation?.ok) throw new Error("request was not accepted");
  const principals = (choice.principals ?? evaluation.principals).filter((p) => evaluation.principals.includes(p));
  if (principals.length === 0) throw new Error("no principals selected");
  const ttl = Math.min(choice.ttl ?? evaluation.ttl, evaluation.maxTtl);
  if (!Number.isSafeInteger(ttl) || ttl <= 0) throw new Error("bad ttl");

  const keyId = `yessh:${req.label}:${req.id}`;
  const critical = policy.sourceAddress ? { "source-address": policy.sourceAddress } : {};
  const cert = await buildUserCert({
    ca,
    subject: req.pubkey,
    keyId,
    principals,
    validAfter: now - BACKDATE,
    validBefore: now + ttl,
    criticalOptions: critical,
    extensions: policy.extensions ?? DEFAULT_POLICY.extensions,
  });
  return {
    response: { id: req.id, ts: now, status: "approved", cert: cert.line },
    audit: {
      at: now, decision: "approved", id: req.id, label: req.label, who: req.who, principals, ttl,
      fingerprint: await fingerprint(parsePublicKey(req.pubkey).blob), serial: cert.serial.toString(),
      keyId,
    },
  };
}

export async function deny({ req, now }) {
  let fp = "";
  try {
    fp = await fingerprint(parsePublicKey(req.pubkey).blob);
  } catch {
    // malformed key: still record the denial
  }
  return {
    response: { id: req.id, ts: now, status: "denied" },
    audit: {
      at: now, decision: "denied", id: req.id, label: req.label, who: req.who,
      principals: req.principals, ttl: req.ttl,
      fingerprint: fp,
    },
  };
}

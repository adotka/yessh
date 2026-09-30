// OpenSSH user certificate construction, signed by a WebCrypto ECDSA P-256 CA key.
// Layout per OpenSSH PROTOCOL.certkeys, encodings per RFC 4251.

import { b64decode, b64encode, concat, fromUtf8, randomBytes, utf8 } from "./encoding.js";

export const CA_KEY_TYPE = "ecdsa-sha2-nistp256";
const CURVE = "nistp256";
const USER_CERT = 1;

const CERT_TYPES = {
  "ssh-ed25519": "ssh-ed25519-cert-v01@openssh.com",
  "ecdsa-sha2-nistp256": "ecdsa-sha2-nistp256-cert-v01@openssh.com",
};

// ---- RFC 4251 wire encoding ----

export function u32(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new RangeError("uint32 out of range");
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}

export function u64(n) {
  const v = BigInt(n);
  if (v < 0n || v > 0xffffffffffffffffn) throw new RangeError("uint64 out of range");
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v);
  return b;
}

export function sshString(data) {
  const bytes = typeof data === "string" ? utf8(data) : data;
  return concat(u32(bytes.length), bytes);
}

// Unsigned big-endian magnitude -> RFC 4251 mpint body (without the length prefix):
// strip leading zeros, prepend 0x00 when the top bit is set. Zero is the empty string.
export function mpint(magnitude) {
  let i = 0;
  while (i < magnitude.length && magnitude[i] === 0) i++;
  const m = magnitude.subarray(i);
  if (m.length > 0 && m[0] & 0x80) return concat(new Uint8Array([0]), m);
  return m.slice();
}

// Sequential reader over an SSH wire blob.
export class Reader {
  constructor(buf) {
    this.buf = buf;
    this.off = 0;
    this.view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  need(n) {
    if (this.off + n > this.buf.length) throw new Error("ssh wire: truncated");
  }
  u32() {
    this.need(4);
    const v = this.view.getUint32(this.off);
    this.off += 4;
    return v;
  }
  u64() {
    this.need(8);
    const v = this.view.getBigUint64(this.off);
    this.off += 8;
    return v;
  }
  bytes() {
    const n = this.u32();
    this.need(n);
    const v = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return v;
  }
  str() {
    return fromUtf8(this.bytes());
  }
  get done() {
    return this.off === this.buf.length;
  }
  end() {
    if (!this.done) throw new Error("ssh wire: trailing data");
  }
}

// ---- signatures ----

// WebCrypto ECDSA output (r||s, 32 bytes each for P-256) -> SSH signature blob.
export function ecdsaSigToSsh(raw) {
  if (raw.length !== 64) throw new Error("expected 64-byte P-256 signature");
  const inner = concat(sshString(mpint(raw.subarray(0, 32))), sshString(mpint(raw.subarray(32))));
  return concat(sshString(CA_KEY_TYPE), sshString(inner));
}

// SSH ECDSA signature blob -> r||s (inverse of ecdsaSigToSsh; strict about mpint form).
export function sshSigToEcdsa(blob) {
  const r = new Reader(blob);
  if (r.str() !== CA_KEY_TYPE) throw new Error("unexpected signature type");
  const inner = new Reader(r.bytes());
  r.end();
  const out = new Uint8Array(64);
  for (const off of [0, 32]) {
    const m = inner.bytes();
    if (m.length > 0 && (m[0] & 0x80)) throw new Error("negative mpint");
    if (m.length > 1 && m[0] === 0 && !(m[1] & 0x80)) throw new Error("non-minimal mpint");
    const mag = m.length > 0 && m[0] === 0 ? m.subarray(1) : m;
    if (mag.length > 32) throw new Error("mpint too large");
    out.set(mag, off + 32 - mag.length);
  }
  inner.end();
  return out;
}

// ---- public keys ----

export async function caPublicKeyBlob(publicKey) {
  const q = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
  return concat(sshString(CA_KEY_TYPE), sshString(CURVE), sshString(q));
}

export async function caPublicKeyLine(publicKey, comment = "yessh-ca") {
  return `${CA_KEY_TYPE} ${b64encode(await caPublicKeyBlob(publicKey))} ${comment}`;
}

// Parse an OpenSSH public key line ("type base64 [comment]") for a supported subject key.
// Returns { type, blob, keyFields } where keyFields is the blob minus its leading type string,
// i.e. exactly what a certificate carries in its public key section.
export function parsePublicKey(line) {
  const parts = String(line).trim().split(/\s+/);
  if (parts.length < 2) throw new Error("malformed public key line");
  const [type, b64] = parts;
  if (!(type in CERT_TYPES)) throw new Error(`unsupported key type: ${type}`);
  let blob;
  try {
    blob = b64decode(b64);
  } catch {
    throw new Error("malformed public key base64");
  }
  const r = new Reader(blob);
  if (r.str() !== type) throw new Error("key type mismatch");
  const start = r.off;
  if (type === "ssh-ed25519") {
    if (r.bytes().length !== 32) throw new Error("bad ed25519 key length");
  } else {
    if (r.str() !== CURVE) throw new Error("bad ecdsa curve");
    const q = r.bytes();
    if (q.length !== 65 || q[0] !== 0x04) throw new Error("bad ecdsa point");
  }
  r.end();
  return { type, blob, keyFields: blob.subarray(start) };
}

async function assertValidPoint(pk) {
  if (pk.type !== "ecdsa-sha2-nistp256") return;
  const q = new Reader(pk.keyFields);
  q.str();
  try {
    await crypto.subtle.importKey("raw", q.bytes(), { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
  } catch {
    throw new Error("ecdsa point not on curve");
  }
}

// OpenSSH-style fingerprint: "SHA256:" + unpadded base64 of SHA-256(blob).
export async function fingerprint(blob) {
  const h = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
  return "SHA256:" + b64encode(h).replace(/=+$/, "");
}

// ---- certificates ----

function encodeOptions(opts) {
  const names = Object.keys(opts).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return concat(
    ...names.map((name) => {
      const v = opts[name];
      if (typeof v !== "string") throw new TypeError(`option ${name}: value must be a string`);
      return concat(sshString(name), sshString(v === "" ? new Uint8Array(0) : sshString(v)));
    }),
  );
}

function checkText(what, s, max = 256) {
  if (typeof s !== "string" || s.length === 0 || s.length > max || /[\x00-\x20\x7f,]/.test(s)) {
    throw new Error(`invalid ${what}: ${JSON.stringify(s)}`);
  }
}

/**
 * Build and sign an OpenSSH user certificate.
 *
 * @param {object} p
 * @param {CryptoKeyPair} p.ca              ECDSA P-256 key pair (private key may be non-extractable)
 * @param {string} p.subject                OpenSSH public key line of the key being certified
 * @param {string} p.keyId
 * @param {string[]} p.principals
 * @param {number} p.validAfter             unix seconds
 * @param {number} p.validBefore            unix seconds
 * @param {number|bigint} [p.serial]        defaults to Date.now()
 * @param {Object<string,string>} [p.criticalOptions]  e.g. {"source-address": "10.0.0.0/8"}
 * @param {string[]|Object<string,string>} [p.extensions]  default ["permit-pty"]
 * @param {Uint8Array} [p.nonce]            32 random bytes by default (tests only)
 * @returns {Promise<{line:string, blob:Uint8Array, type:string, serial:bigint}>}
 */
export async function buildUserCert(p) {
  const subject = parsePublicKey(p.subject);
  await assertValidPoint(subject);
  const certType = CERT_TYPES[subject.type];

  checkText("key id", p.keyId);
  if (!Array.isArray(p.principals) || p.principals.length === 0) throw new Error("no principals");
  p.principals.forEach((pr) => checkText("principal", pr, 64));

  const validAfter = BigInt(p.validAfter);
  const validBefore = BigInt(p.validBefore);
  if (validBefore <= validAfter) throw new Error("validBefore must be after validAfter");

  const serial = BigInt(p.serial ?? Date.now());
  const nonce = p.nonce ?? randomBytes(32);
  let extensions = p.extensions ?? ["permit-pty"];
  if (Array.isArray(extensions)) extensions = Object.fromEntries(extensions.map((e) => [e, ""]));

  const tbs = concat(
    sshString(certType),
    sshString(nonce),
    subject.keyFields,
    u64(serial),
    u32(USER_CERT),
    sshString(p.keyId),
    sshString(concat(...p.principals.map((pr) => sshString(pr)))),
    u64(validAfter),
    u64(validBefore),
    sshString(encodeOptions(p.criticalOptions ?? {})),
    sshString(encodeOptions(extensions)),
    sshString(new Uint8Array(0)),
    sshString(await caPublicKeyBlob(p.ca.publicKey)),
  );
  const raw = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, p.ca.privateKey, tbs),
  );
  const blob = concat(tbs, sshString(ecdsaSigToSsh(raw)));
  return { line: `${certType} ${b64encode(blob)} ${p.keyId}`, blob, type: certType, serial };
}

function decodeOptions(buf) {
  const r = new Reader(buf);
  const out = {};
  while (!r.done) {
    const name = r.str();
    const data = r.bytes();
    out[name] = data.length === 0 ? "" : new Reader(data).str();
  }
  return out;
}

/**
 * Parse (and, with caPublicKey, verify) an OpenSSH certificate line or blob produced for an
 * ECDSA P-256 CA. Used by the PWA log view and tests; the host does its own verification.
 */
export async function parseCert(lineOrBlob, { verify = true } = {}) {
  const blob =
    typeof lineOrBlob === "string" ? b64decode(lineOrBlob.trim().split(/\s+/)[1]) : lineOrBlob;
  const r = new Reader(blob);
  const type = r.str();
  const subjectType = Object.keys(CERT_TYPES).find((k) => CERT_TYPES[k] === type);
  if (!subjectType) throw new Error(`unsupported cert type: ${type}`);
  const nonce = r.bytes();
  const keyStart = r.off;
  if (subjectType === "ssh-ed25519") r.bytes();
  else {
    r.str();
    r.bytes();
  }
  const keyFields = blob.subarray(keyStart, r.off);
  const cert = {
    type,
    nonce,
    subjectBlob: concat(sshString(subjectType), keyFields),
    serial: r.u64(),
    certType: r.u32(),
    keyId: r.str(),
    principals: [],
    validAfter: 0n,
    validBefore: 0n,
  };
  const pr = new Reader(r.bytes());
  while (!pr.done) cert.principals.push(pr.str());
  cert.validAfter = r.u64();
  cert.validBefore = r.u64();
  cert.criticalOptions = decodeOptions(r.bytes());
  cert.extensions = decodeOptions(r.bytes());
  r.bytes(); // reserved
  cert.signatureKey = r.bytes();
  const signedLen = r.off;
  cert.signature = r.bytes();
  r.end();

  if (verify) {
    const k = new Reader(cert.signatureKey);
    if (k.str() !== CA_KEY_TYPE || k.str() !== CURVE) throw new Error("unsupported CA key");
    const q = k.bytes();
    k.end();
    const pub = await crypto.subtle.importKey("raw", q, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      pub,
      sshSigToEcdsa(cert.signature),
      blob.subarray(0, signedLen),
    );
    if (!ok) throw new Error("certificate signature invalid");
  }
  return cert;
}

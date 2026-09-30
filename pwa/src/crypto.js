// Key generation for the phone side.

import { randomBytes } from "./encoding.js";

/** CA key pair: ECDSA P-256, private key non-extractable. The public key is always exportable. */
export function generateCA() {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
}

export function generatePSK() {
  return randomBytes(32);
}

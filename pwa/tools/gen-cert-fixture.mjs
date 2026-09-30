// Writes host/internal/sshcert/testdata/js-cert.json: a certificate built by the PWA code,
// verified by the Go host verifier in verify_test.go.
//   node pwa/tools/gen-cert-fixture.mjs
import { writeFileSync } from "node:fs";
import { DEFAULT_POLICY, approve, evaluateRequest } from "../src/protocol.js";
import { caPublicKeyLine } from "../src/sshcert.js";
import { b64encode, b64urlEncode, randomBytes } from "../src/encoding.js";

const now = 1790000000;
const ca = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
const ed = await crypto.subtle.generateKey("Ed25519", true, ["sign"]);
const raw = new Uint8Array(await crypto.subtle.exportKey("raw", ed.publicKey));
const blob = new Uint8Array([0, 0, 0, 11, ...new TextEncoder().encode("ssh-ed25519"), 0, 0, 0, 32, ...raw]);
const key = "ssh-ed25519 " + b64encode(blob);
const req = { id: b64urlEncode(randomBytes(16)), ts: now, label: "fixture", who: "test@fixture", pubkey: key, principals: ["root"], ttl: 3600 };
const policy = { ...DEFAULT_POLICY, allowedPrincipals: ["root"] };
const evaluation = evaluateRequest(req, policy, { now, seen: () => false });
const { response } = await approve({ ca, req, policy, evaluation, now });
const out = { ca: await caPublicKeyLine(ca.publicKey), key, cert: response.cert, principals: req.principals, ttl: req.ttl, now };
writeFileSync(new URL("../../host/internal/sshcert/testdata/js-cert.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");

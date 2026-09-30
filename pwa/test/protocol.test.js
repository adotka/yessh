import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import {
  AAD_REQ,
  AAD_RESP,
  DEFAULT_POLICY,
  approve,
  deny,
  derive,
  evaluateRequest,
  hkdf,
  makePairing,
  open,
  openRaw,
  parsePairing,
  seal,
} from "../src/protocol.js";
import { parseCert } from "../src/sshcert.js";
import { b64urlEncode, randomBytes } from "../src/encoding.js";

const vectors = JSON.parse(
  readFileSync(new URL("../../host/internal/protocol/testdata/vectors.json", import.meta.url), "utf8"),
);
const fromHex = (h) => Uint8Array.from(Buffer.from(h, "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");

test("Go vectors: HKDF key and topics", async () => {
  const psk = fromHex(vectors.psk_hex);
  assert.equal(toHex(await hkdf(psk, "yessh1 enc", 32)), vectors.enc_key_hex);
  const k = await derive(psk);
  assert.equal(k.reqTopic, vectors.req_topic);
  assert.equal(k.respTopic, vectors.resp_topic);
});

test("Go vectors: envelopes open, and JS seal is byte-identical", async () => {
  const { encKey } = await derive(fromHex(vectors.psk_hex));
  for (const ev of vectors.envelopes) {
    assert.equal(await openRaw(encKey, ev.aad, ev.envelope), ev.plaintext);
    assert.equal(await seal(encKey, ev.aad, ev.plaintext, fromHex(ev.nonce_hex)), ev.envelope);
  }
  for (const ev of vectors.reject) {
    assert.equal(await openRaw(encKey, ev.aad, ev.envelope), null, ev.envelope);
  }
});

test("Go vectors: pairing string", () => {
  const p = parsePairing(vectors.pairing.string);
  const d = vectors.pairing.decoded;
  assert.equal(p.ntfy, d.ntfy);
  assert.equal(p.pwa, d.pwa);
  assert.equal(p.ca, d.ca);
  assert.equal(toHex(p.psk), vectors.psk_hex);
  assert.equal(makePairing({ ...d, psk: p.psk }), vectors.pairing.string);
});

test("open drops wrong key, wrong direction, non-object JSON", async () => {
  const a = await derive(randomBytes(32));
  const b = await derive(randomBytes(32));
  const env = await seal(a.encKey, AAD_REQ, { x: 1 });
  assert.deepEqual(await open(a.encKey, AAD_REQ, env), { x: 1 });
  assert.equal(await open(b.encKey, AAD_REQ, env), null);
  assert.equal(await open(a.encKey, AAD_RESP, env), null);
  assert.equal(await open(a.encKey, AAD_REQ, await seal(a.encKey, AAD_REQ, "[1,2]")), null);
  assert.equal(await open(a.encKey, AAD_REQ, await seal(a.encKey, AAD_REQ, "nope")), null);
  assert.notEqual(await seal(a.encKey, AAD_REQ, "x"), await seal(a.encKey, AAD_REQ, "x"));
});

// ---------------------------------------------------------------------------

const ED_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";
const NOW = 1790000000;
const mkReq = (over = {}) => ({
  id: b64urlEncode(randomBytes(16)),
  ts: NOW,
  label: "mgmt-1",
  who: "claude@mgmt-1",
  pubkey: ED_PUB,
  principals: ["root"],
  ttl: 4 * 3600,
  ...over,
});
const policy = { ...DEFAULT_POLICY, allowedPrincipals: ["root", "deploy"] };
const ctx = { now: NOW, seen: () => false };

test("evaluateRequest: freshness, replay, malformed", () => {
  assert.equal(evaluateRequest(mkReq({ ts: NOW - 121 }), policy, ctx).reason, "stale");
  assert.equal(evaluateRequest(mkReq({ ts: NOW + 121 }), policy, ctx).reason, "stale");
  assert.ok(evaluateRequest(mkReq({ ts: NOW - 120 }), policy, ctx).ok);
  assert.equal(evaluateRequest(mkReq(), policy, { now: NOW, seen: () => true }).reason, "replay");
  for (const over of [
    { id: "short" }, { ts: "1" }, { label: "a:b" }, { label: "" }, { who: "a\nb" }, { principals: [] },
    { principals: ["a,b"] }, { principals: "root" }, { ttl: 0 }, { ttl: 1.5 }, { pubkey: "ssh-rsa AAAA" },
  ]) {
    assert.equal(evaluateRequest(mkReq(over), policy, ctx).reason, "malformed", JSON.stringify(over));
  }
});

test("evaluateRequest: principal and TTL clamping", () => {
  const e = evaluateRequest(mkReq({ principals: ["root", "admin", "root"], ttl: 99 * 3600 }), policy, ctx);
  assert.deepEqual(e, { ok: true, principals: ["root"], maxTtl: 8 * 3600, ttl: 3600 });
  const small = evaluateRequest(mkReq({ ttl: 600 }), policy, ctx);
  assert.equal(small.maxTtl, 600);
  assert.equal(small.ttl, 600);
  const none = evaluateRequest(mkReq({ principals: ["admin"] }), policy, ctx);
  assert.deepEqual(none, { ok: false, reason: "principals-not-allowed", detail: ["admin"] });
  // Default policy has no allowed principals: first request forces the user to add them.
  assert.equal(evaluateRequest(mkReq(), DEFAULT_POLICY, ctx).reason, "principals-not-allowed");
});

test("approve never grants more than evaluated; cert fields match", async () => {
  const ca = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const req = mkReq({ principals: ["root", "deploy"], ttl: 7200 });
  const evaluation = evaluateRequest(req, policy, ctx);
  const { response, audit } = await approve({
    ca, req, policy, evaluation, now: NOW,
    choice: { principals: ["deploy", "admin"], ttl: 999999 },
  });
  assert.equal(response.id, req.id);
  assert.equal(response.status, "approved");
  const cert = await parseCert(response.cert);
  assert.deepEqual(cert.principals, ["deploy"]);
  assert.equal(cert.validAfter, BigInt(NOW - 60));
  assert.equal(cert.validBefore, BigInt(NOW + 7200));
  assert.equal(cert.keyId, `yessh:mgmt-1:${req.id}`);
  assert.deepEqual(cert.extensions, { "permit-pty": "" });
  assert.deepEqual(cert.criticalOptions, {});
  assert.equal(audit.ttl, 7200);
  assert.match(audit.fingerprint, /^SHA256:/);

  await assert.rejects(approve({ ca, req, policy, evaluation, now: NOW, choice: { principals: ["admin"] } }));
  const withSrc = await approve({ ca, req, policy: { ...policy, sourceAddress: "10.0.0.0/8" }, evaluation, now: NOW });
  assert.deepEqual((await parseCert(withSrc.response.cert)).criticalOptions, { "source-address": "10.0.0.0/8" });
});

test("deny", async () => {
  const req = mkReq();
  const { response, audit } = await deny({ req, now: NOW });
  assert.deepEqual(response, { id: req.id, ts: NOW, status: "denied" });
  assert.equal(audit.decision, "denied");
});

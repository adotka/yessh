import { test } from "node:test";
import assert from "node:assert/strict";

import { App } from "../src/app.js";
import { memoryStore } from "../src/store.js";
import { AAD_REQ, AAD_RESP, derive, open, parsePairing, seal } from "../src/protocol.js";
import { parseCert } from "../src/sshcert.js";
import { b64urlEncode, randomBytes } from "../src/encoding.js";

// In-memory ntfy speaking just enough HTTP for the PWA's poll/publish.
function fakeNtfy() {
  const msgs = [];
  let n = 0;
  const fetchImpl = async (url, init = {}) => {
    const u = new URL(url);
    const parts = u.pathname.split("/").filter(Boolean);
    if ((init.method ?? "GET") === "POST") {
      msgs.push({ id: String(++n), time: Math.floor(Date.now() / 1000), event: "message", topic: parts[0], message: init.body });
      return new Response("{}", { status: 200 });
    }
    assert.equal(parts[1], "json");
    assert.equal(u.searchParams.get("poll"), "1");
    const body = msgs.filter((m) => m.topic === parts[0]).map((m) => JSON.stringify(m)).join("\n");
    return new Response(body, { status: 200 });
  };
  return { msgs, fetchImpl };
}

const ED_PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";

async function setup() {
  const nt = fakeNtfy();
  const store = memoryStore();
  const app = new App({ store, fetchImpl: nt.fetchImpl });
  await app.createCA({ ntfyUrl: "https://ntfy.example/", pwaUrl: "https://pwa.example/" });
  const info = await app.info();
  const pairing = parsePairing(info.pairing);
  const host = await derive(pairing.psk); // what the host derives from the pairing string
  const send = async (over = {}) => {
    const req = {
      id: b64urlEncode(randomBytes(16)), ts: Math.floor(Date.now() / 1000), label: "mgmt-1",
      who: "claude@mgmt-1", pubkey: ED_PUB, principals: ["root"], ttl: 7200, ...over,
    };
    await nt.fetchImpl(`https://ntfy.example/${host.reqTopic}`, { method: "POST", body: await seal(host.encKey, AAD_REQ, req) });
    return req;
  };
  const responses = async () => {
    const out = [];
    for (const m of nt.msgs.filter((m) => m.topic === host.respTopic)) out.push(await open(host.encKey, AAD_RESP, m.message));
    return out;
  };
  return { app, store, nt, info, pairing, host, send, responses };
}

test("createCA, persisted reload, info", async () => {
  const { app, store, info, pairing } = await setup();
  assert.equal(pairing.ntfy, "https://ntfy.example");
  assert.equal(pairing.pwa, "https://pwa.example/");
  assert.match(info.caLine, /^ecdsa-sha2-nistp256 AAAA\S+ yessh-ca$/);
  assert.equal(pairing.ca, info.caLine);
  assert.equal(info.subscribeLink, `ntfy://ntfy.example/${info.reqTopic}`);
  const ca = await store.get("ca");
  assert.equal(ca.privateKey.extractable, false);

  const again = new App({ store });
  assert.equal(await again.load(), true);
  assert.equal((await again.info()).caLine, info.caLine);
  await assert.rejects(app.createCA({ pwaUrl: "x" }), /already exists/);
});

test("request flow: allow principal, approve, replay rejected, log", async () => {
  const { app, send, responses } = await setup();
  const req = await send({ principals: ["root", "admin"] });
  // Noise on the topic is ignored.
  const other = await derive(randomBytes(32));
  await app.fetchImpl(`https://ntfy.example/${app.keys.reqTopic}`, { method: "POST", body: await seal(other.encKey, AAD_REQ, { id: "x" }) });

  let pending = await app.refresh();
  assert.equal(pending.length, 1);
  assert.equal(pending[0].evaluation.reason, "principals-not-allowed");
  await assert.rejects(app.approve(req.id), /principals-not-allowed/);

  await app.allowPrincipals(["root"]);
  pending = await app.pending();
  assert.equal(pending[0].evaluation.ok, true);
  assert.deepEqual(pending[0].evaluation.principals, ["root"]);
  assert.equal(pending[0].evaluation.ttl, 3600); // defaultTtl preselected

  const audit = await app.approve(req.id, { ttl: 1800 });
  assert.equal(audit.decision, "approved");
  assert.equal(audit.ttl, 1800);
  const [resp] = await responses();
  assert.equal(resp.id, req.id);
  assert.equal(resp.status, "approved");
  const cert = await parseCert(resp.cert);
  assert.deepEqual(cert.principals, ["root"]);
  assert.equal(Number(cert.validBefore - cert.validAfter), 1800 + 60);

  // The same request re-delivered (replay) is not pending any more.
  app.requests.clear();
  assert.equal((await app.refresh()).length, 0);
  assert.equal((await app.evaluate(req.id)).evaluation.reason, "replay");

  const log = await app.log();
  assert.equal(log.length, 1);
  assert.equal(log[0].label, "mgmt-1");
});

test("deny and stale", async () => {
  const { app, send, responses } = await setup();
  await app.allowPrincipals(["root"]);
  const r1 = await send();
  const r2 = await send({ ts: Math.floor(Date.now() / 1000) - 600 });
  const pending = await app.refresh();
  assert.deepEqual(pending.map((p) => p.req.id), [r1.id]);
  assert.equal((await app.evaluate(r2.id)).evaluation.reason, "stale");
  await assert.rejects(app.approve(r2.id), /expired/);
  await app.deny(r1.id);
  const [resp] = await responses();
  assert.deepEqual(resp, { id: r1.id, ts: resp.ts, status: "denied" });
  assert.equal((await app.log())[0].decision, "denied");
});

test("policy validation", async () => {
  const { app } = await setup();
  const p = await app.setPolicy({ allowedPrincipals: [" root ", "", "root", "deploy"], maxTtl: 3600, defaultTtl: 7200 });
  assert.deepEqual(p.allowedPrincipals, ["root", "deploy"]);
  assert.equal(p.defaultTtl, 3600);
  await assert.rejects(app.setPolicy({ maxTtl: 0 }));
});

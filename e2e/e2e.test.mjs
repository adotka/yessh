// End-to-end: real ntfy, real `yessh` binary, the PWA's App logic as the phone, real sshd.
//
//   E2E_NTFY      ntfy base URL             (default http://localhost:18080, from docker-compose.yml)
//   E2E_SSHD      "docker" | "local"        (default docker: the compose sshd on 127.0.0.1:12222;
//                                            local: spawn /usr/sbin/sshd on 127.0.0.1:12223)
//   YESSH_BIN     path to yessh             (default: go build from ../host)
//   E2E_EXPIRY    "0" to skip the ~70 s expiry check
//
// Run via e2e/run.sh, or: node --test e2e/

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { App } from "../pwa/src/app.js";
import { memoryStore } from "../pwa/src/store.js";
import { AAD_RESP, derive, parsePairing, seal } from "../pwa/src/protocol.js";
import { buildUserCert } from "../pwa/src/sshcert.js";

const here = dirname(fileURLToPath(import.meta.url));
const NTFY = process.env.E2E_NTFY ?? "http://localhost:18080";
const SSHD_MODE = process.env.E2E_SSHD ?? "docker";
const SSH_PORT = SSHD_MODE === "local" ? 12223 : 12222;
const caDir = join(here, "work", "ca");

let work, env, yessh, app, pairing, sshdProc;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function run(args, opts = {}) {
  return new Promise((resolve) => {
    const p = spawn(yessh, args, { env, ...opts });
    let out = "";
    let err = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("close", (code) => resolve({ code, out, err }));
  });
}

async function waitPending(pred = () => true, ms = 15000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const items = (await app.refresh()).filter(pred);
    if (items.length) return items[0];
    await sleep(300);
  }
  throw new Error("no pending request arrived");
}

function ssh(cmd = "echo e2e-ok") {
  return spawnSync("ssh", [
    "-p", String(SSH_PORT),
    "-i", join(env.YESSH_DIR, "id_yessh"),
    "-o", `CertificateFile=${join(env.YESSH_DIR, "id_yessh-cert.pub")}`,
    "-o", "IdentitiesOnly=yes",
    "-o", "IdentityAgent=none",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "LogLevel=ERROR",
    "root@127.0.0.1", cmd,
  ], { encoding: "utf8", timeout: 20000 });
}

before(async () => {
  work = mkdtempSync(join(tmpdir(), "yessh-e2e-"));
  env = {
    ...process.env,
    YESSH_CONFIG: join(work, "config", "config.json"),
    YESSH_DIR: join(work, "run"),
  };
  yessh = process.env.YESSH_BIN ?? join(work, "yessh");
  if (!process.env.YESSH_BIN) {
    execFileSync("go", ["build", "-o", yessh, "./cmd/yessh"], { cwd: join(here, "..", "host"), stdio: "inherit" });
  }

  // Phone: create the CA against the real ntfy.
  app = new App({ store: memoryStore() });
  await app.createCA({ ntfyUrl: NTFY, pwaUrl: "https://pwa.invalid/" });
  const info = await app.info();
  pairing = info.pairing;

  // Fleet host trusts the CA.
  mkdirSync(caDir, { recursive: true });
  writeFileSync(join(caDir, "ca.pub"), info.caLine + "\n");

  if (SSHD_MODE === "local") {
    const hostKey = join(work, "ssh_host_ed25519_key");
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", hostKey]);
    const cfg = join(work, "sshd_config");
    writeFileSync(cfg, [
      `Port ${SSH_PORT}`, "ListenAddress 127.0.0.1", `HostKey ${hostKey}`,
      `TrustedUserCAKeys ${join(caDir, "ca.pub")}`, "AuthorizedKeysFile none",
      "PasswordAuthentication no", "KbdInteractiveAuthentication no",
      "PermitRootLogin prohibit-password", "UsePAM no", `PidFile ${join(work, "sshd.pid")}`,
    ].join("\n") + "\n");
    mkdirSync("/run/sshd", { recursive: true });
    sshdProc = spawn("/usr/sbin/sshd", ["-D", "-e", "-f", cfg], { stdio: "ignore" });
    await sleep(500);
  }
});

after(() => {
  sshdProc?.kill();
  if (work) rmSync(work, { recursive: true, force: true });
});

test("pair", async () => {
  const r = await run(["pair", pairing]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /ecdsa-sha2-nistp256/);
  const ca = await run(["ca"]);
  assert.equal(ca.out.trim(), parsePairing(pairing).ca);
});

test("approve → cert → ssh works; ensure reuses it", async () => {
  const req = run(["request", "-p", "root", "-t", "10m", "--label", "e2e"]);
  const t0 = Date.now();
  const item = await waitPending((i) => i.req.label === "e2e");
  assert.equal(item.evaluation.reason, "principals-not-allowed"); // default policy is empty
  await app.allowPrincipals(["root"]);
  const ev = await app.evaluate(item.req.id);
  assert.equal(ev.evaluation.ok, true);
  assert.equal(ev.evaluation.maxTtl, 600);
  await app.approve(item.req.id, { ttl: 600 });
  const r = await req;
  assert.equal(r.code, 0, r.err);
  assert.ok(Date.now() - t0 < 10000, "round trip under 10 s");

  const status = await run(["status"]);
  assert.equal(status.code, 0, status.err);
  assert.match(status.out, /Principals:\s+root/);

  const s = ssh();
  assert.equal(s.status, 0, s.stderr);
  assert.equal(s.stdout.trim(), "e2e-ok");

  const ensure = await run(["ensure", "-p", "root", "--min-remaining", "1m"]);
  assert.equal(ensure.code, 0, ensure.err);
  assert.equal(ensure.err, "", "ensure should be silent when the cert is fine");
});

test("deny → exit 3, previous cert untouched", async () => {
  const before = readFileSync(join(env.YESSH_DIR, "id_yessh-cert.pub"), "utf8");
  const req = run(["request", "-p", "root", "--label", "e2e-deny"]);
  const item = await waitPending((i) => i.req.label === "e2e-deny");
  await app.deny(item.req.id);
  const r = await req;
  assert.equal(r.code, 3, r.err);
  assert.equal(readFileSync(join(env.YESSH_DIR, "id_yessh-cert.pub"), "utf8"), before);
});

test("timeout → exit 2", async () => {
  const r = await run(["request", "-p", "root", "--label", "e2e-timeout", "--timeout", "3s"]);
  assert.equal(r.code, 2, r.err);
});

test("tampered response (cert from another CA) → rejected, nothing written", async () => {
  const dir = join(work, "tamper");
  const tenv = { ...env, YESSH_DIR: dir };
  const req = run(["request", "-p", "root", "--label", "e2e-tamper"], { env: tenv });
  const item = await waitPending((i) => i.req.label === "e2e-tamper");
  // An attacker who has the PSK but not the CA key.
  const rogue = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const now = Math.floor(Date.now() / 1000);
  const cert = await buildUserCert({
    ca: rogue, subject: item.req.pubkey, keyId: "evil", principals: ["root"], validAfter: now - 60, validBefore: now + 600,
  });
  const body = await seal(app.keys.encKey, AAD_RESP, { id: item.req.id, ts: now, status: "approved", cert: cert.line });
  await fetch(`${NTFY}/${app.keys.respTopic}`, { method: "POST", body });
  const r = await req;
  assert.equal(r.code, 1);
  assert.match(r.err, /rejected response: cert: signed by an unexpected CA/);
  assert.ok(!existsSync(join(dir, "id_yessh-cert.pub")));
});

test("wrong-PSK request is invisible to the phone; replayed request is rejected", async () => {
  const wrong = await derive(crypto.getRandomValues(new Uint8Array(32)));
  const forged = await seal(wrong.encKey, "yessh1|req", { id: "A".repeat(22), ts: Math.floor(Date.now() / 1000) });
  await fetch(`${NTFY}/${app.keys.reqTopic}`, { method: "POST", body: forged });
  const before = app.requests.size;
  await app.refresh();
  assert.equal(app.requests.size, before);

  // Replay: the requests answered above are still in the ntfy cache; none may come back as pending.
  // (The timeout/tamper requests were never answered, so they legitimately still show.)
  app.requests.clear();
  const labels = (await app.refresh()).map((p) => p.req.label);
  assert.ok(labels.length > 0, "cache should still hold unanswered requests");
  for (const answered of ["e2e", "e2e-deny"]) assert.ok(!labels.includes(answered), `${answered} came back`);
});

test("cert stops working after expiry", { skip: process.env.E2E_EXPIRY === "0" && "E2E_EXPIRY=0" }, async () => {
  const req = run(["request", "-p", "root", "-t", "1m", "--label", "e2e-expiry"]);
  const item = await waitPending((i) => i.req.label === "e2e-expiry");
  await app.approve(item.req.id);
  assert.equal((await req).code, 0);
  assert.equal(ssh().status, 0);
  await sleep(62_000);
  const s = ssh();
  assert.notEqual(s.status, 0, "ssh must fail with an expired cert");
  const status = await run(["status"]);
  assert.equal(status.code, 1);
  assert.match(status.out, /EXPIRED/);
});

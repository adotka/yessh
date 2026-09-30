import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  buildUserCert,
  caPublicKeyLine,
  ecdsaSigToSsh,
  fingerprint,
  mpint,
  parseCert,
  parsePublicKey,
  Reader,
  sshSigToEcdsa,
} from "../src/sshcert.js";
import { b64decode, b64encode } from "../src/encoding.js";

const hex = (s) => Uint8Array.from(s.match(/../g) ?? [], (h) => parseInt(h, 16));
const toHex = (b) => Buffer.from(b).toString("hex");

const hasKeygen = spawnSync("ssh-keygen", ["-?"], { stdio: "ignore" }).error === undefined;
const needKeygen = { skip: hasKeygen ? false : "ssh-keygen not installed" };

const tmp = () => mkdtempSync(join(tmpdir(), "yessh-test-"));

function keygen(dir, type) {
  const f = join(dir, `id_${type}`);
  const args = type === "ecdsa" ? ["-t", "ecdsa", "-b", "256"] : ["-t", type];
  execFileSync("ssh-keygen", [...args, "-N", "", "-q", "-C", "subject", "-f", f]);
  return readFileSync(f + ".pub", "utf8").trim();
}

// Run `ssh-keygen -L` on a certificate line and parse the interesting fields.
function keygenList(dir, certLine) {
  const f = join(dir, `cert-${Math.random().toString(36).slice(2)}-cert.pub`);
  writeFileSync(f, certLine + "\n");
  const out = execFileSync("ssh-keygen", ["-L", "-f", f], { env: { ...process.env, TZ: "UTC" } }).toString();
  const field = (name) => out.match(new RegExp(`^\\s+${name}: ?(.*)$`, "m"))?.[1];
  const list = (name) => {
    const m = out.match(new RegExp(`^\\s+${name}: ?(.*)\\n((?:\\s{16}.*\\n)*)`, "m"));
    if (!m) return undefined;
    if (m[1].trim() === "(none)") return [];
    return m[2].split("\n").map((s) => s.trim()).filter(Boolean);
  };
  return {
    raw: out,
    type: field("Type"),
    publicKey: field("Public key"),
    signingCa: field("Signing CA"),
    keyId: field("Key ID"),
    serial: field("Serial"),
    valid: field("Valid"),
    principals: list("Principals"),
    critical: list("Critical Options"),
    extensions: list("Extensions"),
  };
}

const newCa = () =>
  crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);

const iso = (s) => new Date(s * 1000).toISOString().slice(0, 19);

// ---------------------------------------------------------------------------

test("mpint vectors", () => {
  const cases = [
    ["", ""],
    ["00", ""],
    ["0000", ""],
    ["01", "01"],
    ["7f", "7f"],
    ["80", "0080"],
    ["ff", "00ff"],
    ["0080", "0080"],
    ["000080", "0080"],
    ["00007f", "7f"],
    ["0001ff", "01ff"],
    ["00000000000000000000000000000000000000000000000000000000000000ab", "00ab"],
    ["8000000000000000000000000000000000000000000000000000000000000001",
      "008000000000000000000000000000000000000000000000000000000000000001"],
    ["0f00000000000000000000000000000000000000000000000000000000000000",
      "0f00000000000000000000000000000000000000000000000000000000000000"],
  ];
  for (const [input, want] of cases) assert.equal(toHex(mpint(hex(input))), want, `mpint(${input})`);
});

test("ECDSA r||s -> SSH signature blob, high-bit and leading-zero cases", () => {
  const r = hex("ff" + "11".repeat(31)); // top bit set -> 33-byte mpint
  const s = hex("0000" + "7f" + "22".repeat(29)); // leading zeros stripped -> 30 bytes
  const blob = ecdsaSigToSsh(new Uint8Array([...r, ...s]));
  const expect =
    "00000013" + Buffer.from("ecdsa-sha2-nistp256").toString("hex") +
    "00000047" + // 4+33 + 4+30 = 71
    "00000021" + "00" + toHex(r) +
    "0000001e" + toHex(s.subarray(2));
  assert.equal(toHex(blob), expect);
  assert.deepEqual(sshSigToEcdsa(blob), new Uint8Array([...r, ...s]));

  // s == 0x80 00.. and r with a leading zero followed by a high bit byte.
  const r2 = hex("00" + "80" + "33".repeat(30));
  const s2 = hex("80" + "00".repeat(31));
  const blob2 = ecdsaSigToSsh(new Uint8Array([...r2, ...s2]));
  assert.equal(toHex(blob2).slice(54), "00000020" + "00" + toHex(r2.subarray(1)) + "00000021" + "00" + toHex(s2));
  assert.deepEqual(sshSigToEcdsa(blob2), new Uint8Array([...r2, ...s2]));
});

test("sshSigToEcdsa rejects non-minimal mpints", () => {
  const bad = ecdsaSigToSsh(new Uint8Array(64).fill(1));
  // inner r = 00000020 0101.. ; hand-craft a non-minimal "00 01.." encoding
  const inner = hex("00000021" + "00" + "01".repeat(32) + "00000020" + "01".repeat(32));
  const blob = new Uint8Array([...bad.subarray(0, 23), ...hex("00000049"), ...inner]);
  assert.throws(() => sshSigToEcdsa(blob), /non-minimal/);
});

test("parsePublicKey rejects junk", () => {
  assert.throws(() => parsePublicKey("ssh-rsa AAAAB3NzaC1yc2E= x"), /unsupported/);
  assert.throws(() => parsePublicKey("ssh-ed25519"), /malformed/);
  assert.throws(() => parsePublicKey("ssh-ed25519 !!!"), /base64/);
  // valid framing, wrong length
  const blob = new Uint8Array([0, 0, 0, 11, ...Buffer.from("ssh-ed25519"), 0, 0, 0, 2, 1, 2]);
  assert.throws(() => parsePublicKey("ssh-ed25519 " + b64encode(blob)), /length/);
  // type in line differs from type in blob
  const ed = new Uint8Array([0, 0, 0, 11, ...Buffer.from("ssh-ed25519"), 0, 0, 0, 32, ...new Uint8Array(32)]);
  assert.throws(() => parsePublicKey("ecdsa-sha2-nistp256 " + b64encode(ed)), /mismatch/);
});

test("buildUserCert rejects invalid inputs", async () => {
  const ca = await newCa();
  const subject = "ssh-ed25519 " + b64encode(
    new Uint8Array([0, 0, 0, 11, ...Buffer.from("ssh-ed25519"), 0, 0, 0, 32, ...new Uint8Array(32).fill(7)]),
  );
  const base = { ca, subject, keyId: "k", principals: ["root"], validAfter: 1000, validBefore: 2000 };
  await buildUserCert(base);
  await assert.rejects(buildUserCert({ ...base, principals: [] }), /no principals/);
  await assert.rejects(buildUserCert({ ...base, principals: ["a,b"] }), /principal/);
  await assert.rejects(buildUserCert({ ...base, principals: ["ro ot"] }), /principal/);
  await assert.rejects(buildUserCert({ ...base, keyId: "a\nb" }), /key id/);
  await assert.rejects(buildUserCert({ ...base, validBefore: 1000 }), /validBefore/);
  // ECDSA point not on the curve
  const q = new Uint8Array(65).fill(1);
  q[0] = 4;
  const ecBlob = new Uint8Array([
    0, 0, 0, 19, ...Buffer.from("ecdsa-sha2-nistp256"), 0, 0, 0, 8, ...Buffer.from("nistp256"), 0, 0, 0, 65, ...q,
  ]);
  await assert.rejects(buildUserCert({ ...base, subject: "ecdsa-sha2-nistp256 " + b64encode(ecBlob) }), /curve/);
});

test("CA public key line and fingerprint match ssh-keygen -l", needKeygen, async () => {
  const dir = tmp();
  try {
    const ca = await newCa();
    const line = await caPublicKeyLine(ca.publicKey);
    assert.match(line, /^ecdsa-sha2-nistp256 AAAA\S+ yessh-ca$/);
    writeFileSync(join(dir, "ca.pub"), line + "\n");
    const out = execFileSync("ssh-keygen", ["-l", "-f", join(dir, "ca.pub")]).toString();
    const fp = await fingerprint(b64decode(line.split(" ")[1]));
    assert.equal(out.trim(), `256 ${fp} yessh-ca (ECDSA)`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

for (const keyType of ["ed25519", "ecdsa"]) {
  test(`${keyType} subject: ssh-keygen -L agrees with builder`, needKeygen, async () => {
    const dir = tmp();
    try {
      const ca = await newCa();
      const caLine = await caPublicKeyLine(ca.publicKey);
      const caFp = await fingerprint(b64decode(caLine.split(" ")[1]));
      const subject = keygen(dir, keyType);
      const subjectFp = await fingerprint(b64decode(subject.split(" ")[1]));
      const now = 1790000000;
      const cert = await buildUserCert({
        ca,
        subject,
        keyId: "yessh:mgmt-1:AAECAwQFBgcICQoLDA0ODw",
        principals: ["root", "deploy"],
        validAfter: now - 60,
        validBefore: now + 3600,
        serial: 1790000000123,
      });
      const certType = keyType === "ed25519" ? "ssh-ed25519-cert-v01@openssh.com" : "ecdsa-sha2-nistp256-cert-v01@openssh.com";
      assert.ok(cert.line.startsWith(certType + " "));
      assert.ok(cert.line.endsWith(" yessh:mgmt-1:AAECAwQFBgcICQoLDA0ODw"));

      const l = keygenList(dir, cert.line);
      assert.equal(l.type, `${certType} user certificate`, l.raw);
      assert.equal(l.publicKey, `${keyType === "ed25519" ? "ED25519" : "ECDSA"}-CERT ${subjectFp}`);
      assert.equal(l.signingCa, `ECDSA ${caFp} (using ecdsa-sha2-nistp256)`);
      assert.equal(l.keyId, '"yessh:mgmt-1:AAECAwQFBgcICQoLDA0ODw"');
      assert.equal(l.serial, "1790000000123");
      assert.equal(l.valid, `from ${iso(now - 60)} to ${iso(now + 3600)}`);
      assert.deepEqual(l.principals, ["root", "deploy"]);
      assert.deepEqual(l.critical, []);
      assert.deepEqual(l.extensions, ["permit-pty"]);

      // Our own parser agrees and verifies the signature.
      const parsed = await parseCert(cert.line);
      assert.deepEqual(parsed.principals, ["root", "deploy"]);
      assert.equal(parsed.validBefore, BigInt(now + 3600));
      assert.equal(parsed.certType, 1);
      assert.equal(await fingerprint(parsed.subjectBlob), subjectFp);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

test("critical options and sorted extensions", needKeygen, async () => {
  const dir = tmp();
  try {
    const ca = await newCa();
    const now = Math.floor(Date.now() / 1000);
    const cert = await buildUserCert({
      ca,
      subject: keygen(dir, "ed25519"),
      keyId: "yessh:x:y",
      principals: ["root"],
      validAfter: now - 60,
      validBefore: now + 60,
      criticalOptions: { "source-address": "10.0.0.0/8,192.168.1.1" },
      extensions: ["permit-pty", "permit-agent-forwarding", "permit-port-forwarding"],
    });
    const l = keygenList(dir, cert.line);
    assert.deepEqual(l.critical, ["source-address 10.0.0.0/8,192.168.1.1"], l.raw);
    assert.deepEqual(l.extensions, ["permit-agent-forwarding", "permit-port-forwarding", "permit-pty"]);
    const parsed = await parseCert(cert.line);
    assert.deepEqual(parsed.criticalOptions, { "source-address": "10.0.0.0/8,192.168.1.1" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("many signatures parse (exercises random r/s high-bit and length variants)", needKeygen, async () => {
  const dir = tmp();
  try {
    const ca = await newCa();
    const subject = keygen(dir, "ed25519");
    const lens = new Set();
    // Write all certs, then let ssh-keygen -L parse (and verify) each one.
    const files = [];
    for (let i = 0; i < 64; i++) {
      const cert = await buildUserCert({
        ca, subject, keyId: `k${i}`, principals: ["root"], validAfter: 1000, validBefore: 2000 + i,
      });
      const sig = new Reader((await parseCert(cert.line)).signature);
      sig.str();
      const inner = new Reader(sig.bytes());
      lens.add(inner.bytes().length).add(inner.bytes().length);
      const f = join(dir, `c${i}-cert.pub`);
      writeFileSync(f, cert.line + "\n");
      files.push(f);
      assert.equal((await parseCert(cert.line)).keyId, `k${i}`);
    }
    // 64 signatures -> 128 mpints: both the 33-byte (high bit) and 32-byte forms must occur.
    assert.ok(lens.has(33) && lens.has(32), `mpint lengths seen: ${[...lens]}`);
    for (const f of files) execFileSync("ssh-keygen", ["-L", "-f", f], { stdio: "ignore" });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("ssh-keygen -L rejects tampered certificates (signature is really checked)", needKeygen, async () => {
  const dir = tmp();
  try {
    const ca = await newCa();
    const cert = await buildUserCert({
      ca, subject: keygen(dir, "ed25519"), keyId: "yessh:a:b", principals: ["root"], validAfter: 1000, validBefore: 2000,
    });
    // Flip one byte inside the principals ("root" -> "roou") and one in the signature.
    const idx = Buffer.from(cert.blob).indexOf(Buffer.from("root"));
    for (const pos of [idx + 3, cert.blob.length - 5]) {
      const blob = cert.blob.slice();
      blob[pos] ^= 1;
      const f = join(dir, `t${pos}-cert.pub`);
      writeFileSync(f, `${cert.type} ${b64encode(blob)} x\n`);
      const res = spawnSync("ssh-keygen", ["-L", "-f", f]);
      assert.notEqual(res.status, 0, `tampered byte ${pos} accepted:\n${res.stdout}`);
      await assert.rejects(parseCert(blob));
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

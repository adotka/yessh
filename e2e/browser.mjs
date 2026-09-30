// Browser-driven smoke test of the real PWA UI (Chromium via Playwright):
// create CA → read pairing string → `yessh pair` → `yessh request` → approve in the UI.
//
//   node e2e/browser.mjs            (needs Playwright; set PLAYWRIGHT_MODULE if not resolvable)
//   E2E_NTFY=http://localhost:18080  E2E_SCREENSHOTS=dir  YESSH_BIN=path
//
// Serves pwa/ itself on http://localhost:18000 (localhost is a secure context for WebCrypto).

import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import assert from "node:assert/strict";

const here = dirname(fileURLToPath(import.meta.url));
const pwaDir = join(here, "..", "pwa");
const NTFY = process.env.E2E_NTFY ?? "http://localhost:18080";
const shots = process.env.E2E_SCREENSHOTS;

async function loadPlaywright() {
  for (const spec of [process.env.PLAYWRIGHT_MODULE, "playwright"].filter(Boolean)) {
    try {
      return await import(spec.startsWith("/") ? pathToFileURL(join(spec, "index.mjs")).href : spec);
    } catch {
      // try next
    }
  }
  const globalRoot = execFileSync("npm", ["root", "-g"], { encoding: "utf8" }).trim();
  return import(pathToFileURL(join(globalRoot, "playwright", "index.mjs")).href);
}

const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css",
  ".webmanifest": "application/manifest+json", ".svg": "image/svg+xml", ".png": "image/png" };

function serve(port) {
  const srv = createServer((req, res) => {
    let p = normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^(\.\.[/\\])+/, "");
    if (p.endsWith("/")) p += "index.html";
    const file = join(pwaDir, p);
    try {
      if (!file.startsWith(pwaDir) || !statSync(file).isFile()) throw new Error();
      res.writeHead(200, { "Content-Type": TYPES[extname(file)] ?? "application/octet-stream" });
      res.end(readFileSync(file));
    } catch {
      res.writeHead(404).end();
    }
  });
  return new Promise((r) => srv.listen(port, "127.0.0.1", () => r(srv)));
}

const { chromium } = await loadPlaywright();
const work = mkdtempSync(join(tmpdir(), "yessh-browser-"));
const env = { ...process.env, YESSH_CONFIG: join(work, "config.json"), YESSH_DIR: join(work, "run") };
const yessh = process.env.YESSH_BIN ?? join(work, "yessh");
if (!process.env.YESSH_BIN) execFileSync("go", ["build", "-o", yessh, "./cmd/yessh"], { cwd: join(here, "..", "host") });
const srv = await serve(18000);
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
const errors = [];
let n = 0;
const shot = async (page, name) => {
  if (!shots) return;
  mkdirSync(shots, { recursive: true });
  await page.screenshot({ path: join(shots, `${String(++n).padStart(2, "0")}-${name}.png`), fullPage: true });
};

try {
  const ctx = await browser.newContext({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, colorScheme: "dark" });
  await ctx.grantPermissions(["clipboard-read", "clipboard-write"]);
  const page = await ctx.newPage();
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => m.type() === "error" && errors.push(m.text()));

  await page.goto("http://localhost:18000/");
  await page.getByRole("heading", { name: "Create your SSH CA" }).waitFor();
  await page.fill("#ntfy", NTFY);
  await shot(page, "create");
  await page.getByRole("button", { name: "Create CA" }).click();
  await page.getByRole("heading", { name: "Setup" }).waitFor();

  await page.fill("#principals", "root");
  await page.getByRole("button", { name: "Save policy" }).click();
  await page.getByText("Saved.").waitFor();

  await page.getByRole("button", { name: "Show pairing string" }).click();
  const pairing = (await page.locator(".mono.card", { hasText: "yessh1:" }).first().textContent()).trim();
  assert.match(pairing, /^yessh1:/);
  await shot(page, "setup");

  execFileSync(yessh, ["pair", pairing], { env });

  const req = spawn(yessh, ["request", "-p", "root", "-p", "admin", "-t", "4h", "--label", "browser"], { env });
  let err = "";
  req.stderr.on("data", (d) => (err += d));
  const exited = new Promise((r) => req.on("close", r));

  await page.goto("http://localhost:18000/#/");
  const card = page.locator("a.card", { hasText: "browser" });
  await card.waitFor({ timeout: 15000 });
  await shot(page, "pending");
  await card.click();
  await page.getByRole("button", { name: "yessh", exact: true }).waitFor();
  if (process.env.E2E_DEBUG) console.log(await page.locator("main").innerHTML());
  // admin is not allowed by policy: only root is offered, TTL preselects defaultTtl (1h).
  assert.deepEqual(await page.locator("input[type=checkbox]").evaluateAll((els) => els.map((e) => e.value)), ["root"]);
  assert.equal(await page.locator("#ttl").inputValue(), "3600");
  assert.match(await page.locator(".fp").textContent(), /^SHA256:/);
  await shot(page, "approve");
  await page.getByRole("button", { name: "yessh", exact: true }).click();
  await page.getByRole("heading", { name: "Approved" }).waitFor();

  const code = await exited;
  assert.equal(code, 0, err);
  const status = execFileSync(yessh, ["status"], { env, encoding: "utf8" });
  assert.match(status, /Principals:\s+root\n/);

  await page.goto("http://localhost:18000/#/log");
  await page.locator(".badge.approved").waitFor();
  await shot(page, "log");

  // Reload: CA survives in IndexedDB; service worker registered.
  await page.reload();
  await page.locator(".badge.approved").waitFor();
  const swReady = await page.evaluate(async () => !!(await navigator.serviceWorker.ready));
  assert.ok(swReady, "service worker");

  assert.deepEqual(errors, []);
  console.log("browser e2e: ok");
} finally {
  await browser.close();
  srv.close();
  rmSync(work, { recursive: true, force: true });
}

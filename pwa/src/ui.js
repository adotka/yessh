// DOM layer: routing and screens. All untrusted text goes through textContent, never innerHTML.

import { App } from "./app.js";
import { indexedDBStore } from "./store.js";
import qrcode from "../vendor/qrcode.mjs";

const EXTENSIONS = [
  "permit-pty",
  "permit-agent-forwarding",
  "permit-port-forwarding",
  "permit-X11-forwarding",
  "permit-user-rc",
];
const TTL_CHOICES = [5 * 60, 15 * 60, 30 * 60, 3600, 2 * 3600, 4 * 3600, 8 * 3600, 12 * 3600, 24 * 3600];

const app = new App({ store: indexedDBStore });
const main = document.getElementById("main");
const nav = document.getElementById("nav");
let timers = [];

// ---- helpers ----

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (k === "class") el.className = v;
    else if (k in el && typeof v !== "string") el[k] = v;
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

function fmtDur(s) {
  s = Math.max(0, Math.round(s));
  if (s < 90) return `${s}s`;
  if (s < 3600) return `${Math.round(s / 60)}m`;
  const hrs = Math.floor(s / 3600);
  const m = Math.round((s % 3600) / 60);
  return m ? `${hrs}h ${m}m` : `${hrs}h`;
}

const fmtTime = (unix) => new Date(unix * 1000).toLocaleString();

function render(...nodes) {
  for (const t of timers) clearInterval(t);
  timers = [];
  main.replaceChildren(...nodes.flat(Infinity).filter((n) => n !== null && n !== undefined && n !== false));
  window.scrollTo(0, 0);
}

function every(ms, fn) {
  timers.push(setInterval(fn, ms));
}

async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const old = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => (button.textContent = old), 1500);
  } catch {
    button.textContent = "Copy failed: select the text manually";
  }
}

function copyBlock(text, label = "Copy") {
  const btn = h("button", { type: "button" }, label);
  btn.addEventListener("click", () => copy(text, btn));
  return h("div", {}, h("p", { class: "mono card" }, text), btn);
}

function qrSvg(text) {
  const qr = qrcode(0, "L");
  qr.addData(text, "Byte");
  qr.make();
  const n = qr.getModuleCount();
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `-2 -2 ${n + 4} ${n + 4}`);
  svg.setAttribute("shape-rendering", "crispEdges");
  let d = "";
  for (let r = 0; r < n; r++) for (let c = 0; c < n; c++) if (qr.isDark(r, c)) d += `M${c} ${r}h1v1h-1z`;
  const path = document.createElementNS(ns, "path");
  path.setAttribute("d", d);
  path.setAttribute("fill", "#000");
  svg.append(path);
  return h("div", { class: "qr" }, svg);
}

function errorBox(e) {
  return h("p", { class: "error" }, String(e?.message ?? e));
}

// ---- screens ----

function screenCreate() {
  const ntfyInput = h("input", { type: "url", id: "ntfy", value: "https://ntfy.sh", required: true });
  const tokenInput = h("input", { type: "password", id: "token", autocomplete: "off" });
  const status = h("div");
  const btn = h("button", { class: "primary", type: "button" }, "Create CA");
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    status.replaceChildren(h("p", { class: "muted" }, "Generating…"));
    try {
      const pwaUrl = location.origin + location.pathname;
      await app.createCA({ ntfyUrl: ntfyInput.value.trim(), token: tokenInput.value.trim(), pwaUrl });
      location.hash = "#/setup";
      route();
    } catch (e) {
      btn.disabled = false;
      status.replaceChildren(errorBox(e));
    }
  });
  render(
    h("h1", {}, "Create your SSH CA"),
    h("p", {}, "This generates an ECDSA P-256 certificate authority that never leaves this browser, and a random key shared with your management host."),
    h("label", { for: "ntfy" }, "ntfy server"),
    ntfyInput,
    h("label", { for: "token" }, "ntfy access token (optional, for self-hosted with auth)"),
    tokenInput,
    h("div", { class: "actions" }, btn),
    status,
  );
}

async function screenPending() {
  const list = h("div", {}, h("p", { class: "muted" }, "Checking for requests…"));
  const refreshBtn = h("button", { type: "button" }, "Refresh");
  render(h("div", { class: "row" }, h("h1", {}, "Pending requests"), refreshBtn), list);

  const draw = async () => {
    try {
      const items = await app.refresh();
      if (items.length === 0) {
        list.replaceChildren(h("p", { class: "muted" }, "Nothing waiting. Requests show up here for 2 minutes after they're sent."));
        return;
      }
      list.replaceChildren(
        ...items.map((it) =>
          h("a", { class: "card", href: `#/r/${encodeURIComponent(it.req.id)}` },
            h("div", { class: "row" }, h("strong", {}, it.req.label), h("span", { class: "muted small" }, `${fmtDur(it.age)} ago`)),
            h("div", { class: "small" }, `${it.req.who} → ${it.req.principals.join(", ")} for ${fmtDur(it.req.ttl)}`),
            h("div", { class: "mono muted" }, it.fingerprint),
          ),
        ),
      );
    } catch (e) {
      list.replaceChildren(errorBox(e));
    }
  };
  refreshBtn.addEventListener("click", draw);
  await draw();
  every(5000, draw);
}

async function screenRequest(id) {
  render(h("p", { class: "muted" }, "Loading request…"));
  let item = null;
  let error = null;
  // The request may take a moment to show up in the ntfy cache after the notification.
  for (let i = 0; i < 10 && !item; i++) {
    try {
      await app.refresh();
      item = await app.evaluate(id);
    } catch (e) {
      error = e;
    }
    if (!item) await new Promise((r) => setTimeout(r, 1500));
  }
  if (!item) {
    render(
      h("h1", {}, "Request not found"),
      error ? errorBox(error) : h("p", { class: "muted" }, "It may have expired or been answered already."),
      h("a", { href: "#/" }, "Back to pending"),
    );
    return;
  }
  drawRequest(item);
}

function drawRequest(item) {
  const { req, evaluation, fingerprint } = item;
  const status = h("div");
  const age = h("span", {}, fmtDur(item.age));
  const tick = () => {
    const a = Math.floor(Date.now() / 1000) - req.ts;
    age.textContent = `${fmtDur(a)} ago`;
    if (a > 120) age.className = "error";
  };
  tick();

  const details = h("dl", { class: "kv" },
    h("dt", {}, "From"), h("dd", {}, req.label),
    h("dt", {}, "Who"), h("dd", {}, req.who),
    h("dt", {}, "Age"), h("dd", {}, age),
    h("dt", {}, "Requested"), h("dd", {}, `${req.principals.join(", ")} for ${fmtDur(req.ttl)}`),
  );
  const keyCard = h("div", { class: "card" },
    h("div", { class: "muted small" }, "Ephemeral key fingerprint"),
    h("div", { class: "fp" }, fingerprint || "(invalid key)"),
  );

  const nope = h("button", { type: "button", class: "danger" }, "nope");
  nope.addEventListener("click", () => answer(() => app.deny(req.id)));

  const answer = async (fn) => {
    for (const b of main.querySelectorAll("button")) b.disabled = true;
    status.replaceChildren(h("p", { class: "muted" }, "Sending…"));
    try {
      const audit = await fn();
      render(
        h("h1", {}, audit.decision === "approved" ? "Approved" : "Denied"),
        h("p", {}, audit.decision === "approved"
          ? `${audit.label}: ${audit.principals.join(", ")} for ${fmtDur(audit.ttl)} (serial ${audit.serial})`
          : `${audit.label}: request denied.`),
        h("a", { href: "#/" }, "Back to pending"),
      );
    } catch (e) {
      for (const b of main.querySelectorAll("button")) b.disabled = false;
      status.replaceChildren(errorBox(e));
    }
  };

  if (!evaluation.ok) {
    const reasons = {
      stale: "This request is too old (or from the future). The host has given up on it.",
      replay: "This request was already answered.",
      malformed: `Malformed request (${evaluation.detail}).`,
    };
    const children = [h("h1", {}, "Request"), details, keyCard];
    if (evaluation.reason === "principals-not-allowed") {
      const add = h("button", { type: "button" }, `Allow ${evaluation.detail.join(", ")}`);
      add.addEventListener("click", async () => {
        await app.allowPrincipals(evaluation.detail);
        drawRequest(await app.evaluate(req.id));
      });
      children.push(
        h("div", { class: "warn" },
          h("p", {}, `None of the requested principals are in your allowlist: ${evaluation.detail.join(", ")}.`),
          add),
      );
    } else {
      children.push(h("div", { class: "warn" }, reasons[evaluation.reason] ?? evaluation.reason));
    }
    children.push(h("div", { class: "actions" }, nope), status);
    render(...children);
    every(1000, tick);
    return;
  }

  const boxes = evaluation.principals.map((p) =>
    h("label", { class: "check" }, h("input", { type: "checkbox", value: p, checked: true }), p),
  );
  const dropped = req.principals.filter((p) => !evaluation.principals.includes(p));
  const ttlSelect = h("select", { id: "ttl" },
    [...new Set([...TTL_CHOICES.filter((t) => t < evaluation.maxTtl), evaluation.maxTtl])]
      .sort((a, b) => a - b)
      .map((t) => h("option", { value: String(t), selected: t === evaluation.ttl }, fmtDur(t))),
  );
  const yes = h("button", { type: "button", class: "primary" }, "yessh");
  yes.addEventListener("click", () => {
    const principals = boxes.map((b) => b.querySelector("input")).filter((i) => i.checked).map((i) => i.value);
    if (principals.length === 0) {
      status.replaceChildren(errorBox("Select at least one principal."));
      return;
    }
    answer(() => app.approve(req.id, { principals, ttl: Number(ttlSelect.value) }));
  });

  render(
    h("h1", {}, `Certificate for ${req.label}?`),
    details,
    keyCard,
    h("h2", {}, "Principals"),
    boxes,
    dropped.length ? h("p", { class: "muted small" }, `Not allowed by policy, will be dropped: ${dropped.join(", ")}`) : null,
    h("label", { for: "ttl" }, "Valid for"),
    ttlSelect,
    h("div", { class: "actions" }, nope, yes),
    status,
  );
  every(1000, tick);
}

async function screenLog() {
  const entries = await app.log();
  const exportBtn = h("button", { type: "button" }, "Export JSON");
  exportBtn.addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(entries.slice().reverse(), null, 2)], { type: "application/json" });
    const a = h("a", { href: URL.createObjectURL(blob), download: `yessh-log-${new Date().toISOString().slice(0, 10)}.json` });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  render(
    h("div", { class: "row" }, h("h1", {}, "Log"), exportBtn),
    entries.length === 0
      ? h("p", { class: "muted" }, "No issuances or denials yet.")
      : entries.map((e) =>
          h("div", { class: "card small" },
            h("div", { class: "row" },
              h("strong", {}, e.label),
              h("span", { class: `badge ${e.decision}` }, e.decision)),
            h("div", { class: "muted" }, fmtTime(e.at)),
            h("div", {}, `${(e.principals ?? []).join(", ")} for ${fmtDur(e.ttl)}`),
            e.serial ? h("div", { class: "muted" }, `serial ${e.serial}`) : null,
            h("div", { class: "mono muted" }, e.fingerprint),
          ),
        ),
  );
}

async function screenSetup() {
  const info = await app.info();
  const policy = await app.getPolicy();

  // Pairing string: hidden until asked for, because it contains the PSK.
  const pairingBox = h("div");
  const reveal = h("button", { type: "button" }, "Show pairing string");
  reveal.addEventListener("click", () => {
    pairingBox.replaceChildren(
      h("div", { class: "warn" }, "Contains the shared secret. Type or paste it into a shell on your management host yourself. Never give it to a coding agent or paste it into chat."),
      copyBlock(info.pairing),
      h("p", { class: "muted small" }, "On the host:"),
      h("p", { class: "mono card" }, "yessh pair '<pairing string>'"),
      qrSvg(info.pairing),
    );
  });
  pairingBox.append(reveal);

  // Policy form.
  const principals = h("input", { type: "text", id: "principals", value: policy.allowedPrincipals.join(", "), placeholder: "root, deploy" });
  const maxTtl = h("input", { type: "number", id: "maxTtl", min: "0.1", step: "0.25", value: String(policy.maxTtl / 3600) });
  const defTtl = h("input", { type: "number", id: "defTtl", min: "0.1", step: "0.25", value: String(policy.defaultTtl / 3600) });
  const extBoxes = EXTENSIONS.map((x) =>
    h("label", { class: "check" }, h("input", { type: "checkbox", value: x, checked: policy.extensions.includes(x) }), x),
  );
  const srcAddr = h("input", { type: "text", id: "src", value: policy.sourceAddress, placeholder: "e.g. 203.0.113.7/32 (off when empty)" });
  const policyStatus = h("div");
  const save = h("button", { type: "button", class: "primary" }, "Save policy");
  save.addEventListener("click", async () => {
    try {
      const next = await app.setPolicy({
        allowedPrincipals: principals.value.split(/[\s,]+/),
        maxTtl: Math.round(Number(maxTtl.value) * 3600),
        defaultTtl: Math.round(Number(defTtl.value) * 3600),
        extensions: extBoxes.map((b) => b.querySelector("input")).filter((i) => i.checked).map((i) => i.value),
        sourceAddress: srcAddr.value.trim(),
      });
      principals.value = next.allowedPrincipals.join(", ");
      policyStatus.replaceChildren(h("p", { class: "muted" }, "Saved."));
    } catch (e) {
      policyStatus.replaceChildren(errorBox(e));
    }
  });

  const resetInput = h("input", { type: "text", id: "reset", placeholder: "type: delete my CA" });
  const resetBtn = h("button", { type: "button", class: "danger" }, "Delete CA and all data");
  resetBtn.addEventListener("click", async () => {
    if (resetInput.value.trim() !== "delete my CA") return;
    await app.reset();
    location.hash = "#/";
    route();
  });

  render(
    h("h1", {}, "Setup"),
    h("h2", {}, "1. CA public key"),
    h("p", { class: "muted small" }, "Put this line in /etc/ssh/yessh_ca.pub on fleet hosts and set TrustedUserCAKeys to that file."),
    copyBlock(info.caLine),
    h("p", { class: "small" }, "Fingerprint: ", h("span", { class: "mono" }, info.caFingerprint)),
    h("h2", {}, "2. Pair the management host"),
    pairingBox,
    h("h2", {}, "3. Notifications"),
    h("p", { class: "small" }, "Install the ntfy app and subscribe to this topic on ", h("span", { class: "mono" }, info.ntfy), ":"),
    h("p", { class: "mono card" }, info.reqTopic),
    h("a", { class: "button", href: info.subscribeLink }, "Subscribe in ntfy"),
    h("h2", {}, "4. Policy"),
    h("label", { for: "principals" }, "Allowed principals"),
    principals,
    h("label", { for: "maxTtl" }, "Maximum TTL (hours)"),
    maxTtl,
    h("label", { for: "defTtl" }, "Default TTL (hours)"),
    defTtl,
    h("label", {}, "Extensions"),
    extBoxes,
    h("label", { for: "src" }, "source-address (critical option)"),
    srcAddr,
    h("div", { class: "actions" }, save),
    policyStatus,
    h("h2", {}, "Danger zone"),
    h("p", { class: "muted small" }, "Deleting the CA is permanent. Fleet hosts will need the new CA line."),
    resetInput,
    h("div", { class: "actions" }, resetBtn),
  );
}

// ---- routing ----

async function route() {
  const hash = location.hash || "#/";
  nav.hidden = !app.paired;
  for (const a of nav.querySelectorAll("a")) a.classList.toggle("active", a.getAttribute("href") === hash);
  try {
    if (!app.paired) return screenCreate();
    const m = hash.match(/^#\/r\/([A-Za-z0-9_-]{1,64})$/);
    if (m) return await screenRequest(m[1]);
    if (hash === "#/log") return await screenLog();
    if (hash === "#/setup") return await screenSetup();
    return await screenPending();
  } catch (e) {
    render(h("h1", {}, "Error"), errorBox(e));
  }
}

async function start() {
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register("sw.js").catch(() => {});
  }
  // Ask the browser not to evict our storage: it holds the CA key.
  navigator.storage?.persist?.().catch(() => {});
  try {
    await app.load();
  } catch (e) {
    render(h("h1", {}, "Storage error"), errorBox(e));
    return;
  }
  window.addEventListener("hashchange", route);
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "visible" && app.paired && (location.hash === "" || location.hash === "#/")) route();
  });
  route();
}

start();

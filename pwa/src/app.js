// DOM-free controller for the PWA. ui.js renders it; the e2e harness drives it directly.

import { generateCA, generatePSK } from "./crypto.js";
import { b64decode } from "./encoding.js";
import * as ntfy from "./ntfy.js";
import {
  AAD_REQ,
  AAD_RESP,
  DEFAULT_POLICY,
  MAX_SKEW,
  SEEN_TTL,
  approve,
  deny,
  derive,
  evaluateRequest,
  makePairing,
  open,
  seal,
} from "./protocol.js";
import { caPublicKeyLine, fingerprint, parsePublicKey } from "./sshcert.js";

const PENDING_WINDOW = 600; // seconds: how far back the pending list looks

export class App {
  /**
   * @param {object} opts
   * @param {object} opts.store      indexedDBStore or memoryStore() from store.js
   * @param {Function} [opts.fetchImpl]
   * @param {() => number} [opts.now]  unix seconds
   */
  constructor({ store, fetchImpl, now }) {
    this.store = store;
    this.fetchImpl = fetchImpl ?? ((...a) => fetch(...a));
    this.now = now ?? (() => Math.floor(Date.now() / 1000));
    this.requests = new Map(); // id -> { req, receivedAt }
    this.ca = null;
    this.keys = null;
    this.settings = null;
  }

  get paired() {
    return !!this.ca;
  }

  /** Load CA, PSK and settings from storage. Returns whether a CA exists. */
  async load() {
    const [ca, psk, settings] = await Promise.all([
      this.store.get("ca"),
      this.store.get("psk"),
      this.store.get("settings"),
    ]);
    if (ca && psk && settings) {
      this.ca = ca;
      this.psk = psk;
      this.settings = settings;
      this.keys = await derive(psk);
    }
    return this.paired;
  }

  /** First-launch setup: generate CA + PSK. */
  async createCA({ ntfyUrl = "https://ntfy.sh", token = "", pwaUrl }) {
    if (this.paired) throw new Error("a CA already exists; reset first");
    const u = new URL(ntfyUrl);
    if (u.protocol !== "https:" && u.protocol !== "http:") throw new Error("ntfy URL must be http(s)");
    const ca = await generateCA();
    const psk = generatePSK();
    const settings = { ntfy: u.href.replace(/\/+$/, ""), token, pwa: pwaUrl };
    await this.store.put("ca", ca);
    await this.store.put("psk", psk);
    await this.store.put("settings", settings);
    if (!(await this.store.get("policy"))) await this.store.put("policy", { ...DEFAULT_POLICY });
    await this.load();
  }

  async reset() {
    await this.store.wipe();
    this.ca = this.psk = this.keys = this.settings = null;
    this.requests.clear();
  }

  async info() {
    const caLine = await caPublicKeyLine(this.ca.publicKey);
    return {
      caLine,
      caFingerprint: await fingerprint(b64decode(caLine.split(" ")[1])),
      pairing: makePairing({
        ntfy: this.settings.ntfy,
        pwa: this.settings.pwa,
        psk: this.psk,
        ca: caLine,
        token: this.settings.token || undefined,
      }),
      ntfy: this.settings.ntfy,
      reqTopic: this.keys.reqTopic,
      respTopic: this.keys.respTopic,
      subscribeLink: ntfy.subscribeLink(this.settings.ntfy, this.keys.reqTopic),
    };
  }

  async getPolicy() {
    return { ...DEFAULT_POLICY, ...(await this.store.get("policy")) };
  }

  async setPolicy(p) {
    const cur = await this.getPolicy();
    const next = { ...cur, ...p };
    next.allowedPrincipals = [...new Set(next.allowedPrincipals.map((s) => s.trim()).filter(Boolean))];
    if (!(next.maxTtl > 0 && next.defaultTtl > 0)) throw new Error("TTLs must be positive");
    if (next.defaultTtl > next.maxTtl) next.defaultTtl = next.maxTtl;
    await this.store.put("policy", next);
    return next;
  }

  async allowPrincipals(list) {
    const p = await this.getPolicy();
    return this.setPolicy({ allowedPrincipals: [...p.allowedPrincipals, ...list] });
  }

  /** Poll the request topic and decrypt what is there. Returns pending(). */
  async refresh() {
    const msgs = await ntfy.poll(this.settings.ntfy, this.keys.reqTopic, {
      since: `${PENDING_WINDOW / 60}m`,
      token: this.settings.token,
      fetchImpl: this.fetchImpl,
    });
    for (const m of msgs) {
      const req = await open(this.keys.encKey, AAD_REQ, m.message);
      if (!req || typeof req.id !== "string" || this.requests.has(req.id)) continue;
      this.requests.set(req.id, { req, receivedAt: m.time });
    }
    return this.pending();
  }

  /** Evaluate one known request now. */
  async evaluate(id) {
    const item = this.requests.get(id);
    if (!item) return null;
    const now = this.now();
    const seen = await this.store.loadSeen(now, SEEN_TTL);
    const policy = await this.getPolicy();
    const evaluation = evaluateRequest(item.req, policy, { now, seen: (x) => seen.has(x) });
    let fp = "";
    try {
      fp = await fingerprint(parsePublicKey(item.req.pubkey).blob);
    } catch {
      // malformed; evaluation says so
    }
    return { ...item, evaluation, policy, fingerprint: fp, age: now - item.req.ts };
  }

  /** Unanswered requests that are still fresh (or only need principals added), newest first. */
  async pending() {
    const out = [];
    for (const id of this.requests.keys()) {
      const e = await this.evaluate(id);
      if (e.evaluation.ok || e.evaluation.reason === "principals-not-allowed") out.push(e);
    }
    return out.sort((a, b) => b.req.ts - a.req.ts);
  }

  async #respond(id, build) {
    const item = await this.evaluate(id);
    if (!item) throw new Error("unknown request");
    const { response, audit } = await build(item);
    const body = await seal(this.keys.encKey, AAD_RESP, response);
    await ntfy.publish(this.settings.ntfy, this.keys.respTopic, body, {
      token: this.settings.token,
      fetchImpl: this.fetchImpl,
    });
    await this.store.markSeen(id, this.now());
    await this.store.appendLog(audit);
    this.requests.delete(id);
    return audit;
  }

  /** Approve with the user's choice ({principals?, ttl?}); re-checks freshness at tap time. */
  approve(id, choice = {}) {
    return this.#respond(id, async ({ req, evaluation, policy }) => {
      if (!evaluation.ok) {
        const why = { stale: "request expired", replay: "request already answered" }[evaluation.reason];
        throw new Error(why ?? `request not acceptable: ${evaluation.reason}`);
      }
      return approve({ ca: this.ca, req, policy, evaluation, choice, now: this.now() });
    });
  }

  deny(id) {
    return this.#respond(id, ({ req }) => deny({ req, now: this.now() }));
  }

  async log() {
    return (await this.store.readLog()).reverse();
  }
}

export { MAX_SKEW };

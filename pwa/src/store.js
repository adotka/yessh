// IndexedDB persistence: CA key pair, PSK, settings, policy, answered request ids, audit log.
// CryptoKey objects are structured-cloneable, so the non-extractable CA key is stored as is.

const DB_NAME = "yessh";
const DB_VERSION = 1;

let dbPromise;

function db() {
  dbPromise ??= new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const d = req.result;
      d.createObjectStore("kv");
      d.createObjectStore("seen"); // request id -> unix seconds answered
      d.createObjectStore("log", { autoIncrement: true });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  return dbPromise;
}

async function tx(store, mode, fn) {
  const d = await db();
  return new Promise((resolve, reject) => {
    const t = d.transaction(store, mode);
    let result;
    Promise.resolve(fn(t.objectStore(store))).then((r) => (result = r), reject);
    t.oncomplete = () => resolve(result);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

const wrap = (req) =>
  new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

export const get = (key) => tx("kv", "readonly", (s) => wrap(s.get(key)));
export const put = (key, value) => tx("kv", "readwrite", (s) => wrap(s.put(value, key)));
export const del = (key) => tx("kv", "readwrite", (s) => wrap(s.delete(key)));

// ---- answered request ids (replay protection) ----

export async function markSeen(id, now) {
  await tx("seen", "readwrite", (s) => wrap(s.put(now, id)));
}

/** Load answered ids newer than maxAge seconds into a Set, pruning older ones. */
export async function loadSeen(now, maxAge) {
  return tx("seen", "readwrite", async (s) => {
    const out = new Set();
    await new Promise((resolve, reject) => {
      const cur = s.openCursor();
      cur.onsuccess = () => {
        const c = cur.result;
        if (!c) return resolve();
        if (now - c.value > maxAge) c.delete();
        else out.add(c.key);
        c.continue();
      };
      cur.onerror = () => reject(cur.error);
    });
    return out;
  });
}

// ---- audit log (append-only from the UI's point of view) ----

export const appendLog = (entry) => tx("log", "readwrite", (s) => wrap(s.add(entry)));
export const readLog = () => tx("log", "readonly", (s) => wrap(s.getAll()));

/** The IndexedDB-backed store as one object (the interface App expects). */
export const indexedDBStore = { get, put, del, markSeen, loadSeen, appendLog, readLog, wipe: () => wipe() };

/** In-memory store with the same interface, for tests and the Node e2e harness. */
export function memoryStore() {
  const kv = new Map();
  const seen = new Map();
  const log = [];
  return {
    get: async (k) => kv.get(k),
    put: async (k, v) => void kv.set(k, v),
    del: async (k) => void kv.delete(k),
    markSeen: async (id, now) => void seen.set(id, now),
    loadSeen: async (now, maxAge) => {
      for (const [id, t] of seen) if (now - t > maxAge) seen.delete(id);
      return new Set(seen.keys());
    },
    appendLog: async (e) => void log.push(structuredClone(e)),
    readLog: async () => structuredClone(log),
    wipe: async () => {
      kv.clear();
      seen.clear();
      log.length = 0;
    },
  };
}

/** Delete everything (used by "Reset CA"). */
export async function wipe() {
  const d = await db();
  d.close();
  dbPromise = undefined;
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = resolve;
    req.onerror = () => reject(req.error);
    req.onblocked = resolve;
  });
}

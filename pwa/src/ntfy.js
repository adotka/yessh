// Minimal ntfy client for the PWA: poll cached messages and publish.

const topicUrl = (base, topic) => `${base.replace(/\/+$/, "")}/${encodeURIComponent(topic)}`;

function headers(token) {
  return token ? { Authorization: `Bearer ${token}` } : {};
}

/** Fetch cached messages on a topic (default: last 10 minutes). Returns ntfy message objects. */
export async function poll(base, topic, { since = "10m", token, fetchImpl = fetch } = {}) {
  const res = await fetchImpl(`${topicUrl(base, topic)}/json?poll=1&since=${encodeURIComponent(since)}`, {
    headers: headers(token),
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`ntfy poll: ${res.status} ${res.statusText}`);
  const text = await res.text();
  const out = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      const m = JSON.parse(line);
      if (m.event === "message" && typeof m.message === "string") out.push(m);
    } catch {
      // ignore malformed lines
    }
  }
  return out;
}

export async function publish(base, topic, body, { token, fetchImpl = fetch } = {}) {
  const res = await fetchImpl(topicUrl(base, topic), { method: "POST", body, headers: headers(token) });
  if (!res.ok) throw new Error(`ntfy publish: ${res.status} ${res.statusText}`);
}

/** Deep link that opens the ntfy Android app subscribed to topic on base. */
export function subscribeLink(base, topic) {
  const u = new URL(base);
  const path = u.pathname.replace(/\/+$/, "");
  const insecure = u.protocol === "http:" ? "?secure=false" : "";
  return `ntfy://${u.host}${path}/${encodeURIComponent(topic)}${insecure}`;
}

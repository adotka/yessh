// Tiny deterministic animation runtime for the README GIFs.
// Each scene defines window.SCENE = { duration, width, height, render(t) } where render draws the
// state at time t (seconds) from scratch. render.mjs steps t frame by frame; opening a scene HTML
// file directly in a browser plays it in real time for previewing.

export const clamp01 = (x) => Math.max(0, Math.min(1, x));
export const easeOut = (x) => 1 - Math.pow(1 - clamp01(x), 3);
export const easeInOut = (x) => {
  x = clamp01(x);
  return x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2;
};
/** 0 before a, 1 after b, eased in between. */
export const prog = (t, a, b, ease = easeOut) => ease((t - a) / (b - a));
/** Fade in at a, fade out at b (each over d seconds). */
export const window01 = (t, a, b, d = 0.25) => Math.min(prog(t, a, a + d), 1 - prog(t, b, b + d));

export const $ = (sel) => document.querySelector(sel);

export function esc(s) {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/**
 * Terminal transcript.
 * events: { at, cmd } typed at `cps` chars/s after a prompt (with `typed: n`, only n chars are
 * typed and the rest is pasted), or { at, out } printed at once,
 * or { at, prompt: true } for an idle prompt with a blinking cursor. `cls` adds a CSS class.
 */
export function renderTerminal(el, events, t, { prompt = "$ ", cps = 22 } = {}) {
  const lines = [];
  let cursorOn = false;
  const visible = events.filter((e) => t >= e.at);
  visible.forEach((e, i) => {
    const last = i === visible.length - 1;
    if (e.cmd !== undefined) {
      const rate = e.cps ?? cps;
      let n = Math.min(e.cmd.length, Math.floor((t - e.at) * rate));
      // `typed`: only the first `typed` chars are typed; the rest is pasted 0.35 s later.
      if (e.typed !== undefined) n = t - e.at >= e.typed / rate + 0.35 ? e.cmd.length : Math.min(n, e.typed);
      const typing = n < e.cmd.length;
      lines.push(`<span class="p">${esc(e.prompt ?? prompt)}</span>${esc(e.cmd.slice(0, n))}${last ? cursor(t, typing) : ""}`);
      cursorOn ||= last;
    } else if (e.prompt) {
      if (!last) return; // an idle prompt is replaced by whatever comes next
      lines.push(`<span class="p">${esc(typeof e.prompt === "string" ? e.prompt : prompt)}</span>${last ? cursor(t, false) : ""}`);
    } else {
      lines.push(`<span class="${e.cls ?? ""}">${esc(e.out)}</span>`);
    }
  });
  el.innerHTML = lines.map((l) => `<div class="ln">${l || "&nbsp;"}</div>`).join("");
  el.scrollTop = el.scrollHeight;
  return cursorOn;
}

function cursor(t, solid) {
  const on = solid || Math.floor(t * 2) % 2 === 0;
  return `<span class="cur" style="opacity:${on ? 1 : 0}">&nbsp;</span>`;
}

/** Tap indicator: a circle that pops at (x, y) relative to `parent` around time `at`. */
export function tap(el, t, at, x, y) {
  const p = (t - at) / 0.45;
  if (p < -0.4 || p > 1) {
    el.style.opacity = 0;
    return;
  }
  const appear = clamp01((p + 0.4) / 0.4); // finger approaches
  const ripple = clamp01(p);
  el.style.left = `${x}px`;
  el.style.top = `${y}px`;
  el.style.opacity = p < 0 ? appear * 0.85 : 0.85 * (1 - ripple);
  el.style.transform = `translate(-50%,-50%) scale(${p < 0 ? 1.15 - 0.15 * appear : 1 + ripple * 0.9})`;
}

export function play(scene) {
  window.SCENE = scene;
  window.renderAt = (t) => scene.render(t);
  if (!new URLSearchParams(location.search).has("frames")) {
    const start = performance.now();
    const loop = () => {
      scene.render(((performance.now() - start) / 1000) % scene.duration);
      requestAnimationFrame(loop);
    };
    loop();
  } else {
    scene.render(0);
  }
}

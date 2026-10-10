// Generates the yessh brand assets from one definition:
//   docs/brand/yessh-wordmark-{dark,light}.svg   README title (letters outlined, no fonts needed)
//   docs/brand/yessh-mark-{dark,light}.svg       the two-bar mark on its own
//   docs/brand/yessh-icon.svg                    app icon (also used by the README GIFs)
//   docs/brand/social-preview.png                1280×640 GitHub social preview
//   android/app/src/main/res/drawable/ic_launcher_{foreground,monochrome}.xml, ic_stat_yessh.xml
//
//   cd docs/brand/src && npm install && node build.mjs
//
// The idea: "yessh" is yess + ssh sharing "ss". Two tinted bars (green = yess, blue = ssh, the
// ssh bar 20% taller) overlap behind the shared letters. Type is Inter in one ink colour: "ye"
// semibold italic, "ss" extra-bold italic, "h" extra-bold upright. Overlap colours are computed
// up front (55% tints, screen-blended on dark, multiplied on light), so the SVGs need no blend
// modes and render the same everywhere.
import opentype from "opentype.js";
import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const brand = join(here, "..");
const repo = join(brand, "..", "..");
const fontFile = (f) => opentype.parse(readFileSync(join(here, "node_modules/@fontsource/inter/files", f)).buffer);
const FONTS = {
  ye: fontFile("inter-latin-600-italic.woff"),
  ss: fontFile("inter-latin-800-italic.woff"),
  h: fontFile("inter-latin-800-normal.woff"),
};

// ---------------------------------------------------------------- colours

const THEMES = {
  dark: { bg: [13, 17, 23], ink: "#e6edf3", green: [63, 185, 80], blue: [88, 166, 255], mode: "screen" },
  light: { bg: [255, 255, 255], ink: "#1f2328", green: [74, 222, 128], blue: [96, 165, 250], mode: "multiply" },
};
const ALPHA = 0.55;

function blend(backdrop, src, alpha, mode) {
  return backdrop.map((b, i) => {
    const B = b / 255, S = src[i] / 255;
    const mixed = mode === "screen" ? B + S - B * S : B * S;
    return Math.round(255 * ((1 - alpha) * B + alpha * mixed));
  });
}
const hex = (c) => "#" + c.map((v) => v.toString(16).padStart(2, "0")).join("");

function palette(theme, bg = theme.bg, alpha = ALPHA) {
  const left = blend(bg, theme.green, alpha, theme.mode);
  const right = blend(bg, theme.blue, alpha, theme.mode);
  const overlap = blend(left, theme.blue, alpha, theme.mode); // the blue bar is drawn over the green one
  return { left: hex(left), right: hex(right), overlap: hex(overlap), ink: theme.ink };
}

// ---------------------------------------------------------------- shapes

const r2 = (v) => Math.round(v * 100) / 100;

function roundRectPath({ x, y, w, h, r }) {
  return `M${r2(x + r)} ${r2(y)}H${r2(x + w - r)}A${r2(r)} ${r2(r)} 0 0 1 ${r2(x + w)} ${r2(y + r)}` +
    `V${r2(y + h - r)}A${r2(r)} ${r2(r)} 0 0 1 ${r2(x + w - r)} ${r2(y + h)}H${r2(x + r)}` +
    `A${r2(r)} ${r2(r)} 0 0 1 ${r2(x)} ${r2(y + h - r)}V${r2(y + r)}A${r2(r)} ${r2(r)} 0 0 1 ${r2(x + r)} ${r2(y)}Z`;
}

/** Two bars sharing a middle: green left, blue right (taller), overlap in its own colour. */
function barsSvg(left, right, pal, id) {
  return `<defs><clipPath id="${id}"><path d="${roundRectPath(left)}"/></clipPath></defs>` +
    `<path d="${roundRectPath(left)}" fill="${pal.left}"/>` +
    `<path d="${roundRectPath(right)}" fill="${pal.right}"/>` +
    `<path d="${roundRectPath(right)}" fill="${pal.overlap}" clip-path="url(#${id})"/>`;
}

// ---------------------------------------------------------------- wordmark

const S = 100; // font size in SVG units
const LS = -0.03; // letter spacing (em)

function run(font, text, x, y) {
  const upm = font.unitsPerEm;
  const glyphs = [...text].map((c) => font.charToGlyph(c)); // plain letters; no shaping needed
  let d = "";
  const bbox = { x1: Infinity, y1: Infinity, x2: -Infinity, y2: -Infinity };
  glyphs.forEach((g, i) => {
    const p = g.getPath(x, y, S);
    d += p.toPathData(2);
    const bb = p.getBoundingBox();
    bbox.x1 = Math.min(bbox.x1, bb.x1); bbox.y1 = Math.min(bbox.y1, bb.y1);
    bbox.x2 = Math.max(bbox.x2, bb.x2); bbox.y2 = Math.max(bbox.y2, bb.y2);
    x += (g.advanceWidth / upm) * S + LS * S;
    if (i < glyphs.length - 1) x += (font.getKerningValue(g, glyphs[i + 1]) / upm) * S;
  });
  return { d, end: x, bbox };
}

function wordmark(themeName) {
  const pal = palette(THEMES[themeName]);
  const f = FONTS.h;
  const asc = f.tables.hhea.ascender / f.unitsPerEm, desc = -f.tables.hhea.descender / f.unitsPerEm;
  const baseline = ((1 - (asc + desc)) / 2 + asc) * S; // CSS line-height: 1
  const ye = run(FONTS.ye, "ye", 0, baseline);
  const ss = run(FONTS.ss, "ss", ye.end, baseline);
  const h = run(FONTS.h, "h", ss.end, baseline);

  // W3: bars 1.04em tall from 0.02em; the ssh bar 20% taller (centred), 0.05em longer, radius ×1.1.
  const pad = 0.1 * S, top = 0.02 * S, hgt = 1.04 * S, rad = 0.2 * S;
  const H = hgt * 1.2;
  const left = { x: -pad, y: top, w: ss.end - 0 + 2 * pad, h: hgt, r: rad };
  const right = { x: ye.end - pad, y: top - (H - hgt) / 2, w: h.end - ye.end + 2 * pad + 0.05 * S, h: H, r: rad * 1.1 };

  const m = 0.06 * S;
  const minX = Math.min(left.x, ye.bbox.x1) - m, maxX = Math.max(right.x + right.w, h.bbox.x2) + m;
  const minY = Math.min(right.y, ye.bbox.y1) - m, maxY = Math.max(right.y + right.h, ye.bbox.y2) + m;
  const w = maxX - minX, ht = maxY - minY;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${r2(minX)} ${r2(minY)} ${r2(w)} ${r2(ht)}" width="${Math.round(w * 2.4)}" height="${Math.round(ht * 2.4)}" role="img" aria-label="yessh">` +
    `<title>yessh</title>` + barsSvg(left, right, pal, "yess") +
    `<path fill="${pal.ink}" d="${ye.d}${ss.d}${h.d}"/></svg>\n`;
}

// ---------------------------------------------------------------- mark and icon

// In a 100×100 box: green bar (yess) 44×30, blue bar (ssh) 50×36 (20% taller), sharing 22 units.
const MARK = {
  left: { x: 14, y: 35, w: 44, h: 30, r: 9 },
  right: { x: 36, y: 32, w: 50, h: 36, r: 10.8 },
};
const NAVY = [15, 23, 42];
const ICON_THEME = { ...THEMES.dark, bg: NAVY };
const iconPal = palette(ICON_THEME, NAVY, 0.9);

function markSvg(themeName) {
  const pal = palette(THEMES[themeName]);
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="10 28 80 44" width="160" height="88" role="img" aria-label="yessh">` +
    barsSvg(MARK.left, MARK.right, pal, "m") + `</svg>\n`;
}

function iconSvg() {
  // 512×512 rounded square; the 100-unit mark scaled into the middle.
  const s = 4.6, t = 256 - 50 * s;
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512" role="img" aria-label="yessh">` +
    `<rect width="512" height="512" rx="112" fill="${hex(NAVY)}"/>` +
    `<g transform="translate(${t} ${t}) scale(${s})">${barsSvg(MARK.left, MARK.right, iconPal, "i")}</g></svg>\n`;
}

// ---------------------------------------------------------------- Android vector drawables

function scaled(rr, s, tx, ty) {
  return { x: rr.x * s + tx, y: rr.y * s + ty, w: rr.w * s, h: rr.h * s, r: rr.r * s };
}

function launcherForeground() {
  // 108dp adaptive canvas; keep the mark inside the 66dp safe circle (58dp wide).
  const s = 58 / 72, t = 54 - 50 * s;
  const L = scaled(MARK.left, s, t, t), R = scaled(MARK.right, s, t, t);
  return `<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by docs/brand/src/build.mjs: the yessh mark (yess + ssh sharing a middle). -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path android:fillColor="${iconPal.left}" android:pathData="${roundRectPath(L)}" />
    <path android:fillColor="${iconPal.right}" android:pathData="${roundRectPath(R)}" />
    <group>
        <clip-path android:pathData="${roundRectPath(L)}" />
        <path android:fillColor="${iconPal.overlap}" android:pathData="${roundRectPath(R)}" />
    </group>
</vector>
`;
}

function launcherMonochrome() {
  // Themed icons only use alpha: each bar at 60%, so the shared middle reads denser.
  const s = 58 / 72, t = 54 - 50 * s;
  const L = scaled(MARK.left, s, t, t), R = scaled(MARK.right, s, t, t);
  return `<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by docs/brand/src/build.mjs. Themed (monochrome) launcher icon. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="108dp"
    android:height="108dp"
    android:viewportWidth="108"
    android:viewportHeight="108">
    <path android:fillColor="#FFFFFFFF" android:fillAlpha="0.6" android:pathData="${roundRectPath(L)}" />
    <path android:fillColor="#FFFFFFFF" android:fillAlpha="0.6" android:pathData="${roundRectPath(R)}" />
</vector>
`;
}

function statusIcon() {
  // 24dp status bar glyph: both bars as one shape with the shared middle knocked out.
  const s = 20 / 72, t = 12 - 50 * s;
  const L = scaled(MARK.left, s, t, t), R = scaled(MARK.right, s, t, t);
  return `<?xml version="1.0" encoding="utf-8"?>
<!-- Generated by docs/brand/src/build.mjs. Notification icon: two bars, shared middle cut out. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path android:fillColor="#FFFFFFFF" android:fillType="evenOdd" android:pathData="${roundRectPath(L)}${roundRectPath(R)}" />
</vector>
`;
}

// ---------------------------------------------------------------- write

const out = (p, s) => {
  writeFileSync(p, s);
  console.log("wrote", p.replace(repo + "/", ""));
};
const dark = wordmark("dark"), light = wordmark("light");
out(join(brand, "yessh-wordmark-dark.svg"), dark);
out(join(brand, "yessh-wordmark-light.svg"), light);
out(join(brand, "yessh-mark-dark.svg"), markSvg("dark"));
out(join(brand, "yessh-mark-light.svg"), markSvg("light"));
out(join(brand, "yessh-icon.svg"), iconSvg());
copyFileSync(join(brand, "yessh-icon.svg"), join(repo, "docs/media/src/icon.svg"));
console.log("wrote docs/media/src/icon.svg");
const res = join(repo, "android/app/src/main/res/drawable");
out(join(res, "ic_launcher_foreground.xml"), launcherForeground());
out(join(res, "ic_launcher_monochrome.xml"), launcherMonochrome());
out(join(res, "ic_stat_yessh.xml"), statusIcon());

// Social preview (and PNG previews of everything) through Chromium.
const { chromium } = await import("playwright");
const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 640 } });
  const uri = (svg) => "data:image/svg+xml;base64," + Buffer.from(svg).toString("base64");
  const inter = readFileSync(join(here, "node_modules/@fontsource/inter/files/inter-latin-500-normal.woff2")).toString("base64");
  await page.setContent(`<html><head><style>@font-face{font-family:Inter;font-weight:500;src:url(data:font/woff2;base64,${inter})}</style></head>
  <body style="margin:0;width:1280px;height:640px;background:#0d1117;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:44px">
    <img src="${uri(dark)}" style="width:640px">
    <div style="font:500 30px Inter;color:#8b949e;letter-spacing:.01em">SSH certificates, approved on your phone.</div>
  </body></html>`);
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: join(brand, "social-preview.png") });
  console.log("wrote docs/brand/social-preview.png");
} finally {
  await browser.close();
}

// Renders the README GIFs into ../ (docs/media/*.gif).
//   npm install && node render.mjs [scene ...]        (needs ffmpeg and gifsicle on PATH)
//   node render.mjs --still flow 5.2                  (one PNG frame, for checking layout)
import { chromium } from "playwright";
import { execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const FPS = 15;
const ALL = ["flow", "setup", "review", "cli"];

const args = process.argv.slice(2);
const still = args[0] === "--still";
const scenes = still ? [args[1]] : args.length ? args : ALL;

// ES modules don't load from file://, so serve this folder.
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml", ".woff2": "font/woff2" };
const server = createServer((req, res) => {
  const file = join(here, normalize(decodeURIComponent(new URL(req.url, "http://x").pathname)).replace(/^([/\\]|\.\.)+/, ""));
  try {
    if (!file.startsWith(here)) throw new Error();
    res.writeHead(200, { "Content-Type": TYPES[extname(file)] ?? "application/octet-stream" }).end(readFileSync(file));
  } catch {
    res.writeHead(404).end();
  }
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const base = `http://127.0.0.1:${server.address().port}`;

const browser = await chromium.launch(process.env.CHROMIUM_PATH ? { executablePath: process.env.CHROMIUM_PATH } : {});
try {
  for (const name of scenes) {
    const page = await browser.newPage();
    await page.goto(`${base}/${name}.html?frames`);
    await page.waitForFunction(() => window.SCENE && document.fonts.status === "loaded");
    const { width, height, duration } = await page.evaluate(() => window.SCENE);
    await page.setViewportSize({ width, height });

    if (still) {
      await page.evaluate((t) => window.renderAt(t), Number(args[2] ?? 0));
      const out = join(here, `still-${name}.png`);
      await page.screenshot({ path: out });
      console.log(out);
      continue;
    }

    const dir = mkdtempSync(join(tmpdir(), `yessh-${name}-`));
    const frames = Math.round(duration * FPS);
    for (let i = 0; i < frames; i++) {
      await page.evaluate((t) => window.renderAt(t), i / FPS);
      await page.screenshot({ path: join(dir, `${String(i).padStart(4, "0")}.png`) });
    }
    const gif = join(here, "..", `${name}.gif`);
    execFileSync("ffmpeg", [
      "-loglevel", "error", "-y", "-framerate", String(FPS), "-i", join(dir, "%04d.png"),
      "-filter_complex", "[0:v]split[a][b];[a]palettegen=max_colors=128:stats_mode=diff[p];[b][p]paletteuse=dither=none:diff_mode=rectangle",
      "-loop", "0", gif,
    ]);
    execFileSync("gifsicle", ["-b", "-O3", "--lossy=30", gif]);
    console.log(`${name}.gif  ${frames} frames  ${(statSync(gif).size / 1024).toFixed(0)} KiB`);
    rmSync(dir, { recursive: true, force: true });
    await page.close();
  }
} finally {
  await browser.close();
  server.close();
}

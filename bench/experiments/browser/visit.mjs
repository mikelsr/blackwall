// visit.mjs <difficulty> <name=url>...: what a visitor's browser goes through
// on each server's challenge page, from the first request to the website
// behind it. Writes one JSON line per visit to stdout:
//   { server, device, difficulty, visit, repeat, paintMs, sentMs, reachedMs,
//     files: [{ path, status, bytes }] }
// Times are from the first request: the first paint (null when the page left
// before painting), the solution's request (pass-challenge), and the
// website's response. Files are what went over the network up to and with
// that request, bytes counting headers. A "first" visit starts with an empty
// cache; a "returning" one reuses a browser that has visited before, with its
// cookies cleared, so only cached files differ. Each visit is a new visitor.
import { chromium } from "playwright-core";

const REPEATS = Number(process.env.REPEATS || 7);
const CHROME = process.env.CHROME || "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const DEVICES = [
  { device: "desktop", viewport: { width: 1440, height: 900 }, scale: 1, cpu: 1, net: null },
  // A phone on a mediocre mobile connection: 100 ms per request round trip,
  // 5 Mbit/s down, 1 Mbit/s up, and a CPU 4 times slower than the host.
  { device: "phone", viewport: { width: 390, height: 844 }, scale: 3, cpu: 4,
    net: { offline: false, latency: 100, downloadThroughput: 5e6 / 8, uploadThroughput: 1e6 / 8 } },
];
const [difficulty, ...args] = process.argv.slice(2);
const servers = args.map(a => a.split("="));
const browser = await chromium.launch({ executablePath: CHROME });

async function visit(context, url, d) {
  const page = await context.newPage();
  // A new visitor's address, which both servers read from X-Real-IP, as in
  // the benchmarks.
  await page.setExtraHTTPHeaders({ "X-Real-IP": `203.0.113.${1 + Math.floor(Math.random() * 250)}` });
  const cdp = await context.newCDPSession(page);
  if (d.cpu !== 1) await cdp.send("Emulation.setCPUThrottlingRate", { rate: d.cpu });
  if (d.net) {
    await cdp.send("Network.enable");
    await cdp.send("Network.emulateNetworkConditions", d.net);
  }
  let paintMs = null, sentMs = null, reachedMs = null;
  const files = [];
  await page.exposeFunction("reportPaint", t => { paintMs ??= Math.round(t); });
  await page.addInitScript(() => new PerformanceObserver(l => {
    for (const e of l.getEntries()) if (e.name === "first-contentful-paint") window.reportPaint(e.startTime);
  }).observe({ type: "paint", buffered: true }));
  const t0 = Date.now();
  page.on("request", r => { if (sentMs === null && r.url().includes("pass-challenge")) sentMs = Date.now() - t0; });
  page.on("response", r => {
    if (sentMs !== null && reachedMs === null && r.request().isNavigationRequest() && r.status() === 200) reachedMs = Date.now() - t0;
  });
  page.on("requestfinished", async r => {
    const solution = r.url().includes("pass-challenge");
    if (sentMs !== null && !solution) return;
    const res = await r.response();
    const s = await r.sizes();
    // Workers' blob: scripts and memory-cache hits never reach the network.
    if (!res || (s.responseBodySize <= 0 && !solution)) return;
    files.push({ path: new URL(r.url()).pathname, status: res.status(), bytes: s.responseBodySize + s.responseHeadersSize });
  });
  await page.goto(url);
  const deadline = Date.now() + 10000;
  while (reachedMs === null && Date.now() < deadline) await page.waitForTimeout(20);
  await page.close();
  if (reachedMs === null) throw new Error(`${url}: the website wasn't reached within 10 s`);
  return { paintMs, sentMs, reachedMs, files };
}

for (const d of DEVICES) {
  for (const [server, url] of servers) {
    for (const kind of ["first", "returning"]) {
      let context = null;
      for (let repeat = 1; repeat <= REPEATS; repeat++) {
        if (kind === "first" || !context) {
          await context?.close();
          context = await browser.newContext({ viewport: d.viewport, deviceScaleFactor: d.scale });
          if (kind === "returning") await visit(context, url, d); // fills the cache
        }
        await context.clearCookies();
        const v = await visit(context, url, d);
        console.log(JSON.stringify({ server, device: d.device, difficulty: Number(difficulty), visit: kind, repeat, ...v }));
        console.error(`${d.device} ${server} ${kind} ${repeat}: website reached in ${v.reachedMs} ms`);
      }
      await context.close();
    }
  }
}
await browser.close();

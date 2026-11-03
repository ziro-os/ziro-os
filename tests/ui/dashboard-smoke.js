#!/usr/bin/env node
// Smoke test for the Postgres dashboard (tools/ziroctl/cmd/ui): the real page, served with the real
// Content-Security-Policy by a fake API with canned answers, driven by Chromium through Playwright.
// It checks sign-in, the fleet view, a cancelled and a confirmed switchover, the restore wizard, the
// configuration plan, that refreshes keep unsaved edits, and that nothing breaks the CSP.
// Usage: node tests/ui/dashboard-smoke.js [screenshot-dir]   (exit 0 = pass, 77 = skipped)
"use strict";

const http = require("http");
const fs = require("fs");
const path = require("path");

let chromium;
try {
  ({ chromium } = require("playwright"));
} catch (e) {
  console.log("skip: playwright is not installed");
  process.exit(77);
}

const UI = path.join(__dirname, "../../tools/ziroctl/cmd/ui");
const CSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; " +
  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const TOKEN = "ziro_test_token";
const now = Date.now();
const iso = (msAgo) => new Date(now - msAgo).toISOString().replace(/\.\d{3}Z$/, "Z");

const overview = [
  { name: "shop", version: "17", health: "degraded", primary: "m1@n1", groups: 1, members: 3, ready: 2, max_lag_ms: 1200,
    conn_pct: 41, disk_pct: 83, backups: true, last_backup: iso(3 * 3600e3), window: "", alerts_24h: 1,
    attention: ["m3 is catching up (1200ms behind)", "a data volume is 83% full"] },
  { name: "logs", version: "16", health: "healthy", primary: "m1@n2", groups: 1, members: 2, ready: 2, max_lag_ms: 0,
    conn_pct: 5, disk_pct: 20, backups: false, alerts_24h: 0 },
];
const shop = {
  name: "shop", version: "17", sync: "quorum", replicas: 2, database: "app", user: "app", sharded: false,
  endpoints: { rw: "shop-rw.cluster.ziro:5432", ro: "shop-ro.cluster.ziro:5432" },
  groups: [{ name: "main", epoch: 3, primary: "m1", reasons: ["m3 is catching up (1200ms behind)"], members: [
    { id: "m1", node: "n1", role: "primary", state: "ready", lsn: "0/3000060", timeline: 3 },
    { id: "m2", node: "n2", role: "replica", state: "ready", lsn: "0/3000060", timeline: 3, lag_ms: 0, joined: true },
    { id: "m3", node: "n3", role: "replica", state: "catching-up", lsn: "0/2FFF000", timeline: 3, lag_ms: 1200, joined: true },
  ] }],
};
const backups = [{ group: "main", repository: "s3://acme-db/ziro/shop (stanza main)", status: "ok",
  backups: [{ label: "20261102-010002F", type: "full", start: iso(30 * 3600e3), stop: iso(30 * 3600e3 - 8000), size: 31477376, repo_size: 4020563 }],
  recoverable_from: iso(30 * 3600e3 - 8000), recoverable_to: iso(60e3) }];
const spec = { postgres: { version: 1, name: "shop", postgres: "17", replicas: 2, params: { work_mem: "64MB" } } };
const posts = [];

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://x");
  if (url.pathname.startsWith("/ui/")) {
    const name = url.pathname.slice(4) || "index.html";
    const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };
    if (!/^[a-z]+\.(html|js|css)$/.test(name)) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "Content-Type": types[path.extname(name)], "Content-Security-Policy": CSP, "X-Content-Type-Options": "nosniff" });
    return res.end(fs.readFileSync(path.join(UI, name)));
  }
  const reply = (code, v) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(v)); };
  if (req.headers.authorization !== "Bearer " + TOKEN) return reply(401, { status: "error", message: "invalid or missing bearer token" });
  let body = "";
  req.on("data", (c) => (body += c));
  req.on("end", () => {
    if (req.method === "POST") posts.push({ path: url.pathname, body: body ? JSON.parse(body) : null });
    const routes = {
      "GET /api/v1/pg-overview": overview,
      "GET /api/v1/pg/shop": shop,
      "GET /api/v1/pg/shopnew": { ...shop, name: "shopnew" }, // the page opens the restored cluster
      "GET /api/v1/pg/shop/backups": backups,
      "GET /api/v1/pg/shop/events": [{ at: iso(600e3), group: "main", message: "m2 joined as a replica" },
        { at: iso(60e3), group: "main", severity: "warning", message: "a data volume is 83% full" }],
      "GET /api/v1/pg/shop/roles": [{ kind: "role", name: "app", detail: "application user", state: "ready", secret: "pg-shop-url" }],
      "GET /api/v1/pg/shop/spec": spec,
      "POST /api/v1/pg/shop/switchover": { status: "ok", message: "switchover requested" },
      "POST /api/v1/pg-restore": { name: "shopnew" },
      "POST /api/v1/pg-plan": { cluster: "shop", changes: [{ section: "param", item: "work_mem=128MB", action: "update", detail: "from 64MB" }] },
    };
    const v = routes[req.method + " " + url.pathname];
    return v === undefined ? reply(404, { status: "error", message: "no such route" }) : reply(200, v);
  });
});

function check(cond, msg) {
  if (!cond) throw new Error(msg);
  console.log("ok: " + msg);
}

(async () => {
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 });
  const problems = [];
  page.on("pageerror", (e) => problems.push("page error: " + e.message));
  // The refused token's 401 is logged by the browser as a failed load: that one is expected.
  page.on("console", (m) => { if (m.type() === "error" && !m.text().includes("status of 401")) problems.push("console: " + m.text()); });
  const shots = process.argv[2];
  const shot = async (n) => { if (shots) await page.screenshot({ path: path.join(shots, n + ".png"), fullPage: true }); };
  try {
    await page.goto(base + "/ui/");
    check(await page.isVisible("#login"), "the page asks for a token first");
    await page.fill("#token", "wrong");
    await page.click("#login-form button");
    await page.waitForSelector("#login-error:not(:empty)");
    check((await page.textContent("#login-error")).includes("refused"), "a refused token says so");

    await page.fill("#token", TOKEN);
    await page.click("#login-form button");
    await page.waitForSelector("table tbody tr");
    const rows = await page.$$eval("tbody tr th", (ths) => ths.map((t) => t.textContent));
    check(rows.join(",") === "shop,logs", "the fleet lists the clusters, the degraded one first");
    check((await page.textContent(".attention")).includes("83% full"), "the fleet says what needs attention");
    check(!(await page.evaluate(() => Object.keys(localStorage).length)), "the token is not in localStorage");
    await shot("fleet");

    await page.click('tbody a:has-text("shop")');
    await page.waitForSelector("svg.topology");
    check((await page.textContent("main")).includes("PostgreSQL 17, quorum replication"), "the cluster page shows the cluster");
    await shot("cluster");
    await page.click('button[aria-label="Switch over to m2"]');
    await page.waitForSelector("dialog[open]");
    await page.click('dialog button[value="cancel"]');
    check(posts.length === 0, "a cancelled switchover sends nothing");
    await page.click('button[aria-label="Switch over to m2"]');
    await page.click("#confirm-ok");
    await page.waitForFunction(() => document.querySelector("#toast").textContent.includes("done"));
    const sw = posts.find((p) => p.path === "/api/v1/pg/shop/switchover");
    check(sw && sw.body.to === "m2" && sw.body.group === "main", "a confirmed switchover asks for m2 in group main");

    await page.click('.tabs a:has-text("Backups")');
    await page.waitForSelector("#restore-name");
    check((await page.textContent("main")).includes("20261102-010002F"), "the backups are listed");
    await page.fill("#restore-name", "shopnew");
    await page.uncheck("#restore-latest");
    const max = await page.getAttribute("#restore-when", "max");
    await page.fill("#restore-when", max);
    await page.waitForTimeout(2600); // a refresh must not wipe the form
    check((await page.inputValue("#restore-name")) === "shopnew", "a refresh keeps the restore form");
    await shot("restore");
    await page.click("text=Preview and restore");
    await page.waitForSelector("dialog[open]");
    await page.click("#confirm-ok");
    await page.waitForFunction(() => location.hash === "#/c/shopnew");
    const rs = posts.find((p) => p.path === "/api/v1/pg-restore");
    check(rs && rs.body.name === "shopnew" && rs.body.from === "shop" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:00Z$/.test(rs.body.to), "the restore asks for the chosen moment, in UTC");

    await page.goto(base + "/ui/#/c/shop/config");
    await page.waitForSelector("#spec");
    await page.fill("#spec", JSON.stringify({ postgres: { version: 1, name: "shop", params: { work_mem: "128MB" } } }, null, 2));
    await page.waitForTimeout(2600);
    check((await page.inputValue("#spec")).includes("128MB"), "a refresh keeps unsaved configuration edits");
    await page.click("text=Show the plan");
    await page.waitForSelector(".plan");
    check((await page.textContent(".plan")).includes("~ param") , "the plan shows the change");
    const plan = posts.find((p) => p.path === "/api/v1/pg-plan");
    check(plan && plan.body.spec.postgres.params.work_mem === "128MB", "the plan is asked for the edited file");
    await shot("config");

    const unnamed = await page.$$eval("button", (bs) => bs.filter((b) => !(b.textContent.trim() || b.getAttribute("aria-label"))).length);
    check(unnamed === 0, "every button has an accessible name");
    check(problems.length === 0, "no script errors or CSP violations" + (problems.length ? ": " + problems.join("; ") : ""));
    console.log("pass");
  } catch (e) {
    console.error("FAIL: " + e.message);
    if (problems.length) console.error(problems.join("\n"));
    process.exitCode = 1;
  } finally {
    await browser.close();
    server.close();
  }
})();

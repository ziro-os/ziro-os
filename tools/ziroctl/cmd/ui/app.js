// Ziro Postgres dashboard (pg_ui.go). Plain JavaScript, no dependencies. Every value from the API is
// added to the page as text (el() never parses HTML), and every change goes through the same API the
// CLI uses, with the user's token, after a confirmation.
"use strict";

const TOKEN_KEY = "ziro.pg.token";
const REFRESH_MS = 2000;
let refreshTimer = null;
let editing = false; // a dialog or field has focus: do not redraw under the user
let dirty = false;   // a form has changes not applied yet: keep it until applied or discarded

// ---- helpers ----

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (k === "class") n.className = v;
    else n.setAttribute(k, v === true ? "" : String(v));
  }
  for (const k of kids.flat()) {
    if (k === null || k === undefined || k === false) continue;
    n.append(k instanceof Node ? k : document.createTextNode(String(k)));
  }
  return n;
}

const $ = (id) => document.getElementById(id);

function toast(msg, isError) {
  const t = el("div", { class: isError ? "error" : "" }, msg);
  $("toast").append(t);
  setTimeout(() => t.remove(), 6000);
}

class APIError extends Error {
  constructor(status, msg) { super(msg); this.status = status; }
}

async function api(method, path, body) {
  const headers = { Authorization: "Bearer " + sessionStorage.getItem(TOKEN_KEY) };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
  let data = null;
  try { data = await res.json(); } catch (_) { /* empty answer */ }
  if (!res.ok) {
    if (res.status === 401) { signOut("Your token was refused. Sign in again."); }
    throw new APIError(res.status, (data && data.message) || res.statusText);
  }
  return data;
}

function confirmDialog(title, text, danger) {
  const d = $("confirm");
  $("confirm-title").textContent = title;
  $("confirm-text").textContent = text;
  $("confirm-ok").className = danger ? "danger" : "";
  editing = true;
  d.showModal();
  return new Promise((resolve) => {
    d.addEventListener("close", () => { editing = false; resolve(d.returnValue === "ok"); }, { once: true });
  });
}

async function act(title, text, method, path, body, danger) {
  if (!(await confirmDialog(title, text, danger))) return null;
  try {
    const out = await api(method, path, body);
    toast(title + ": done");
    render();
    return out;
  } catch (e) {
    toast(title + " failed: " + e.message, true);
    return null;
  }
}

const ms = (v) => (v >= 1000 ? (v / 1000).toFixed(1) + " s" : v + " ms");
function ago(iso) {
  if (!iso) return "";
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 90) return Math.round(s) + " s ago";
  if (s < 5400) return Math.round(s / 60) + " min ago";
  if (s < 129600) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " days ago";
}
function size(n) {
  if (n >= 1 << 30) return (n / (1 << 30)).toFixed(1) + " GiB";
  if (n >= 1 << 20) return (n / (1 << 20)).toFixed(1) + " MiB";
  return Math.round(n / 1024) + " KiB";
}
const badge = (s) => el("span", { class: "badge " + s }, s);
const enc = encodeURIComponent;

// ---- routing ----

function route() {
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (parts[0] === "c" && parts[1]) return { page: "cluster", name: parts[1], tab: parts[2] || "overview" };
  return { page: "fleet" };
}

function crumbs(r) {
  const c = $("crumbs");
  c.replaceChildren(el("a", { href: "#/" }, "Clusters"));
  if (r.page === "cluster") c.append(el("span", {}, "/"), el("span", { "aria-current": "page" }, r.name));
}

async function render() {
  if (!sessionStorage.getItem(TOKEN_KEY)) return showLogin();
  if (editing || dirty) return;
  const r = route();
  crumbs(r);
  try {
    const view = r.page === "cluster" ? await clusterPage(r) : await fleetPage();
    if (editing || dirty) return; // a dialog opened, or a form changed, while loading
    $("view").replaceChildren(view);
    $("updated").textContent = "updated " + new Date().toLocaleTimeString();
  } catch (e) {
    if (e.status !== 401) $("view").replaceChildren(el("p", { class: "error", role: "alert" }, "Could not load: " + e.message));
  }
}

function schedule() {
  clearInterval(refreshTimer);
  refreshTimer = setInterval(() => { if (!document.hidden) render(); }, REFRESH_MS);
}

// ---- sign in ----

function showLogin(msg) {
  clearInterval(refreshTimer);
  $("login").hidden = false;
  $("view").replaceChildren();
  $("logout").hidden = true;
  $("crumbs").replaceChildren();
  $("updated").textContent = "";
  $("login-error").textContent = msg || "";
  $("token").focus();
}

function signOut(msg) {
  sessionStorage.removeItem(TOKEN_KEY);
  showLogin(msg);
}

async function signIn(ev) {
  ev.preventDefault();
  const token = $("token").value.trim();
  if (!token) return;
  sessionStorage.setItem(TOKEN_KEY, token);
  try {
    await api("GET", "/api/v1/pg-overview");
  } catch (e) {
    sessionStorage.removeItem(TOKEN_KEY);
    $("login-error").textContent = e.status === 401 ? "That token was refused." : "Sign-in failed: " + e.message;
    return;
  }
  $("token").value = "";
  $("login").hidden = true;
  $("logout").hidden = false;
  render();
  schedule();
}

// ---- fleet ----

async function fleetPage() {
  const rows = await api("GET", "/api/v1/pg-overview");
  const root = el("div", {}, el("h1", {}, "Postgres clusters"));
  if (!rows.length) {
    root.append(el("p", {}, "No clusters yet. Create one with ", el("code", {}, "ziroctl pg create <name>"), " or a cluster file."));
    return root;
  }
  const counts = { healthy: 0, degraded: 0, down: 0, paused: 0 };
  rows.forEach((r) => counts[r.health]++);
  root.append(el("div", { class: "grid2" },
    ...Object.entries(counts).map(([k, v]) => el("div", { class: "card" }, el("h3", {}, k), el("div", { class: "big " + k }, v)))));
  const table = el("table", {},
    el("caption", { class: "muted" }, "Worst first. Select a cluster for its members, backups, events and configuration."),
    el("thead", {}, el("tr", {}, ...["Name", "PG", "Health", "Primary", "Ready", "Max lag", "Connections", "Disk", "Last backup", "Alerts (24 h)"]
      .map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, ...rows.map((r) => el("tr", {},
      el("th", { scope: "row" }, el("a", { href: "#/c/" + enc(r.name) }, r.name)),
      el("td", {}, r.version), el("td", {}, badge(r.health)), el("td", {}, r.primary || "–"),
      el("td", { class: "num" }, r.ready + "/" + r.members), el("td", { class: "num" }, ms(r.max_lag_ms)),
      el("td", { class: "num" }, r.conn_pct + "%"), el("td", { class: "num" }, r.disk_pct + "%"),
      el("td", {}, r.backups ? (r.last_backup ? ago(r.last_backup) : "none yet") : "off"),
      el("td", { class: "num" }, r.alerts_24h)))));
  root.append(table);
  const attention = rows.flatMap((r) => (r.attention || []).map((a) => [r.name, a]));
  if (attention.length) {
    root.append(el("div", { class: "attention", role: "region", "aria-label": "Needs attention" },
      el("strong", {}, "Needs attention"),
      el("ul", {}, ...attention.map(([n, a]) => el("li", {}, el("a", { href: "#/c/" + enc(n) }, n), ": " + a)))));
  }
  return root;
}

// ---- one cluster ----

const TABS = [["overview", "Overview"], ["backups", "Backups"], ["events", "Events"], ["roles", "Roles and databases"], ["config", "Configuration"]];

async function clusterPage(r) {
  const name = r.name;
  const root = el("div", {});
  const v = await api("GET", "/api/v1/pg/" + enc(name));
  const o = (await api("GET", "/api/v1/pg-overview")).find((x) => x.name === name) || {};
  root.append(el("h1", {}, name, " ", badge(o.health || "unknown")),
    el("p", { class: "muted" }, `PostgreSQL ${v.version}, ${v.sync} replication, ${v.replicas} replica(s) per group` +
      (v.maintenance ? `, maintenance window ${v.maintenance}` : "")));
  root.append(el("nav", { class: "tabs", "aria-label": "Cluster" },
    ...TABS.map(([id, label]) => el("a", { href: `#/c/${enc(name)}/${id}`, "aria-current": r.tab === id ? "page" : null }, label))));
  const tab = { overview: overviewTab, backups: backupsTab, events: eventsTab, roles: rolesTab, config: configTab }[r.tab] || overviewTab;
  root.append(await tab(name, v, o));
  return root;
}

function topology(v) {
  const W = 880, rowH = 110, svg = (t, a) => { const n = document.createElementNS("http://www.w3.org/2000/svg", t); for (const [k, x] of Object.entries(a)) n.setAttribute(k, x); return n; };
  const s = svg("svg", { class: "topology", viewBox: `0 0 ${W} ${v.groups.length * rowH + 10}`, role: "img",
    "aria-label": "Topology: " + v.groups.map((g) => `group ${g.name}, primary ${g.primary || "none"}, ${g.members.length} members`).join("; ") });
  v.groups.forEach((g, gi) => {
    const y = gi * rowH + 10;
    s.append(svg("rect", { x: 0, y, width: W, height: rowH - 16, rx: 8 }));
    const label = svg("text", { x: 12, y: y + 20 }); label.textContent = "group " + g.name + " (epoch " + g.epoch + ")"; s.append(label);
    const primary = g.members.find((m) => m.role === "primary");
    const xs = g.members.map((_, i) => 80 + i * 150);
    const py = y + 58, pi = g.members.indexOf(primary);
    g.members.forEach((m, i) => {
      if (m !== primary && pi >= 0) s.append(svg("line", { x1: xs[pi], y1: py, x2: xs[i], y2: py }));
    });
    g.members.forEach((m, i) => {
      const cls = m.state === "down" ? "down" : m.role === "primary" ? "primary" : "replica";
      const grp = svg("g", { class: cls });
      grp.append(svg("circle", { cx: xs[i], cy: py, r: 14 }));
      const t = svg("text", { x: xs[i] - 30, y: py + 32 });
      t.textContent = `${m.id} ${m.role === "primary" ? "primary" : m.lag_ms ? ms(m.lag_ms) : m.state}`;
      grp.append(t);
      s.append(grp);
    });
  });
  return s;
}

async function overviewTab(name, v, o) {
  const root = el("div", {});
  const canBackup = o.backups;
  root.append(el("div", { class: "toolbar", role: "toolbar", "aria-label": "Actions" },
    el("button", { onclick: () => act("Switchover", `Hand the primary role to the replica furthest ahead. Writes pause for a few seconds.`, "POST", `/api/v1/pg/${enc(name)}/switchover`, {}) }, "Switchover"),
    el("button", { disabled: !canBackup, title: canBackup ? null : "Backups are off", onclick: () => act("Incremental backup", "Take an incremental backup now.", "POST", `/api/v1/pg/${enc(name)}/backup`, { type: "incr" }) }, "Back up now"),
    el("button", { class: "ghost", onclick: () => act("Rolling restart", "Restart every member, one at a time, the primary last after a switchover.", "POST", `/api/v1/pg/${enc(name)}/restart`, {}) }, "Rolling restart"),
    v.paused
      ? el("button", { class: "ghost", onclick: () => act("Resume", "Let the controller manage roles again.", "POST", `/api/v1/pg/${enc(name)}/resume`, {}) }, "Resume controller")
      : el("button", { class: "ghost danger", onclick: () => act("Pause", "The controller stops changing roles: no failover until you resume.", "POST", `/api/v1/pg/${enc(name)}/pause`, {}, true) }, "Pause controller")));
  if ((o.attention || []).length) {
    root.append(el("div", { class: "attention" }, el("strong", {}, "Needs attention"), el("ul", {}, ...o.attention.map((a) => el("li", {}, a)))));
  }
  root.append(topology(v));
  root.append(el("p", {}, "Writes: ", el("code", {}, v.endpoints.rw), " · reads: ", el("code", {}, v.endpoints.ro)));
  for (const g of v.groups) {
    root.append(el("h2", {}, "Group " + g.name));
    root.append(el("table", {},
      el("thead", {}, el("tr", {}, ...["Member", "Node", "Role", "State", "LSN", "Timeline", "Lag", ""].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, ...g.members.map((m) => el("tr", {},
        el("th", { scope: "row" }, m.id), el("td", {}, m.node), el("td", {}, m.role), el("td", {}, badge(m.state), m.detail ? el("div", { class: "muted" }, m.detail) : null),
        el("td", {}, m.lsn || "–"), el("td", { class: "num" }, m.timeline || "–"), el("td", { class: "num" }, m.role === "primary" ? "–" : ms(m.lag_ms)),
        el("td", {}, m.role === "replica" ? el("button", { class: "ghost", "aria-label": "Switch over to " + m.id,
          onclick: () => act("Switchover to " + m.id, `Hand the primary role of group ${g.name} to ${m.id}.`, "POST", `/api/v1/pg/${enc(name)}/switchover`, { group: g.name, to: m.id }) }, "Make primary") : null))))));
    if ((g.reasons || []).length) root.append(el("ul", {}, ...g.reasons.map((x) => el("li", { class: "error" }, x))));
    if ((g.waiting || []).length) root.append(el("p", { class: "muted" }, g.waiting.join(", ") + " restart for a new configuration in the maintenance window."));
  }
  return root;
}

async function backupsTab(name) {
  const root = el("div", {});
  let views;
  try { views = await api("GET", `/api/v1/pg/${enc(name)}/backups`); } catch (e) { return el("p", { class: "error" }, e.message); }
  if (!views || !views.length) {
    return el("p", {}, "Backups are off for this cluster. Turn them on with ", el("code", {}, `ziroctl pg backup enable ${name} ...`), " or a cluster file.");
  }
  for (const g of views) {
    root.append(el("h2", {}, "Group " + g.group), el("p", { class: "muted" }, g.repository, g.status ? " · " + g.status : "", g.running ? " · a backup is running" : ""));
    if (g.recoverable_from) root.append(el("p", {}, `Restorable to any moment from ${new Date(g.recoverable_from).toLocaleString()} to ${new Date(g.recoverable_to).toLocaleString()}.`));
    if (g.last_log) root.append(el("p", { class: "error" }, "Last error: " + g.last_log));
    root.append(el("table", {},
      el("thead", {}, el("tr", {}, ...["Label", "Type", "Finished", "Took", "Database", "Stored"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, ...(g.backups || []).slice().reverse().map((b) => el("tr", {},
        el("td", {}, el("code", {}, b.label)), el("td", {}, b.type), el("td", {}, new Date(b.stop).toLocaleString()),
        el("td", { class: "num" }, Math.round((new Date(b.stop) - new Date(b.start)) / 1000) + " s"),
        el("td", { class: "num" }, size(b.size)), el("td", { class: "num" }, size(b.repo_size)))))));
  }
  root.append(restoreWizard(name, views[0]));
  return root;
}

function restoreWizard(name, g) {
  const box = el("section", { class: "card", "aria-labelledby": "restore-title" }, el("h2", { id: "restore-title" }, "Restore into a new cluster"));
  if (!g.recoverable_from) {
    box.append(el("p", { class: "muted" }, "Available once a backup has finished."));
    return box;
  }
  const local = (iso) => { const d = new Date(iso); d.setMinutes(d.getMinutes() - d.getTimezoneOffset()); return d.toISOString().slice(0, 16); };
  const touch = () => (dirty = true);
  const newName = el("input", { id: "restore-name", required: true, pattern: "[a-z][a-z0-9]{0,15}", value: name.slice(0, 13) + "new", oninput: touch });
  const when = el("input", { id: "restore-when", type: "datetime-local", min: local(g.recoverable_from), max: local(g.recoverable_to), oninput: touch });
  const latest = el("input", { id: "restore-latest", type: "checkbox", checked: true, onchange: () => { touch(); when.disabled = latest.checked; } });
  when.disabled = true;
  box.append(
    el("p", {}, "The cluster keeps running; the copy is a new cluster you can move apps to."),
    el("label", { for: "restore-name" }, "New cluster name"), newName,
    el("label", {}, latest, " The latest state"),
    el("label", { for: "restore-when" }, "Or the state at (your local time)"), when,
    el("div", { class: "toolbar" }, el("button", {
      onclick: async () => {
        if (!newName.checkValidity()) { toast("The name is 1-16 lower-case letters and digits, starting with a letter.", true); return; }
        let to = "latest";
        if (!latest.checked) {
          if (!when.value) { toast("Choose a moment, or the latest state.", true); return; }
          to = new Date(when.value).toISOString().replace(/\.\d{3}Z$/, "Z");
        }
        dirty = false;
        const out = await act("Restore " + name, `Create cluster ${newName.value} from the backups of ${name}, at ${to === "latest" ? "the latest state" : new Date(to).toLocaleString()}.`,
          "POST", "/api/v1/pg-restore", { name: newName.value, from: name, to }, false);
        if (out) location.hash = "#/c/" + enc(newName.value);
      },
    }, "Preview and restore")));
  return box;
}

async function eventsTab(name) {
  const events = await api("GET", `/api/v1/pg/${enc(name)}/events`);
  if (!events.length) return el("p", { class: "muted" }, "No events yet.");
  return el("table", {},
    el("thead", {}, el("tr", {}, ...["Time", "Group", "Severity", "Event"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, ...events.slice().reverse().map((e) => el("tr", {},
      el("td", {}, new Date(e.at).toLocaleString()), el("td", {}, e.group),
      el("td", {}, e.severity ? el("span", { class: "badge " + (e.severity === "high" || e.severity === "critical" ? "down" : "degraded") }, e.severity) : ""),
      el("td", {}, e.message)))));
}

async function rolesTab(name) {
  const rows = await api("GET", `/api/v1/pg/${enc(name)}/roles`);
  return el("div", {},
    el("p", { class: "muted" }, "Add roles and databases on the Configuration tab, or with ", el("code", {}, "ziroctl pg role"), " and ", el("code", {}, "ziroctl pg db"), ". Passwords are never shown here: an app gets them with ", el("code", {}, "apps deploy --pg"), "."),
    el("table", {},
      el("thead", {}, el("tr", {}, ...["Kind", "Name", "State", "Detail", "Credentials secret"].map((h) => el("th", { scope: "col" }, h)))),
      el("tbody", {}, ...rows.map((r) => el("tr", {}, el("td", {}, r.kind), el("th", { scope: "row" }, r.name), el("td", {}, badge(r.state)),
        el("td", {}, r.detail), el("td", {}, r.secret ? el("code", {}, r.secret) : ""))))));
}

async function configTab(name) {
  const spec = await api("GET", `/api/v1/pg/${enc(name)}/spec`);
  const area = el("textarea", { id: "spec", spellcheck: "false", "aria-describedby": "spec-help",
    oninput: () => (dirty = true) }, JSON.stringify(spec, null, 2));
  const out = el("div", { id: "plan", "aria-live": "polite" });
  const parse = () => { try { return JSON.parse(area.value); } catch (e) { toast("Not valid JSON: " + e.message, true); return null; } };
  const showPlan = (p) => {
    const sym = { create: "+", update: "~", unchanged: "=", remove: "-", refused: "!" };
    out.replaceChildren(el("div", { class: "plan" }, ...p.changes.map((c) => el("div", { class: c.action === "refused" ? "error" : "" },
      `${sym[c.action]} ${c.section.padEnd(12)} ${c.item || ""}${c.detail ? "  (" + c.detail + ")" : ""}`))));
  };
  return el("div", {},
    el("p", { id: "spec-help", class: "muted" }, "The cluster as a declarative file (the same as ", el("code", {}, `ziroctl pg get ${name} -o json`), "). Edit it, see the plan, then apply: everything applies, or nothing does. No secrets are in it."),
    el("label", { for: "spec" }, "Cluster file"), area,
    el("div", { class: "toolbar" },
      el("button", { class: "ghost", onclick: async () => {
        const s = parse(); if (!s) return;
        try { showPlan(await api("POST", "/api/v1/pg-plan", { spec: s })); } catch (e) { toast("Plan failed: " + e.message, true); }
      } }, "Show the plan"),
      el("button", { onclick: async () => {
        const s = parse(); if (!s) return;
        const keep = dirty;
        dirty = false;
        const p = await act("Apply the configuration", "Apply the file to " + name + ". Changes that restart members roll out one at a time.", "POST", "/api/v1/pg-apply", { spec: s });
        if (p) showPlan(p); else dirty = keep;
      } }, "Apply"),
      el("button", { class: "ghost", onclick: () => { editing = false; dirty = false; render(); } }, "Discard changes")),
    out);
}

// ---- start ----

document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", signIn);
  $("logout").addEventListener("click", () => signOut("Signed out."));
  window.addEventListener("hashchange", () => { editing = false; dirty = false; render(); });
  if (sessionStorage.getItem(TOKEN_KEY)) {
    $("login").hidden = true;
    $("logout").hidden = false;
    render();
    schedule();
  } else {
    showLogin();
  }
});

/*
 * 悠三堂 有機JAS管理システム — API Worker
 *
 * Serves the app from ./public and exposes a small JSON API under /api.
 * Data lives in D1. Records are last-writer-wins on `updated_at`, which is
 * what lets a phone that was out of signal catch up safely when it reconnects.
 *
 * Auth is deliberately simple for a three-person team: one shared passcode,
 * chosen on first run, plus the member's name. A signed cookie keeps the
 * session for 180 days. Upgrade to Cloudflare Access later if the team grows.
 */

const SESSION_DAYS = 180;
const COOKIE = "yjas_sess";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) {
      return env.ASSETS.fetch(request);
    }
    try {
      return await api(request, env, url);
    } catch (e) {
      return json({ error: "server_error", message: String(e && e.message || e) }, 500);
    }
  },
};

/* ---------------- routing ---------------- */

async function api(request, env, url) {
  const path = url.pathname.replace(/^\/api/, "");
  const method = request.method;

  if (method === "GET" && path === "/status") return status(request, env);
  if (method === "POST" && path === "/setup") return setup(request, env);
  if (method === "POST" && path === "/login") return login(request, env);
  if (method === "POST" && path === "/logout") return logout();
  // calendar feed: Google fetches it without cookies, so the URL carries its own token
  const cal = path.match(/^\/calendar\/([a-f0-9]{32})\.ics$/);
  if (method === "GET" && cal) return calendarFeed(env, cal[1]);

  const member = await currentMember(request, env);
  if (!member) return json({ error: "unauthorized" }, 401);

  if (method === "GET" && path === "/calendar-url") return calendarUrl(env, url);

  if (method === "GET" && path === "/sync") return pull(env, url);
  if (method === "POST" && path === "/sync") return push(request, env, member);
  if (method === "GET" && path === "/backup") return backup(env);
  if (method === "GET" && path === "/audit") return auditList(env);

  return json({ error: "not_found" }, 404);
}

/* ---------------- settings & auth ---------------- */

async function getSetting(env, key) {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
  return row ? row.value : null;
}
async function setSetting(env, key, value) {
  await env.DB.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  ).bind(key, value).run();
}

async function status(request, env) {
  const hash = await getSetting(env, "passcode_hash");
  const member = hash ? await currentMember(request, env) : null;
  return json({ setup: !!hash, member });
}

async function setup(request, env) {
  const existing = await getSetting(env, "passcode_hash");
  if (existing) return json({ error: "already_set_up" }, 409);
  const body = await readJson(request);
  const passcode = String(body.passcode || "").trim();
  const member = cleanMember(body.member);
  if (passcode.length < 6) return json({ error: "passcode_too_short" }, 400);
  if (!member) return json({ error: "member_required" }, 400);

  const salt = randomHex(16);
  const hash = await pbkdf2(passcode, salt);
  await setSetting(env, "passcode_salt", salt);
  await setSetting(env, "passcode_hash", hash);
  await setSetting(env, "session_secret", randomHex(32));
  await setSetting(env, "calendar_token", randomHex(16));
  await audit(env, member, "setup", "");
  return withSession(json({ ok: true, member }), env, member);
}

async function login(request, env) {
  const hash = await getSetting(env, "passcode_hash");
  if (!hash) return json({ error: "not_set_up" }, 409);
  const body = await readJson(request);
  const passcode = String(body.passcode || "").trim();
  const member = cleanMember(body.member);
  if (!member) return json({ error: "member_required" }, 400);
  const salt = await getSetting(env, "passcode_salt");
  const candidate = await pbkdf2(passcode, salt);
  if (!timingSafeEqual(candidate, hash)) {
    await audit(env, member, "login_failed", "");
    // a small delay blunts brute force without annoying a real user
    await new Promise((r) => setTimeout(r, 400));
    return json({ error: "wrong_passcode" }, 401);
  }
  await audit(env, member, "login", "");
  return withSession(json({ ok: true, member }), env, member);
}

function logout() {
  const res = json({ ok: true });
  res.headers.append("Set-Cookie", `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`);
  return res;
}

async function withSession(res, env, member) {
  const secret = await getSetting(env, "session_secret");
  const exp = Date.now() + SESSION_DAYS * 86400000;
  const payload = b64url(JSON.stringify({ m: member, e: exp }));
  const sig = await hmac(secret, payload);
  const maxAge = SESSION_DAYS * 86400;
  res.headers.append(
    "Set-Cookie",
    `${COOKIE}=${payload}.${sig}; Path=/; Max-Age=${maxAge}; HttpOnly; Secure; SameSite=Lax`
  );
  return res;
}

async function currentMember(request, env) {
  const cookie = request.headers.get("Cookie") || "";
  const m = cookie.match(new RegExp(`(?:^|;\\s*)${COOKIE}=([^;]+)`));
  if (!m) return null;
  const [payload, sig] = m[1].split(".");
  if (!payload || !sig) return null;
  const secret = await getSetting(env, "session_secret");
  if (!secret) return null;
  const expect = await hmac(secret, payload);
  if (!timingSafeEqual(expect, sig)) return null;
  try {
    const data = JSON.parse(fromB64url(payload));
    if (!data.e || data.e < Date.now()) return null;
    return cleanMember(data.m);
  } catch (e) {
    return null;
  }
}

/* ---------------- sync ---------------- */

// GET /api/sync?since=<ms>  → everything changed after `since`
async function pull(env, url) {
  const since = Number(url.searchParams.get("since") || 0) || 0;
  const now = Date.now();
  const recs = await env.DB.prepare(
    "SELECT id, kind, date, updated_at, deleted, member, body FROM records WHERE updated_at > ? ORDER BY updated_at ASC LIMIT 2000"
  ).bind(since).all();
  const masters = await env.DB.prepare(
    "SELECT key, updated_at, body FROM masters WHERE updated_at > ?"
  ).bind(since).all();

  const records = (recs.results || []).map((r) => ({
    id: r.id, kind: r.kind, date: r.date, updatedAt: r.updated_at,
    deleted: !!r.deleted, member: r.member, body: safeParse(r.body),
  }));
  const m = {};
  for (const row of masters.results || []) {
    m[row.key] = { updatedAt: row.updated_at, body: safeParse(row.body) };
  }
  // when the page is capped, tell the client to ask again from the last row it got
  const more = records.length >= 2000;
  return json({ now, records, masters: m, more });
}

// POST /api/sync {records:[...], masters:{...}}  → last-writer-wins upsert
async function push(request, env, member) {
  const body = await readJson(request);
  const records = Array.isArray(body.records) ? body.records : [];
  const masters = body.masters && typeof body.masters === "object" ? body.masters : {};
  let accepted = 0, skipped = 0;

  const stmts = [];
  for (const r of records) {
    if (!r || typeof r.id !== "string" || !/^[A-Za-z0-9_-]{4,64}$/.test(r.id)) { skipped++; continue; }
    if (!["log", "proc", "grade", "clean"].includes(r.kind)) { skipped++; continue; }
    const updatedAt = Number(r.updatedAt) || 0;
    if (!updatedAt) { skipped++; continue; }
    const bodyText = JSON.stringify(r.body || {});
    if (bodyText.length > 64 * 1024) { skipped++; continue; }
    stmts.push(
      env.DB.prepare(
        `INSERT INTO records (id, kind, date, updated_at, deleted, member, body)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           kind = excluded.kind, date = excluded.date, updated_at = excluded.updated_at,
           deleted = excluded.deleted, member = excluded.member, body = excluded.body
         WHERE excluded.updated_at > records.updated_at`
      ).bind(r.id, r.kind, r.date || null, updatedAt, r.deleted ? 1 : 0, r.member || member, bodyText)
    );
    accepted++;
  }
  for (const key of Object.keys(masters)) {
    if (!/^[a-z_]{1,32}$/.test(key)) continue;
    const m = masters[key] || {};
    const updatedAt = Number(m.updatedAt) || 0;
    if (!updatedAt) continue;
    const bodyText = JSON.stringify(m.body || {});
    if (bodyText.length > 256 * 1024) continue;
    stmts.push(
      env.DB.prepare(
        `INSERT INTO masters (key, updated_at, body) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET updated_at = excluded.updated_at, body = excluded.body
         WHERE excluded.updated_at > masters.updated_at`
      ).bind(key, updatedAt, bodyText)
    );
  }
  if (stmts.length) await env.DB.batch(stmts);
  if (accepted) await audit(env, member, "sync", `${accepted} records`);
  return json({ ok: true, now: Date.now(), accepted, skipped });
}

async function backup(env) {
  const recs = await env.DB.prepare("SELECT * FROM records ORDER BY updated_at").all();
  const masters = await env.DB.prepare("SELECT * FROM masters").all();
  const out = {
    exportedAt: new Date().toISOString(),
    records: (recs.results || []).map((r) => ({ ...r, body: safeParse(r.body) })),
    masters: (masters.results || []).map((m) => ({ ...m, body: safeParse(m.body) })),
  };
  const res = json(out);
  res.headers.set("Content-Disposition", `attachment; filename="yusando-jas-backup-${out.exportedAt.slice(0, 10)}.json"`);
  return res;
}

async function auditList(env) {
  const rows = await env.DB.prepare("SELECT at, member, action, detail FROM audit ORDER BY at DESC LIMIT 200").all();
  return json({ entries: rows.results || [] });
}

async function audit(env, member, action, detail) {
  try {
    await env.DB.prepare("INSERT INTO audit (at, member, action, detail) VALUES (?, ?, ?, ?)")
      .bind(Date.now(), member || null, action, detail || null).run();
  } catch (e) { /* never let the log break the request */ }
}

/* ---------------- calendar feed (iCal) ---------------- */

async function calendarUrl(env, url) {
  let token = await getSetting(env, "calendar_token");
  if (!token) { token = randomHex(16); await setSetting(env, "calendar_token", token); }
  return json({ url: `${url.origin}/api/calendar/${token}.ics` });
}

async function calendarFeed(env, token) {
  const expect = await getSetting(env, "calendar_token");
  if (!expect || !timingSafeEqual(expect, token)) return new Response("not found", { status: 404 });

  const mrow = await env.DB.prepare("SELECT body FROM masters WHERE key = 'all'").first();
  const masters = mrow ? safeParse(mrow.body) : {};
  const labels = masters.labels || {};
  const fieldName = (id) => {
    const f = (masters.fields || []).find((x) => x.id === id);
    return f ? (f.ja || f.en || id) : id;
  };
  /* fallbacks so a stage added in the app still reads properly in the calendar
     before the registers have been pushed again */
  const BUILTIN = {
    stages: { aracha: "荒茶づくり", finish: "仕上げ加工", sort: "選別", mill: "粉砕" },
    equip: { aracha_line: "製茶ライン", finish_line: "仕上げライン", sorter: "選別機", mill: "粉砕機",
             roaster: "焙煎機", packer: "小分け・包装機", container: "保管容器・袋",
             storage: "保管場所", transport: "運搬車両" },
  };
  const L = (group, k) =>
    (labels[group] && labels[group][k]) || (BUILTIN[group] && BUILTIN[group][k]) || k;

  const rows = await env.DB.prepare(
    "SELECT id, kind, date, updated_at, body FROM records WHERE deleted = 0 AND date >= date('now', '-2 years') ORDER BY date"
  ).all();

  const lines = [
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Yusando//Organic JAS Records//JA",
    "CALSCALE:GREGORIAN", "METHOD:PUBLISH",
    "X-WR-CALNAME:悠三堂 作業記録", "X-WR-TIMEZONE:Asia/Tokyo",
  ];
  for (const r of rows.results || []) {
    const b = safeParse(r.body);
    if (!r.date || !/^\d{4}-\d{2}-\d{2}$/.test(r.date)) continue;
    let summary = "", desc = [];
    const workers = (b.workers || []).map((w) => String(w).split("/")[0].trim()).join("、");
    if (r.kind === "log") {
      const tasks = (b.tasks || []).map((k) => L("tasks", k)).join("・");
      const fields = (b.fieldIds || []).map(fieldName).join("、");
      summary = `${tasks || "作業"} — ${fields}`;
      const q = b.qtyByField || {};
      const qs = Object.keys(q).map((id) => `${fieldName(id)} ${q[id]}kg`).join("、");
      if (qs) { summary += ` (${qs})`; desc.push(`収穫量: ${qs}`); }
      const lots = b.lots || {};
      const ls = Object.keys(lots).map((id) => lots[id]).join(" ");
      if (ls) desc.push(`ロット: ${ls}`);
      if (b.weather) desc.push(`天候: ${L("weather", b.weather)}`);
      if ((b.machineIds || []).length) desc.push(`機械: ${b.machineIds.map((id) => { const m = (masters.machines || []).find((x) => x.id === id); return m ? m.ja : id; }).join("、")}`);
      desc.push(`資材: ${b.material === "used" ? (b.materialNote || "使用あり") : "なし"}`);
    } else if (r.kind === "proc") {
      const teas = (b.teas || []).map((k) => L("teas", k)).join("・");
      summary = `【加工】${L("stages", b.stage)} ${teas} ${b.out ? b.out + "kg" : ""}`.trim();
      desc.push(`工場: ${L("factories", b.factory)}`);
      desc.push(`投入 ${b.inKg || 0}kg → 製造 ${b.out || 0}kg`);
      if (b.ext) desc.push(`仕入れ原料: ${b.extName || "—"} ${b.extKg || 0}kg`);
      desc.push(`ロット: ${b.lot || ""}`);
      desc.push(`区分: ${b.organic === "organic" ? "有機" : "有機でない"}`);
    } else if (r.kind === "grade") {
      const teas = (b.teas || []).map((k) => L("teas", k)).join("・");
      summary = `【格付】${teas} ${b.qty ? b.qty + "kg" : ""} ${b.result === "pass" ? "適合" : "不適合"}`.trim();
      desc.push(`原料ロット: ${b.sourceLot || ""} → 格付ロット: ${b.lot || ""}`);
      desc.push(`${b.gram || 0}g × ${b.packs || 0}袋、シール ${b.mark === "seal" ? (b.seals || 0) + "枚" : "印刷済み包材"}`);
    } else if (r.kind === "clean") {
      const eq = (b.equip || []).map((k) => L("equip", k)).concat(b.equipOther ? [b.equipOther] : []).join("・");
      summary = `【洗浄】${eq}${b.prev === "nonorganic" ? "（有機以外からの切替）" : ""}`.trim();
      desc.push(`場所: ${L("factories", b.factory)}`);
      if (b.method) desc.push(`方法: ${b.method}`);
      desc.push(`結果: ${b.result === "redo" ? "再洗浄した" : "残留なしを確認"}`);
    } else continue;
    if (workers) desc.push(`作業者: ${workers}`);
    if (b.memo) desc.push(`メモ: ${b.memo}`);

    const d = r.date.replace(/-/g, "");
    const next = nextDay(r.date);
    lines.push(
      "BEGIN:VEVENT",
      `UID:${r.id}@yusando-jas`,
      `DTSTAMP:${icsStamp(r.updated_at)}`,
      `LAST-MODIFIED:${icsStamp(r.updated_at)}`,
      `DTSTART;VALUE=DATE:${d}`,
      `DTEND;VALUE=DATE:${next}`,
      `SUMMARY:${icsText(summary)}`,
      `DESCRIPTION:${icsText(desc.join("\n"))}`,
      `CATEGORIES:${r.kind === "log" ? "栽培" : r.kind === "proc" ? "加工" : "格付"}`,
      "END:VEVENT"
    );
  }
  lines.push("END:VCALENDAR");
  const body = lines.map(foldLine).join("\r\n") + "\r\n";
  return new Response(body, {
    headers: {
      "Content-Type": "text/calendar; charset=utf-8",
      "Cache-Control": "no-cache",
      "Content-Disposition": 'inline; filename="yusando-kiroku.ics"',
    },
  });
}

function nextDay(ymd) {
  const d = new Date(ymd + "T00:00:00Z"); d.setUTCDate(d.getUTCDate() + 1);
  return d.toISOString().slice(0, 10).replace(/-/g, "");
}
function icsStamp(ms) {
  return new Date(Number(ms) || Date.now()).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}
function icsText(s) {
  return String(s || "").replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/,/g, "\\,").replace(/;/g, "\\;");
}
// RFC 5545: lines longer than 75 octets are folded with CRLF + space
function foldLine(line) {
  const enc = new TextEncoder(); const out = []; let cur = "";
  for (const ch of line) {
    if (enc.encode(cur + ch).length > 74) { out.push(cur); cur = " " + ch; } else cur += ch;
  }
  out.push(cur);
  return out.join("\r\n");
}

/* ---------------- helpers ---------------- */

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
async function readJson(request) {
  try { return await request.json(); } catch (e) { return {}; }
}
function safeParse(s) { try { return JSON.parse(s); } catch (e) { return {}; } }
function cleanMember(m) {
  const s = String(m || "").trim().slice(0, 40);
  return s || null;
}
function randomHex(n) {
  const a = new Uint8Array(n); crypto.getRandomValues(a);
  return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("");
}
async function pbkdf2(passcode, saltHex) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(passcode), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: hexToBytes(saltHex), iterations: 100000 }, key, 256
  );
  return bytesToHex(new Uint8Array(bits));
}
async function hmac(secretHex, data) {
  const key = await crypto.subtle.importKey("raw", hexToBytes(secretHex), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return bytesToHex(new Uint8Array(sig));
}
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
function hexToBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(b) { return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""); }
function b64url(s) {
  return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64url(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return decodeURIComponent(escape(atob(s)));
}

import { XMLParser } from "fast-xml-parser";

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  ADMIN_TOKEN?: string;
  AUTH_ENABLED?: string;
  SESSION_DAYS?: string;
  AUTH_RATE_LIMIT?: string;
  AUTH_RATE_WINDOW_MIN?: string;
  TURNSTILE_SECRET_KEY?: string;
  TURNSTILE_SITE_KEY?: string;
  TRANSLATE_PROVIDER?: string;
  LIBRETRANSLATE_URL?: string;
  GOOGLE_TRANSLATE_KEY?: string;
  GOOGLE_TRANSLATE_REGION?: string;
  AI_TRANSLATE_URL?: string;
  AI_TRANSLATE_KEY?: string;
  GOOGLE_CLIENT_ID?: string;
  GOOGLE_CLIENT_SECRET?: string;
  PUBLIC_BASE_URL?: string;
  REFRESH_BATCH?: string;
  REFRESH_INTERVAL_MIN?: string;
  MAX_ITEMS_PER_FEED?: string;
}

type FeedRow = {
  id: number;
  url: string;
  access_key: string | null;
  title: string | null;
  site_url: string | null;
  etag: string | null;
  last_modified: string | null;
  last_fetch_at: number | null;
  next_fetch_at: number | null;
  enabled: number;
};

type ParsedItem = {
  guid: string;
  title?: string;
  link?: string;
  author?: string;
  summary?: string;
  content?: string;
  published_at?: number;
};

type UserRow = {
  id: string;
  email: string;
  password_hash: string | null;
  password_salt: string | null;
  role: string;
  google_sub: string | null;
};

type SessionRow = {
  id: string;
  user_id: string;
  expires_at: number;
};

type TranslationRow = {
  key: string;
  translated_text: string;
  updated_at: number;
};

const xml = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  trimValues: true,
  parseTagValue: true,
  parseAttributeValue: true,
});

function json(data: unknown, init: ResponseInit = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...(init.headers || {}),
    },
  });
}

function badRequest(message: string, status = 400) {
  return json({ error: message }, { status });
}

function nowMs() {
  return Date.now();
}

function intEnv(env: Env, key: keyof Env, fallback: number) {
  const v = (env[key] as string | undefined) ?? "";
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
}

function boolEnv(env: Env, key: keyof Env, fallback = false) {
  const v = String((env[key] as string | undefined) ?? "").trim().toLowerCase();
  if (!v) return fallback;
  return v === "true" || v === "1" || v === "yes";
}

function base64Url(bytes: Uint8Array) {
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlToBytes(value: string) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function parseCookies(header: string | null) {
  const map = new Map<string, string>();
  if (!header) return map;
  for (const part of header.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (!key) continue;
    map.set(key, rest.join("="));
  }
  return map;
}

function isAuthEnabled(env: Env) {
  return boolEnv(env, "AUTH_ENABLED", false) || !!(env.ADMIN_TOKEN || "").trim();
}

function sessionMaxAge(env: Env) {
  const days = intEnv(env, "SESSION_DAYS", 7);
  return Math.max(1, Math.min(days, 30)) * 24 * 60 * 60;
}

function authRateLimit(env: Env) {
  return Math.max(1, intEnv(env, "AUTH_RATE_LIMIT", 5));
}

function authRateWindowMs(env: Env) {
  return Math.max(1, intEnv(env, "AUTH_RATE_WINDOW_MIN", 10)) * 60_000;
}

function getClientIp(request: Request) {
  const cfConnectingIp = request.headers.get("cf-connecting-ip");
  if (cfConnectingIp) return cfConnectingIp.trim();
  const forwarded = request.headers.get("x-forwarded-for");
  if (!forwarded) return "unknown";
  return forwarded.split(",")[0]?.trim() || "unknown";
}

function resolveTranslateProvider(env: Env) {
  const preferred = (env.TRANSLATE_PROVIDER || "").trim().toLowerCase();
  const libre = (env.LIBRETRANSLATE_URL || "").trim();
  const google = (env.GOOGLE_TRANSLATE_KEY || "").trim();
  const ai = (env.AI_TRANSLATE_URL || "").trim() && (env.AI_TRANSLATE_KEY || "").trim();
  if (preferred === "libre" && libre) return "libre";
  if (preferred === "google" && google) return "google";
  if (preferred === "ai" && ai) return "ai";
  if (libre) return "libre";
  if (google) return "google";
  if (ai) return "ai";
  return "";
}

async function translateWithLibre(env: Env, text: string, target: string) {
  const url = (env.LIBRETRANSLATE_URL || "").trim();
  if (!url) throw new Error("LibreTranslate not configured");
  const res = await fetch(`${url.replace(/\/+$/, "")}/translate`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ q: text, source: "auto", target, format: "text" }),
  });
  if (!res.ok) throw new Error("LibreTranslate failed");
  const data = await res.json<{ translatedText?: string }>();
  return data.translatedText || text;
}

async function translateWithGoogle(env: Env, text: string, target: string) {
  const key = (env.GOOGLE_TRANSLATE_KEY || "").trim();
  if (!key) throw new Error("Google Translate not configured");
  const region = (env.GOOGLE_TRANSLATE_REGION || "").trim();
  const params = new URLSearchParams({
    q: text,
    target,
    format: "text",
    key,
  });
  if (region) params.set("model", "nmt");
  const res = await fetch(`https://translation.googleapis.com/language/translate/v2?${params.toString()}`);
  if (!res.ok) throw new Error("Google Translate failed");
  const data = await res.json<{ data?: { translations?: Array<{ translatedText?: string }> } }>();
  return data.data?.translations?.[0]?.translatedText || text;
}

async function translateWithAI(env: Env, text: string, target: string) {
  const url = (env.AI_TRANSLATE_URL || "").trim();
  const key = (env.AI_TRANSLATE_KEY || "").trim();
  if (!url || !key) throw new Error("AI translate not configured");
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json", Authorization: `Bearer ${key}` },
    body: JSON.stringify({ text, target }),
  });
  if (!res.ok) throw new Error("AI translate failed");
  const data = await res.json<{ translated_text?: string }>();
  return data.translated_text || text;
}

async function translateText(env: Env, text: string, target: string) {
  const provider = resolveTranslateProvider(env);
  if (!provider) return text;
  if (provider === "libre") return translateWithLibre(env, text, target);
  if (provider === "google") return translateWithGoogle(env, text, target);
  return translateWithAI(env, text, target);
}

async function translationKey(text: string, target: string) {
  const enc = new TextEncoder();
  const data = enc.encode(`${target}:${text}`);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return base64Url(new Uint8Array(digest));
}

async function getCachedTranslation(env: Env, key: string) {
  const { results } = await env.DB.prepare(
    `SELECT key, translated_text, updated_at FROM translations WHERE key = ?`
  ).bind(key).all<TranslationRow>();
  return results?.[0] || null;
}

async function cacheTranslation(env: Env, key: string, translated: string) {
  await env.DB.prepare(
    `INSERT OR REPLACE INTO translations (key, translated_text, updated_at)
     VALUES (?, ?, ?)`
  ).bind(key, translated, nowMs()).run();
}

async function verifyTurnstile(request: Request, env: Env, token: string) {
  const secret = (env.TURNSTILE_SECRET_KEY || "").trim();
  if (!secret) return true;
  if (!token) return false;
  const body = new URLSearchParams({
    secret,
    response: token,
    remoteip: getClientIp(request),
  });
  const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!res.ok) return false;
  const data = await res.json<{ success: boolean }>();
  return !!data?.success;
}

function extractAccessKey(url: URL) {
  let accessKey: string | null = null;
  for (const [key, value] of url.searchParams.entries()) {
    if (/access_?key/i.test(key)) {
      accessKey = value;
      url.searchParams.delete(key);
    }
  }
  return accessKey;
}

function normalizeFeedInput(input: string): { url: string; accessKey: string | null } {
  let s = input.trim();
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  const url = new URL(s);
  url.hash = "";
  const accessKey = extractAccessKey(url);
  return { url: url.toString(), accessKey };
}

async function hashPassword(password: string, salt: Uint8Array) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100_000, hash: "SHA-256" },
    key,
    256
  );
  return base64Url(new Uint8Array(bits));
}

async function verifyPassword(password: string, salt: Uint8Array, expected: string) {
  const hash = await hashPassword(password, salt);
  return hash === expected;
}

async function loadSessionUser(request: Request, env: Env) {
  const cookies = parseCookies(request.headers.get("cookie"));
  const sessionId = cookies.get("session");
  if (!sessionId) return null;
  const { results } = await env.DB.prepare(
    `SELECT s.id, s.user_id, s.expires_at, u.email, u.role
       FROM sessions s
       JOIN users u ON u.id = s.user_id
      WHERE s.id = ?`
  ).bind(sessionId).all<SessionRow & { email: string; role: string }>();
  const row = results?.[0];
  if (!row) return null;
  if (row.expires_at <= nowMs()) {
    await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(sessionId).run();
    return null;
  }
  return { id: row.user_id, email: row.email, role: row.role };
}

function getBearerAdmin(request: Request, env: Env) {
  const token = (env.ADMIN_TOKEN || "").trim();
  if (!token) return false;
  const auth = request.headers.get("authorization") || "";
  return auth.toLowerCase().startsWith("bearer ") && auth.slice(7).trim() === token;
}

async function getAuthContext(request: Request, env: Env) {
  const authEnabled = isAuthEnabled(env);
  if (!authEnabled) {
    return { role: "admin", authEnabled: false as const, user: null as any };
  }
  if (getBearerAdmin(request, env)) {
    return { role: "admin", authEnabled: true as const, user: { id: "admin-token", email: "admin@token" } };
  }
  const user = await loadSessionUser(request, env);
  return { role: user?.role || "user", authEnabled: true as const, user };
}

async function requireAdmin(request: Request, env: Env) {
  const ctx = await getAuthContext(request, env);
  if (!ctx.authEnabled) return null;
  if (ctx.role === "admin") return null;
  const auth = request.headers.get("authorization") || "";
  if (!auth && !ctx.user) return badRequest("Unauthorized", 401);
  return badRequest("Forbidden", 403);
}

function sessionCookieValue(sessionId: string, maxAge: number) {
  return `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function clearSessionCookie() {
  return "session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}

/**
 * Robust-ish date parsing for RSS/Atom.
 * Returns milliseconds or null.
 */
function parseDateMs(v: unknown): number | null {
  if (typeof v !== "string" || !v.trim()) return null;
  const ms = Date.parse(v);
  return Number.isFinite(ms) ? ms : null;
}

function pickText(v: any): string | undefined {
  if (v == null) return undefined;
  if (typeof v === "string") return v;
  if (typeof v === "number") return String(v);
  if (typeof v === "object") {
    // fast-xml-parser may produce { "#text": "..." }
    if (typeof v["#text"] === "string") return v["#text"];
    if (typeof v["text"] === "string") return v["text"];
  }
  return undefined;
}

function pickLinkFromAtom(linkNode: any): string | undefined {
  if (!linkNode) return undefined;
  if (typeof linkNode === "string") return linkNode;
  if (Array.isArray(linkNode)) {
    const alt = linkNode.find((l) => l?.["@_rel"] === "alternate") ?? linkNode[0];
    return alt?.["@_href"] || alt?.["@_url"] || pickText(alt);
  }
  return linkNode["@_href"] || linkNode["@_url"] || pickText(linkNode);
}

function ensureGuid(s?: string) {
  const v = (s || "").trim();
  return v || null;
}

function toGuid(feedUrl: string, candidate: string | null) {
  // Namespaced guid to avoid cross-feed collision
  if (!candidate) {
    return `${feedUrl}#${crypto.randomUUID()}`;
  }
  return `${feedUrl}#${candidate}`;
}

function parseFeedDocument(doc: any, feedUrl: string): { title?: string; siteUrl?: string; items: ParsedItem[] } {
  // RSS 2.0: rss.channel.item
  const rss = doc?.rss;
  if (rss?.channel) {
    const ch = rss.channel;
    const title = pickText(ch.title);
    const siteUrl = pickText(ch.link);
    const rawItems = ch.item ? (Array.isArray(ch.item) ? ch.item : [ch.item]) : [];
    const items = rawItems.map((it: any): ParsedItem => {
      const guidRaw = ensureGuid(pickText(it.guid)) || ensureGuid(pickText(it.link)) || ensureGuid(pickText(it.title));
      const guid = toGuid(feedUrl, guidRaw);
      const published = parseDateMs(pickText(it.pubDate)) ?? parseDateMs(pickText(it["dc:date"])) ?? null;
      return {
        guid,
        title: pickText(it.title),
        link: pickText(it.link),
        author: pickText(it.author) || pickText(it["dc:creator"]),
        summary: pickText(it.description),
        content: pickText(it["content:encoded"]),
        published_at: published ?? undefined,
      };
    });
    return { title, siteUrl, items };
  }

  // Atom: feed.entry
  const atomFeed = doc?.feed;
  if (atomFeed) {
    const title = pickText(atomFeed.title);
    const siteUrl = pickLinkFromAtom(atomFeed.link);
    const rawEntries = atomFeed.entry ? (Array.isArray(atomFeed.entry) ? atomFeed.entry : [atomFeed.entry]) : [];
    const items = rawEntries.map((en: any): ParsedItem => {
      const guidRaw = ensureGuid(pickText(en.id)) || ensureGuid(pickLinkFromAtom(en.link)) || ensureGuid(pickText(en.title));
      const guid = toGuid(feedUrl, guidRaw);
      const published = parseDateMs(pickText(en.published)) ?? parseDateMs(pickText(en.updated)) ?? null;
      const summary = pickText(en.summary);
      const content = pickText(en.content);
      const author = pickText(en.author?.name) || pickText(en.author);
      return {
        guid,
        title: pickText(en.title),
        link: pickLinkFromAtom(en.link),
        author,
        summary,
        content,
        published_at: published ?? undefined,
      };
    });
    return { title, siteUrl, items };
  }

  // RDF-ish (rare): rdf:RDF.channel/item
  const rdf = doc?.["rdf:RDF"];
  if (rdf?.channel) {
    const ch = rdf.channel;
    const title = pickText(ch.title);
    const siteUrl = pickText(ch.link);
    const rawItems = rdf.item ? (Array.isArray(rdf.item) ? rdf.item : [rdf.item]) : [];
    const items = rawItems.map((it: any): ParsedItem => {
      const guidRaw = ensureGuid(pickText(it.guid)) || ensureGuid(pickText(it.link)) || ensureGuid(pickText(it.title));
      const guid = toGuid(feedUrl, guidRaw);
      const published = parseDateMs(pickText(it.date)) ?? parseDateMs(pickText(it.pubDate)) ?? null;
      return {
        guid,
        title: pickText(it.title),
        link: pickText(it.link),
        summary: pickText(it.description),
        published_at: published ?? undefined,
      };
    });
    return { title, siteUrl, items };
  }

  return { items: [] };
}

function buildFeedFetchUrl(feed: FeedRow) {
  if (!feed.access_key) return feed.url;
  const url = new URL(feed.url);
  if (![...url.searchParams.keys()].some((key) => /access_?key/i.test(key))) {
    url.searchParams.set("access_key", feed.access_key);
  }
  return url.toString();
}

async function fetchAndParseFeed(feed: FeedRow): Promise<{
  status: "not_modified" | "ok";
  title?: string;
  siteUrl?: string;
  etag?: string | null;
  lastModified?: string | null;
  items?: ParsedItem[];
}> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("timeout"), 12_000);

  try {
    const headers = new Headers({
      "user-agent": "rss-reader-cloudflare/0.1 (+https://cloudflare.com/)",
      "accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*",
    });

    if (feed.etag) headers.set("if-none-match", feed.etag);
    if (feed.last_modified) headers.set("if-modified-since", feed.last_modified);

    const res = await fetch(buildFeedFetchUrl(feed), {
      headers,
      redirect: "follow",
      signal: controller.signal,
    });

    if (res.status === 304) {
      return { status: "not_modified" };
    }
    if (!res.ok) {
      throw new Error(`fetch failed: ${res.status} ${res.statusText}`);
    }

    const body = await res.text();
    const doc = xml.parse(body);
    const parsed = parseFeedDocument(doc, feed.url);

    return {
      status: "ok",
      title: parsed.title,
      siteUrl: parsed.siteUrl,
      etag: res.headers.get("etag"),
      lastModified: res.headers.get("last-modified"),
      items: parsed.items ?? [],
    };
  } finally {
    clearTimeout(timeout);
  }
}

async function upsertFeedMeta(env: Env, feedId: number, meta: { title?: string; siteUrl?: string; etag?: string | null; lastModified?: string | null }, nextFetchAt: number) {
  const now = nowMs();
  await env.DB.prepare(
    `UPDATE feeds
       SET title = COALESCE(?, title),
           site_url = COALESCE(?, site_url),
           etag = COALESCE(?, etag),
           last_modified = COALESCE(?, last_modified),
           last_fetch_at = ?,
           next_fetch_at = ?
     WHERE id = ?`
  ).bind(
    meta.title || null,
    meta.siteUrl || null,
    meta.etag ?? null,
    meta.lastModified ?? null,
    now,
    nextFetchAt,
    feedId
  ).run();
}

async function insertItems(env: Env, feedId: number, items: ParsedItem[], maxInsert: number) {
  // Insert newest first, but cap to avoid huge writes.
  const sorted = [...items].sort((a, b) => (b.published_at ?? 0) - (a.published_at ?? 0));
  const slice = sorted.slice(0, maxInsert);

  const now = nowMs();
  const stmts: D1PreparedStatement[] = [];
  for (const it of slice) {
    stmts.push(
      env.DB.prepare(
        `INSERT OR IGNORE INTO items
          (feed_id, guid, title, link, author, summary, content, published_at, fetched_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        feedId,
        it.guid,
        it.title || null,
        it.link || null,
        it.author || null,
        it.summary || null,
        it.content || null,
        it.published_at ?? null,
        now
      )
    );
  }
  if (stmts.length) {
    await env.DB.batch(stmts);
  }
}

async function enforceRetention(env: Env, feedId: number, maxItems: number) {
  // Delete items older than the most recent N items (by published_at then id).
  await env.DB.prepare(
    `DELETE FROM items
      WHERE feed_id = ?
        AND id NOT IN (
          SELECT id FROM items
           WHERE feed_id = ?
           ORDER BY COALESCE(published_at, 0) DESC, id DESC
           LIMIT ?
        )`
  ).bind(feedId, feedId, maxItems).run();
}

async function refreshOneFeed(env: Env, feed: FeedRow): Promise<{ inserted: number; status: "not_modified" | "ok" }> {
  const intervalMin = intEnv(env, "REFRESH_INTERVAL_MIN", 30);
  const nextFetchAt = nowMs() + intervalMin * 60_000;

  const result = await fetchAndParseFeed(feed);

  if (result.status === "not_modified") {
    await upsertFeedMeta(env, feed.id, {}, nextFetchAt);
    return { inserted: 0, status: "not_modified" };
  }

  const items = result.items || [];
  const maxInsert = 20; // per refresh per feed
  await insertItems(env, feed.id, items, maxInsert);

  const maxItems = intEnv(env, "MAX_ITEMS_PER_FEED", 500);
  await enforceRetention(env, feed.id, maxItems);

  await upsertFeedMeta(
    env,
    feed.id,
    { title: result.title, siteUrl: result.siteUrl, etag: result.etag ?? null, lastModified: result.lastModified ?? null },
    nextFetchAt
  );

  return { inserted: Math.min(items.length, maxInsert), status: "ok" };
}

async function getDueFeeds(env: Env, batch: number): Promise<FeedRow[]> {
  const now = nowMs();
  const { results } = await env.DB.prepare(
    `SELECT id, url, access_key, title, site_url, etag, last_modified, last_fetch_at, next_fetch_at, enabled
       FROM feeds
      WHERE enabled = 1
        AND (next_fetch_at IS NULL OR next_fetch_at <= ?)
      ORDER BY COALESCE(next_fetch_at, 0) ASC, id ASC
      LIMIT ?`
  ).bind(now, batch).all<FeedRow>();

  return (results || []) as FeedRow[];
}

async function refreshBatch(env: Env): Promise<{ refreshed: number; inserted: number }> {
  const batchSize = intEnv(env, "REFRESH_BATCH", 10);
  const feeds = await getDueFeeds(env, batchSize);

  let refreshed = 0;
  let inserted = 0;

  for (const f of feeds) {
    try {
      const r = await refreshOneFeed(env, f);
      refreshed += 1;
      inserted += r.inserted;
    } catch (e) {
      // Soft-fail: mark it as "tried" so it doesn't hammer one broken feed.
      const intervalMin = intEnv(env, "REFRESH_INTERVAL_MIN", 30);
      const nextFetchAt = nowMs() + intervalMin * 60_000;
      await upsertFeedMeta(env, f.id, {}, nextFetchAt);
      // Intentionally swallow error; keep batch moving.
    }
  }

  return { refreshed, inserted };
}

async function listFeeds(env: Env, userId: string) {
  const { results } = await env.DB.prepare(
    `SELECT f.id, f.url, f.title, f.site_url, f.last_fetch_at, f.enabled
       FROM feeds f
       JOIN user_feeds uf ON uf.feed_id = f.id
      WHERE uf.user_id IN (?, 'public')
      ORDER BY uf.is_default DESC, f.id DESC`
  ).bind(userId).all();
  return { feeds: results || [] };
}

async function addFeed(env: Env, userId: string, url: string) {
  const now = nowMs();
  const { url: normalized, accessKey } = normalizeFeedInput(url);

  // Insert first; then validate via refresh (so UI can show it immediately).
  const r = await env.DB.prepare(
    `INSERT INTO feeds (url, access_key, created_at, enabled, next_fetch_at)
     VALUES (?, ?, ?, 1, ?)
     ON CONFLICT(url) DO UPDATE SET enabled = 1, access_key = COALESCE(excluded.access_key, access_key)`
  ).bind(normalized, accessKey, now, 0).run();

  // Determine id of inserted/updated row:
  const { results } = await env.DB.prepare(`SELECT id, url, access_key, title, site_url, etag, last_modified, last_fetch_at, next_fetch_at, enabled FROM feeds WHERE url = ?`)
    .bind(normalized)
    .all<FeedRow>();

  const feed = (results?.[0] as FeedRow | undefined);
  if (!feed) throw new Error("failed to load feed row after insert");

  await env.DB.prepare(
    `INSERT OR IGNORE INTO user_feeds (user_id, feed_id, created_at, is_default)
     VALUES (?, ?, ?, 0)`
  ).bind(userId, feed.id, now).run();

  // Try refresh once to populate title/items
  await refreshOneFeed(env, feed);

  return { ok: true, feed_id: feed.id };
}

async function deleteFeed(env: Env, userId: string, id: number) {
  await env.DB.prepare(`DELETE FROM user_feeds WHERE user_id = ? AND feed_id = ?`).bind(userId, id).run();
  const { results } = await env.DB.prepare(`SELECT COUNT(*) as count FROM user_feeds WHERE feed_id = ?`).bind(id).all<{ count: number }>();
  if ((results?.[0]?.count || 0) === 0) {
    await env.DB.prepare(`DELETE FROM feeds WHERE id = ?`).bind(id).run();
  }
  return { ok: true };
}

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function isValidEmail(email: string) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function isFirstUser(env: Env) {
  const { results } = await env.DB.prepare(`SELECT COUNT(*) as count FROM users`).all<{ count: number }>();
  return (results?.[0]?.count || 0) === 0;
}

async function createUser(env: Env, opts: { email: string; password?: string; googleSub?: string }) {
  const id = crypto.randomUUID();
  const now = nowMs();
  let passwordHash: string | null = null;
  let passwordSalt: string | null = null;
  if (opts.password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    passwordHash = await hashPassword(opts.password, salt);
    passwordSalt = base64Url(salt);
  }
  const role = (await isFirstUser(env)) ? "admin" : "user";
  await env.DB.prepare(
    `INSERT INTO users (id, email, password_hash, password_salt, role, google_sub, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, opts.email, passwordHash, passwordSalt, role, opts.googleSub || null, now).run();
  return { id, email: opts.email, role };
}

async function createSession(env: Env, userId: string) {
  const sessionId = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  const maxAge = sessionMaxAge(env);
  const expiresAt = nowMs() + maxAge * 1000;
  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)`
  ).bind(sessionId, userId, expiresAt, nowMs()).run();
  return { sessionId, maxAge };
}

async function ensureGoogleUser(env: Env, profile: { email: string; sub: string }) {
  const { results } = await env.DB.prepare(
    `SELECT id, email, role, google_sub, password_hash, password_salt FROM users WHERE google_sub = ? OR email = ?`
  ).bind(profile.sub, profile.email).all<UserRow>();
  const existing = results?.[0];
  if (existing) {
    if (!existing.google_sub) {
      await env.DB.prepare(`UPDATE users SET google_sub = ? WHERE id = ?`).bind(profile.sub, existing.id).run();
    }
    return { id: existing.id, email: existing.email, role: existing.role };
  }
  return createUser(env, { email: profile.email, googleSub: profile.sub });
}

async function exchangeGoogleToken(env: Env, code: string) {
  const clientId = (env.GOOGLE_CLIENT_ID || "").trim();
  const clientSecret = (env.GOOGLE_CLIENT_SECRET || "").trim();
  const baseUrl = (env.PUBLIC_BASE_URL || "").trim();
  if (!clientId || !clientSecret || !baseUrl) {
    throw new Error("Google OAuth is not configured");
  }
  const redirectUri = `${baseUrl.replace(/\/+$/, "")}/api/auth/google/callback`;
  const body = new URLSearchParams({
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
    grant_type: "authorization_code",
  });
  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Google token exchange failed: ${text}`);
  }
  return res.json();
}

async function fetchGoogleProfile(accessToken: string) {
  const res = await fetch("https://openidconnect.googleapis.com/v1/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Google profile fetch failed: ${text}`);
  }
  return res.json() as Promise<{ sub: string; email: string }>;
}

async function consumeRateLimit(env: Env, key: string) {
  const now = nowMs();
  const windowMs = authRateWindowMs(env);
  const limit = authRateLimit(env);
  const { results } = await env.DB.prepare(
    `SELECT key, count, window_start
       FROM auth_rate_limits
      WHERE key = ?`
  ).bind(key).all<{ key: string; count: number; window_start: number }>();
  const row = results?.[0];
  if (!row || now - row.window_start >= windowMs) {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO auth_rate_limits (key, count, window_start)
       VALUES (?, ?, ?)`
    ).bind(key, 1, now).run();
    return { allowed: true, remaining: limit - 1 };
  }
  if (row.count >= limit) {
    return { allowed: false, remaining: 0 };
  }
  await env.DB.prepare(
    `UPDATE auth_rate_limits SET count = count + 1 WHERE key = ?`
  ).bind(key).run();
  return { allowed: true, remaining: limit - row.count - 1 };
}

async function listItems(env: Env, userId: string, opts: { feedId?: number; unreadOnly?: boolean; cursor?: number; limit: number }) {
  const where: string[] = [];
  const bind: any[] = [];

  if (opts.feedId) {
    where.push("i.feed_id = ?");
    bind.push(opts.feedId);
  }
  if (opts.cursor) {
    where.push("i.id < ?");
    bind.push(opts.cursor);
  }
  if (opts.unreadOnly) {
    where.push("r.item_id IS NULL");
  }

  const whereSql = where.length ? `WHERE ${where.join(" AND ")}` : "";

  const sql = `
    SELECT
      i.id, i.feed_id, i.title, i.link, i.author, i.summary, i.content, i.published_at, i.fetched_at,
      f.title AS feed_title,
      CASE WHEN r.item_id IS NULL THEN 0 ELSE 1 END AS read
    FROM items i
    JOIN feeds f ON f.id = i.feed_id
    JOIN user_feeds uf ON uf.feed_id = f.id AND uf.user_id IN (?, 'public')
    LEFT JOIN reads r ON r.item_id = i.id AND r.user_id = ?
    ${whereSql}
    ORDER BY COALESCE(i.published_at, 0) DESC, i.id DESC
    LIMIT ?
  `;

  const limit = Math.min(Math.max(opts.limit, 1), 200);
  const args = [userId, userId, ...bind, limit + 1];

  const { results } = await env.DB.prepare(sql).bind(...args).all<any>();
  const rows = results || [];

  const hasMore = rows.length > limit;
  const items = rows.slice(0, limit);
  const nextCursor = hasMore ? items[items.length - 1]?.id : null;

  return { items, next_cursor: nextCursor };
}

async function setRead(env: Env, userId: string, itemId: number, read: boolean) {
  const t = nowMs();
  if (read) {
    await env.DB.prepare(`INSERT OR REPLACE INTO reads (user_id, item_id, read_at) VALUES (?, ?, ?)`)
      .bind(userId, itemId, t)
      .run();
  } else {
    await env.DB.prepare(`DELETE FROM reads WHERE user_id = ? AND item_id = ?`)
      .bind(userId, itemId)
      .run();
  }
  return { ok: true };
}

async function markAllRead(env: Env, userId: string, feedId?: number) {
  const t = nowMs();

  // Insert reads for items that are currently unread.
  // This is intentionally a single SQL statement for efficiency.
  if (feedId) {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO reads (user_id, item_id, read_at)
       SELECT ?, i.id, ?
         FROM items i
         LEFT JOIN reads r ON r.user_id = ? AND r.item_id = i.id
        WHERE i.feed_id = ?
          AND r.item_id IS NULL`
    ).bind(userId, t, userId, feedId).run();
  } else {
    await env.DB.prepare(
      `INSERT OR IGNORE INTO reads (user_id, item_id, read_at)
       SELECT ?, i.id, ?
         FROM items i
         LEFT JOIN reads r ON r.user_id = ? AND r.item_id = i.id
        WHERE r.item_id IS NULL`
    ).bind(userId, t, userId).run();
  }

  return { ok: true };
}

function route(pathname: string) {
  // Very small router
  const parts = pathname.split("/").filter(Boolean);
  return parts;
}

async function getUserContext(request: Request, env: Env) {
  const ctx = await getAuthContext(request, env);
  if (!ctx.authEnabled) {
    return { userId: "public", isAuthenticated: true, role: ctx.role };
  }
  if (ctx.user) {
    return { userId: ctx.user.id, isAuthenticated: true, role: ctx.role };
  }
  return { userId: "public", isAuthenticated: false, role: ctx.role };
}

async function requireUser(request: Request, env: Env) {
  const ctx = await getAuthContext(request, env);
  if (!ctx.authEnabled) return null;
  if (ctx.user || ctx.role === "admin") return null;
  return badRequest("Unauthorized", 401);
}

async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const parts = route(url.pathname);

  // /api/...
  if (parts[0] !== "api") return badRequest("not an api route", 404);

  // GET /api/auth/me
  if (request.method === "GET" && parts[1] === "auth" && parts[2] === "me" && parts.length === 3) {
    const ctx = await getAuthContext(request, env);
    return json({
      role: ctx.role,
      auth_enabled: ctx.authEnabled,
      user: ctx.user ? { id: ctx.user.id, email: ctx.user.email } : null,
      turnstile_site_key: (env.TURNSTILE_SITE_KEY || "").trim() || null,
    });
  }

  // POST /api/auth/register {email, password}
  if (request.method === "POST" && parts[1] === "auth" && parts[2] === "register" && parts.length === 3) {
    if (!isAuthEnabled(env)) return badRequest("Auth disabled", 400);
    const ip = getClientIp(request);
    const rate = await consumeRateLimit(env, `register:${ip}`);
    if (!rate.allowed) return badRequest("Too many attempts", 429);
    const body = await request.json().catch(() => ({}));
    const turnstileToken = String(body?.turnstileToken || "");
    const turnstileOk = await verifyTurnstile(request, env, turnstileToken);
    if (!turnstileOk) return badRequest("Turnstile required", 400);
    const email = normalizeEmail(String(body?.email || ""));
    const password = String(body?.password || "");
    if (!isValidEmail(email)) return badRequest("Invalid email", 400);
    if (password.length < 8) return badRequest("Password too short", 400);

    const { results } = await env.DB.prepare(
      `SELECT id, email, password_hash, password_salt, role, google_sub FROM users WHERE email = ?`
    ).bind(email).all<UserRow>();
    const existing = results?.[0];
    if (existing?.password_hash) {
      return badRequest("Email already registered", 409);
    }
    let user = existing;
    if (!user) {
      const created = await createUser(env, { email, password });
      user = { id: created.id, email: created.email, role: created.role, password_hash: "", password_salt: "", google_sub: null };
    } else {
      const salt = crypto.getRandomValues(new Uint8Array(16));
      const passwordHash = await hashPassword(password, salt);
      await env.DB.prepare(
        `UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?`
      ).bind(passwordHash, base64Url(salt), existing.id).run();
    }
    const session = await createSession(env, user.id);
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "set-cookie": sessionCookieValue(session.sessionId, session.maxAge),
      },
    });
  }

  // POST /api/auth/login {email, password}
  if (request.method === "POST" && parts[1] === "auth" && parts[2] === "login" && parts.length === 3) {
    if (!isAuthEnabled(env)) return badRequest("Auth disabled", 400);
    const body = await request.json().catch(() => ({}));
    const ip = getClientIp(request);
    const rate = await consumeRateLimit(env, `login:${ip}`);
    if (!rate.allowed) return badRequest("Too many attempts", 429);
    const turnstileToken = String(body?.turnstileToken || "");
    const turnstileOk = await verifyTurnstile(request, env, turnstileToken);
    if (!turnstileOk) return badRequest("Turnstile required", 400);
    const email = normalizeEmail(String(body?.email || ""));
    const password = String(body?.password || "");
    if (!isValidEmail(email)) return badRequest("Invalid email", 400);
    const { results } = await env.DB.prepare(
      `SELECT id, email, password_hash, password_salt, role FROM users WHERE email = ?`
    ).bind(email).all<UserRow>();
    const user = results?.[0];
    if (!user || !user.password_hash || !user.password_salt) return badRequest("Invalid credentials", 401);
    const salt = base64UrlToBytes(user.password_salt);
    const ok = await verifyPassword(password, salt, user.password_hash);
    if (!ok) return badRequest("Invalid credentials", 401);
    const session = await createSession(env, user.id);
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "set-cookie": sessionCookieValue(session.sessionId, session.maxAge),
      },
    });
  }

  // POST /api/auth/logout
  if (request.method === "POST" && parts[1] === "auth" && parts[2] === "logout" && parts.length === 3) {
    const cookies = parseCookies(request.headers.get("cookie"));
    const sessionId = cookies.get("session");
    if (sessionId) {
      await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(sessionId).run();
    }
    return new Response(JSON.stringify({ ok: true }), {
      headers: {
        "content-type": "application/json; charset=utf-8",
        "set-cookie": clearSessionCookie(),
      },
    });
  }

  // POST /api/translate {text, target}
  if (request.method === "POST" && parts[1] === "translate" && parts.length === 2) {
    const authErr = await requireUser(request, env);
    if (authErr) return authErr;
    const body = await request.json().catch(() => ({}));
    const text = String(body?.text || "").trim();
    const target = String(body?.target || "").trim();
    if (!text || text.length > 500) return badRequest("Invalid text", 400);
    if (!/^[a-z]{2}$/.test(target)) return badRequest("Invalid target", 400);
    const ip = getClientIp(request);
    const rate = await consumeRateLimit(env, `translate:${ip}`);
    if (!rate.allowed) return badRequest("Too many attempts", 429);
    const key = await translationKey(text, target);
    const cached = await getCachedTranslation(env, key);
    if (cached) return json({ translated_text: cached.translated_text, cached: true });
    const translated = await translateText(env, text, target);
    await cacheTranslation(env, key, translated);
    return json({ translated_text: translated, cached: false });
  }

  // GET /api/auth/google/start
  if (request.method === "GET" && parts[1] === "auth" && parts[2] === "google" && parts[3] === "start" && parts.length === 4) {
    if (!isAuthEnabled(env)) return badRequest("Auth disabled", 400);
    const clientId = (env.GOOGLE_CLIENT_ID || "").trim();
    const baseUrl = (env.PUBLIC_BASE_URL || "").trim() || new URL(request.url).origin;
    if (!clientId) return badRequest("Google OAuth not configured", 500);
    const state = base64Url(crypto.getRandomValues(new Uint8Array(16)));
    await env.DB.prepare(
      `INSERT INTO oauth_states (state, created_at) VALUES (?, ?)`
    ).bind(state, nowMs()).run();
    const redirectUri = `${baseUrl.replace(/\/+$/, "")}/api/auth/google/callback`;
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri,
      response_type: "code",
      scope: "openid email profile",
      state,
      access_type: "online",
      prompt: "select_account",
    });
    return Response.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`, 302);
  }

  // GET /api/auth/google/callback
  if (request.method === "GET" && parts[1] === "auth" && parts[2] === "google" && parts[3] === "callback" && parts.length === 4) {
    if (!isAuthEnabled(env)) return badRequest("Auth disabled", 400);
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    if (!code || !state) return badRequest("Missing code", 400);
    const { results } = await env.DB.prepare(
      `SELECT state, created_at FROM oauth_states WHERE state = ?`
    ).bind(state).all<{ state: string; created_at: number }>();
    const row = results?.[0];
    if (!row || nowMs() - row.created_at > 10 * 60 * 1000) {
      return badRequest("Invalid state", 400);
    }
    await env.DB.prepare(`DELETE FROM oauth_states WHERE state = ?`).bind(state).run();
    const token = await exchangeGoogleToken(env, code);
    const profile = await fetchGoogleProfile(token.access_token as string);
    if (!profile?.email || !profile?.sub) return badRequest("Missing Google profile", 400);
    const user = await ensureGoogleUser(env, { email: normalizeEmail(profile.email), sub: profile.sub });
    const session = await createSession(env, user.id);
    const redirectTo = (env.PUBLIC_BASE_URL || "").trim() || new URL(request.url).origin;
    return new Response(null, {
      status: 302,
      headers: {
        location: redirectTo,
        "set-cookie": sessionCookieValue(session.sessionId, session.maxAge),
      },
    });
  }

  // GET /api/feeds
  if (request.method === "GET" && parts[1] === "feeds" && parts.length === 2) {
    const ctx = await getUserContext(request, env);
    return json(await listFeeds(env, ctx.userId));
  }

  // POST /api/feeds  {url}
  if (request.method === "POST" && parts[1] === "feeds" && parts.length === 2) {
    const authErr = await requireUser(request, env);
    if (authErr) return authErr;
    const ctx = await getUserContext(request, env);

    const body = await request.json().catch(() => ({}));
    const urlStr = String(body?.url || "").trim();
    if (!urlStr) return badRequest("Missing 'url'");
    try {
      return json(await addFeed(env, ctx.userId, urlStr));
    } catch (e: any) {
      return badRequest(e?.message || "Failed to add feed", 400);
    }
  }

  // DELETE /api/feeds/:id
  if (request.method === "DELETE" && parts[1] === "feeds" && parts[2] && parts.length === 3) {
    const authErr = await requireUser(request, env);
    if (authErr) return authErr;
    const ctx = await getUserContext(request, env);

    const id = Number(parts[2]);
    if (!Number.isFinite(id) || id <= 0) return badRequest("Invalid feed id");
    return json(await deleteFeed(env, ctx.userId, id));
  }

  // POST /api/feeds/:id/refresh
  if (request.method === "POST" && parts[1] === "feeds" && parts[2] && parts[3] === "refresh") {
    const authErr = await requireAdmin(request, env);
    if (authErr) return authErr;

    const id = Number(parts[2]);
    if (!Number.isFinite(id) || id <= 0) return badRequest("Invalid feed id");
    const { results } = await env.DB.prepare(
      `SELECT id, url, access_key, title, site_url, etag, last_modified, last_fetch_at, next_fetch_at, enabled
         FROM feeds
        WHERE id = ?`
    ).bind(id).all<FeedRow>();
    const feed = results?.[0];
    if (!feed) return badRequest("Feed not found", 404);
    await refreshOneFeed(env, feed as any);
    return json({ ok: true });
  }

  // POST /api/refresh (manual batch)
  if (request.method === "POST" && parts[1] === "refresh" && parts.length === 2) {
    const authErr = await requireAdmin(request, env);
    if (authErr) return authErr;

    return json(await refreshBatch(env));
  }

  // GET /api/items?feed_id=&unread=&cursor=&limit=
  if (request.method === "GET" && parts[1] === "items" && parts.length === 2) {
    const ctx = await getUserContext(request, env);
    const feedIdRaw = url.searchParams.get("feed_id");
    const feedId = feedIdRaw ? Number(feedIdRaw) : undefined;
    const unread = url.searchParams.get("unread") === "1";
    const cursorRaw = url.searchParams.get("cursor");
    const cursor = cursorRaw ? Number(cursorRaw) : undefined;
    const limitRaw = url.searchParams.get("limit");
    const limit = limitRaw ? Number(limitRaw) : 50;
    return json(await listItems(env, ctx.userId, { feedId, unreadOnly: unread, cursor, limit: Number.isFinite(limit) ? limit : 50 }));
  }

  // POST /api/items/:id/read  {read:true|false}
  if (request.method === "POST" && parts[1] === "items" && parts[2] && parts[3] === "read") {
    const ctx = await getUserContext(request, env);
    const body = await request.json().catch(() => ({}));
    const read = !!body?.read;
    const id = Number(parts[2]);
    if (!Number.isFinite(id) || id <= 0) return badRequest("Invalid item id");
    return json(await setRead(env, ctx.userId, id, read));
  }

  // POST /api/mark_all_read?feed_id=
  if (request.method === "POST" && parts[1] === "mark_all_read" && parts.length === 2) {
    const ctx = await getUserContext(request, env);
    const feedIdRaw = url.searchParams.get("feed_id");
    const feedId = feedIdRaw ? Number(feedIdRaw) : undefined;
    if (feedIdRaw && (!Number.isFinite(feedId) || (feedId as number) <= 0)) return badRequest("Invalid feed id");
    return json(await markAllRead(env, ctx.userId, feedId));
  }

  return badRequest("Not found", 404);
}

async function serveAssets(request: Request, env: Env): Promise<Response> {
  // Try static asset first
  const assetResp = await env.ASSETS.fetch(request);
  if (assetResp.status !== 404) return assetResp;

  // SPA fallback: serve /index.html
  const url = new URL(request.url);
  url.pathname = "/index.html";
  return env.ASSETS.fetch(new Request(url.toString(), request));
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.startsWith("/api/")) {
      return handleApi(request, env);
    }

    // Basic health check
    if (url.pathname === "/healthz") {
      return json({ ok: true, ts: nowMs() });
    }

    return serveAssets(request, env);
  },

  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    // Run refresh in background
    ctx.waitUntil(refreshBatch(env));
  },
} satisfies ExportedHandler<Env>;

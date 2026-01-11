import { XMLParser } from "fast-xml-parser";

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  ADMIN_TOKEN?: string;
  REFRESH_BATCH?: string;
  REFRESH_INTERVAL_MIN?: string;
  MAX_ITEMS_PER_FEED?: string;
}

type FeedRow = {
  id: number;
  url: string;
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

function normalizeUrl(u: string) {
  let s = u.trim();
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  const url = new URL(s);
  url.hash = "";
  return url.toString();
}

function requireAdmin(request: Request, env: Env) {
  const token = (env.ADMIN_TOKEN || "").trim();
  if (!token) return null; // open mode

  const auth = request.headers.get("authorization") || "";
  const ok = auth.toLowerCase().startsWith("bearer ") && auth.slice(7).trim() === token;
  if (!ok) return badRequest("Unauthorized", 401);
  return null;
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

    const res = await fetch(feed.url, {
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
    `SELECT id, url, title, site_url, etag, last_modified, last_fetch_at, next_fetch_at, enabled
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

async function listFeeds(env: Env) {
  const { results } = await env.DB.prepare(
    `SELECT id, url, title, site_url, last_fetch_at, enabled
       FROM feeds
      ORDER BY id DESC`
  ).all();
  return { feeds: results || [] };
}

async function addFeed(env: Env, url: string) {
  const now = nowMs();
  const normalized = normalizeUrl(url);

  // Insert first; then validate via refresh (so UI can show it immediately).
  const r = await env.DB.prepare(
    `INSERT INTO feeds (url, created_at, enabled, next_fetch_at)
     VALUES (?, ?, 1, ?)
     ON CONFLICT(url) DO UPDATE SET enabled = 1`
  ).bind(normalized, now, 0).run();

  // Determine id of inserted/updated row:
  const { results } = await env.DB.prepare(`SELECT id, url, title, site_url, etag, last_modified, last_fetch_at, next_fetch_at, enabled FROM feeds WHERE url = ?`)
    .bind(normalized)
    .all<FeedRow>();

  const feed = (results?.[0] as FeedRow | undefined);
  if (!feed) throw new Error("failed to load feed row after insert");

  // Try refresh once to populate title/items
  await refreshOneFeed(env, feed);

  return { ok: true, feed_id: feed.id };
}

async function deleteFeed(env: Env, id: number) {
  await env.DB.prepare(`DELETE FROM feeds WHERE id = ?`).bind(id).run();
  return { ok: true };
}

async function listItems(env: Env, opts: { feedId?: number; unreadOnly?: boolean; cursor?: number; limit: number }) {
  const userId = "default";
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
    LEFT JOIN reads r ON r.item_id = i.id AND r.user_id = ?
    ${whereSql}
    ORDER BY COALESCE(i.published_at, 0) DESC, i.id DESC
    LIMIT ?
  `;

  const limit = Math.min(Math.max(opts.limit, 1), 200);
  const args = [userId, ...bind, limit + 1];

  const { results } = await env.DB.prepare(sql).bind(...args).all<any>();
  const rows = results || [];

  const hasMore = rows.length > limit;
  const items = rows.slice(0, limit);
  const nextCursor = hasMore ? items[items.length - 1]?.id : null;

  return { items, next_cursor: nextCursor };
}

async function setRead(env: Env, itemId: number, read: boolean) {
  const userId = "default";
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

async function markAllRead(env: Env, feedId?: number) {
  const userId = "default";
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

async function handleApi(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const parts = route(url.pathname);

  // /api/...
  if (parts[0] !== "api") return badRequest("not an api route", 404);

  // GET /api/feeds
  if (request.method === "GET" && parts[1] === "feeds" && parts.length === 2) {
    return json(await listFeeds(env));
  }

  // POST /api/feeds  {url}
  if (request.method === "POST" && parts[1] === "feeds" && parts.length === 2) {
    const authErr = requireAdmin(request, env);
    if (authErr) return authErr;

    const body = await request.json().catch(() => ({}));
    const urlStr = String(body?.url || "").trim();
    if (!urlStr) return badRequest("Missing 'url'");
    try {
      return json(await addFeed(env, urlStr));
    } catch (e: any) {
      return badRequest(e?.message || "Failed to add feed", 400);
    }
  }

  // DELETE /api/feeds/:id
  if (request.method === "DELETE" && parts[1] === "feeds" && parts[2] && parts.length === 3) {
    const authErr = requireAdmin(request, env);
    if (authErr) return authErr;

    const id = Number(parts[2]);
    if (!Number.isFinite(id) || id <= 0) return badRequest("Invalid feed id");
    return json(await deleteFeed(env, id));
  }

  // POST /api/feeds/:id/refresh
  if (request.method === "POST" && parts[1] === "feeds" && parts[2] && parts[3] === "refresh") {
    const authErr = requireAdmin(request, env);
    if (authErr) return authErr;

    const id = Number(parts[2]);
    if (!Number.isFinite(id) || id <= 0) return badRequest("Invalid feed id");
    const { results } = await env.DB.prepare(
      `SELECT id, url, title, site_url, etag, last_modified, last_fetch_at, next_fetch_at, enabled
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
    const authErr = requireAdmin(request, env);
    if (authErr) return authErr;

    return json(await refreshBatch(env));
  }

  // GET /api/items?feed_id=&unread=&cursor=&limit=
  if (request.method === "GET" && parts[1] === "items" && parts.length === 2) {
    const feedIdRaw = url.searchParams.get("feed_id");
    const feedId = feedIdRaw ? Number(feedIdRaw) : undefined;
    const unread = url.searchParams.get("unread") === "1";
    const cursorRaw = url.searchParams.get("cursor");
    const cursor = cursorRaw ? Number(cursorRaw) : undefined;
    const limitRaw = url.searchParams.get("limit");
    const limit = limitRaw ? Number(limitRaw) : 50;
    return json(await listItems(env, { feedId, unreadOnly: unread, cursor, limit: Number.isFinite(limit) ? limit : 50 }));
  }

  // POST /api/items/:id/read  {read:true|false}
  if (request.method === "POST" && parts[1] === "items" && parts[2] && parts[3] === "read") {
    const body = await request.json().catch(() => ({}));
    const read = !!body?.read;
    const id = Number(parts[2]);
    if (!Number.isFinite(id) || id <= 0) return badRequest("Invalid item id");
    return json(await setRead(env, id, read));
  }

  // POST /api/mark_all_read?feed_id=
  if (request.method === "POST" && parts[1] === "mark_all_read" && parts.length === 2) {
    const feedIdRaw = url.searchParams.get("feed_id");
    const feedId = feedIdRaw ? Number(feedIdRaw) : undefined;
    if (feedIdRaw && (!Number.isFinite(feedId) || (feedId as number) <= 0)) return badRequest("Invalid feed id");
    return json(await markAllRead(env, feedId));
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

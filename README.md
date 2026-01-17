# RSS Reader on Cloudflare (Free-friendly, RSS-only)

A minimal “集中阅读” RSS/Atom reader built as a **single Cloudflare Worker** serving:
- a static UI (from `./public`)
- an API (under `/api/*`)
- a D1 database for feeds/items/read-state
- a scheduled refresh job via Cron Triggers

This is intentionally **RSS-only** (no RSSHub / scraping).

## What you get (MVP)
- Add a feed URL
- List feeds
- Unified item stream (All Feeds) or per-feed view
- Unread-only toggle
- Mark read/unread
- Mark all read
- Manual refresh (batch / per-feed)
- Scheduled refresh (Cron)

## Requirements
- Node.js 18+
- A Cloudflare account
- Wrangler CLI (included as a devDependency)

## 1) Install
```bash
npm install
```

## 2) Create a D1 database and bind it
Create a D1 database (name used here: `rss_reader`):

```bash
npx wrangler d1 create rss_reader
```

Wrangler will output a JSON snippet including `database_id`.
Paste that `database_id` into `wrangler.jsonc` under `d1_databases[0].database_id`.

Notes:
- D1 binding configuration is documented in Cloudflare’s D1 getting-started guide. 
- Cron Triggers use the `scheduled()` handler. 
- Static assets are configured via the `assets` section. 

(See Cloudflare docs for D1, Cron Triggers, and Static Assets.)

## 3) Apply schema (migrations)
Local:
```bash
npx wrangler d1 migrations apply rss_reader --local
```

Remote (your deployed DB):
```bash
npx wrangler d1 migrations apply rss_reader --remote
```

## 3.1) Default feeds (seed)
This repo includes a seed migration (`migrations/0002_seed.sql`) that inserts a small set of popular **CN + Global** RSS/Atom feeds using `INSERT OR IGNORE`.

Notes:
- If you do **not** want any defaults, delete that migration file (or clear its SQL) before applying migrations.
- If you have already deployed, apply migrations again (`--remote`) to seed the additional feeds.

## Feeds per user
User subscriptions are stored in `user_feeds` so public/default feeds can be shared while
each user can add/remove their own feeds without duplicating the feed record.
The table includes an index on `user_id` for faster lookups.

## 4) Run locally
```bash
npm run dev
```

Open the local URL printed by Wrangler.

## 5) Deploy
```bash
npm run deploy
```

## Optional: protect write endpoints
If you set `ADMIN_TOKEN`, all **mutating endpoints** require:
`Authorization: Bearer <token>`.

Set `ADMIN_TOKEN` in the Cloudflare dashboard (Worker > Settings > Variables) or via Wrangler secrets:

```bash
npx wrangler secret put ADMIN_TOKEN
```

You can generate a strong token locally, for example:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64url'))"
```

If you do **not** set `ADMIN_TOKEN`, the app runs in “open mode”.

## Auth (email + Google)
Enable login by setting `AUTH_ENABLED=true` (or by setting `ADMIN_TOKEN`).

### Email/password
- `POST /api/auth/register` `{ "email": "...", "password": "..." }`
- `POST /api/auth/login` `{ "email": "...", "password": "..." }`
- `POST /api/auth/logout`

The first registered user becomes an admin automatically.

### Google OAuth
Set the following Worker variables:
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `PUBLIC_BASE_URL` (e.g. `https://your-domain.com`)

The app uses `GET /api/auth/google/start` and `GET /api/auth/google/callback`.

### Session cookies
Sessions are stored in D1 and sent via HttpOnly cookies. Use `SESSION_DAYS`
to control duration (default 7 days).

### Rate limiting
Registration is protected with a simple IP-based limiter. Configure:
- `AUTH_RATE_LIMIT` (default 5)
- `AUTH_RATE_WINDOW_MIN` (default 10)

### Turnstile (human verification)
If you set Turnstile keys, both registration and login will require a completed challenge.
- `TURNSTILE_SITE_KEY`
- `TURNSTILE_SECRET_KEY`

### Translations (UI + titles)
The API caches translations in D1 and supports multiple providers, preferring free options.
Configure one or more of:
- `LIBRETRANSLATE_URL` (preferred if set)
- `GOOGLE_TRANSLATE_KEY`
- `GOOGLE_TRANSLATE_REGION` (optional)
- `AI_TRANSLATE_URL`
- `AI_TRANSLATE_KEY`
- `TRANSLATE_PROVIDER` (optional: `libre`, `google`, or `ai`)
- `TRANSLATE_FEED_TITLES` (optional, default false)
- `TRANSLATE_RATE_LIMIT` (default 60)
- `TRANSLATE_RATE_WINDOW_MIN` (default 10)

Translation requests require an authenticated user when auth is enabled.

## Refresh strategy
- Cron runs every 10 minutes (see `triggers.crons` in `wrangler.jsonc`)
- Each run refreshes `REFRESH_BATCH` feeds (default 10)
- Each feed is eligible again after `REFRESH_INTERVAL_MIN` minutes (default 30)
- Per feed, we insert at most 20 new items per refresh and retain the newest `MAX_ITEMS_PER_FEED`

Adjust these in `wrangler.jsonc` as you scale.

## API reference (quick)
- `GET /api/feeds`
- `POST /api/feeds` `{ "url": "https://..." }`
- `DELETE /api/feeds/:id`
- `POST /api/feeds/:id/refresh`
- `POST /api/refresh`
- `GET /api/items?feed_id=&unread=1&cursor=&limit=`
- `POST /api/items/:id/read` `{ "read": true|false }`
- `POST /api/mark_all_read?feed_id=`
- `POST /api/translate` `{ "text": "...", "target": "en" }`

## Next upgrades (if you want)
- OPML import/export
- Full-text search (D1 FTS or Vectorize)
- Better dedup (hash content)
- Feed discovery (auto-detect RSS from site URL)

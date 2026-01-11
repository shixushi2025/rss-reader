-- D1 migration: initial schema

CREATE TABLE IF NOT EXISTS feeds (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT NOT NULL UNIQUE,
  title TEXT,
  site_url TEXT,
  etag TEXT,
  last_modified TEXT,
  last_fetch_at INTEGER,
  next_fetch_at INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  feed_id INTEGER NOT NULL,
  guid TEXT NOT NULL,
  title TEXT,
  link TEXT,
  author TEXT,
  summary TEXT,
  content TEXT,
  published_at INTEGER,
  fetched_at INTEGER NOT NULL,
  UNIQUE(feed_id, guid),
  FOREIGN KEY(feed_id) REFERENCES feeds(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reads (
  user_id TEXT NOT NULL,
  item_id INTEGER NOT NULL,
  read_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, item_id),
  FOREIGN KEY(item_id) REFERENCES items(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_items_feed_pub ON items(feed_id, published_at DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_items_pub ON items(published_at DESC, id DESC);

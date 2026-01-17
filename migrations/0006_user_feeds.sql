-- D1 migration: user feeds mapping

CREATE TABLE IF NOT EXISTS user_feeds (
  user_id TEXT NOT NULL,
  feed_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  is_default INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, feed_id),
  FOREIGN KEY(feed_id) REFERENCES feeds(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_feeds_user ON user_feeds(user_id);

-- Backfill existing feeds as public defaults
INSERT OR IGNORE INTO user_feeds (user_id, feed_id, created_at, is_default)
SELECT 'public', id, strftime('%s','now') * 1000, 1 FROM feeds;

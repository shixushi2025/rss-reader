-- D1 migration: cached translations

CREATE TABLE IF NOT EXISTS translations (
  key TEXT PRIMARY KEY,
  translated_text TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

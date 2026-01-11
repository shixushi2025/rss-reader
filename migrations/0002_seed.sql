-- D1 migration: seed some popular feeds (CN + Global)
-- Safe to re-run: url is UNIQUE and we use INSERT OR IGNORE.

INSERT OR IGNORE INTO feeds (url, title, created_at, enabled, next_fetch_at)
VALUES
  ('https://feeds.bbci.co.uk/news/rss.xml', 'BBC News', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('http://rss.cnn.com/rss/cnn_topstories.rss', 'CNN Top Stories', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://www.theguardian.com/world/rss', 'The Guardian | World', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('http://feeds.nytimes.com/nyt/rss/HomePage', 'The New York Times | Home Page', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://feeds.arstechnica.com/arstechnica/index', 'Ars Technica', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://techcrunch.com/feed/', 'TechCrunch', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://www.wired.com/feed/rss', 'WIRED', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://news.ycombinator.com/rss', 'Hacker News', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://github.com/blog.atom', 'GitHub Blog', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://blog.google/rss/', 'Google Blog', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),

  ('https://sspai.com/feed', '少数派', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://www.ifanr.com/feed', '爱范儿 (全文)', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('http://live.ifanr.com/feed', '爱范儿 (快讯)', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://36kr.com/feed', '36氪', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://rss.huxiu.com/', '虎嗅', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('http://www.ruanyifeng.com/blog/atom.xml', '阮一峰的网络日志', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://www.v2ex.com/index.xml', 'V2EX', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('https://www.solidot.org/index.rss', 'Solidot', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0),
  ('http://feeds.appinn.com/appinns/', '小众软件', CAST(strftime('%s','now') AS INTEGER) * 1000, 1, 0);

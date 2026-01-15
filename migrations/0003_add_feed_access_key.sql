-- D1 migration: store RSSHub access keys separately

ALTER TABLE feeds ADD COLUMN access_key TEXT;

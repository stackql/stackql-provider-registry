-- StackQL Provider Registry analytics (D1).
-- One row per .tgz download. providers.yaml requests are NOT logged.

CREATE TABLE IF NOT EXISTS downloads (
  ts          TEXT NOT NULL,      -- ISO8601 timestamp of the download
  provider    TEXT NOT NULL,      -- e.g. aws, google, github
  version     TEXT,               -- e.g. v0.1.3 (or v0.1.3-dev on the dev origin)
  pathname    TEXT NOT NULL,      -- full request path, e.g. /providers/dist/aws/v0.1.3.tgz
  host        TEXT,               -- request Host header
  ip_addr     TEXT,               -- CF-Connecting-IP
  user_agent  TEXT
);

CREATE INDEX IF NOT EXISTS idx_downloads_ts_provider ON downloads (ts, provider);

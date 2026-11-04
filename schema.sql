-- Splonk database: one row per saved item (round, course, club, video note, settings),
-- tagged with the owner's verified email address.
CREATE TABLE IF NOT EXISTS docs (
  user       TEXT    NOT NULL,
  key        TEXT    NOT NULL,
  data       TEXT    NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted    INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user, key)
);
CREATE INDEX IF NOT EXISTS docs_user_updated ON docs (user, updated_at);

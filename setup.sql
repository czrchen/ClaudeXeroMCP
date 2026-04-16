-- Xero MCP Auth — NeonDB table setup
-- Run this once in your Neon project's SQL editor before starting server.js

CREATE TABLE IF NOT EXISTS xero_tokens (
  id            INTEGER PRIMARY KEY DEFAULT 1,
  access_token  TEXT    NOT NULL,
  refresh_token TEXT    NOT NULL,
  expires_at    BIGINT  NOT NULL,
  tenant_id     TEXT,
  tenant_name   TEXT,
  authorised_at TEXT,
  refreshed_at  TEXT
);

-- This table holds exactly one row (id = 1).
-- The server upserts into it on every login and token refresh.

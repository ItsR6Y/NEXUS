import type { Migration } from '../database'

export const m001: Migration = {
  version: 1,
  name: 'initial schema',
  sql: `
CREATE TABLE servers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 80),
  host TEXT NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  username TEXT NOT NULL CHECK (length(username) BETWEEN 1 AND 64),
  auth_type TEXT NOT NULL CHECK (auth_type IN ('password','key')),
  key_path TEXT,
  approval_policy TEXT NOT NULL DEFAULT 'ask' CHECK (approval_policy IN ('sensitive','ask','always')),
  mcp_access_enabled INTEGER NOT NULL DEFAULT 0 CHECK (mcp_access_enabled IN (0,1)),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Used only when falling back from OS keyring to Electron safeStorage (DPAPI ciphertext only; never plaintext).
CREATE TABLE credential_refs (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  kind TEXT NOT NULL CHECK (kind IN ('password','passphrase')),
  blob BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (server_id, kind)
);

CREATE TABLE known_hosts (
  host TEXT NOT NULL,
  port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  key_type TEXT NOT NULL,
  fingerprint_sha256 TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  PRIMARY KEY (host, port, key_type)
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  connection_epoch INTEGER NOT NULL DEFAULT 0 CHECK (connection_epoch >= 0),
  state TEXT NOT NULL CHECK (state IN ('connecting','connected','disconnected','error')),
  opened_at INTEGER NOT NULL,
  closed_at INTEGER,
  error TEXT
);
CREATE INDEX idx_sessions_server ON sessions(server_id);

CREATE TABLE executions (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  source TEXT NOT NULL CHECK (source IN ('user','claude')),
  requester TEXT NOT NULL,
  command_sanitized TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('LOW','MEDIUM','HIGH','CRITICAL','DESTRUCTIVE')),
  flags TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL CHECK (status IN ('running','completed','failed','timeout','cancelled','denied')),
  exit_code INTEGER,
  signal TEXT,
  started_at INTEGER NOT NULL,
  finished_at INTEGER,
  truncated INTEGER NOT NULL DEFAULT 0,
  output TEXT NOT NULL DEFAULT '',
  denial_reason TEXT,
  approval_id TEXT
);
CREATE INDEX idx_exec_server ON executions(server_id, started_at DESC);
CREATE INDEX idx_exec_session ON executions(session_id, started_at DESC);

CREATE TABLE approvals (
  id TEXT PRIMARY KEY,
  binding_hash TEXT NOT NULL,
  command_sanitized TEXT NOT NULL,
  server_id TEXT NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  epoch INTEGER NOT NULL,
  timeout_ms INTEGER NOT NULL,
  max_output_bytes INTEGER NOT NULL,
  source TEXT NOT NULL CHECK (source IN ('user','claude')),
  requester TEXT NOT NULL,
  level TEXT NOT NULL CHECK (level IN ('LOW','MEDIUM','HIGH','CRITICAL','DESTRUCTIVE')),
  reasons TEXT NOT NULL DEFAULT '[]',
  flags TEXT NOT NULL DEFAULT '[]',
  policy_version TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected','expired','cancelled','invalidated','consumed')),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  decided_at INTEGER,
  consumed_at INTEGER,
  invalidation_reason TEXT
);
CREATE INDEX idx_approvals_status ON approvals(status);

CREATE TABLE security_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  type TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info','warning','critical')),
  server_id TEXT,
  details TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  actor TEXT NOT NULL,
  data TEXT NOT NULL,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE
);
CREATE TRIGGER audit_log_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER audit_log_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
`
}

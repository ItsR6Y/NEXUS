import type { Migration } from '../database'

/** Indexes for teardown, dashboard and retention queries on hot paths. */
export const m002: Migration = {
  version: 2,
  name: 'hot-path indexes',
  sql: `
CREATE INDEX idx_executions_status ON executions(status);
CREATE INDEX idx_approvals_session ON approvals(session_id);
CREATE INDEX idx_approvals_server ON approvals(server_id);
CREATE INDEX idx_security_events_ts ON security_events(ts);
CREATE INDEX idx_audit_log_ts ON audit_log(ts);
`
}

# NEXUS Terminal — Security Model

## Trust Boundaries

1. **Electron Main Process (Trusted):** Sole authority for credentials, SQLite, SSH transport, host-key verification, command classification, approval dialogs, audit logging, and the MCP bridge.
2. **Renderer Process (Untrusted):** Runs with `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`, `webSecurity: true`, `webviewTag: false`, `allowRunningInsecureContent: false`. Served from `nexus-app://app/` in production. Has **no** IPC channels to approve commands or trust/replace host keys.
3. **MCP Stdio Process (`out/mcp/nexus-mcp.mjs`, Untrusted Client):** Standalone Node process with zero Electron, SSH, SQLite, or credential imports. Authenticates to main via HMAC-SHA256 challenge-response over a per-launch named pipe. Cannot open/close sessions, create/delete servers, read credentials, or approve commands.

## Threat Model & Controls

| Threat | Control |
|---|---|
| Compromised renderer approves a malicious command or trusts an attacker host key | Approval and host-key decisions are strictly native main-process `dialog.showMessageBox` calls defaulting to **Deny/Reject**. No IPC decision channels exist. |
| Command smuggling / bypass via MCP payload spoofing | `source` (`'user'` vs `'claude'`) is hard-coded by the transport; `.strict()` Zod schemas reject extra fields (`source`, `approved`, `risk`, `policy`). |
| Approval replay, tampering, or reconnect race | Approvals bind SHA-256 over raw command bytes + server + session + epoch + timeout + output cap + source + policy version. Consumption is an atomic SQLite `UPDATE ... WHERE status='approved' AND consumed_at IS NULL AND expires_at>?`. Reconnects bump `connection_epoch` and invalidate active approvals. |
| Inline secrets leaking into SQLite, logs, UI, or MCP | `approvals.command_sanitized`, `executions.command_sanitized`, `audit_log`, `nexus.log`, and all command/terminal outputs pass through `redactText` / `StreamRedactor` (regex patterns + exact stored secrets). |
| SSH MitM / host-key change | Strict `hostVerifier` keyed by `(host, port, keyType)`. Unknown keys pause connect for native user approval (Reject default, 60s timeout). Mismatches hard-block with no "continue anyway" option. |
| Private key theft via IPC/MCP | Private keys stay on disk at `servers.key_path`, are read only in main at SSH connect time, and the key `Buffer` is zeroed (`fill(0)`) immediately after connect. `ServerPublicInfo` omits `keyPath`. |
| Compromised renderer opens a PTY and types commands with stored credentials | **Accepted by design** (see "Consequence" below): keystrokes are not approval-gated, so renderer integrity is the boundary. `ssh.connect.begin`, `shell.opened` (with the originating `webContents.id`) and `ssh.disconnected` are audited. Programmatic execution stays fully gated. |
| Host-key type downgrade on an already-pinned endpoint | Endpoint pins are checked first; if the presented key *type* differs from every pin for that endpoint, a distinct `SSH HOST KEY TYPE CHANGED` dialog is shown (default **Reject**) and a `host_key_type_mismatch` critical security event is recorded. |
| Local pipe hijacking / brute force | Fresh 256-bit HMAC secret per launch in `<userData>/bridge.json` (deleted on quit), challenge-response nonces with `timingSafeEqual`, rate limiting (10 req/s), in-flight cap (4), frame cap (1 MB), and lockout after 5 failures. |

## Interactive Keystrokes vs. Programmatic Execution

Per `NEXUS-BUILD-PLAN.md` §1 row 6:
- **Interactive keystrokes** typed directly by the user inside an xterm.js SSH shell tab are not approval-gated (identical to standard SSH clients).
- **Programmatic execution** — both the GUI "Run Command" drawer and every MCP `nexus_run_command` call — passes unconditionally through `ExecutionService` and `CommandAuthorizer`.

### Consequence: a compromised renderer has an unapproved remote shell (accepted risk)

`terminal:input` is deliberately **not** authorization-gated, so the renderer can type into any connected session. Together with `sessions:connect` and `terminal:open` (also ungated by design, because establishing a connection is not command execution), this means:

> **A compromised renderer can connect to any stored server, open a PTY, and run arbitrary commands with that server's stored credentials without any approval dialog.**

This is an accepted design decision, not an oversight:

- The build plan explicitly excludes user keystrokes from approval (row 6); gating individual keystrokes would make an interactive terminal unusable.
- Approvals exist to gate *machine-initiated* execution, where a confused-deputy risk exists. A human typing in a PTY is the authority; the renderer is merely the keyboard.
- The security boundary for this path is therefore **renderer integrity**: `contextIsolation`, `sandbox: true`, `nodeIntegration: false`, strict CSP with no remote origins, no `nodeIntegration`, and exact-origin + exact-`webContents.id` IPC checks. Any renderer RCE or XSS is equivalent to shell access on every stored server.

Auditability: `ssh.connect.begin`, `ssh.disconnected` and `shell.opened` (which records the originating `webContents.id`) are written to the hash-chained audit log, so this path is attributable after the fact. If a future requirement is "renderer compromise must not yield a shell", the only effective control is a native per-session "Open interactive shell" confirmation in the main process — it cannot be enforced in the renderer, and does not exist today.

## Known Limitations

- **Same-user OS threat:** Any process running as the same Windows user can read `%APPDATA%\NEXUS\bridge.json` or access DPAPI/Credential Manager entries belonging to that user.
- **Audit hash-chain tail truncation:** The local SHA-256 chain detects modifications and mid-chain deletions, but cannot detect truncation of the newest tail entries without an external anchor.
- **Renderer compromise equals shell access:** See "Consequence" above. The renderer holds no approvals and no credentials, but it can still drive an interactive PTY on any connected session. This is accepted by design and is the reason renderer isolation is treated as a primary control.
- **Command classification is defense-in-depth:** Shell parsing is conservative and fail-closed, but the primary security boundary is explicit human approval in the native OS dialog.
- **Unsigned Windows binary:** `signAndEditExecutable` is `false` until a code-signing certificate is configured.

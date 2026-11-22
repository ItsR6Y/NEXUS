# NEXUS Terminal — MCP Integration

## Bridge Architecture

NEXUS runs a local authenticated bridge inside Electron main and ships a separate thin stdio MCP server (`out/mcp/nexus-mcp.mjs`, bundled with `esbuild` with zero `electron`, `ssh2`, `node:sqlite`, or `@napi-rs/keyring` imports):

1. When MCP is enabled in **Claude / MCP**, Electron main opens a per-launch local pipe (`\\.\pipe\nexus-bridge-<hash>-<rand>` on Windows; Unix socket with `0o600` on POSIX) and writes `<userData>/bridge.json` containing `{ version, pipeName, secret, pid }`.
2. When NEXUS exits or MCP is disabled, the pipe closes and `bridge.json` is deleted.
3. On connection, main sends a 256-bit server nonce; the MCP client responds with a 256-bit client nonce and `HMAC-SHA256(secret, serverNonce + clientNonce)`.
4. If NEXUS is not running or MCP is off, every tool returns `isError: true` with `app_not_running`. The MCP server never launches NEXUS.
5. All MCP diagnostics write to `stderr` only (`stdout` is strictly the MCP stdio JSON-RPC transport).

## Local Transport Permissions (DACL Posture)

- **Windows:** the bridge is a per-launch named pipe (`\\.\pipe\nexus-bridge-<hash>-<rand>`). NEXUS does not shell out to `icacls`; the pipe and `bridge.json` rely on the per-user `%APPDATA%\NEXUS` directory being user-private by default, plus the mandatory 256-bit HMAC challenge-response on every connection. Any local process running as the same Windows user is therefore inside the trust boundary — the HMAC secret in `bridge.json` is the control, not the pipe ACL.
- **POSIX:** the Unix socket and `bridge.json` are created with `0o600`; startup fails if the endpoint file permissions cannot be restricted to the current user.

## The Exact Five MCP Tools

| Tool | Parameters | Behavior & Restrictions |
|---|---|---|
| `nexus_list_servers` | `{}` | Lists servers with `mcpAccessEnabled: true` as `ServerPublicInfo` only (no `keyPath`, no credentials). |
| `nexus_list_sessions` | `{}` | Lists currently connected SSH sessions on MCP-enabled servers. |
| `nexus_run_command` | `{ serverId, sessionId, command, timeoutMs?, maxOutputBytes? }` | Hard-codes `source: 'claude'`. Routes through `ExecutionService` -> `CommandAuthorizer` -> native OS approval dialog. Blocks until user decides or timeout. Denials/timeouts return `isError: true`. Output is ANSI-stripped and redacted. |
| `nexus_get_history` | `{ serverId?, limit? (<= 100) }` | Returns sanitized, redacted command history for MCP-enabled servers. |
| `nexus_read_terminal_tail` | `{ sessionId, lines? (<= 200) }` | Reads bounded, ANSI-stripped, secret-redacted lines from the session's main-process ring buffer. |

**Explicitly prohibited for MCP:** creating/updating/deleting servers, opening/closing/reconnecting sessions, reading credentials or key paths, and approving commands.

## Manual Registration with Claude Code

NEXUS never edits your global Claude Code configuration automatically. After running `npm run build`, register the MCP server manually in your own terminal:

```powershell
claude mcp add nexus --scope project -- node "C:\path\to\NEXUS-FINAL\out\mcp\nexus-mcp.mjs"
```

Verify the 5-tool handshake with Claude Code once NEXUS Terminal is open and MCP is toggled **Enable MCP**.

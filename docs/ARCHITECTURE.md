# NEXUS Terminal — Architecture

## High-Level Topology

```text
+----------------------- Electron Main Process (Sole Trusted Authority) -----------------------+
| index.ts  --> protocol.ts (nexus-app://) | window.ts (sandboxed) | csp.ts | logger.ts        |
| ipc/      --> registry.ts (sender.id + exact origin + strict Zod + sanitized errors)         |
| services/ --> ServerService | SessionManager | ExecutionService | McpService                 |
| ssh/      --> host-keys.ts | hostkey-prompt.ts (native dialog) | terminal-tail.ts            |
| security/ --> policy-engine.ts | tokenizer.ts | command-rules.ts | authorization.ts |        |
|               approvals-ui.ts (native dialog) | redaction.ts                                 |
| storage/  --> db/database.ts (node:sqlite) | migrations/ | repositories/ | credential-store  |
| audit/    --> audit-logger.ts (SHA-256 hash-chained append-only audit_log + security_events) |
| bridge/   --> bridge-server.ts (HMAC framed pipe) | pipe.ts (no icacls) | tool-router.ts     |
+------------------^---------------------------------------------------^-----------------------+
                   | contextBridge (frozen allowlist, zero decisions)  | \\.\pipe\nexus-bridge-*
         +---------+-----------+                             +---------+-----------+
         | Preload + React UI  |                             | MCP Stdio Process   |
         | (Untrusted Sandbox) |                             | (Zero SSH/DB/Creds) |
         +---------------------+                             +---------------------+
```

## Component Responsibilities

- **`src/main/protocol.ts` & `src/main/window.ts`:** Serves production renderer assets exclusively from `nexus-app://app/` with decode/traversal/backslash/symlink protection, exact CSP headers, navigation/redirect/popup/webview/permission/certificate-error lockdown, and strict `BrowserWindow` `webPreferences`.
- **`src/preload/index.ts` & `src/main/ipc/registry.ts`:** Exposes a deeply frozen `window.nexus` API with explicit named methods only. Every IPC call verifies `event.sender.id`, exact `senderFrame.url` origin, and strict Zod schemas from `src/shared/ipc.ts`.
- **`src/main/core/db/`:** Built-in `node:sqlite` (`DatabaseSync`) wrapped behind a minimal `Db` interface (`WAL`, `foreign_keys = ON`, `busy_timeout = 5000`, transactional sequential migrations).
- **`src/main/core/credentials/credential-store.ts`:** `CredentialStore` abstraction preferring `@napi-rs/keyring` (OS keyring / Windows Credential Manager) with graceful fallback to Electron `safeStorage` (DPAPI ciphertext in SQLite `credential_refs`). Private keys remain on disk at `servers.key_path`.
- **`src/main/core/ssh/`:** `ssh2` session lifecycle (`SessionManager`), strict `HostKeyService` + native `HostKeyPresenter`, PTY shell with 16ms/64KB output batching + high-watermark pause/resume + bounded ANSI-stripped/redacted `TerminalTailBuffer`, and a separate `exec` channel for programmatic commands.
- **`src/main/core/security/`:** `policy-engine.ts` + `tokenizer.ts` + `command-rules.ts` + `paths.ts` (conservative 9-command LOW allowlist; composed commands always require approval), `CommandAuthorizer` (WeakSet-branded `AuthorizedExecution`, cryptographic `bindingHash`, atomic single-use consumption, redacted DB storage), `NativeApprovalPresenter`, and `redaction.ts` (`redactText`, `redactValue`, `StreamRedactor`).
- **`src/main/core/execution/execution-service.ts`:** The single execution pipeline shared by GUI programmatic commands (`source: 'user'`) and MCP (`source: 'claude'`).
- **`src/main/core/mcp-bridge/` & `src/mcp/`:** HMAC-SHA256 authenticated local named-pipe bridge and standalone stdio MCP server exposing exactly 5 tools.

## Programmatic Command Data Flow

```text
GUI Run Command (IPC -> source: 'user')  ----+
                                              +--> ExecutionService.execute(input, source)
MCP nexus_run_command (Bridge -> 'claude') --+       1. CommandAuthorizer.authorize()
                                                        - verify session ownership & epoch
                                                        - classifyCommand()
                                                        - evaluate server policy (sensitive|ask|always)
                                                        - persist REDACTED approval + invoke native OS dialog
                                                        - atomically consume single-use approval
                                                        - mint WeakSet-branded AuthorizedExecution
                                                     2. Denied? -> record 'denied' history, ZERO SSH calls
                                                     3. SessionManager.runExec() on dedicated exec channel
                                                     4. Enforce timeoutMs, maxOutputBytes, AbortSignal
                                                     5. Strip ANSI + StreamRedactor (patterns + exact secrets)
                                                     6. Persist redacted result -> return ExecutionResult
```

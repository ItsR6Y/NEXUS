# NEXUS Terminal — Security Source Review

**Review date:** 2026-11-21
**Scope:** product source under `src/` (main, preload, renderer, shared, mcp). Tests, scripts and fixtures are out of scope except where noted.
**Method:** a grep review of the dangerous-API set, followed by manual reading of every hit. This document records what the code does today and what remains unverified — it is not a certification.

Re-run the review with:

```bash
cd NEXUS-FINAL
grep -rn "ipcRenderer" src/
grep -rn "contextBridge" src/
grep -rn "shell.openExternal" src/
grep -rn "eval(" src/
grep -rn "new Function" src/
grep -rn "child_process" src/
grep -rn "dangerouslySetInnerHTML" src/
grep -rn "rejectUnauthorized" src/
```

## 1. Results

| Pattern | Hits in `src/` | Verdict |
|---|---|---|
| `ipcRenderer` | 3, all in `src/preload/index.ts` | Expected and confined |
| `contextBridge` | 3 (2 in `src/preload/index.ts`, 1 in a doc comment in `src/shared/api.ts`) | Expected and confined |
| `shell.openExternal` | **0** | Not used anywhere |
| `eval(` | **0** | Not used anywhere |
| `new Function` | **0** | Not used anywhere |
| `child_process` | **0** | Not used in product code |
| `dangerouslySetInnerHTML` | **0** | Not used anywhere |
| `rejectUnauthorized` | **0** | Not used anywhere (see §2.8) |

The last audit of this tree reported the same negative results; this re-run confirms none of these APIs has been introduced since.

## 2. Justification per hit

### 2.1 `src/preload/index.ts:1` — `import { contextBridge, ipcRenderer } from 'electron'`

The preload script is the only place in the product allowed to touch Electron IPC primitives, and it is the intended bridge. It runs in an isolated, sandboxed preload context (`contextIsolation: true`, `sandbox: true`, `nodeIntegration: false` — asserted by `tests/unit/security-hardening.test.ts` case 1), not in the renderer's own JavaScript world.

### 2.2 `src/preload/index.ts:98` — `if (typeof contextBridge !== 'undefined' && typeof ipcRenderer !== 'undefined')`

A guard so the module can be imported by unit tests (which pass a fake `ipc` object to `buildPreloadApi()`) without crashing outside Electron. It exposes nothing by itself.

### 2.3 `src/preload/index.ts:99` — `contextBridge.exposeInMainWorld('nexus', buildPreloadApi(ipcRenderer))`

This is the entire renderer-facing attack surface, and it is an allowlist:

- `buildPreloadApi()` builds one arrow function per named channel by calling `ipc.invoke(channel, payload)` with a hard-coded channel string. There is no generic `invoke`, `send`, or `on` on the exposed object; the renderer cannot name a channel.
- The returned object is passed through `deepFreeze()`, so a renderer cannot monkey-patch the bridge for later use by injected code.
- The object has no approval, host-key-trust, or terminal-guard methods. `tests/unit/security-hardening.test.ts` case 4 asserts `invoke`/`send`/`hostKeys` are absent and that `approvals` exposes only `list`.
- Event subscriptions (`nexus.on.*`) are a fixed list of seven read-only event names from `src/shared/events.ts`, each returning an unsubscribe function.

`contextBridge.exposeInMainWorld` itself is a privilege boundary, not an escape: only the frozen, enumerated API crosses it.

### 2.4 `src/shared/api.ts:22` — the word `contextBridge` in a comment

Documentation of the above. No code.

### 2.5–2.9 Absent patterns

| Pattern | Why the absence matters | What would need review if it appears |
|---|---|---|
| `shell.openExternal` | The app never asks the OS to open an arbitrary URL, so a renderer cannot use the bridge to launch a handler/protocol. | Any link-opening feature; must be scheme-allowlisted in main. |
| `eval(` / `new Function` | No dynamic code evaluation, and production CSP (`src/main/csp.ts`) forbids `unsafe-eval` anyway. | Anything that parses user-authored expressions. |
| `child_process` | No subprocess execution from the app: host-key prompting uses Electron dialogs, the MCP bridge uses `net` named pipes, and the earlier `icacls` shell-out was removed. | Any new shell-out; must never interpolate untrusted strings. |
| `dangerouslySetInnerHTML` | All command output, audit data and log lines reach React as text nodes, so ANSI output and crafted commands cannot inject markup or script. | Rendering HTML from a remote host. |
| `rejectUnauthorized` | There is no TLS/socket option that can disable certificate checks, and there is no setting that disables SSH host-key verification. | Any new `tls.connect`/`https` client. |

### 2.10 Host-key verification (why no `rejectUnauthorized` is needed)

SSH host keys are not verified by a boolean Node TLS option. `SessionManager` installs an ssh2 `hostVerifier` (`src/main/core/ssh/session-manager.ts:295`) that calls `HostKeyService.verify()` and answers the handshake with its verdict; a rejection aborts the connection inside ssh2 before authentication. `HostKeyService` then applies the policy: pinned-and-matching → accept, pinned-and-different-fingerprint → hard block with no bypass, pinned-but-different-key-type → distinct warning, unknown → native prompt that defaults to Reject with a 60 s timeout. Covered by `tests/integration/ssh-hostkeys-exec.test.ts` and `tests/integration/ssh-lifecycle.test.ts`.

## 3. Residual risks recorded elsewhere

These are known and documented, not review failures:

1. **Ungated interactive keystrokes.** A renderer compromise can open a PTY on a connected session and type without an approval dialog. Renderer isolation is therefore a primary control; see the "Consequence" section of `docs/SECURITY.md` and the matching README bullet.
2. **Dev-only CSP in the HTML meta tag (D9).** `src/renderer/index.html` carries `script-src 'self'`; the relaxed development CSP is applied by `installSessionSecurity()`. Production is unaffected.
3. **Audit-chain caching.** `dashboard:get` uses `AuditLogger.lastVerify()`, which verifies only rows appended since the last check. In-place tampering of an already-verified row is detected solely by the explicit "Verify now" action. The append-only triggers (`audit_log_no_update`, `audit_log_no_delete`) block that tampering path in the first place.
4. **Renderer test coverage** now exists for the five named components, but there is still no automated test of the native approval dialog itself (`NativeApprovalPresenter`); its logic is exercised through `StubApprovalPresenter`.

## 4. What this review does not establish

- It does not prove the absence of vulnerabilities; it shows that the eight named risky primitives are used only where expected and are absent elsewhere.
- It does not cover dependency supply-chain risk (`node_modules` is not reviewed here).
- It does not cover the Windows DACL of the MCP named pipe; `docs/MCP.md` documents the intended posture, and the audit records it as unasserted.
- The renderer is still an executable attack surface by design; see §3.1.

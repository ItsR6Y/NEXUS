# NEXUS Terminal — Testing & Verification Status

**Last updated:** 2026-11-21
**Host used for the results below:** Windows 11 x64 (desktop session), Node 26.13.0, npm 11.20.0
**Maturity label supported by the evidence:** core functionality and security workflows verified in unit/integration/renderer tests, plus the real native Windows dialog paths, the real Windows Credential Manager and both desktop Playwright suites. **Native Windows packaging, a live Claude Code session and a packaged-app smoke launch remain unverified** — packaging was out of scope for this pass, and the live client is blocked by provider region restrictions (see §4). This project is not claimed to be production-ready.

Every number in this document comes from a command run in this repository. If you change the code, re-run `npm run verify` and update the numbers rather than trusting this file.

## 1. Commands

```bash
npm run typecheck         # tsc -p tsconfig.node.json + tsc -p tsconfig.web.json
npm run lint              # ESLint (no-console in main/mcp, renderer import boundary, hooks rules)
npm test                  # Vitest: unit + integration + renderer component suites
npm run test:unit         # tests/unit only
npm run test:integration  # tests/integration only (real ssh2 server, node:sqlite, IPC, MCP pipe)
npm run scan-secrets      # static scan for secrets and forbidden files
npm run build             # electron-vite build + standalone MCP bundle + import check
npm run test:e2e          # build, then Playwright Electron e2e (needs a desktop session)
npm run verify            # typecheck → lint → test → build → scan-secrets
```

## 2. Current results

`npm run verify` — **exit 0**.

| Stage | Observed result |
|---|---|
| `npm run typecheck` | PASS — both TS projects clean |
| `npm run lint` | PASS — 0 errors, 0 warnings |
| `npm test` | PASS — `Test Files 28 passed | 2 skipped (30)`, `Tests 288 passed | 2 skipped (290)` |
| `npm run build` | PASS — `out/main/index.js` 211.07 kB, `out/preload/index.js` 4.11 kB, `out/renderer/assets/index-DIZZpVxb.js` 1,095.08 kB + 9 lazy page chunks (3–17 kB each) + `index-BPgk9bzr.css` 39.04 kB, MCP bundle `out/mcp/nexus-mcp.mjs` ≈1.3 MB with `build-mcp: verified clean bundle` |
| `npm run scan-secrets` | PASS — `scan-secrets: clean` |

- `npm run test:e2e` — **PASS** — `2 passed (47.2s)`: `app.e2e.ts` (launch over `nexus-app://`, zero Node globals in the renderer, read-only approval UI) and `stage3-native-dialogs.e2e.ts` (real Windows message boxes driven through UI Automation).
- Opt-in suites on this Windows host: `stage3-credential-real.test.ts` **PASS** (real Credential Manager round-trip); `stage3-claude-live.test.ts` **BLOCKED** by the model provider (see §4).

The 2 skipped files in the default run are the opt-in suites, which require an explicit opt-in even on Windows (see §4).

## 3. What the suite covers

30 test files: 9 unit, 14 integration, 7 renderer.

### Unit (`tests/unit`, 9 files)

| File | What it verifies |
|---|---|
| `policy-corpus.test.ts` | 190+ adversarial and parse-hygiene cases: conservative LOW allowlist, composed commands, obfuscation, wrappers, pipe-to-shell, credential theft, destructive and system-changing commands |
| `policy-engine.test.ts` | LOW/MEDIUM/HIGH/CRITICAL/DESTRUCTIVE classification, composed-command gating, NUL/bidi/unicode tricks |
| `redaction.test.ts` | Pattern redaction (JWT, AWS, GitHub, Slack, Stripe, bearer, `password=`, `mysql -pSECRET`, `curl -u user:SECRET`), exact short secrets, PEM blocks (including newline-free chunked bodies), streaming chunk boundaries, one secret-list expansion per `push()` |
| `security-hardening.test.ts` | `buildWebPreferences()` flags, production CSP, `nexus-app://` traversal/encoded/backslash/symlink blocking, frozen preload surface with no decision methods |
| `logger.test.ts` | Redacted JSON-lines output and size-based rotation |
| `scan-secrets.test.ts` | The secret scanner actually catches `.env` files and leaked key patterns |
| `e2e-mode.test.ts` | Plaintext-credential E2E gate requires unpackaged **and** `--e2e` **and** `NEXUS_E2E=1` **and** a non-blank `NEXUS_E2E_USERDATA` |
| `protocol-cache.test.ts` | `Cache-Control` policy for `nexus-app://` (HTML revalidates, hashed assets immutable) |
| `terminal-tail.test.ts` | Chunked tail ring: cap enforcement, no U+FFFD across chunk boundaries, byte-equality with the single-trim reference, redaction, lowered cap |

### Integration (`tests/integration`, 12 running + 2 opt-in)

| File | What it verifies |
|---|---|
| `authorization.test.ts` | MCP approval default, per-server `sensitive|ask|always`, denied command ⇒ **zero** SSH calls, replay/expiry/binding-mismatch rejection, forged `AuthorizedExecution` rejection, no raw secrets in `approvals` |
| `execution-service.test.ts` | Single pipeline: sanitized command persistence, output caps, timeout, cancellation, history/output paging |
| `execution-authorization.test.ts` | Policy truth table, pre-aborted signal, policy semantics |
| `ssh-hostkeys-exec.test.ts` | First-use prompt accept/reject/timeout, matching pin, hard-blocked fingerprint mismatch, `key_path` auth with `ServerPublicInfo` hygiene, session ownership mismatch, truncation, cancellation, redacted tail |
| `ssh-lifecycle.test.ts` | Disconnect during handshake, differing key type, tail UTF-8 boundary |
| `dashboard-audit-cache.test.ts` | `dashboard:get` issues no full `audit_log` scan; cached verify extends over appended rows; in-place tampering only surfaces via explicit verify |
| `database-credentials.test.ts` | Idempotent migrations (v1→v2), audit-chain integrity, raw-DB canary absence, fail-closed encryption, retention pruning |
| `ipc-security.test.ts` | Untrusted origin, wrong `sender.id`, strict extra-field rejection, absence of approval/host-key channels |
| `mcp-bridge.test.ts` | Exact 5-tool surface, HMAC rejection, `source`/`approved` spoof rejection, deny ⇒ zero SSH, redaction across history/tail/MCP |
| `security-regression.test.ts` | Hostile shell syntax fails closed; canaries absent from audit, approvals, history, MCP responses and raw DB bytes |
| `hardening-wave4.test.ts` | Short-secret/`-p` redaction canaries, chunked PEM, keyring availability probe, execution-store eviction, index usage |
| `stream-stress.test.ts` | 8 MB flood, backpressure pause/resume, five concurrent sessions, shutdown during flood |

### Renderer (`tests/renderer`, 7 files, jsdom + `@testing-library/react`)

| File | What it verifies |
|---|---|
| `server-form.test.tsx` | Save gating, exact `servers:create` payload, password↔key field swap |
| `run-command-drawer.test.tsx` | Cancel control appears while a command is in flight and cancels by `clientCommandId` |
| `history-filters.test.tsx` | Server/source/level/status filters are turned into the right `executions:list` payloads |
| `modal.test.tsx` | Focus moves into the dialog, Tab/Shift+Tab stay inside it, Escape closes, focus is restored |
| `terminal-shortcuts.test.tsx` | `Ctrl+W` closes the selected tab; the window keydown listener is not re-registered on unrelated renders |
| `app-status.test.tsx` | Status bar reports authenticated MCP clients, not merely a listening bridge |
| `developer-mark.test.tsx` | The sidebar developer credit renders and the status bar still mounts |

## 4. Opt-in and unrun suites

| Suite | Trigger | Status here |
|---|---|---|
| `stage3-credential-real.test.ts` | `NEXUS_REAL_KEYRING=1` | **PASS** — 1 test, real Windows Credential Manager round-trip (store/read/delete) |
| `stage3-claude-live.test.ts` | `NEXUS_LIVE_CLAUDE=1` | **BLOCKED** — Claude Code 2.1.318 exits 1 before any MCP handshake: the configured endpoint answers `403 The Coarena Model API is not available in your country or region (SY)`. Not a NEXUS failure; no mock was substituted. |
| `tests/e2e/app.e2e.ts` | `npm run test:e2e` | **PASS** — 2.4 s on the Windows desktop |
| `tests/e2e/stage3-native-dialogs.e2e.ts` | `npm run test:e2e` | **PASS** — 43.9 s; see §6 for what it asserts and what stays manual |

`npx playwright test --list` collects exactly those two files (`Total: 2 tests in 2 files`); the abandoned `tmp-*` probes are gone.

The dialog suite depends on `scripts/stage3-uia-dialog.ps1`. Its here-string terminator was indented (`  '@`), which PowerShell rejects outright, so the helper failed to parse and the suite could never drive a dialog. The terminator is now at column 0; a parse check exits `2` (`dialog-not-found`) in under a second.

## 5. Packaging verification (Windows target, cross-built on Linux)

Commands and observations from the packaging pass:

- `npx electron-builder --dir --win --publish never` → exit 0, produced `release/win-unpacked` (Electron 45.3.4 win32-x64). `npm run package:dir` alone targets the host platform, so it produces a *Linux* dir on Linux; the explicit `--win` is required for a Windows tree.
- Fuses read back with `npx @electron/fuses read --app "release/win-unpacked/NEXUS Terminal.exe"`: `RunAsNode` Disabled, `EnableCookieEncryption` Enabled, `EnableNodeOptionsEnvironmentVariable` Disabled, `EnableNodeCliInspectArguments` Disabled, `EnableEmbeddedAsarIntegrityValidation` Disabled, `OnlyLoadAppFromAsar` Enabled, `GrantFileProtocolExtraPrivileges` Disabled.
- `resources/mcp/nexus-mcp.mjs` present (1,379,126 bytes).
- `resources/app.asar`: top level exactly `node_modules, out, package.json`; no project `tests/`, `docs/`, `artifacts/` or `scripts/` entries; no `.db`, `.log`, `.env`, `.pem`, `.key` files; no `/out/**` sourcemaps.
- Zip packaging (`scripts/package-zip.mjs`) excludes `artifacts/` and `*.db`/`*.db-wal`/`*.db-shm`/`*.log`/`.env*`/key files — verified on a real archive (`ZIP_FORBIDDEN_COUNT=0`).

**One caveat that makes this artifact non-shippable:**

1. **Wrong keyring binary.** A Linux cross-build installs only `@napi-rs/keyring-linux-x64-gnu`. The Windows package must be built on Windows so that `@napi-rs/keyring-win32-x64-msvc` is installed; otherwise the app falls back to `safeStorage` (or reports credentials unavailable) on Windows.
`build/icon.ico` is present in the tree, so the previously recorded *missing icon* caveat no longer applies: `win.icon` and `directories.buildResources: "build"` both resolve, and `scripts/verify-zip.mjs` finds its required icon file.

A packaged-app smoke launch was **not** performed: the Windows binary cannot run on this Linux host (no Wine) and there is no X server for a Linux build.

## 6. Windows-host checks and their status

Executed 2026-11-21 on Windows 11 x64 with a desktop session.

| # | Check | Status |
|---|---|---|
| 1 | `npm install`, then confirm `node_modules/@napi-rs/keyring-win32-x64-msvc` | **PASS** — present, and it is the only keyring binary installed |
| 2 | `npm run verify` | **PASS** — exit 0, 30 files / 290 tests as in §2 |
| 3 | `npm run test:e2e` → `app.e2e.ts` | **PASS** — `nexus-app://` launch, zero Node globals, navigation |
| 4 | `npm run test:e2e` → `stage3-native-dialogs.e2e.ts` (automated paths) | **PASS** — approval dialog shows server/source/command/session/risk; closing it denies and the SSH server records no command; an unapproved request expires and still cannot execute late; an unknown host key prompts and rejecting stores no pin; a changed host key is hard-blocked with the original pin preserved |
| 5 | **Manually click** “Trust & Save Host Key” and “Approve once” | **MANUAL** — the custom Chromium task-dialog buttons expose no invokable UI Automation pattern; the automated suite only exercises the dismiss/deny path |
| 6 | `NEXUS_REAL_KEYRING=1 npx vitest run tests/integration/stage3-credential-real.test.ts` | **PASS** — real Credential Manager round-trip |
| 7 | `NEXUS_LIVE_CLAUDE=1` with a registered Claude Code client | **BLOCKED** — provider `403 … not available in your country or region (SY)`; see §4 |
| 8 | `npm run package`, then smoke-launch `release/win-unpacked/NEXUS Terminal.exe` | **NOT RUN** — packaging was excluded from this validation pass |

The exact commands for 5–7:

```powershell
# 6. real keyring
$env:NEXUS_REAL_KEYRING="1"; npx vitest run tests/integration/stage3-credential-real.test.ts

# 7. live Claude Code client (needs a model your endpoint serves)
$env:NEXUS_LIVE_CLAUDE="1"; $env:NEXUS_LIVE_CLAUDE_MODEL="<model-id>"; npx vitest run tests/integration/stage3-claude-live.test.ts

# 8. packaging (not part of the validation pass)
npm run package
```

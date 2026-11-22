# GitHub Repository Readiness — `nexus-terminal`

Phase 3 deliverable: what is in the repository, what is deliberately excluded, how secrets were
checked, and what the two workflows do. Everything below was checked against the working tree on
2026-11-21, before the initial commit.

## Repository structure

Present at the root after this phase:

| Required | Status | Notes |
| --- | --- | --- |
| `src/` | present | 63 source files (main, preload, renderer, shared, MCP) |
| `build/` | present | `icon.ico` (multi-size ICO) and `icon.svg` |
| `scripts/` | present | build/package/verify/scan scripts, `after-pack.cjs`, `lib/` |
| `tests/` | present | unit, integration, renderer, e2e, fixtures |
| `docs/` | present | architecture, security, security review, MCP, testing, distribution |
| `README.md` | present | rewritten for end users in this phase |
| `LICENSE` | present | MIT, © 2026 Ray |
| `CONTRIBUTING.md` | **new** | development workflow and review rules |
| `SECURITY.md` | **new** | root vulnerability-reporting policy (private channel, scope, disclosure) |
| `package.json` / `package-lock.json` | present | lockfile committed; `private: true` so it can never be accidentally published to npm |
| `electron.vite.config.ts` | present | |
| `tsconfig.json`, `tsconfig.node.json`, `tsconfig.web.json` | present | |
| `eslint.config.mjs` | present | |
| `vitest.config.ts`, `playwright.config.ts` | present | |
| `.gitignore` | present | extended in this phase |
| `.gitattributes` | **new** | LF normalization, binary markers, CRLF for `.ps1`/`.cmd`/`.bat` |
| `.npmrc` | present | `audit=false`, `fund=false` (no registry credentials, no install-time scripts added) |
| `.github/workflows/` | **new** | `windows-build.yml`, `release.yml` |

`docs/SECURITY.md` (architecture and threat model) is kept intact; the new root `SECURITY.md` is
only the reporting policy, and links to it.

## `.gitignore` coverage

| Pattern required | Present |
| --- | --- |
| `node_modules/` | yes |
| `out/` | yes |
| `dist/` | yes |
| `release/` | yes |
| `coverage/` | yes |
| `test-results/` | yes |
| `playwright-report/` | yes |
| `artifacts/` | yes |
| `*.db`, `*.db-wal`, `*.db-shm` | yes (plus `*.sqlite`) |
| `*.log` | yes |
| `.env*` | yes |
| `*.pem`, `*.key`, `*.p12`, `*.pfx` | yes |
| `.mcp.json` | yes |
| Temp/IDE (`*.tsbuildinfo`, `*.bak`, `*.swp`, `.idea/`, `*~`, `Thumbs.db`, `desktop.ini`, `.DS_Store`) | yes |
| `package-lock.json` **preserved** | yes — not ignored, and staged |

Intentional additions this phase keep internal working notes out of the public repository while
leaving them on disk: `FIRST-RUN-REPORT.md`, `SESSION-HANDOFF.md`,
`docs/COMPLETE-PROJECT-AUDIT.md`, `docs/DEEPSEEK-HANDOFF.md`,
`docs/STAGE-2-FUNCTIONAL-VALIDATION.md`, `docs/EXECUTION-READINESS.md`. These are development
history, not product documentation.

## Secret and privacy audit

- `npm run scan-secrets` → `scan-secrets: clean` (exit 0). The scanner walks the tree and fails on
  key/token/password shapes; its allow-list covers only `tests/`, `docs/` and the scanner's own
  fixtures, which are fake by construction.
- `git grep --cached` across all staged files for `ramia`, `C:\Users`, `/Users/` and similar
  absolute paths: **one hit was found and removed** (a host path in
  `docs/DISTRIBUTION-ASSESSMENT.md`, now written as "the repository root"). The only remaining
  `C:/Users` string is a URL-path fixture inside `tests/unit/security-hardening.test.ts`
  (`file:///C:/Users/index.html`), which tests protocol path validation and contains no personal
  data.
- No certificates, signing passwords, API keys, database files, logs, `userData` copies or
  `artifacts/` are staged. `git diff --cached --name-only | grep` for `node_modules`, `release/`,
  `out/`, `artifacts/`, `*.log`, `*.db`, `.env`, `*.pem`, `*.key` returns nothing.
- Verified against the **staged index**, not just the working tree, so nothing is smuggled in by
  an ignore rule.

Staged content: 137 files — 63 `src/`, 37 `tests/`, 8 `scripts/`, 10 `docs/`, 2 `build/`, plus root
config and metadata. Nothing was auto-deleted; anything questionable was excluded from the index
only.

## Workflows

### `.github/workflows/windows-build.yml`

- Triggers: `push` to `main`, `pull_request`, `workflow_dispatch`.
- `permissions: contents: read` at workflow level; no repository secrets are referenced at all, so
  a pull request from a fork cannot read them.
- `concurrency` group cancels superseded runs on the same ref.
- Runs on `windows-latest` (Windows Server 2022 x64) with Node.js `22` LTS and `npm ci` +
  `actions/setup-node` npm caching keyed on `package-lock.json`.
- Ordered steps: `npm ci` → `typecheck` → `lint` → `npm test` (unit + renderer) →
  `test:integration` → `scan-secrets` → `build` → `package` → `node scripts/verify-package.mjs`
  → `@electron/fuses read` on the packaged executable → checksum generation → upload of the
  installer, archive and `SHA256SUMS.txt` as a build artifact.
- `CSC_IDENTITY_AUTO_DISCOVERY: 'false'` keeps the runner from looking for a certificate; the
  build is intentionally unsigned.

### `.github/workflows/release.yml`

- Triggers **only** on tags matching `v[0-9]+.[0-9]+.[0-9]+`. A push to `main` can never publish.
- Validates that the tag equals `v` + `package.json` `version`, and fails otherwise.
- `permissions: contents: read` at workflow level, raised to `contents: write` **only** for the
  release job.
- Runs the same build and verification sequence, then:
  - optional Authenticode signing (see below),
  - recomputes `SHA256SUMS.txt` after signing,
  - generates `RELEASE_NOTES.md` with a download table, checksum list, install notes and the
    unsigned-build/SmartScreen disclosure,
  - `gh release create <tag> --notes-file ...` with the installer, the archive and the checksums.
- Signing is opt-in via secrets and stays dormant otherwise:

  | Name | Kind | Purpose |
  | --- | --- | --- |
  | `WINDOWS_CERTIFICATE_BASE64` | secret | base64 `.pfx` |
  | `WINDOWS_CERTIFICATE_PASSWORD` | secret | `.pfx` password |
  | `WINDOWS_TIMESTAMP_URL` | variable (optional) | RFC 3161 timestamp server |

  Adding the first two turns the step on; no code change is needed. Certificates are never
  committed, and no certificate exists in this repository.

### Action pinning

The workflows use first-party `actions/checkout`, `actions/setup-node` and
`actions/upload-artifact` at reviewed major tags (`@v4`), which GitHub maintains as immutable
release lines, plus the runner-provided `gh` CLI. No third-party actions are used, so there is no
unaudited publisher in the supply chain. If you prefer SHAs, replace the three `uses:` lines with
the commit SHA of the same release; nothing else needs to change.

## Branch, tag and push policy

- Local branch: `main`. Single initial commit prepared.
- No remote is configured, nothing is pushed, no tag exists, no release is published.
- Recommended first release: tag `v1.0.0` on the initial commit once the repository is public.

## Remaining actions (require your authorization)

1. Create the GitHub repository `nexus-terminal` and add it as `origin`.
2. Push `main`.
3. Tag `v1.0.0` and push the tag — that is what triggers `release.yml`.
4. Optionally add the signing secrets first, so the very first release is signed.

# Contributing to NEXUS Terminal

Thanks for taking a look. This project is a security tool, so contributions are reviewed with
that in mind: a feature that makes the product nicer but widens the trust boundary will not be
merged.

## Before you start

- Read `docs/ARCHITECTURE.md` (data flows and trust boundaries) and `docs/SECURITY.md`
  (threat model and accepted limitations).
- Search existing issues before opening a new one.
- For anything larger than a bug fix, open an issue first so the design can be discussed.

## Ground rules

1. **The main process owns privilege.** SSH, credentials, the database, the audit log and every
   authorization decision stay in Electron main. The renderer gets a frozen, origin-pinned
   preload surface and nothing else.
2. **Neither the renderer nor MCP may approve anything.** Approvals are native OS dialogs in
   main that default to deny. Do not add IPC that lets the renderer resolve an approval.
3. **No new renderer privileges.** Do not enable `nodeIntegration`, disable `contextIsolation`
   or `sandbox`, load `file://`, or relax the CSP without a written justification in the PR.
4. **Host-key verification is not configurable.** Changes that add an override, a "trust
   anyway" button, or an environment-variable bypass will be rejected.
5. **Never commit secrets or user data.** Fakes belong in `tests/` and `docs/`; the
   `scan-secrets` allow-list covers those two directories only.
6. **No dependency churn.** Do not upgrade unrelated packages in a functional PR, and never
   bypass a security advisory with `--force` or `--ignore-scripts`.

## Development setup

Requirements: Windows 11 x64 (for the packaged path), Node.js >= 22.5.0 (for `node:sqlite`).

```powershell
npm ci
npm run dev
```

`npm run dev` runs `electron-vite dev` with a Vite dev server for the renderer.

## Checks that must pass

Run these before pushing. CI runs the same set on `windows-latest`.

```powershell
npm run typecheck
npm run lint
npm test
npm run test:integration
npm run scan-secrets
npm run build
```

`npm run verify` chains typecheck, lint, the unit suite, build and the secret scan.
`npm run test:e2e` builds and runs the Playwright Electron suite (single worker, needs a
Windows desktop session).

Tests live in `tests/unit` (pure logic and policy), `tests/integration` (database, credentials,
SSH wiring, MCP bridge) and `tests/e2e` (a real Electron process). Keep new tests in the
directory that matches what they exercise, and prefer asserting behaviour over
implementation detail.

## Code style

- TypeScript throughout, `strict` mode; the shared types in `src/shared` are the IPC contract.
- ESLint config: `eslint.config.mjs` (`npm run lint`). No inline disables without a reason.
- Comments explain *why* a security control exists, not what the line does.
- Follow the existing module layout: `src/main/core/<area>` for domain logic,
  `src/main/ipc/registry.ts` for channel registration, `src/renderer/src` for UI.

## Commit and pull request

- Keep commits focused; one logical change per commit.
- Commit messages: a short imperative subject, then a body explaining the motivation.
- In the PR description: what changed, why, which checks you ran, and any security impact.
- By contributing you agree your work is licensed under the project's MIT license.

## Reporting security issues

Do not open a public issue. See `SECURITY.md`.

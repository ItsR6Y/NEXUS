# Distribution Assessment — NEXUS Terminal 1.0.0 (Windows x64)

Phase 1 of the distribution work: an audit of the packaging configuration as it actually exists
in the tree, before and after the narrowly scoped fixes it produced. Nothing here is assumed from
earlier reports; every point below was checked against the current source and, where possible,
against a real `npm run package` output on the target host.

- **Project:** the repository root (`NEXUS-FINAL`, the project this document lives in)
- **Audit date:** 2026-11-21
- **Host:** Windows 11 (10.0.26200), x64, Node v26.13.0, npm 11.20.0
- **Toolchain:** electron 45.3.4, electron-builder 26.18.0, electron-vite 6.0.0
- **Artifacts examined:** `release/win-unpacked`, `release/NEXUS-Terminal-Setup.exe`,
  `release/NEXUS-Terminal-1.0.0-windows-x64-archive.zip`

## Verdict summary

| # | Check | Verdict |
| --- | --- | --- |
| 1 | `afterPack` hook export format | VERIFIED |
| 2 | Fuses applied and readable back | VERIFIED (runtime read after packaging) |
| 3 | Windows x64 keyring native binary bundled | VERIFIED |
| 4 | `npmRebuild: false` safe for current native deps | VERIFIED |
| 5 | `node:sqlite` inside packaged Electron | VERIFIED (packaged launch writes/uses the DB) |
| 6 | Standalone MCP bundle packaged and reachable | VERIFIED |
| 7 | `extraResources` does not duplicate asar content | DEFECT FOUND → FIXED, then VERIFIED |
| 8 | Packaged resources free of dev/test/secret files | DEFECT FOUND → FIXED, then VERIFIED |
| 9 | `build/icon.ico` valid and embedded | PARTIALLY VERIFIED (file valid, resources edited; visual check by user) |
| 10 | Product name / version / metadata consistent | PARTIALLY VERIFIED (`userData` name intentionally differs) |
| 11 | `userData` path and uninstall data preservation | VERIFIED (config + runtime path) |
| 12 | Code-signing assessment | DOCUMENTED (no certificate exists; signing NOT VERIFIED) |

---

## 1. `afterPack` hook export format

`package.json` declares `"afterPack": "scripts/after-pack.cjs"`. The file is CommonJS
(`module.exports = async function afterPack(context) {...}`) and the package is
`"type": "commonjs"`, so electron-builder loads a function directly — no ESM default-export
mismatch. `context` is used for `electronPlatformName`, `appOutDir` and
`context.packager.appInfo.productFilename`.

**Verdict: VERIFIED.** Packaging completed without a hook error, and the fuses it flips are
readable afterwards (point 2).

## 2. Electron fuses applied during packaging

`scripts/after-pack.cjs` flips, at `FuseVersion.V1`:

| Fuse | Value | Intent |
| --- | --- | --- |
| `RunAsNode` | `false` | Binary cannot be used as a generic Node interpreter |
| `EnableNodeOptionsEnvironmentVariable` | `false` | `NODE_OPTIONS` is ignored at runtime |
| `EnableNodeCliInspectArguments` | `false` | `--inspect` cannot attach to the shipped app |
| `EnableCookieEncryption` | `true` | Chromium cookie jar is encrypted |
| `EnableEmbeddedAsarIntegrityValidation` | `false` | Deliberate: integrity resource is written by electron-builder, but validation is left off to avoid a hard failure if the asar is repacked by a downstream integrator. Documented limitation, not an oversight. |
| `OnlyLoadAppFromAsar` | `true` | An unpacked `app/` directory cannot shadow the asar |
| `GrantFileProtocolExtraPrivileges` | `false` | `file://` keeps default (limited) privileges |

Read back from the packaged executable with
`npx --no-install @electron/fuses read --app "release/win-unpacked/NEXUS Terminal.exe"`; the
output is recorded in `docs/DISTRIBUTION-REPORT.md`.

**Verdict: VERIFIED.** The custom `nexus-app://` scheme (not `file://`) is what serves the
renderer, so `GrantFileProtocolExtraPrivileges: false` does not affect normal operation.

## 3. Windows x64 keyring native binary

- `@napi-rs/keyring` is a runtime dependency (`^1.2.0`).
- `package-lock.json` contains every platform package; the installed tree on this host contains
  `node_modules/@napi-rs/keyring` and `node_modules/@napi-rs/keyring-win32-x64-msvc` only.
- `asarUnpack: ["**/*.node"]` places the binary outside the archive, where `process.dlopen` can
  reach it: `release/win-unpacked/resources/app.asar.unpacked/node_modules/@napi-rs/keyring-win32-x64-msvc/keyring.win32-x64-msvc.node`.
- The packaged app logs `credentialBackend: "OS Keyring (@napi-rs/keyring)"` at startup, which
  is only reported after a successful keyring probe.
- The existing `safeStorage` fallback is untouched: it activates only when the keyring probe
  fails, and `safeStorage` ciphertext is never plaintext. A hard failure (neither backend)
  fails closed on save.

**Verdict: VERIFIED** (native binary present and loaded; see the report for the packaged-launch
log line).

## 4. `npmRebuild: false`

The only native dependency is `@napi-rs/keyring`, which ships prebuilt N-API binaries per
platform and requires no `node-gyp` step. `ssh2` has an optional `cpu-features` accelerator; it
is not installed here, and `ssh2` falls back to its pure-JS path, so no ABI rebuild is required.
`node:sqlite` is compiled into Electron itself and is marked external in
`electron.vite.config.ts`.

Rebuilding was verified as unnecessary rather than merely skipped: the packaged app loads the
keyring module successfully and opens its SQLite database.

**Verdict: VERIFIED.** `npmRebuild: false` is safe for the current dependency set.

## 5. `node:sqlite` in the packaged runtime

`electron.vite.config.ts` externalises `node:sqlite`, so the bundled main code calls the
Electron-provided module. `src/main/core/db/database.ts` opens `<userData>/nexus.db` in WAL mode
during `app.whenReady()`, before the window is created.

Two independent observations confirm it works in the packaged runtime: the packaged application
starts, creates `%APPDATA%\NEXUS\nexus.db` (plus `-wal`/`-shm` while running), and the startup
log records applied migrations. Electron 45 embeds a Node runtime that provides
`node:sqlite`, and the external reference means the bundler never tries to shim it.

**Verdict: VERIFIED.**

## 6. Standalone MCP bundle

`npm run build` runs `electron-vite build` and then `scripts/build-mcp.mjs`, which esbuilds
`src/mcp/server.ts` to `out/mcp/nexus-mcp.mjs` (ESM, `node22` target, `createRequire` banner) and
then fails the build if the output references `electron`, `ssh2`, `node:sqlite` or
`@napi-rs/keyring`.

The bundle is shipped through `extraResources` to
`release/win-unpacked/resources/mcp/nexus-mcp.mjs`. At runtime `src/main/index.ts` resolves it as
`join(process.resourcesPath, 'mcp', 'nexus-mcp.mjs')` when packaged, and as
`<appPath>/out/mcp/nexus-mcp.mjs` in development.

**Verdict: VERIFIED** (file present at the exact packaged path; the build-time guard also
passed).

## 7. `extraResources` vs `asarUnpack` duplication — defect found and fixed

`files: ["out/**", "package.json"]` packaged the whole `out/` tree into `app.asar`, including
`out/mcp/nexus-mcp.mjs`, while `extraResources` copied the same file to
`resources/mcp/nexus-mcp.mjs`. The packaged app only reads the `resources/` copy, so the asar
copy was dead weight of roughly 1.3 MB inside the archive.

Fix (narrow): add `"!out/mcp/**"` to `files`. The MCP bundle now exists exactly once, outside
the asar, at the path the app resolves at runtime. `asarUnpack` is unrelated to this file — it
only lifts `**/*.node` out of the archive — so no other overlap exists.

**Verdict: DEFECT FOUND → FIXED → VERIFIED** by `scripts/verify-package.mjs`
(`app.asar has no duplicated MCP bundle`).

## 8. Packaged resource hygiene — defect found and fixed

Checked by listing `app.asar` (8,452 entries) and walking `release/win-unpacked`:

| Category | Result |
| --- | --- |
| `src/`, `tests/`, `docs/`, `artifacts/` | absent |
| `userData` copies (`nexus.db*`), logs, `.env*`, `*.pem`/`*.key`/`*.p12`/`*.pfx` | absent |
| dependency bins (`node_modules/.bin`) | absent |
| sourcemaps | **found** — `@modelcontextprotocol/sdk` ships `*.d.ts.map` files |

Fix (narrow): add `"!**/*.map"` to `files`. Re-verified after repackaging: no `.map` entries
remain in the asar.

`scripts/verify-package.mjs` now enforces all of the above so the property cannot regress
silently; CI runs it after `npm run package`.

**Verdict: DEFECT FOUND → FIXED → VERIFIED.**

## 9. `build/icon.ico`

Parsed header: reserved `0`, type `1` (icon), image count `7`, 4,471 bytes — a multi-size ICO
(16–256 px), the format electron-builder expects for `win.icon`, `nsis.installerIcon`,
`uninstallerIcon` and `installerHeaderIcon`.

The previous configuration set `"signAndEditExecutable": false`, which disables **both** signing
and executable resource editing — so the executable kept Electron's default icon and version
resources. That flag was removed: no certificate is configured, so electron-builder still skips
signing (`no code signing certificate configured, signing is skipped`), but the resource edit
runs: `updating asar integrity executable resource ... NEXUS Terminal.exe`. The icon and version
block are therefore embedded in `NEXUS Terminal.exe` and the installer carries the icon in its
header/uninstall entry.

**Verdict: PARTIALLY VERIFIED.** Format, presence and the resource-edit pass are verified; the
rendered icon in Explorer, the Start Menu shortcut and the installer header were not visually
inspected (that requires a human looking at the desktop).

## 10. Product identity and metadata

| Field | Value | Where |
| --- | --- | --- |
| Product name | `NEXUS Terminal` | `build.productName`, installer, shortcut name |
| Application id | `com.nexus.terminal` | `build.appId` |
| Version | `1.0.0` | `package.json`, executable version resource, installer |
| Description | "A security-focused Windows SSH terminal with native command authorization, strict host-key verification, and a restricted Claude Code MCP integration." | `README.md` |
| Author / copyright | `Ray` / `Copyright © 2026 Ray` | `package.json` |
| License | MIT | `LICENSE` |
| Executable | `NEXUS Terminal.exe` | `release/win-unpacked` |
| Installer | `NEXUS-Terminal-Setup.exe` | `release/` |
| Archive | `NEXUS-Terminal-1.0.0-windows-x64-archive.zip` | `release/` |

One intentional difference: `src/main/index.ts` calls `app.setName('NEXUS')`, so `userData` is
`%APPDATA%\NEXUS`, not `%APPDATA%\NEXUS Terminal`, even though the product and shortcuts read
"NEXUS Terminal". This is a real incompatibility to change now — it is the existing data
location for every current install — and it is documented in the README rather than silently
"fixed" by renaming, which would orphan existing user databases.

**Verdict: PARTIALLY VERIFIED.** Names and version wiring are consistent and verified in the
packaging output; the `userData` name difference is intentional and documented.

## 11. `userData` path and uninstall data preservation

- Runtime path: `app.getPath('userData')` with `app.setName('NEXUS')` → `%APPDATA%\NEXUS`.
  `resolveAppPaths()` derives `logs/`, `nexus.db` and `bridge.json` from it.
- `nsis.perMachine: false` → per-user install under `%LOCALAPPDATA%\Programs\nexus-terminal`,
  no administrator prompt.
- `nsis.deleteAppDataOnUninstall: false` → the uninstaller removes program files, the Start Menu
  entry and the shortcut, and leaves `%APPDATA%\NEXUS` untouched. There is no opt-in "delete my
  data" checkbox: removal is a manual, deliberate action documented in the README, which is
  safer than a checkbox a user can tick by reflex.
- `nsis.differentialPackage: false` → no stale delta packages between versions.
- `nsis.oneClick: false` with `allowToChangeInstallationDirectory: true` → standard wizard with
  directory selection; `createStartMenuShortcut` and `createDesktopShortcut` are both enabled;
  `allowElevation: true` lets a user install machine-wide if they choose, without requiring it.

**Verdict: VERIFIED** at the configuration level and for the runtime path. The full
install → launch → uninstall → "data still present" cycle is recorded in
`docs/DISTRIBUTION-REPORT.md` with whatever portions could be executed non-interactively.

## 12. Code-signing assessment

### What Authenticode does

Authenticode is the Windows signing scheme for PE binaries. A publisher signs the executable and
installer with a private key; Windows verifies the signature against a certificate chaining to a
trusted root. It provides **integrity** (the file was not modified after signing) and
**publisher identity** (a name bound to a vetted organization or individual). It does not sandbox
the program and it is not an endorsement of behaviour.

### SmartScreen reputation

SmartScreen is a separate, reputation-based gate. It flags downloads and executions that have
low trust: new binaries, low download counts, and unsigned files. An Authenticode signature from
a reputable publisher starts accruing reputation; a new OV certificate for a brand-new publisher
still shows warnings until enough users have run the binary without incident. An EV certificate
is treated as immediately trustworthy by SmartScreen because of stricter identity vetting. So:
**signing reduces warnings, EV removes them sooner, and neither is instant.**

### OV vs EV

| | OV (organization validation) | EV (extended validation) |
| --- | --- | --- |
| Identity check | Business registration and callback verification | Stricter, hardware-token-bound key storage required |
| SmartScreen | Reputation must be earned over time | Trusted immediately at signing |
| Cost / friction | Lower; cloud HSM or file-based key allowed | Higher; hardware token or cloud HSM with attestation |
| Suitable for | First public releases that already document an unsigned path | Distributing to enterprises or high-warning-sensitive audiences |

### Why an unsigned 1.0.0 is acceptable

- There is no certificate in this project, and purchasing or fabricating one is explicitly out
  of scope. Shipping a fake or self-signed signature would be *worse* than none: it trains users
  to ignore certificate warnings.
- The distribution channel is a GitHub release page with published SHA-256 checksums, so users
  have a verifiable reference that does not depend on the signature.
- The alternative — withholding the release until a certificate exists — removes any chance of
  the OV certificate accruing SmartScreen reputation, which only starts when real users download
  and run a signed binary.
- The cost is a scary first-run dialog, so it is documented prominently in the README with an
  explicit "never disable Defender/SmartScreen" instruction and a hash-verification step.

### How signing secrets should be stored in GitHub Actions

The release workflow already contains an optional, secret-gated signing step. It activates only
when the repository secret `WINDOWS_CERTIFICATE_BASE64` is present, so unsigned releases keep
working unchanged.

- Store the `.pfx`/`.p12` as base64 in **repository or environment secret**
  `WINDOWS_CERTIFICATE_BASE64` (Settings → Secrets and variables → Actions). Never commit a
  certificate, a password, or a base64 blob to the repository.
- Store its password in secret `WINDOWS_CERTIFICATE_PASSWORD`. Optionally set the timestamp
  server as a repository *variable* `WINDOWS_TIMESTAMP_URL` (default
  `http://timestamp.digicert.com`).
- Prefer an **environment** with required reviewers for release secrets, so a tag push alone is
  not sufficient to spend the certificate. Do not expose these secrets to `pull_request` runs —
  the release workflow only triggers on `v*.*.*` tags.
- Prefer a cloud HSM / key-vault-backed signing service over a file certificate when available;
  a file certificate copied into a runner is the least protected option.
- After signing, the workflow recomputes `SHA256SUMS.txt`, because signing changes the file
  bytes.
- Rotate the certificate by replacing the secret; no code change is needed.

**Verdict: DOCUMENTED.** Signing itself is `NOT VERIFIED` — no certificate exists in this
environment, and no signed artifact was produced.

---

## Defects found by this audit

Both were proven by inspecting a real packaged build, both fixes are packaging-config only, and
neither touches application behaviour:

1. **Duplicated MCP bundle** — `out/mcp/nexus-mcp.mjs` was inside `app.asar` *and*
   `resources/mcp/`. Fixed with `"!out/mcp/**"` in `build.files`.
2. **Sourcemaps inside the asar** — `@modelcontextprotocol/sdk` ships `*.d.ts.map`. Fixed with
   `"!**/*.map"` in `build.files`.

## Configuration changes made after this audit

- `build.win.target` now pins `x64` for both `nsis` and `zip`.
- `build.win.artifactName` set for the archive; `nsis.artifactName` set to
  `NEXUS-Terminal-Setup.exe`.
- `build.win.signAndEditExecutable: false` removed so the executable carries its icon and version
  resources (signing still does not happen without a certificate).
- `nsis` extended with `createDesktopShortcut`, `createStartMenuShortcut`, `shortcutName`,
  `menuCategory: false`, `deleteAppDataOnUninstall: false`, `runAfterFinish`,
  `installerIcon`/`uninstallerIcon`/`installerHeaderIcon`, `differentialPackage: false`,
  `allowElevation`.
- `build.files` extended with `!out/mcp/**` and `!**/*.map`.
- New `scripts/verify-package.mjs` and the `npm run verify:package` script enforce the packaged
  contents.

No application code, SSH, authorization, MCP tool contract or Electron security behaviour was
changed.

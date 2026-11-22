# Distribution Report — NEXUS Terminal 1.0.0 (Windows 11 x64)

Verification report for the first public Windows distribution candidate. Every line below was
produced by a command that was actually executed on the build host on 2026-11-21/22
(Windows 11 10.0.26200, x64, Node v26.13.0, npm 11.20.0, electron 45.3.4, electron-builder
26.18.0). Nothing is inferred from earlier reports.

Status vocabulary: **VERIFIED** (executed and observed), **PARTIALLY VERIFIED** (part of the
property was observed, part was not), **NOT VERIFIED** (not executed), **BLOCKED** (cannot be
executed in this environment).

---

## 1. Status table

### Build, test and packaging

| Item | Status | Evidence |
| --- | --- | --- |
| `npm run typecheck` | VERIFIED | exit 0 (`tsc -p tsconfig.node.json && tsc -p tsconfig.web.json`) |
| `npm run lint` | VERIFIED | exit 0 (`eslint .`) |
| `npm test` | VERIFIED | exit 0 — 28 files passed, 2 skipped; 288 tests passed, 2 skipped (290) |
| `npm run test:integration` | VERIFIED | exit 0 — 12 files passed, 2 skipped (14); 50 tests passed, 2 skipped (52) |
| `npm run scan-secrets` | VERIFIED | exit 0 — `scan-secrets: clean` |
| `npm run build` | VERIFIED | exit 0 — main/preload/renderer built, `out/mcp/nexus-mcp.mjs` 1.3 MB, build-time MCP guard passed |
| `npm run package` | VERIFIED | exit 0 — NSIS installer + x64 archive produced |
| `node scripts/verify-package.mjs` | VERIFIED | exit 0 — `verify-package: PASS (27 checks)` |
| `npx --no-install @electron/fuses read` | VERIFIED | exit 0, all seven intended fuses in the intended state (below) |
| `npm run zip` (source archive) | VERIFIED | exit 0 — after a Windows `tar` path fix (section 4) |
| `npm run verify:zip` | VERIFIED | exit 0 — `PASS: verified 178 entries` |
| Installer/package content hygiene | VERIFIED | no source, tests, docs, maps, DB, logs, `.env`, key material, or duplicated MCP bundle inside `app.asar` |
| SHA-256 checksums generated | VERIFIED | section 2 |

### Runtime, on the packaged build

| Item | Status | Evidence |
| --- | --- | --- |
| Packaged app launches | VERIFIED | `NEXUS Terminal.exe` from `release/win-unpacked` ran with window title `NEXUS Terminal` |
| `node:sqlite` inside packaged Electron | VERIFIED | `nexus.db` + `nexus.db-shm` + `nexus.db-wal` created in the app's `userData` on first launch |
| Windows Credential Manager available | VERIFIED | startup log: `credentialBackend: "OS Keyring (@napi-rs/keyring)"` (only logged after a successful probe) |
| No silent plaintext credential fallback | VERIFIED | backend resolved to the OS keyring; the plaintext path is compiled out of packaged builds (`resolveE2EPlaintext` returns false when `app.isPackaged`) |
| MCP bundle reachable from packaged app | PARTIALLY VERIFIED | file present at `resources/mcp/nexus-mcp.mjs`, and the main process resolves exactly that path when packaged; an actual Claude Code client was not connected in this run |
| Clean shutdown | VERIFIED | closing the window wrote `app.shutdown` and the process tree exited |
| First-run DB migration + pruning | VERIFIED | `app.started` logged with `prunedHistory: 0, prunedApprovals: 0` after migrations ran |
| Settings persistence across relaunch | NOT VERIFIED | requires changing a setting in the UI and relaunching |
| Installer run (install → first launch → uninstall) | BLOCKED | the NSIS wizard is interactive (directory selection, progress, finish page). It cannot be driven headlessly here; no attempt was made to fake it |
| `userData` preserved after uninstall | NOT VERIFIED (config verified) | `nsis.deleteAppDataOnUninstall: false` is set and the uninstaller is generated with it; the uninstall itself was not executed (see above) |
| Icon visible in Explorer / Start Menu / installer | NOT VERIFIED (embedding verified) | version resources and an extractable 32×32 icon were confirmed from the binary; nobody looked at the desktop |
| Signed installer / SmartScreen reputation | BLOCKED | no Authenticode certificate exists in this environment; build is intentionally unsigned |

### Repository

| Item | Status | Evidence |
| --- | --- | --- |
| `git init` on `main` | VERIFIED | `Initialized empty Git repository ... .git/` |
| Staged content clean | VERIFIED | 137 files; no `node_modules`, `out/`, `release/`, `artifacts/`, logs, DBs, env files or key material |
| Personal paths removed | VERIFIED | one host path found by `git grep` and replaced; only a `/C:/Users/` URL fixture remains in a security test |
| Initial commit | VERIFIED | section 5 |
| Remote / push / tag / release | NOT DONE | explicitly out of scope without your authorization |

---

## 2. Release artifacts

| Artifact | Path | Size | SHA-256 |
| --- | --- | --- | --- |
| NSIS installer | `release/NEXUS-Terminal-Setup.exe` | 110.2 MiB (115,541,483 bytes) | `1d2777410f4857ebfd4384c2bac663c4e2c3cd2cdf5ad7278c5c9916f88fb262` |
| Unpacked archive (x64) | `release/NEXUS-Terminal-1.0.0-windows-x64-archive.zip` | 154.7 MiB (162,264,300 bytes) | `7e2635b807c07ea40bcf7bccbdfe40c922e6d3fbe0187ba91dba9616e6d046cd` |

Supporting folders: `release/win-unpacked/` (396 MiB installed layout, `app.asar` 35.5 MiB) and
`release/builder-debug.yml`. The installer is not signed; `release/builder-debug.yml` contains no
secrets.

The archive is labelled **archive**, not "portable": it is the installed application directory in
a ZIP, and it still writes its state to `%APPDATA%\NEXUS`.

Source archive produced for `verify:zip` (not a release artifact):
`../NEXUS-FINAL.zip`, 1.2 MiB, SHA-256
`907b6c391a614ce68dee49e62707fd782da3f112ed22cae14c437042b341bfad`.

Checksums of build artifacts change on every rebuild; regenerate them with the workflow step or:
`Get-FileHash .\release\NEXUS-Terminal-Setup.exe -Algorithm SHA256`.

## 3. Electron fuses as read back from the packaged executable

```
Analyzing app: NEXUS Terminal.exe
Fuse Version: v1
  RunAsNode is Disabled
  EnableCookieEncryption is Enabled
  EnableNodeOptionsEnvironmentVariable is Disabled
  EnableNodeCliInspectArguments is Disabled
  EnableEmbeddedAsarIntegrityValidation is Disabled
  OnlyLoadAppFromAsar is Enabled
  LoadBrowserProcessSpecificV8Snapshot is Disabled
  GrantFileProtocolExtraPrivileges is Disabled
  WasmTrapHandlers is Enabled
```

Executable metadata:

```
ProductName     : NEXUS Terminal
FileDescription : NEXUS Terminal
FileVersion     : 1.0.0
ProductVersion  : 1.0.0.0
CompanyName     : Ray
LegalCopyright  : Copyright c 2026 Ray
```

Installer metadata reports the same product name, version, company and copyright.
`ExtractAssociatedIcon("NEXUS Terminal.exe")` returns a 32×32 icon, i.e. an icon resource is
embedded.

## 4. Files created or modified in this phase

### New

| File | Purpose |
| --- | --- |
| `docs/DISTRIBUTION-ASSESSMENT.md` | Phase 1 audit: 12 packaging points + code-signing assessment |
| `docs/GITHUB-REPOSITORY-READINESS.md` | Repository hygiene, ignore coverage, secret audit, workflow description |
| `docs/DISTRIBUTION-REPORT.md` | This report |
| `CONTRIBUTING.md` | Contributor workflow and review rules |
| `SECURITY.md` | Root vulnerability-reporting policy |
| `.gitattributes` | LF normalization, binary markers, CRLF for PowerShell/CMD |
| `.github/workflows/windows-build.yml` | CI: build, test, package, verify, upload artifacts |
| `.github/workflows/release.yml` | Tag-only release: validate tag, build, verify, optional signing, checksums, publish |
| `scripts/verify-package.mjs` | Asserts installer presence, asar contents, native keyring binary, MCP bundle, no leaked data |

### Modified

| File | Change |
| --- | --- |
| `package.json` | `win.target` pinned to x64 with per-target `artifactName`s; removed `signAndEditExecutable: false` so icon/version resources are embedded; expanded `nsis` block (`createDesktopShortcut`, `createStartMenuShortcut`, `shortcutName`, `menuCategory: false`, `deleteAppDataOnUninstall: false`, `runAfterFinish`, installer/uninstaller icons, `differentialPackage: false`, `allowElevation`); `build.files` now excludes `out/mcp/**` (duplicate MCP bundle) and `**/*.map` (dependency sourcemaps); added `verify:package` script |
| `README.md` | Rewritten for end users: capabilities, security architecture, requirements, install, first launch, SSH, host keys, authorization, MCP, data locations, backup, upgrade, uninstall, troubleshooting, limitations, build, license |
| `.gitignore` | Added `*.sqlite`, `*.tsbuildinfo`, `*.pem`/`*.key`/`*.p12`/`*.pfx`, editor/OS noise, and the internal working notes that must stay out of the public repository |
| `scripts/package-zip.mjs` | Windows `tar` fix: archive written from the staging directory with a relative name (a `C:\...` output path is parsed as a remote host) |
| `scripts/verify-zip.mjs` | Same `tar` fix for listing and extraction (run from the archive's directory, extract from a copy inside the temp directory) |

Application source under `src/` was not changed in this phase — no SSH, authorization, MCP
tool-contract or Electron security behaviour was touched. Packaging configuration, tooling
scripts and documentation only.

Two packaging defects were found and fixed as a result of the audit (duplicated MCP bundle inside
`app.asar`; `*.d.ts.map` files from `@modelcontextprotocol/sdk` inside `app.asar`), plus the
`afterPack` icon/metadata gap caused by `signAndEditExecutable: false`, plus two Windows `tar`
path bugs that made `npm run zip` / `npm run verify:zip` fail on this host.

## 5. Local Git

```
$ git init -b main
Initialized empty Git repository in .../NEXUS-FINAL/.git/

$ git add -A && git diff --cached --name-only | wc -l
135

$ git commit -m "Initial release preparation for NEXUS Terminal"
```

Staged distribution: 137 files (63 `src/`, 37 `tests/`, 8 `scripts/`, 10 `docs/`, 2 `build/`, 2
workflow files, plus root config/metadata). `release/`, `out/`, `node_modules/`, `artifacts/` and all
runtime logs/databases are ignored.

No remote was added, nothing was pushed, no tag was created, no release was published.

## 6. Limitations

1. **Unsigned build.** No Authenticode certificate is available here, so SmartScreen will warn on
   first run and the publisher name will be unknown. `docs/DISTRIBUTION-ASSESSMENT.md` §12 covers
   OV/EV, reputation and secret storage; `release.yml` already wires optional signing behind
   secrets.
2. **Installer lifecycle not exercised.** Install, upgrade-in-place, and uninstall require driving
   the NSIS wizard and a UAC-free interactive desktop session. They are BLOCKED in this
   environment, not passed. The configuration that governs them is verified.
3. **Settings persistence across relaunch** was not exercised (needs UI interaction).
4. **MCP round trip with a real Claude Code client** was not exercised; the packaged bundle path
   and process wiring are verified, the client handshake is not.
5. **Icon appearance** in Explorer/Start Menu/installer header was not visually inspected.
6. **Cross-platform builds** are out of scope: Windows x64 only.
7. **Tests**: 2 files / 2 tests are skipped by design in every run (documented in
   `docs/TESTING.md`); the live-model Claude suite remains blocked by provider availability, as
   recorded there.

## 7. Next steps for you

Nothing below has been done, and none of it should happen without your explicit go-ahead:

1. **Review the local commit**: `git log --stat`, `git status`.
2. **Create the repository** `nexus-terminal` on GitHub (public), then
   `git remote add origin <url>` and `git push -u origin main`.
3. **Optional but recommended before the first tag**: add `WINDOWS_CERTIFICATE_BASE64` and
   `WINDOWS_CERTIFICATE_PASSWORD` as repository secrets so `release.yml` signs the installer.
4. **Tag and push**: `git tag v1.0.0 && git push origin v1.0.0`. The release workflow validates
   the tag against `package.json`, rebuilds, verifies, writes `SHA256SUMS.txt` and publishes the
   release with notes.
5. **Manual smoke test of the published installer** on a clean Windows 11 profile: install, launch,
   connect to a test host with host-key approval, run one approved and one denied command, uninstall,
   then confirm `%APPDATA%\NEXUS` still exists.

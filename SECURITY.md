# Security Policy

NEXUS Terminal is a security-focused SSH client. Reports about its security properties are
genuinely welcome — including reports that a control does not work as documented.

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Use GitHub's private vulnerability reporting on this repository
(**Security → Advisories → Report a vulnerability**). That channel is visible only to the
maintainers. If private reporting is unavailable to you, open a public issue that contains no
technical detail and ask for a private contact channel.

Please include:

- the affected version or commit,
- your Windows version and whether the build was installed or run from source,
- exact reproduction steps,
- what you expected and what happened,
- any log excerpt from `%APPDATA%\NEXUS\logs\nexus.log` **with host names, user names and
  credentials removed**.

Never include real credentials, private keys, production host names, or database files in a
report.

## Scope

In scope:

- the Electron main process, preload bridge and renderer isolation (sandbox, context
  isolation, CSP, `nexus-app://` protocol handler, origin and `webContents` pinning),
- SSH host-key verification and known-host pinning,
- command authorization, approvals and the native approval dialogs,
- the MCP bridge (named-pipe authentication, tool contract, per-server access),
- credential storage and the `safeStorage` fallback,
- database, audit-log and log-file handling, redaction, and packaged-artifact contents.

Out of scope:

- the deliberate non-goal that keystrokes typed directly into an interactive terminal are not
  approval-gated (see `docs/SECURITY.md`),
- attacks that require an already-compromised administrator account or physical access to an
  unlocked machine,
- third-party servers you connect to, and the OpenSSH server implementation itself,
- the SmartScreen warning shown for unsigned builds — this is expected and documented, not a
  vulnerability,
- missing code signing, missing auto-update, and the use of Electron's bundled Chromium
  version in itself.

## What to expect

- Acknowledgement of your report, normally within a few days.
- An assessment of severity and a fix or a documented limitation.
- Credit in the release notes if you want it.

## Supported versions

The project is at `1.0.x`. Security fixes land on `main` and are released as patch versions.
There is no long-term support branch yet.

## Known, documented limitations

Read `docs/SECURITY.md` before reporting. It lists the accepted limitations, including the
interactive-keystroke consequence, the absence of a remote-update channel, and the fact that
private keys are read from disk at connect time rather than handled by an agent.

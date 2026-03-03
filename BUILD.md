# Parad0x Command Build Notes

This file summarizes the packaged Parad0x Command release.

Owner: `Parad0x Labs`
Contributor: `@sls_0x`

## Runtime Surface

- Main runtime: `tools/liquefy_desktop_viz.py`
- Main regression suite: `tests/test_desktop_viz.py`
- Wrapper entry point: `parad0x-command`
- One-command setup wrappers:
  - `setup.sh`
  - `setup.ps1`
  - `setup.bat`
- Cross-platform launchers:
  - `Start Parad0x Command on Windows.cmd`
  - `Start Parad0x Command on Linux.sh`
  - `Start Parad0x Command on macOS.command`

## Current Release Expectations

- Local-only server on `127.0.0.1`
- Desktop graph with app nodes, process families, helper orbitals, and hardware nodes
- Multiple inspector cards open at the same time
- Network cut and restore controls
- Browser-tab visibility that depends on what the host OS and browser expose

## Security Features In This Release

- Per-run random API token
- Auth required for `/api/*`
- Dangerous actions moved to authenticated `POST`
- Loopback host and origin or referrer checks
- Wildcard CORS removed from live stats

## Known Platform Limits

- macOS Safari tab discovery is the strongest path.
- Windows and Linux Chromium-family browsers may need a debug port for best tab visibility.
- Linux VM, VNC, or minimal desktop sessions may expose only weak browser-window metadata.

## Release Checklist

Before tagging or pushing:

- README is human-readable and free of personal absolute paths.
- AGENTS.md is repo-specific, not inherited from an upstream project.
- Root `.gitignore` excludes caches, zips, local backups, and generated release artifacts.
- Launcher names in docs match the actual files in the package.
- `pytest -q tests/test_desktop_viz.py` passes after runtime changes.

## Packaging Notes

Do not treat these as source-of-truth release files unless explicitly requested:

- `*.zip`
- `*.failover`
- `*.production`
- `*.windows_failover`

Those are operational or backup artifacts, not the clean repo surface.

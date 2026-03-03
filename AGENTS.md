# Parad0x Command Agent Guide

This file is for external AI agents, operator shells, and automation clients that need to install, launch, or operate Parad0x Command.

Owner: `Parad0x Labs`
Contributor: `@sls_0x`

## Purpose

Parad0x Command provides a local desktop command surface for:

- apps
- process families
- helper subprocesses
- browser activity
- files
- agents
- machine telemetry

It is designed to run on the same machine it observes.

## Install

From the extracted or cloned folder, use one setup command:

```bash
bash ./setup.sh
```

```powershell
.\setup.ps1
```

```cmd
setup.bat
```

Fresh install from GitHub:

```bash
git clone https://github.com/Parad0x-Labs/Parad0x-Command.git && cd Parad0x-Command && bash ./setup.sh
```

```powershell
git clone https://github.com/Parad0x-Labs/Parad0x-Command.git; Set-Location .\Parad0x-Command; .\setup.ps1
```

## Launch

Preferred launchers:

- `Start Parad0x Command on Windows.cmd`
- `Start Parad0x Command on Linux.sh`
- `Start Parad0x Command on macOS.command`

Direct terminal launch:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_parad0x_command_export.ps1
```

```bash
bash ./run_parad0x_command_export.sh
```

Direct CLI:

```bash
./parad0x-command live . --workspace . --desktop --port 8776
```

```bash
./parad0x-command native . --workspace . --desktop --port 8774
```

## What To Expect

- Local interactive graph of apps, processes, browser surfaces, files, agents, and hardware nodes.
- Inspector cards for clicked nodes.
- Multiple inspector cards can stay open at the same time.
- Local process controls and network controls.
- Browser-tab visibility depends on what the operating system and browser expose.

## Platform Notes

- macOS Safari provides the strongest live tab visibility.
- Windows and Linux Chromium-family browsers are strongest when launched with `--remote-debugging-port=9222`.
- Windows and Linux may fall back to browser window titles when real tab metadata is unavailable.
- Linux VM, VNC, stripped desktop, or locked-down Wayland sessions can expose limited browser metadata.

## Security Model

Parad0x Command is local-first and is not intended to be exposed as a remote service.

- The server binds to `127.0.0.1` only.
- Each run generates a random in-memory API token.
- `/api/*` requests require that token.
- Dangerous actions require authenticated `POST`.
- Loopback host and origin or referrer checks are enforced where relevant.
- Wildcard CORS is not enabled for live stats.

Practical meaning:

- Other machines cannot directly access the service in the default setup.
- The localhost control surface is hardened against trivial unauthenticated browser-triggered requests.
- It remains a local desktop tool, not a multi-user remote control server.

## Operational Notes

- Windows network cut prefers WLAN disconnect.
- Windows network restore prefers reconnecting the previously used Wi-Fi profile.
- Adapter disable or enable is only a fallback path.

## Validation

If you modify the runtime, validate with:

```bash
pytest -q tests/test_desktop_viz.py
```

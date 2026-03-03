# Parad0x Command

Local-only command surface for apps, processes, browser activity, files, agents, and machine telemetry.

Owner: `Parad0x Labs`
Contributor: `@sls_0x`

License: `MIT`
See [LICENSE](LICENSE).

## Overview

Parad0x Command runs a local desktop graph and inspector on `127.0.0.1`. It is meant for live situational awareness on the same machine where it is launched.

What it includes:

- App nodes, process families, helper subprocess orbitals, and hardware/system nodes.
- Clickable node inspectors with multiple cards open at the same time.
- Local controls for process actions and network cut/restore.
- Browser tabs when the platform exposes them strongly enough.
- No cloud dependency and no remote dashboard by default.

## One-Command Setup

If the folder is already on the machine, setup can be done with a single command from the repo root:

```bash
bash ./setup.sh
```

```powershell
.\setup.ps1
```

```cmd
setup.bat
```

This installs the local environment and prepares the launchers.

Fresh install from GitHub:

```bash
git clone https://github.com/Parad0x-Labs/Parad0x-Command.git && cd Parad0x-Command && bash ./setup.sh
```

```powershell
git clone https://github.com/Parad0x-Labs/Parad0x-Command.git; Set-Location .\Parad0x-Command; .\setup.ps1
```

## Quick Start

After extracting the folder, use the launcher that matches the machine:

```text
Start Parad0x Command on Windows.cmd
Start Parad0x Command on Linux.sh
Start Parad0x Command on macOS.command
```

Direct terminal launch:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_parad0x_command_export.ps1
```

```bash
bash ./run_parad0x_command_export.sh
```

Windows note:

- `Start Parad0x Command on Windows.cmd` is the preferred launcher.
- It self-elevates so network controls have the permissions they usually need.

## Direct CLI

Live browser UI:

```bash
./parad0x-command live . --workspace . --desktop --port 8776
```

Native window mode:

```bash
./parad0x-command native . --workspace . --desktop --port 8774
```

Use any target path or workspace path you want. The examples above intentionally use relative paths so the package stays portable.

## Platform Expectations

Browser tabs are not equally strong on every OS:

- macOS Safari: strongest live tab visibility.
- Windows Chrome or Edge: best when the browser exposes a Chromium debug endpoint.
- Linux desktop sessions: works best on a full desktop session with X11 or accessible browser session data.
- Linux VM, VNC, stripped desktop, or locked-down Wayland sessions can expose much less metadata.

If Chrome or Edge needs stronger tab visibility on Windows or Linux, launch the browser with:

```text
--remote-debugging-port=9222
```

Windows and Linux can fall back to browser window titles when true per-tab metadata is unavailable.

## Security Hardening

This release runs locally and includes explicit protections for its localhost control surface.

- The server binds to `127.0.0.1` only.
- Each run generates a random in-memory API token.
- `/api/*` requests must present that token.
- Dangerous actions require authenticated `POST`, not unauthenticated `GET`.
- Loopback `Host` plus origin or referrer checks are enforced where relevant.
- Wildcard CORS was removed, so normal websites cannot read local stats from the running session.

Practical meaning:

- Other machines cannot directly reach it over the network in the default setup.
- While running, it is substantially more resistant to unauthorized browser-triggered localhost requests than a raw unauthenticated local control panel.
- It is still a local desktop tool, not a hardened multi-user server.

## Controls

Available controls vary by platform and permissions, but the release is designed around:

- Open URL or app actions from inspector cards.
- Force-close and hard-kill process actions.
- Network cut and restore.
- Multi-card comparison by opening multiple inspector panels at once.

Windows network behavior:

- Wi-Fi cut prefers WLAN disconnect.
- Wi-Fi restore prefers reconnecting the previously used Wi-Fi profile.
- Adapter disable or enable is now only a fallback path.

## Observed Load

Observed on an active Safari tab during testing:

- Traffic pulse: `100%`
- Safari CPU share: `41.9%`
- Approx CPU load: `0.42 / 10 core-equiv`
- Safari memory share: `0.8%`
- Approx Safari RAM: `196.6 MB`

These values depend on the active tab and all other foreground or background processes. They can be much lower or much higher in real use.

Share values are estimated from the current Safari family load, not total machine usage.

## Included Launchers

The packaged release includes:

- `Start Parad0x Command on Windows.cmd`
- `Start Parad0x Command on Linux.sh`
- `Start Parad0x Command on macOS.command`
- `run_parad0x_command_export.ps1`
- `run_parad0x_command_export.sh`
- `parad0x-command`

## Repository Name

Product name:

- `Parad0x Command`

GitHub repository slug:

- `Parad0x-Command`

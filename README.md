# Parad0x Command

![License: MIT](https://img.shields.io/badge/License-MIT-green.svg) ![Mode: Local First](https://img.shields.io/badge/Mode-Local--First-0b0f1a) ![Access: 127.0.0.1](https://img.shields.io/badge/Access-127.0.0.1-blue) ![Platforms: macOS Windows Linux](https://img.shields.io/badge/Platforms-macOS%20%7C%20Windows%20%7C%20Linux-111827)

**Local-first desktop command surface for apps, processes, browser activity, files, agents, and system telemetry.**

Parad0x Command runs on the same machine it observes and renders a live local graph for operational awareness. It is built for direct desktop use, not for remote hosting.

Owner: `Parad0x Labs`  
Contributor: `@sls_0x`  
License: [MIT](./LICENSE)

## Why Parad0x Command

- Live graph of apps, process families, helper subprocesses, files, agents, and hardware nodes.
- Clickable inspector cards with multi-card comparison.
- Local process controls and network cut or restore controls.
- Browser visibility when the host platform exposes the required metadata.
- No cloud dependency and no remote dashboard by default.

## Quick Start

### One-command setup from GitHub

**macOS / Linux**

```bash
git clone https://github.com/Parad0x-Labs/Parad0x-Command.git && cd Parad0x-Command && bash ./setup.sh
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/Parad0x-Labs/Parad0x-Command.git; Set-Location .\Parad0x-Command; .\setup.ps1
```

**Windows (CMD)**

```cmd
git clone https://github.com/Parad0x-Labs/Parad0x-Command.git && cd Parad0x-Command && setup.bat
```

### Setup from an extracted folder

```bash
bash ./setup.sh
```

```powershell
.\setup.ps1
```

```cmd
setup.bat
```

## Launch

### Preferred launchers

```text
Start Parad0x Command on Windows.cmd
Start Parad0x Command on Linux.sh
Start Parad0x Command on macOS.command
```

### Direct terminal launch

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\run_parad0x_command_export.ps1
```

```bash
bash ./run_parad0x_command_export.sh
```

### Direct CLI

Live browser UI:

```bash
./parad0x-command live . --workspace . --desktop --port 8776
```

Native window mode:

```bash
./parad0x-command native . --workspace . --desktop --port 8774
```

Windows note:

- `Start Parad0x Command on Windows.cmd` is the preferred launcher.
- It self-elevates so network controls have the permissions they usually need.

## Security Model

Parad0x Command is local-first and includes explicit protections around its localhost control surface.

- The server binds to `127.0.0.1` only.
- Each run generates a random in-memory API token.
- `/api/*` requests must present that token.
- Dangerous actions require authenticated `POST`, not unauthenticated `GET`.
- Loopback `Host` plus origin or referrer checks are enforced where relevant.
- Wildcard CORS was removed, so normal websites cannot read local stats from the running session.

Practical meaning:

- Other machines cannot directly reach it over the network in the default setup.
- The local control surface is substantially more resistant to unauthorized browser-triggered requests than a raw unauthenticated localhost panel.
- It is a local desktop tool, not a multi-user remote control server.

## Platform Notes

Browser visibility is platform-dependent:

- macOS Safari provides the strongest live tab visibility.
- Windows Chrome or Edge work best when the browser exposes a Chromium debug endpoint.
- Linux works best on a full desktop session with accessible browser or X11 session data.
- Linux VM, VNC, stripped desktop, or locked-down Wayland sessions can expose much less metadata.

If Chrome or Edge needs stronger tab visibility on Windows or Linux, launch the browser with:

```text
--remote-debugging-port=9222
```

Windows and Linux can fall back to browser window titles when true per-tab metadata is unavailable.

## Operational Notes

- Multiple inspector cards can remain open at the same time.
- Wi-Fi cut on Windows prefers WLAN disconnect.
- Wi-Fi restore on Windows prefers reconnecting the previously used Wi-Fi profile.
- Adapter disable or enable is only a fallback path.

## Resource Snapshot

Observed on an active Safari tab during testing:

- Traffic pulse: `100%`
- Safari CPU share: `41.9%`
- Approx CPU load: `0.42 / 10 core-equiv`
- Safari memory share: `0.8%`
- Approx Safari RAM: `196.6 MB`

These values depend on the active tab and all other foreground or background processes. They can be lower or much higher in real use.

Share values are estimated from the current Safari family load, not total machine usage.

## Included Launchers

- `Start Parad0x Command on Windows.cmd`
- `Start Parad0x Command on Linux.sh`
- `Start Parad0x Command on macOS.command`
- `run_parad0x_command_export.ps1`
- `run_parad0x_command_export.sh`
- `parad0x-command`

## Repository

Product name:

- `Parad0x Command`

GitHub repository slug:

- `Parad0x-Command`
